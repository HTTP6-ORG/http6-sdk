package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func readArtifact(dir, name string) (any, error) {
	b, e := os.ReadFile(filepath.Join(dir, name))
	if e != nil {
		return nil, e
	}
	return parse(b)
}
func readDB(dir, role string) (*database, error) {
	p := filepath.Join(dir, role+".sqlite")
	if _, e := os.Stat(p); e != nil {
		return nil, e
	}
	return openReadOnlyDB(p)
}
func verifyNative(p M, key, kind string) error {
	r := obj(p["result"])
	out := obj(r["publicResponse"])
	digest := hash("circuit-result", r)
	if digest != st(p, "resultHash") || st(r, "verifierKey") != key || st(r, "kind") != kind || st(r, "verdict") != "accepted" || integer(out, "rounds") != 12 {
		return errors.New("native public result mismatch")
	}
	pk, e := hex.DecodeString(key)
	if e != nil || len(pk) != 32 {
		return errors.New("invalid native public key")
	}
	for _, pair := range [][2]string{{digest, st(p, "signature")}, {st(out, "outputHash"), st(out, "outputSignature")}} {
		msg, e := hex.DecodeString(pair[0])
		if e != nil || len(msg) != 32 {
			return errors.New("invalid native output hash")
		}
		sig, e := raw64.DecodeString(pair[1])
		if e != nil || !ed25519.Verify(pk, msg, sig) {
			return errors.New("invalid native output signature")
		}
	}
	if kind == "call" || kind == "response" {
		tr := obj(out["transcript"])
		rounds, ok := tr["rounds"].([]any)
		if !ok || len(rounds) != 12 || tr["attemptHash"] != r["contextHash"] || tr["challenge"] != r["challenge"] {
			return errors.New("native transcript mismatch")
		}
		for n, v := range rounds {
			if integer(obj(v), "round") != int64(n+1) || len(st(obj(v), "responseCommitment")) != 64 {
				return errors.New("invalid native transcript round")
			}
		}
		calculated := hash("native-output", M{"attempt": r["contextHash"], "challenge": r["challenge"], "circuit": r["circuitDigest"], "transcriptHash": hash("transcript", tr), "successPayloadHash": tr["successPayloadHash"], "successTag": tr["successTag"]})
		if calculated != st(out, "outputHash") {
			return errors.New("transcript output mismatch")
		}
	}
	return nil
}

type recordedEvent struct {
	seq                        int64
	label, actor, channel, ref string
	data                       M
}

func audit(out string, write bool) error {
	tv, e := readArtifact(out, "trust.json")
	if e != nil {
		return e
	}
	t := obj(tv)
	responseVerifier, e := newGuest(binPath(), "verifier")
	if e != nil {
		return e
	}
	defer responseVerifier.close()
	if _, e = responseVerifier.call("configure", M{"trust": t}); e != nil {
		return e
	}

	fam, e := readArtifact(out, "families.json")
	if e != nil {
		return e
	}
	families := obj(fam)
	tests, e := readArtifact(out, "tests.json")
	if e != nil {
		return e
	}
	results, ok := tests.([]any)
	if !ok || len(results) == 0 {
		return errors.New("missing test results")
	}
	stores := map[string]*ledger{}
	totalEntries, totalOps := 0, 0
	chainHeads := M{}
	counts := M{}
	perOp := map[string][]recordedEvent{}
	denials := map[string]bool{}
	for _, name := range []string{"ledger", "local-ledger"} {
		key := st(t, "ledgerKey")
		snapshotName := "public-ledger.json"
		if name == "local-ledger" {
			key = st(t, "localLedgerKey")
			snapshotName = "local-ledger.json"
		}
		ld, e := readDB(out, name)
		if e != nil {
			return e
		}
		defer ld.close()
		store := &ledger{db: ld}
		stores[name] = store
		events, e := ld.query("SELECT * FROM events ORDER BY seq")
		if e != nil {
			return e
		}
		snapshot, e := readArtifact(out, snapshotName)
		if e != nil {
			return e
		}
		if !bytesEqual(snapshot, events) {
			return errors.New("snapshot differs from durable " + name)
		}
		totalEntries += len(events)
		counts[name] = len(events)
		prev := ""
		for i, row := range events {
			token := st(row, "signature")
			m, e := readSigned(token, key, "ledger-entry")
			if e != nil {
				return e
			}
			seq := int64(i + 1)
			ref := sha([]byte(token))
			data, e := parse([]byte(st(row, "data")))
			if e != nil {
				return e
			}
			if st(m, "prev") != prev || integer(m, "seq") != seq || st(row, "ref") != ref || st(row, "seq") != strconv.Itoa(i+1) || !bytesEqual(m["data"], data) {
				return errors.New("ledger hash chain or row corrupted")
			}
			for _, k := range []string{"actor", "op", "event", "channel"} {
				if st(m, k) != st(row, k) {
					return errors.New("ledger indexed metadata mismatch")
				}
			}
			d := obj(m["data"])
			actor := st(m, "actor")
			ev := recordedEvent{seq, st(m, "event"), actor, st(m, "channel"), ref, d}
			op := st(m, "op")
			perOp[op] = append(perOp[op], ev)
			prev = ref
			if ref := st(d, "controlProofRef"); ref != "" {
				p, e := store.get("objects", ref)
				if e != nil {
					return e
				}
				if hash("proof", p) != ref {
					return errors.New("control evidence address mismatch")
				}
				if e = verifyNative(obj(p), controlKey(t, actor), "ledger-control"); e != nil {
					return e
				}
			}
			if st(d, "decision") == "POLICY_DENIED" && d["proofVerified"] == true && d["policyAllowed"] == false && st(d, "stateBefore") == "ISSUED" && ev.channel == "restricted" && op == actor+"-second-channel" {
				denials[actor] = d["stateAfter"] == "REJECTED"
			}
		}
		chainHeads[name] = prev
	}
	if hash("semantics", t["manifest"]) != st(t, "semantics") || !bytesEqual(obj(t["manifest"])["routes"], t["routes"]) {
		return errors.New("semantic manifest binding")
	}
	builds, e := readArtifact(out, "builds.json")
	if e != nil {
		return e
	}
	if obj(builds)["mint.wasm"] != t["mintBuild"] || obj(builds)["child.wasm"] != t["childBuild"] || obj(builds)["work.wasm"] != obj(t["manifest"])["workerSHA256"] || obj(builds)["http6-pilot"] != obj(t["manifest"])["pilotSHA256"] {
		return errors.New("build evidence mismatch")
	}
	actualRows := map[string][]M{}
	totals := M{}
	allowedOps := map[string]bool{}
	total := 0
	for _, r := range audiences {
		store := stores["local-ledger"]
		if r == "endpoint" {
			store = stores["ledger"]
		}
		if !denials[r] {
			return fmt.Errorf("%s lacks a signed unspent policy denial", r)
		}
		f := obj(families[r])
		grantRef := sha([]byte(st(f, "child")))
		fv, e := store.get("families", grantRef)
		if e != nil || !bytesEqual(fv, f) {
			return errors.New("public family missing or changed")
		}
		origin, e := readSigned(st(f, "origin"), st(t, "operator"), "certified-origin")
		if e != nil {
			return e
		}
		root, e := readSigned(st(f, "root"), st(t, "mint"), "root")
		if e != nil {
			return e
		}
		rt := obj(root["terms"])
		rp := f["rootPolicy"]
		rr := sha([]byte(st(f, "root")))
		originRef := sha([]byte(st(f, "origin")))
		if e = verifyNative(obj(f["rootProof"]), st(t, "mint"), "root-admission"); e != nil {
			return e
		}
		rc := hash("root-ceremony", M{"policy": rp, "terms": rt})
		approval, e := readSigned(st(root, "approval"), st(origin, "key"), "approval")
		if e != nil {
			return e
		}
		if st(approval, "contextHash") != rc || st(obj(obj(f["rootProof"])["result"]), "contextHash") != rc || st(origin, "policyHash") != hash("policy", rp) || st(rt, "originRef") != originRef || st(root, "proofRef") != hash("proof", f["rootProof"]) {
			return errors.New("root origin or ceremony binding failed")
		}
		child, e := readSigned(st(f, "child"), st(t, "mint"), "grant")
		if e != nil {
			return e
		}
		ct := obj(child["terms"])
		ph := hash("policy", f["policy"])
		bc := hash("birth", M{"policy": f["policy"], "terms": ct})
		if st(ct, "rootRef") != rr || st(ct, "parentRef") != rr || st(ct, "originRef") != originRef || st(ct, "policyHash") != ph || st(ct, "policyAddress") != st(obj(obj(t["routes"])[r]), "ledger")+api+"policies/"+ph {
			return errors.New("child heredity mismatch")
		}
		if e = verifyNative(obj(f["birthProof"]), st(t, "mint"), "child-birth"); e != nil {
			return e
		}
		join, e := readSigned(st(child, "join"), st(ct, "key"), "join")
		if e != nil {
			return e
		}
		parent, e := readSigned(st(child, "parentRequest"), st(rt, "key"), "request_grant")
		if e != nil {
			return e
		}
		if st(join, "contextHash") != bc || st(parent, "contextHash") != bc || st(parent, "joinRef") != sha([]byte(st(child, "join"))) || st(obj(obj(f["birthProof"])["result"]), "contextHash") != bc || st(child, "proofRef") != hash("proof", f["birthProof"]) || parent["proofRef"] != child["proofRef"] {
			return errors.New("parent authorization or join binding failed")
		}
		for _, p := range []any{rp, f["policy"]} {
			pol, e := store.get("policies", hash("policy", p))
			if e != nil || !bytesEqual(pol, p) {
				return errors.New("public policy absent or mismatched")
			}
		}
		db, e := readDB(out, r)
		if e != nil {
			return e
		}
		rows, e := db.query("SELECT * FROM effects ORDER BY rowid")
		if e != nil {
			db.close()
			return e
		}
		checks, e := db.query("SELECT * FROM checks ORDER BY id")
		db.close()
		if e != nil {
			return e
		}
		denied := false
		for _, row := range checks {
			if row["decision"] == "POLICY_DENIED" && row["channel"] == "restricted" && row["op"] == r+"-second-channel" {
				for _, ev := range perOp[st(row, "op")] {
					if ev.ref == st(row, "eventRef") && ev.actor == r && ev.data["policyAllowed"] == false {
						denied = true
					}
				}
			}
		}
		if !denied {
			return errors.New("resource did not record the signed policy denial")
		}
		actualRows[r] = rows
		totals[r] = M{"allowed": len(rows), "restricted": 0}
		total += len(rows)
		for _, row := range rows {
			op := st(row, "op")
			if allowedOps[op] || row["state"] != "ACTED" || row["channel"] != "allowed" {
				return errors.New("unexpected or duplicate resource effect")
			}
			allowedOps[op] = true
			observed, e := parse([]byte(st(row, "result")))
			if e != nil {
				return e
			}
			receipt, e := readSigned(st(row, "receipt"), controlKey(t, r), "outcome")
			if e != nil {
				return e
			}
			if st(receipt, "resultHash") != sha(canon(observed)) || st(receipt, "op") != op || st(receipt, "observation") != st(row, "resource") || st(receipt, "redemptionId") != st(row, "redemption") || st(receipt, "recipient") != st(ct, "key") {
				return errors.New("resource outcome mismatch")
			}
			var proved, issued, broker, checked, redeemed, settled, responseChallenge, responseProved, confirmed int64
			for _, ev := range perOp[op] {
				switch ev.label {
				case "REQUEST_PROVED":
					proved = ev.seq
				case "CERTIFICATE_ISSUED":
					issued = ev.seq
				case "CHECKED":
					if ev.data["decision"] != "ELIGIBLE" {
						continue
					}
					if ev.actor == r && checked == 0 {
						checked = ev.seq
					}
					if ev.actor == "broker" && broker == 0 {
						broker = ev.seq
					}
				case "REDEEMED":
					if ev.ref == st(row, "validationRef") {
						redeemed = ev.seq
					}
				case "CUSTODIAN_OUTCOME":
					if st(ev.data, "receiptRef") == sha([]byte(st(row, "receipt"))) {
						settled = ev.seq
					}
				case "RESPONSE_CHALLENGED":
					responseChallenge = ev.seq
				case "RESPONSE_PROVED":
					responseProved = ev.seq
				case "BROKER_CONFIRMED":
					confirmed = ev.seq
				}
			}
			if !(proved > 0 && proved < issued && issued < checked && checked < redeemed && redeemed < settled) {
				return fmt.Errorf("missing pre-effect authorization for %s", op)
			}
			if !(issued < broker && broker < checked && settled < responseChallenge && responseChallenge < responseProved && responseProved < confirmed) {
				return fmt.Errorf("missing independent broker check or native response proof for %s", op)
			}
			ops, err := store.db.query("SELECT certificate,certRef FROM operations WHERE audience=? AND op=?", r, op)
			if err != nil || len(ops) != 1 {
				return errors.New("missing response operation")
			}
			rs, err := store.db.query("SELECT * FROM response_challenges WHERE certRef=? AND state='PROVED'", st(ops[0], "certRef"))
			if err != nil || len(rs) != 1 {
				return errors.New("missing ledger-recorded response proof")
			}
			context, err := store.get("objects", st(rs[0], "contextHash"))
			if err != nil {
				return err
			}
			proof, err := store.get("objects", st(rs[0], "proofRef"))
			if err != nil {
				return err
			}
			if err = verifyNative(obj(proof), st(obj(obj(obj(t["controls"])[r])["policy"]), "responseVerifier"), "response"); err != nil {
				return err
			}
			events, err := store.db.query("SELECT signature FROM events WHERE ref=?", st(rs[0], "eventRef"))
			if err != nil || len(events) != 1 {
				return errors.New("missing response event")
			}
			pkg := M{"context": context, "proof": proof, "challenge": rs[0]["challenge"], "certificate": ops[0]["certificate"], "receipt": row["receipt"]}
			if _, err = responseVerifier.call("historical-response", M{"response": pkg, "entry": events[0]["signature"]}); err != nil {
				return err
			}
			if st(obj(context), "resultHash") != sha(canon(observed)) {
				return errors.New("response payload digest mismatch")
			}

		}
	}
	for name, store := range stores {
		key := st(t, "ledgerKey")
		if name == "local-ledger" {
			key = st(t, "localLedgerKey")
		}
		operations, e := store.db.query("SELECT * FROM operations")
		if e != nil {
			return e
		}
		totalOps += len(operations)
		for _, row := range operations {
			if (name == "ledger") != (row["audience"] == "endpoint") {
				return errors.New("operation recorded on wrong ledger")
			}
			cert, e := readSigned(st(row, "certificate"), key, "certificate")
			if e != nil {
				return e
			}
			op := st(cert, "op")
			aud := st(cert, "audience")
			f := obj(families[aud])
			ct := obj(peek(st(f, "child"))["terms"])
			if st(row, "certRef") != sha([]byte(st(row, "certificate"))) || row["op"] != op || row["audience"] != aud || cert["policyHash"] != ct["policyHash"] || cert["grantRef"] != sha([]byte(st(f, "child"))) || integer(cert, "exp")-integer(cert, "nbf") > 5 {
				return errors.New("issued certificate scope mismatch")
			}
			pv, e := store.get("objects", st(cert, "proofRef"))
			if e != nil {
				return e
			}
			pr := obj(pv)
			if e = verifyNative(pr, st(t, "verifier"), "call"); e != nil {
				return e
			}
			result := obj(pr["result"])
			rq, e := store.get("objects", st(cert, "requestRef"))
			if e != nil {
				return e
			}
			req, ok := rq.(string)
			if !ok {
				return errors.New("bad public request")
			}
			request, e := readSigned(req, st(ct, "key"), "request")
			if e != nil {
				return e
			}
			if st(result, "contextHash") != hash("attempt", request["attempt"]) || st(result, "policyHash") != st(ct, "policyHash") || result["policyAddress"] != ct["policyAddress"] || result["circuitDigest"] != ct["circuitDigest"] || sha([]byte(req)) != st(cert, "requestRef") || hash("proof", pr) != st(cert, "proofRef") || request["proofRef"] != cert["proofRef"] {
				return errors.New("public per-call proof binding mismatch")
			}
			ev := perOp[op]
			if len(ev) == 0 || ev[0].label != "REQUEST_PROVED" {
				return errors.New("agent request missing")
			}
			record := ev[0].data
			transcript, e := store.get("objects", st(record, "transcriptRef"))
			if e != nil || !bytesEqual(transcript, obj(result["publicResponse"])["transcript"]) {
				return errors.New("missing transcript")
			}
			body, e := store.get("objects", st(record, "bodyRef"))
			if e != nil || hash("request-body", body) != st(record, "bodyRef") || st(obj(body), "request") != req {
				return errors.New("missing original call body")
			}
			if strings.HasSuffix(op, "-second-channel") && row["state"] != "REJECTED" {
				return errors.New("policy rejection did not close request")
			}
			if op == "endpoint-expired" && row["state"] != "EXPIRED" {
				return errors.New("held proof did not expire")
			}
			if (row["state"] == "COMMITTED") != allowedOps[op] || row["state"] == "REDEEMED" {
				return errors.New("ledger and actual effects disagree")
			}
		}
	}
	if len(actualRows["wallet"]) != 3 || len(actualRows["endpoint"]) != 6 || len(actualRows["process"]) != 2 || len(actualRows["database"]) != 2 {
		return errors.New("wrong number of actual resource actions")
	}
	for _, v := range results {
		if obj(v)["pass"] != true {
			return errors.New("failed test in evidence")
		}
	}
	wallet, e := readDB(out, "wallet")
	if e != nil {
		return e
	}
	defer wallet.close()
	balance, e := wallet.query("SELECT sats FROM funds WHERE account='fixture'")
	if e != nil || len(balance) != 1 || balance[0]["sats"] != "7750" {
		return errors.New("unexpected synthetic wallet balance")
	}
	for _, row := range actualRows["wallet"] {
		debits, e := wallet.query("SELECT recipient,sats FROM spends WHERE op=?", st(row, "op"))
		if e != nil || len(debits) != 1 || debits[0]["recipient"] != "merchant-a" {
			return errors.New("synthetic wallet posting mismatch")
		}
	}
	if write {
		summary := M{"tests": len(results), "signedLedgerEntries": totalEntries, "entriesPerLedger": counts, "issuedRequests": totalOps, "effects": totals, "chainHeads": chainHeads, "walletBalanceSatoshis": 7750, "allPassed": true}
		if e = artifact(filepath.Join(out, "summary.json"), summary); e != nil {
			return e
		}
		var b bytes.Buffer
		fmt.Fprint(&b, "# HTTP6 local Wasmer delegation results\n\n")
		fmt.Fprintf(&b, "All %d checks passed. The public and host-local ledgers recorded %d signed entries and %d distinct certified calls. The four resources recorded %d actions. Each resource refused a live, correctly signed proof on its restricted channel. That rejection closed the request. A fresh proof authorized the next permitted call.\n\n", len(results), totalEntries, totalOps, total)
		fmt.Fprint(&b, "| Resource | Allowed operation | Observed result | Allowed actions | Restricted actions |\n|---|---|---|---:|---:|\n")
		for _, r := range audiences {
			v := actualRows[r]
			fmt.Fprintf(&b, "| %s | %s | `%s` | %d | 0 |\n", r, st(v[0], "resource"), st(v[0], "result"), len(v))
		}
		fmt.Fprint(&b, "\n## Test outcomes\n\n| Resource | Test | Observed |\n|---|---|---|\n")
		for _, v := range results {
			m := obj(v)
			fmt.Fprintf(&b, "| %s | %s | %s |\n", st(m, "resource"), st(m, "test"), strings.ReplaceAll(st(m, "observed"), "|", "/"))
		}
		fmt.Fprintf(&b, "\nThe offline audit checked both signed chains (%s), their policies and proof transcripts, and the separate resources' SQLite journals. Each completed operation includes a signed resource receipt and a matching ledger redemption recorded before execution.\n\n", string(canon(counts)))
		fmt.Fprint(&b, "[Public ledger entries](public-ledger.json) · [Private local ledger entries](local-ledger.json) · [Portable wallet evidence](spend-evidence.json) · [Root and child evidence](families.json) · [Signed HTTP presentations](presentations.json) · [Test records](tests.json) · [Binary fingerprints](builds.json)\n")
		if e = os.WriteFile(filepath.Join(out, "REPORT.md"), b.Bytes(), 0644); e != nil {
			return e
		}
	}
	fmt.Printf("AUDIT %d tests, %d signed ledger entries, %d issued operations, %d effects, 0 restricted effects\n", len(results), totalEntries, totalOps, total)
	return nil
}

func binPath() string {
	exe, e := os.Executable()
	if e != nil {
		return ""
	}
	return filepath.Dir(exe)
}
