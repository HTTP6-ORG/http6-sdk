package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func exportSpend(out string, t, f M, x invocation) error {
	return writeSpend(out, "spend-evidence.json", t, f, x)
}
func writeSpend(out, filename string, t, f M, x invocation) error {
	db, e := readDB(out, "local-ledger")
	if e != nil {
		return e
	}
	defer db.close()
	op := st(x.attempt, "op")
	rowsByOp, e := db.query("SELECT event,actor,signature,data FROM events WHERE op=? ORDER BY seq", op)
	if e != nil {
		return e
	}
	// Export the seven signed authorizing facts for this effect, even if an earlier delivery was held.
	steps, actors := spendSequence()
	events := []M{}
	for _, row := range rowsByOp {
		idx := len(events)
		if idx == len(steps) {
			break
		}
		if row["event"] != steps[idx] || row["actor"] != actors[idx] {
			continue
		}
		data, e := parse([]byte(st(row, "data")))
		if e != nil {
			return e
		}
		if steps[idx] == "CHECKED" && obj(data)["decision"] != "ELIGIBLE" {
			continue
		}
		events = append(events, M{"signature": row["signature"]})
	}
	if len(events) != len(steps) {
		return errors.New("missing authorization for wallet export")
	}
	wallet, e := readDB(out, "wallet")
	if e != nil {
		return e
	}
	defer wallet.close()
	rows, e := wallet.query("SELECT result,receipt FROM effects WHERE op=? AND state='ACTED'", op)
	if e != nil || len(rows) != 1 {
		return errors.New("missing wallet observation")
	}
	result, e := parse([]byte(st(rows[0], "result")))
	if e != nil {
		return e
	}
	responseRows, e := db.query("SELECT * FROM response_challenges WHERE certRef=? AND state='PROVED'", sha([]byte(x.certificate)))
	if e != nil || len(responseRows) != 1 {
		return errors.New("missing native response proof")
	}
	rp := responseRows[0]
	loadObject := func(ref string) (any, error) {
		found, err := db.query("SELECT data FROM objects WHERE ref=?", ref)
		if err != nil || len(found) != 1 {
			return nil, errors.New("missing response object")
		}
		return parse([]byte(st(found[0], "data")))
	}
	context, e := loadObject(st(rp, "contextHash"))
	if e != nil {
		return e
	}
	proof, e := loadObject(st(rp, "proofRef"))
	if e != nil {
		return e
	}
	response := M{"context": context, "challenge": rp["challenge"], "proof": proof, "certificate": x.certificate, "receipt": rows[0]["receipt"]}
	bundle := M{"v": profile, "kind": "spend-evidence", "trust": t, "family": f, "presentation": x.wire, "events": events, "receipt": rows[0]["receipt"], "result": result,
		"response": response, "responseDecision": rp["decision"], "responseEventRef": rp["eventRef"]}
	// Only public evidence for this spend is exported.
	name := filepath.Join(out, filename)
	if e = artifact(name, bundle); e != nil {
		return e
	}
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	return verifySpend(filepath.Dir(exe), bundle, st(t, "operator"), st(t, "localLedgerKey"))
}
func verifySpend(bin string, b M, operator, key string) error {
	t, e := walletTrust(bin, obj(b["trust"]), operator, key)
	if e != nil {
		return e
	}
	p := obj(b["presentation"])
	i := obj(obj(p["body"])["intent"])
	if st(i, "audience") != "wallet" || st(i, "action") != "wallet.spend" {
		return errors.New("wrong spend audience")
	}
	signerKey := controlKey(t, "wallet")
	receipt, e := readSigned(st(b, "receipt"), signerKey, "outcome")
	if e != nil {
		return e
	}
	entries, ok := b["events"].([]any)
	if !ok {
		normalized, e := parse(canon(b["events"]))
		if e != nil {
			return e
		}
		entries, _ = normalized.([]any)
	}
	expected, actors := spendSequence()
	if len(entries) != len(expected) {
		return errors.New("incomplete signed spend history")
	}
	var previous int64
	var redemption, responseEntry string
	var issue M
	op := st(receipt, "op")
	for n, item := range entries {
		token := st(obj(item), "signature")
		entry, e := readSigned(token, key, "ledger-entry")
		if e != nil {
			return e
		}
		d := obj(entry["data"])
		if integer(entry, "seq") <= previous || entry["event"] != expected[n] || entry["actor"] != actors[n] || entry["op"] != op {
			return errors.New("spend history order or actor mismatch")
		}
		previous = integer(entry, "seq")
		if n >= 1 && d["certificateRef"] != receipt["certificateRef"] {
			return errors.New("certificate changed in spend history")
		}
		if n == 0 {
			issue = d
		}
		if n == 2 || n == 3 {
			if d["decision"] != "ELIGIBLE" || d["policyAllowed"] != true || d["proofVerified"] != true {
				return errors.New("missing spend policy approval")
			}
		}
		if n == 4 {
			redemption = token
			if d["redemptionId"] != receipt["redemptionId"] || d["decision"] != "REDEEMED" {
				return errors.New("wallet redemption mismatch")
			}
		}
		if entry["event"] == "RESPONSE_PROVED" {
			responseEntry = token
		}
		if n >= 5 && st(d, "receiptRef") != sha([]byte(st(b, "receipt"))) {
			return errors.New("wallet receipt absent from signed ledger")
		}
	}
	verifier, e := newGuest(bin, "verifier")
	if e != nil {
		return e
	}
	defer verifier.close()
	if _, e = verifier.call("configure", M{"trust": t}); e != nil {
		return e
	}
	evidence, e := verifier.call("historical-wire", M{"family": b["family"], "presentation": p, "entry": redemption})
	if e != nil {
		return e
	}
	info := obj(evidence)
	cert := obj(info["certificate"])
	native := obj(info["proof"])
	transcript := obj(obj(obj(native["result"])["publicResponse"])["transcript"])
	if e = verifyNative(native, st(t, "verifier"), "call"); e != nil {
		return e
	}
	if issue["transcriptRef"] != hash("transcript", transcript) || issue["bodyRef"] != hash("request-body", p["body"]) || issue["proofRef"] != cert["proofRef"] || issue["intentRef"] != hash("intent", i) || st(receipt, "resultHash") != sha(canon(b["result"])) || st(receipt, "intentHash") != hash("intent", i) || receipt["recipient"] != cert["key"] || receipt["requestRef"] != cert["requestRef"] || receipt["presentationRef"] != info["presentationRef"] {
		return errors.New("spend evidence binding mismatch")
	}
	if responseEntry == "" {
		return errors.New("missing signed native response event")
	}
	if _, e = verifyResponse(verifier, t, p, b, responseEntry); e != nil {
		return e
	}
	args := obj(i["args"])
	actual := obj(b["result"])
	if st(actual, "asset") != "synthetic-satoshi" || actual["network"] != args["network"] || actual["recipient"] != args["recipient"] || integer(actual, "amount") != integerFromString(st(args, "satoshis")) || actual["op"] != cert["op"] {
		return errors.New("wallet outcome differs from authorized spend")
	}
	fmt.Printf("OFFLINE VERIFIED %d synthetic satoshis to %s, operation %s\n", integer(actual, "amount"), st(actual, "recipient"), op)
	return nil
}

func spendSequence() ([]string, []string) {
	expected := []string{"REQUEST_PROVED", "CERTIFICATE_ISSUED", "CHECKED", "CHECKED", "REDEEMED", "CUSTODIAN_OUTCOME", "RESPONSE_PROVED", "BROKER_CONFIRMED"}
	actors := []string{"http6-agent", "ledger", "broker", "wallet", "wallet", "wallet", "wallet", "broker"}

	return expected, actors
}

func walletTrust(bin string, trust M, operator, key string) (M, error) {
	if len(operator) != 64 || len(key) != 64 {
		return nil, errors.New("two pinned public keys are required")
	}
	t := copyMap(trust)
	seal := st(t, "seal")
	delete(t, "seal")
	v, e := readSigned(seal, operator, "installation")
	if e != nil {
		return nil, e
	}
	if st(v, "digest") != hash("installation", t) || st(t, "operator") != operator || st(t, "localLedgerKey") != key || st(obj(obj(t["routes"])["wallet"]), "ledgerKey") != key {
		return nil, errors.New("untrusted installation or local ledger")
	}
	if _, e = manifest(bin); e != nil {
		return nil, e
	}
	if st(obj(obj(t["routes"])["wallet"]), "ledger") != st(t, "localLedger") {
		return nil, errors.New("wallet ledger route mismatch")
	}
	return t, nil
}
