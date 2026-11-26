package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
)

// Each participant derives the reason from the admitted family. The refusal has a different
// signature type from an executable request and never enters the wallet's reservation table.
func (f *front) reviewWallet(body M) (any, error) {
	base := st(f.trust, "localLedger")
	token := st(body, "proposal")
	family, e := f.readPublic(base, "families", st(peek(token), "grantRef"))
	if e != nil {
		return nil, e
	}
	p, e := f.readPublic(base, "policies", hash("policy", obj(family)["policy"]))
	if e != nil {
		return nil, e
	}
	if !bytesEqual(p, obj(family)["policy"]) {
		return nil, deny("LEDGER_POLICY_MISMATCH")
	}
	refusal, e := f.control.call("refuse-wallet", M{"family": family, "proposal": token})
	if e != nil {
		return nil, e
	}
	path := api + "record-refusal"
	b := M{"nonce": nonce(), "proposal": token, "refusal": refusal}
	proof, e := f.control.call("prove", M{"ledger": base, "path": path, "body": b})
	if e != nil {
		return nil, e
	}
	headers := M{"http6-role": "broker", "http6-proof": ":" + base64.StdEncoding.EncodeToString(canon(proof)) + ":", "http6-policy": strconv.Quote(st(obj(obj(proof)["result"]), "policyAddress"))}
	v, e := exchange(f.client, "POST", base+path, b, headers)
	var remote *apiError
	if e != nil && (!errors.As(e, &remote) || remote.Status >= 500) {
		return nil, &apiError{503, "HELD_LEDGER"}
	}
	return v, e
}

func (l *ledger) recordRefusal(body, proof M) (any, error) {
	if l.base != st(l.trust, "localLedger") || public(l.signer) != st(l.trust, "localLedgerKey") {
		return nil, deny("PRIVATE_LEDGER_REQUIRED")
	}
	token, refusal := st(body, "proposal"), st(body, "refusal")
	grant := st(peek(token), "grantRef")
	family, e := l.get("families", grant)
	if e != nil {
		return nil, e
	}
	checked, e := l.verifier.call("wallet-refusal", M{"family": family, "proposal": token, "refusal": refusal})
	if e != nil {
		return nil, e
	}
	r := obj(checked)
	op := st(r, "op")
	existing, e := l.db.query("SELECT digest,grantRef,bundle FROM wallet_refusals WHERE op=?", op)
	if e != nil {
		return nil, e
	}
	if len(existing) > 0 {
		if existing[0]["digest"] != r["proposalHash"] || existing[0]["grantRef"] != grant {
			return nil, deny("OPERATION_CONFLICT")
		}
		return parse([]byte(st(existing[0], "bundle")))
	}
	held, e := l.db.query("SELECT state FROM operations WHERE audience='wallet' AND op=?", op)
	if e != nil {
		return nil, e
	}
	if len(held) > 0 {
		return nil, deny("OPERATION_EXISTS")
	}
	revoked, e := l.isRevoked(grant, st(r, "rootRef"))
	if e != nil {
		return nil, e
	}
	if revoked {
		return nil, deny("REVOKED")
	}
	proposalRef := sha([]byte(token))
	refusalRef := sha([]byte(refusal))
	data := M{"proposalRef": proposalRef}
	for _, k := range []string{"proposalHash", "holder", "agentKey", "rootRef", "originRef", "grantRef", "policyHash", "policyAddress"} {
		data[k] = r[k]
	}
	if e = l.put("objects", proposalRef, token); e != nil {
		return nil, e
	}
	if e = l.put("objects", refusalRef, refusal); e != nil {
		return nil, e
	}
	first, e := l.event("WALLET_PROPOSAL_RECORDED", "http6-agent", op, "wallet", data)
	if e != nil {
		return nil, e
	}
	second := copyMap(data)
	for _, k := range []string{"brokerKey", "brokerOriginRef", "decision", "reason"} {
		second[k] = r[k]
	}
	second["proposalEntryRef"] = first
	second["refusalRef"] = refusalRef
	second["controlProofRef"] = hash("proof", proof)
	last, e := l.event("WALLET_PROPOSAL_REFUSED", "broker", op, "wallet", second)
	if e != nil {
		return nil, e
	}
	rows, e := l.db.query("SELECT signature FROM events WHERE ref IN (?,?) ORDER BY seq", first, last)
	if e != nil {
		return nil, e
	}
	if len(rows) != 2 {
		return nil, errors.New("missing refusal ledger entries")
	}
	bundle := M{"v": profile, "kind": "wallet-refusal-evidence", "proposal": token, "refusal": refusal, "proposalEntry": rows[0]["signature"], "refusalEntry": rows[1]["signature"], "controlBody": body, "controlProof": proof}
	if e = l.db.exec("INSERT INTO wallet_refusals VALUES(?,?,?,?)", op, st(r, "proposalHash"), grant, string(canon(bundle))); e != nil {
		return nil, e
	}
	return bundle, nil
}

func verifyRefusal(bin string, b M, operator, key string) (M, error) {
	if b["kind"] != "wallet-refusal-evidence" || b["v"] != profile {
		return nil, errors.New("wrong refusal evidence type")
	}
	t, e := walletTrust(bin, obj(b["trust"]), operator, key)
	if e != nil {
		return nil, e
	}
	first, e := readSigned(st(b, "proposalEntry"), key, "ledger-entry")
	if e != nil {
		return nil, e
	}
	last, e := readSigned(st(b, "refusalEntry"), key, "ledger-entry")
	if e != nil {
		return nil, e
	}
	prev := sha([]byte(st(b, "proposalEntry")))
	if first["actor"] != "http6-agent" || first["event"] != "WALLET_PROPOSAL_RECORDED" || first["channel"] != "wallet" ||
		last["actor"] != "broker" || last["event"] != "WALLET_PROPOSAL_REFUSED" || last["channel"] != "wallet" ||
		last["prev"] != prev || integer(last, "seq") != integer(first, "seq")+1 || integer(first, "at") > integer(last, "at") {
		return nil, errors.New("refusal ledger chain or role mismatch")
	}
	control := obj(b["controlBody"])
	if control["proposal"] != b["proposal"] || control["refusal"] != b["refusal"] {
		return nil, errors.New("changed ledger callback")
	}
	g, e := newGuest(bin, "verifier")
	if e != nil {
		return nil, e
	}
	defer g.close()
	if _, e = g.call("configure", M{"trust": t}); e != nil {
		return nil, e
	}
	raw, e := g.call("historical-refusal", M{"family": b["family"], "proposal": b["proposal"], "refusal": b["refusal"], "entry": b["refusalEntry"], "controlBody": control, "controlProof": b["controlProof"]})
	if e != nil {
		return nil, e
	}
	r := obj(raw)
	d := M{"proposalRef": sha([]byte(st(b, "proposal")))}
	for _, k := range []string{"proposalHash", "holder", "agentKey", "rootRef", "originRef", "grantRef", "policyHash", "policyAddress"} {
		d[k] = r[k]
	}
	if !bytesEqual(d, first["data"]) || first["op"] != r["op"] || last["op"] != r["op"] || integer(first, "at") < integer(r, "iat") {
		return nil, errors.New("proposal entry binding")
	}
	for _, k := range []string{"brokerKey", "brokerOriginRef", "decision", "reason"} {
		d[k] = r[k]
	}
	d["proposalEntryRef"] = prev
	d["refusalRef"] = sha([]byte(st(b, "refusal")))
	d["controlProofRef"] = hash("proof", b["controlProof"])
	if !bytesEqual(d, last["data"]) {
		return nil, errors.New("refusal entry binding")
	}
	return r, nil
}

func (a *agentServer) walletReview(m M) (any, error) {
	l := a.l
	raw, e := l.children["wallet"].call("sign-wallet-proposal", M{"proposal": m})
	if e != nil {
		return nil, e
	}
	signed := obj(raw)
	if signed["reason"] == nil {
		return nil, nil
	}
	v, e := exchange(l.client, "POST", l.services["broker"].base+api+"review-wallet", M{"proposal": signed["proposal"]}, nil)
	if e != nil {
		var ae *apiError
		if !errors.As(e, &ae) || ae.Status >= 500 {
			return nil, &apiError{503, "HELD_LEDGER"}
		}
		return nil, e
	}
	b := obj(v)
	if b == nil {
		return nil, errors.New("missing refusal evidence")
	}
	b["trust"] = l.trust
	b["family"] = l.families["wallet"]
	r, e := verifyRefusal(l.bin, b, st(l.trust, "operator"), st(l.trust, "localLedgerKey"))
	if e != nil || st(r, "proposalHash") != hash("proposal", m) {
		return nil, &apiError{503, "HELD_LEDGER"}
	}
	name := "refusal-" + st(r, "proposalHash") + ".json"
	if e = artifact(filepath.Join(l.out, name), b); e != nil {
		return nil, &apiError{503, "HELD_LEDGER"}
	}
	return M{"evidenceFile": name, "reason": r["reason"], "proposalRef": r["proposalRef"], "refusalRef": sha([]byte(st(b, "refusal"))), "policyHash": r["policyHash"]}, deny(st(obj(r["reason"]), "code"))
}

func printRefusal(r M) {
	fmt.Println(string(canon(r)))
}
