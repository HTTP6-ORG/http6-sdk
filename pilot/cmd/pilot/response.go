package main

import (
	"errors"
	"path/filepath"
	"strconv"
)

// Verify a response against the exact original presentation and independently pinned trust.
// Historical evidence uses a ledger-signed RESPONSE_PROVED entry as its verification time.
func verifyResponse(v *guest, trust, wire, reply M, historicalEntry string) (M, error) {
	response := obj(reply["response"])
	ctx := obj(response["context"])
	if response == nil || ctx == nil {
		return nil, errors.New("missing native response proof")
	}
	role := st(ctx, "audience")
	route := obj(obj(trust["routes"])[role])
	key := st(route, "ledgerKey")
	if key == "" {
		return nil, errors.New("unknown response resource")
	}
	method := "response-verify"
	args := M{"response": response}
	if historicalEntry != "" {
		method = "historical-response"
		args["entry"] = historicalEntry
	}
	checked, e := v.call(method, args)
	if e != nil {
		return nil, e
	}
	info := obj(checked)
	cert, e := strconv.Unquote(st(obj(wire["headers"]), "http6-certificate"))
	if e != nil {
		return nil, e
	}
	if st(response, "certificate") != cert || st(ctx, "requestRef") != sha([]byte(st(obj(wire["body"]), "request"))) ||
		st(ctx, "presentationRef") != sha([]byte(st(obj(wire["headers"]), "signature"))) ||
		st(ctx, "resultHash") != sha(canon(reply["result"])) || st(response, "receipt") != st(reply, "receipt") {
		return nil, errors.New("response does not match request or result")
	}
	decision, e := readSigned(st(reply, "responseDecision"), key, "decision")
	if e != nil {
		return nil, e
	}
	for k, x := range (M{"decision": "RESPONSE_PROVED", "caller": ctx["audience"], "channel": "allowed", "policyHash": ctx["policyHash"], "op": ctx["op"], "certificateRef": ctx["certificateRef"],
		"presentationRef": ctx["presentationRef"], "requestRef": ctx["requestRef"], "responseProofRef": info["responseProofRef"],
		"responseContextRef": info["responseContextRef"], "responseChallengeRef": info["responseChallengeRef"], "eventRef": reply["responseEventRef"]}) {
		if !bytesEqual(decision[k], x) {
			return nil, errors.New("response ledger decision mismatch")
		}
	}
	if historicalEntry == "" && (integer(decision, "iat") > stamp() || integer(decision, "exp") <= stamp()) {
		return nil, errors.New("stale response ledger decision")
	}
	if historicalEntry != "" {
		if sha([]byte(historicalEntry)) != st(reply, "responseEventRef") {
			return nil, errors.New("wrong response event")
		}
		event, err := readSigned(historicalEntry, key, "ledger-entry")
		if err != nil {
			return nil, err
		}
		if integer(decision, "iat") < integer(event, "at") || integer(decision, "iat") >= integer(ctx, "exp") {
			return nil, errors.New("response decision time mismatch")
		}
	}
	return info, nil
}

// Store only the caller's own response evidence in its private state directory.
func (l *lab) writeResponseEvidence(name, audience string, wire, reply M) error {
	base := st(obj(obj(l.trust["routes"])[audience]), "ledger")
	value, e := exchange(l.client, "GET", base+api+"events", nil, nil)
	if e != nil {
		return e
	}
	rows, ok := value.([]any)
	if !ok {
		return errors.New("ledger events unavailable")
	}
	op := st(obj(obj(reply["response"])["context"]), "op")
	var redemption, responseEvent string
	for _, item := range rows {
		row := obj(item)
		if st(row, "op") != op {
			continue
		}
		if st(row, "event") == "REDEEMED" && st(row, "actor") == audience {
			redemption = st(row, "signature")
		}
		if st(row, "event") == "RESPONSE_PROVED" && st(row, "ref") == st(reply, "responseEventRef") {
			responseEvent = st(row, "signature")
		}
	}
	if redemption == "" || responseEvent == "" {
		return errors.New("response ledger events unavailable")
	}
	bundle := M{"v": profile, "kind": "response-evidence", "trust": l.trust, "family": l.families[audience],
		"presentation": wire, "result": reply["result"], "receipt": reply["receipt"], "response": reply["response"],
		"responseDecision": reply["responseDecision"], "responseEventRef": reply["responseEventRef"],
		"responseEntry": responseEvent, "redemptionEntry": redemption}
	return artifact(filepath.Join(l.out, name), bundle)
}

func verifyResponseEvidence(bin string, bundle M, operator, ledgerKey string) error {
	if len(operator) != 64 || len(ledgerKey) != 64 || st(bundle, "v") != profile || st(bundle, "kind") != "response-evidence" {
		return errors.New("response evidence or trust pins missing")
	}
	trust := copyMap(obj(bundle["trust"]))
	seal := st(trust, "seal")
	delete(trust, "seal")
	installed, e := readSigned(seal, operator, "installation")
	if e != nil {
		return e
	}
	ctx := obj(obj(bundle["response"])["context"])
	role := st(ctx, "audience")
	if st(installed, "digest") != hash("installation", trust) || st(trust, "operator") != operator ||
		st(obj(obj(trust["routes"])[role]), "ledgerKey") != ledgerKey {
		return errors.New("response trust pin mismatch")
	}
	if _, e = manifest(bin); e != nil {
		return e
	}
	v, e := newGuest(bin, "verifier")
	if e != nil {
		return e
	}
	defer v.close()
	if _, e = v.call("configure", M{"trust": trust}); e != nil {
		return e
	}
	original, e := v.call("historical-wire", M{"family": bundle["family"], "presentation": bundle["presentation"], "entry": bundle["redemptionEntry"]})
	if e != nil {
		return e
	}
	if obj(original)["certificateRef"] != ctx["certificateRef"] || obj(original)["presentationRef"] != ctx["presentationRef"] {
		return errors.New("response original request mismatch")
	}
	if _, e = verifyResponse(v, trust, obj(bundle["presentation"]), bundle, st(bundle, "responseEntry")); e != nil {
		return e
	}
	return nil
}
