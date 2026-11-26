package main

import (
	"encoding/base64"
	"errors"
	"path/filepath"
	"strconv"
)

// This private supervisor channel attests the gateway's reported response.
// It does not establish caller identity, policy correctness or actual effect state.
func (f *front) failureCall(step string, body M) (M, error) {
	path := api + step
	base := st(f.trust, "localLedger")
	p, e := f.control.call("prove", M{"ledger": base, "path": path, "body": body})
	if e != nil {
		return nil, e
	}
	headers := M{"http6-role": "broker", "http6-proof": ":" + base64.StdEncoding.EncodeToString(canon(p)) + ":",
		"http6-policy": strconv.Quote(st(obj(obj(p)["result"]), "policyAddress"))}
	value, e := exchange(f.client, "POST", base+path, body, headers)
	if e != nil {
		return nil, e
	}
	return obj(value), nil
}
func (f *front) proveFailure(requestHash string, core M, category string, status int64) (M, error) {
	if f.role != "broker" {
		return nil, errors.New("broker required")
	}
	challenge, e := f.failureCall("failure-challenge", M{"nonce": nonce(), "requestHash": requestHash,
		"resultHash": sha(canon(core)), "category": category, "status": status})
	if e != nil {
		return nil, e
	}
	ctx := obj(challenge["context"])
	token := st(challenge, "challenge")
	if st(ctx, "requestHash") != requestHash || st(ctx, "resultHash") != sha(canon(core)) ||
		st(ctx, "category") != category || integer(ctx, "status") != status {
		return nil, errors.New("failure challenge substitution")
	}
	if _, e = f.verifier.call("failure-open", M{"context": ctx, "challenge": token}); e != nil {
		return nil, e
	}
	witness, e := f.control.call("failure-answer", M{"context": ctx, "challenge": token})
	if e != nil {
		return nil, e
	}
	proof, e := f.verifier.call("failure-attest", M{"context": ctx, "witness": witness})
	if e != nil {
		return nil, e
	}
	pkg := M{"context": ctx, "challenge": token, "proof": proof}
	checked, e := f.verifier.call("failure-verify", M{"failure": pkg})
	if e != nil {
		return nil, e
	}
	recorded, e := f.failureCall("failure-commit", M{"nonce": nonce(), "failure": pkg})
	if e != nil {
		return nil, e
	}
	decision, e := readSigned(st(recorded, "decision"), st(f.trust, "localLedgerKey"), "failure-decision")
	if e != nil {
		return nil, e
	}
	for k, v := range (M{"eventRef": recorded["eventRef"], "failureProofRef": obj(checked)["failureProofRef"],
		"failureContextRef": obj(checked)["failureContextRef"], "failureChallengeRef": obj(checked)["failureChallengeRef"]}) {
		if !bytesEqual(decision[k], v) {
			return nil, errors.New("failure decision mismatch")
		}
	}
	if integer(decision, "iat") > stamp() || integer(decision, "exp") <= stamp() {
		return nil, errors.New("failure decision expired")
	}
	return M{"failure": pkg, "failureDecision": recorded["decision"], "failureEventRef": recorded["eventRef"]}, nil
}

func verifyFailure(v *guest, trust M, result M, requestHash string, status int64, entry string) error {
	pkg := obj(result["failure"])
	ctx := obj(pkg["context"])
	core := obj(result["failureCore"])
	if pkg == nil || ctx == nil || core == nil || st(ctx, "requestHash") != requestHash || integer(ctx, "status") != status ||
		st(ctx, "resultHash") != sha(canon(core)) || st(core, "error") != st(result, "error") || st(core, "category") != st(ctx, "category") {
		return errors.New("failure response binding")
	}
	command := "failure-verify"
	args := M{"failure": pkg}
	if entry != "" {
		command = "historical-failure"
		args["entry"] = entry
	}
	checked, e := v.call(command, args)
	if e != nil {
		return e
	}
	decision, e := readSigned(st(result, "failureDecision"), st(trust, "localLedgerKey"), "failure-decision")
	if e != nil {
		return e
	}
	for k, x := range (M{"eventRef": result["failureEventRef"], "failureProofRef": obj(checked)["failureProofRef"],
		"failureContextRef": obj(checked)["failureContextRef"], "failureChallengeRef": obj(checked)["failureChallengeRef"]}) {
		if !bytesEqual(decision[k], x) {
			return errors.New("failure ledger decision mismatch")
		}
	}
	if entry == "" && (integer(decision, "iat") > stamp() || integer(decision, "exp") <= stamp()) {
		return errors.New("failure decision expired")
	}
	if entry != "" {
		if sha([]byte(entry)) != st(result, "failureEventRef") {
			return errors.New("failure event mismatch")
		}
		event, err := readSigned(entry, st(trust, "localLedgerKey"), "ledger-entry")
		if err != nil || integer(decision, "iat") < integer(event, "at") || integer(decision, "iat") >= integer(ctx, "exp") || integer(decision, "exp") != integer(ctx, "exp") {
			return errors.New("failure decision time mismatch")
		}
	}
	return nil
}

func (l *lab) writeFailureEvidence(name string, result M, requestHash string, status int64) error {
	value, e := exchange(l.client, "GET", st(l.trust, "localLedger")+api+"events", nil, nil)
	if e != nil {
		return e
	}
	rows, ok := value.([]any)
	if !ok {
		return errors.New("failure events unavailable")
	}
	var event string
	for _, item := range rows {
		row := obj(item)
		if st(row, "ref") == st(result, "failureEventRef") && st(row, "event") == "FAILURE_RESPONSE_PROVED" {
			event = st(row, "signature")
		}
	}
	if event == "" {
		return errors.New("failure event absent")
	}
	bundle := M{"v": profile, "kind": "failure-evidence", "trust": l.trust, "failure": result["failure"],
		"failureCore": result["failureCore"], "error": result["error"], "failureDecision": result["failureDecision"],
		"failureEventRef": result["failureEventRef"], "failureEntry": event, "requestHash": requestHash, "status": status}
	return artifact(filepath.Join(l.out, name), bundle)
}

func verifyFailureEvidence(bin string, b M, operator, ledgerKey, requestHash string, status int64) error {
	if st(b, "v") != profile || st(b, "kind") != "failure-evidence" || len(operator) != 64 || len(ledgerKey) != 64 || len(requestHash) != 64 {
		return errors.New("failure evidence or trust pins missing")
	}
	t := copyMap(obj(b["trust"]))
	seal := st(t, "seal")
	delete(t, "seal")
	installation, e := readSigned(seal, operator, "installation")
	if e != nil {
		return e
	}
	if st(installation, "digest") != hash("installation", t) || st(t, "operator") != operator || st(t, "localLedgerKey") != ledgerKey {
		return errors.New("failure trust pin mismatch")
	}
	if st(b, "failureEntry") == "" {
		return errors.New("failure ledger event required")
	}
	if st(b, "requestHash") != requestHash || integer(b, "status") != status {
		return errors.New("failure request or status mismatch")
	}
	if _, e = manifest(bin); e != nil {
		return e
	}
	v, e := newGuest(bin, "verifier")
	if e != nil {
		return e
	}
	defer v.close()
	if _, e = v.call("configure", M{"trust": t}); e != nil {
		return e
	}
	return verifyFailure(v, t, b, requestHash, status, st(b, "failureEntry"))
}
