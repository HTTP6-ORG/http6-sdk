package main

import (
	"errors"
	"strconv"
	"strings"
)

// The ledger records the trusted gateway's assertion about received bytes and
// response bytes. It does not infer identity, policy correctness, or effect state.
func (l *ledger) failureResponse(path string, body M) (any, error) {
	if l.base != st(l.trust, "localLedger") {
		return nil, deny("PRIVATE_LEDGER_REQUIRED")
	}
	if path == api+"failure-challenge" {
		category := st(body, "category")
		status := integer(body, "status")
		valid := (category == "malformed" && status == 400) || (category == "denied" && status == 403) || ((category == "held" || category == "uncertain") && status == 503)
		rh, bh := st(body, "requestHash"), st(body, "resultHash")
		if !valid || len(rh) != 64 || len(bh) != 64 || strings.Trim(rh+bh, "0123456789abcdef") != "" {
			return nil, deny("FAILURE_CONTEXT")
		}
		policy := obj(obj(obj(l.trust["controls"])["broker"])["policy"])
		at := stamp()
		n := nonce()
		ctx := claims("failure-context", M{"category": category, "status": status, "requestHash": rh, "resultHash": bh,
			"method": "POST", "target": api + "propose", "actorKey": policy["key"], "verifierKey": policy["responseVerifier"],
			"policyHash": hash("policy", policy), "policyAddress": l.base + api + "policies/" + hash("policy", policy),
			"nonce": n, "iat": at, "exp": at + 20})
		challenge := signed(l.signer, claims("failure-challenge", M{"context": ctx}))
		if e := l.db.exec("INSERT INTO failure_challenges(nonce,contextHash,challenge,state,deadline) VALUES(?,?,?,'ISSUED',?)", n, hash("failure-context", ctx), challenge, strconv.FormatInt(at+20, 10)); e != nil {
			return nil, e
		}
		ref, e := l.event("FAILURE_RESPONSE_CHALLENGED", "broker", "", category, M{"failureContextRef": hash("failure-context", ctx), "requestHash": rh, "resultHash": bh, "status": status})
		if e != nil {
			return nil, e
		}
		return M{"context": ctx, "challenge": challenge, "eventRef": ref}, nil
	}
	if path != api+"failure-commit" {
		return nil, errors.New("unknown failure endpoint")
	}
	pkg := obj(body["failure"])
	ctx := obj(pkg["context"])
	rows, e := l.db.query("SELECT * FROM failure_challenges WHERE nonce=?", st(ctx, "nonce"))
	if e != nil || len(rows) != 1 {
		return nil, deny("FAILURE_CHALLENGE_MISSING")
	}
	deadline, e := strconv.ParseInt(st(rows[0], "deadline"), 10, 64)
	if e != nil || st(rows[0], "state") != "ISSUED" || stamp() >= deadline || st(rows[0], "challenge") != st(pkg, "challenge") || st(rows[0], "contextHash") != hash("failure-context", ctx) {
		return nil, deny("FAILURE_REPLAY_OR_EXPIRED")
	}
	checked, e := l.verifier.call("failure-verify", M{"failure": pkg})
	if e != nil {
		return nil, e
	}
	info := obj(checked)
	for ref, value := range (M{st(info, "failureProofRef"): pkg["proof"], st(info, "failureContextRef"): ctx, st(info, "failureChallengeRef"): pkg["challenge"]}) {
		if e = l.put("objects", ref, value); e != nil {
			return nil, e
		}
	}
	if e = l.db.exec("UPDATE failure_challenges SET state='PROVED',proofRef=? WHERE nonce=? AND state='ISSUED'", st(info, "failureProofRef"), st(ctx, "nonce")); e != nil {
		return nil, e
	}
	data := M{"failureProofRef": info["failureProofRef"], "failureContextRef": info["failureContextRef"], "failureChallengeRef": info["failureChallengeRef"],
		"requestHash": ctx["requestHash"], "resultHash": ctx["resultHash"], "category": ctx["category"], "status": ctx["status"]}
	event, e := l.event("FAILURE_RESPONSE_PROVED", "broker", "", st(ctx, "category"), data)
	if e != nil {
		return nil, e
	}
	decision := signed(l.signer, claims("failure-decision", M{"eventRef": event, "failureProofRef": info["failureProofRef"],
		"failureContextRef": info["failureContextRef"], "failureChallengeRef": info["failureChallengeRef"], "iat": stamp(), "exp": ctx["exp"]}))
	if e = l.db.exec("UPDATE failure_challenges SET eventRef=?,decision=? WHERE nonce=?", event, decision, st(ctx, "nonce")); e != nil {
		return nil, e
	}
	return M{"decision": decision, "eventRef": event}, nil
}
