package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ledger struct {
	base     string
	db       *database
	verifier *guest
	trust    M
	signer   ed25519.PrivateKey
	mu       sync.Mutex
}

func (l *ledger) init() error {
	for _, sql := range []string{
		"CREATE TABLE objects(ref TEXT PRIMARY KEY, data TEXT NOT NULL)",
		"CREATE TABLE policies(ref TEXT PRIMARY KEY, data TEXT NOT NULL)",
		"CREATE TABLE roots(ref TEXT PRIMARY KEY, data TEXT NOT NULL)",
		"CREATE TABLE families(ref TEXT PRIMARY KEY, data TEXT NOT NULL, root TEXT NOT NULL, birth TEXT NOT NULL, UNIQUE(root,birth))",
		"CREATE TABLE operations(audience TEXT, op TEXT, certRef TEXT UNIQUE, certificate TEXT, grantRef TEXT, intent TEXT, record TEXT UNIQUE, state TEXT, redemption TEXT, presentation TEXT, receipt TEXT, deadline INTEGER NOT NULL, PRIMARY KEY(audience,op))",
		"CREATE TABLE wallet_refusals(op TEXT PRIMARY KEY, digest TEXT NOT NULL, grantRef TEXT NOT NULL, bundle TEXT NOT NULL)",
		"CREATE TABLE response_challenges(nonce TEXT PRIMARY KEY, certRef TEXT, contextHash TEXT, challenge TEXT, proofRef TEXT, eventRef TEXT, decision TEXT, state TEXT, deadline INTEGER)",
		"CREATE TABLE failure_challenges(nonce TEXT PRIMARY KEY,contextHash TEXT,challenge TEXT,proofRef TEXT,eventRef TEXT,decision TEXT,state TEXT,deadline INTEGER)",
		"CREATE TABLE used(nonce TEXT PRIMARY KEY)",
		"CREATE TABLE revoked(grantRef TEXT PRIMARY KEY)",
		"CREATE TABLE events(seq INTEGER PRIMARY KEY, event TEXT, actor TEXT, op TEXT, channel TEXT, data TEXT, signature TEXT, ref TEXT)"} {
		if e := l.db.exec(sql); e != nil {
			return e
		}
	}
	if e := l.put("objects", st(l.trust, "semantics"), l.trust["manifest"]); e != nil {
		return e
	}
	for _, v := range obj(l.trust["controls"]) {
		m := obj(v)
		if e := l.put("policies", hash("policy", m["policy"]), m["policy"]); e != nil {
			return e
		}
		if e := l.put("objects", sha([]byte(st(m, "cert"))), m["cert"]); e != nil {
			return e
		}
	}
	return nil
}
func (l *ledger) put(table, ref string, data any) error {
	return l.db.exec("INSERT OR IGNORE INTO "+table+"(ref,data) VALUES(?,?)", ref, string(canon(data)))
}
func (l *ledger) get(table, ref string) (any, error) {
	rows, e := l.db.query("SELECT data FROM "+table+" WHERE ref=?", ref)
	if e != nil {
		return nil, e
	}
	if len(rows) != 1 {
		return nil, &apiError{404, "MISSING_PUBLIC_RECORD"}
	}
	return parse([]byte(st(rows[0], "data")))
}
func (l *ledger) event(kind, role, op, channel string, data M) (string, error) {
	rows, e := l.db.query("SELECT seq,ref FROM events ORDER BY seq DESC LIMIT 1")
	if e != nil {
		return "", e
	}
	seq := 1
	prev := ""
	if len(rows) > 0 {
		n, e := strconv.Atoi(st(rows[0], "seq"))
		if e != nil {
			return "", e
		}
		seq = n + 1
		prev = st(rows[0], "ref")
	}
	statement := claims("ledger-entry", M{"seq": seq, "prev": prev, "event": kind, "actor": role, "op": op, "channel": channel, "data": data, "at": stamp()})
	token := signed(l.signer, statement)
	ref := sha([]byte(token))
	return ref, l.db.exec("INSERT INTO events VALUES(?,?,?,?,?,?,?,?)", fmt.Sprint(seq), kind, role, op, channel, string(canon(data)), token, ref)
}
func (l *ledger) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if r.Method == "GET" {
		var v any
		var e error
		path := r.URL.Path
		switch {
		case path == api+"catalog":
			v, e = l.catalog()
		case strings.HasPrefix(path, api+"roots/"):
			v, e = l.get("roots", strings.TrimPrefix(path, api+"roots/"))
		case path == api+"events":
			v, e = l.db.query("SELECT * FROM events ORDER BY seq")
		case strings.HasPrefix(path, api+"policies/"):
			v, e = l.get("policies", strings.TrimPrefix(path, api+"policies/"))
		case strings.HasPrefix(path, api+"objects/"):
			v, e = l.get("objects", strings.TrimPrefix(path, api+"objects/"))
		case strings.HasPrefix(path, api+"families/"):
			v, e = l.get("families", strings.TrimPrefix(path, api+"families/"))
		default:
			e = &apiError{404, "UNKNOWN_ROUTE"}
		}
		answer(w, v, e)
		return
	}
	if r.Method != "POST" {
		answer(w, nil, deny("METHOD"))
		return
	}
	body, e := requestBody(r)
	if e != nil {
		answer(w, nil, e)
		return
	}
	var v any
	e = l.db.transaction(func() error {
		var runErr error
		switch path := r.URL.Path; path {
		case api + "admit", api + "birth":
			v, runErr = l.enroll(path, body)
		case api + "reserve":
			v, runErr = l.reserve(body)
		case api + "check", api + "redeem", api + "outcome", api + "confirm", api + "hold", api + "record-refusal", api + "response-challenge", api + "response-commit", api + "failure-challenge", api + "failure-commit":
			v, runErr = l.callback(path, r, body)
		case api + "revoke":
			v, runErr = l.revoke(body)
		default:
			runErr = &apiError{404, "UNKNOWN_ROUTE"}
		}
		return runErr
	})
	answer(w, v, e)
}
func (l *ledger) enroll(path string, f M) (any, error) {
	mode := "root"
	if path == api+"birth" {
		mode = "family"
	}
	v, e := l.verifier.call(mode, M{"family": f})
	if e != nil {
		return nil, e
	}
	terms := obj(v)
	rootRef := sha([]byte(st(f, "root")))
	grant := rootRef
	kind := "ROOT_ADMITTED"
	if mode == "root" {
		if e = l.db.exec("INSERT INTO roots VALUES(?,?)", rootRef, string(canon(f))); e != nil {
			return nil, deny("ROOT_ALREADY_ADMITTED")
		}
	} else {
		if st(terms, "policyAddress") != l.base+api+"policies/"+st(terms, "policyHash") {
			return nil, deny("WRONG_LEDGER")
		}
		prior, e := l.get("roots", rootRef)
		if e != nil {
			return nil, e
		}
		for _, k := range []string{"rootPolicy", "rootProof", "root", "origin"} {
			if string(canon(obj(prior)[k])) != string(canon(f[k])) {
				return nil, deny("PARENT_CHANGED")
			}
		}
		grant = sha([]byte(st(f, "child")))
		kind = "CHILD_MINTED"
		rows, e := l.db.query("SELECT count(*) AS n FROM families WHERE root=?", rootRef)
		if e != nil {
			return nil, e
		}
		cnt, _ := strconv.Atoi(st(rows[0], "n"))
		layers := obj(f["rootPolicy"])["layers"].([]any)
		limit := integer(obj(obj(layers[0])["delegation"]), "maxBirths")
		if int64(cnt) >= limit {
			return nil, deny("BIRTH_LIMIT")
		}
		if e = l.db.exec("INSERT INTO families VALUES(?,?,?,?)", grant, string(canon(f)), rootRef, st(terms, "birthId")); e != nil {
			return nil, deny("DUPLICATE_BIRTH")
		}
	}
	for _, k := range []string{"origin", "root", "child"} {
		if x := st(f, k); x != "" {
			if e = l.put("objects", sha([]byte(x)), x); e != nil {
				return nil, e
			}
		}
	}
	for _, k := range []string{"rootProof", "birthProof"} {
		if p := f[k]; p != nil {
			if e = l.put("objects", hash("proof", p), p); e != nil {
				return nil, e
			}
		}
	}
	for _, k := range []string{"rootPolicy", "policy"} {
		if p := f[k]; p != nil {
			if e = l.put("policies", hash("policy", p), p); e != nil {
				return nil, e
			}
		}
	}
	return l.event(kind, "mint", "", st(terms, "holder"), M{"grantRef": grant, "policyHash": terms["policyHash"], "rootRef": rootRef})
}
func peek(token string) M {
	p := strings.Split(token, ".")
	if len(p) != 3 {
		return nil
	}
	b, e := raw64.DecodeString(p[1])
	if e != nil {
		return nil
	}
	v, _ := parse(b)
	return obj(v)
}
func grantFor(body M) string { return st(obj(peek(st(body, "request"))["attempt"]), "grantRef") }
func (l *ledger) isRevoked(grant, root string) (bool, error) {
	r, e := l.db.query("SELECT grantRef FROM revoked WHERE grantRef IN (?,?)", grant, root)
	return len(r) > 0, e
}
func (l *ledger) reserve(pkg M) (any, error) {
	body := obj(pkg["body"])
	grant := grantFor(body)
	f, e := l.get("families", grant)
	if e != nil {
		return nil, e
	}
	v, e := l.verifier.call("request", M{"family": f, "package": pkg})
	if e != nil {
		return nil, e
	}
	a := obj(v)
	intent := obj(body["intent"])
	revoked, e := l.isRevoked(grant, st(a, "rootRef"))
	if e != nil {
		return nil, e
	}
	if revoked {
		return nil, deny("REVOKED")
	}
	op := st(a, "op")
	aud := st(intent, "audience")
	if aud == "wallet" {
		prior, e := l.db.query("SELECT op FROM wallet_refusals WHERE op=?", op)
		if e != nil {
			return nil, e
		}
		if len(prior) > 0 {
			return nil, deny("REJECTED")
		}
	}
	record := st(a, "record")
	requestRef := sha([]byte(st(body, "request")))
	proofRef := hash("proof", pkg["proof"])
	rows, e := l.db.query("SELECT intent,state FROM operations WHERE audience=? AND op=?", aud, op)
	if e != nil {
		return nil, e
	}
	if len(rows) != 0 {
		return nil, &apiError{409, "OPERATION_EXISTS"}
	}
	// Every outstanding or settled operation counts against the original shared pool.
	layers := obj(obj(f)["policy"])["layers"].([]any)
	for i, layer := range layers {
		var counts []M
		if i == 0 {
			counts, e = l.db.query("SELECT count(*) AS n FROM operations JOIN families ON families.ref=operations.grantRef WHERE families.root=?", st(a, "rootRef"))
		} else {
			counts, e = l.db.query("SELECT count(*) AS n FROM operations WHERE grantRef=?", grant)
		}
		if e != nil {
			return nil, e
		}
		cnt, _ := strconv.Atoi(st(counts[0], "n"))
		if int64(cnt) >= integer(obj(obj(layer)["budget"]), "limit") {
			return nil, deny("BUDGET")
		}
	}
	at := stamp()
	exp := min(at+integer(a, "holdSeconds"), integer(a, "exp"))
	if exp <= at {
		return nil, deny("EXPIRED")
	}
	c := claims("certificate", M{"id": nonce(), "requestRef": requestRef, "proofRef": proofRef, "tenant": intent["tenant"], "audience": aud, "units": 1, "fence": 1, "nbf": at, "exp": exp})
	for _, k := range []string{"op", "record", "rootRef", "grantRef", "policyHash", "policyAddress", "holder", "key", "gen", "epoch", "mode", "intentHash"} {
		c[k] = a[k]
	}
	token := signed(l.signer, c)
	ref := sha([]byte(token))
	transcript := obj(obj(obj(pkg["proof"])["result"])["publicResponse"])["transcript"]
	tr := hash("transcript", transcript)
	br := hash("request-body", body)
	for k, x := range (M{requestRef: body["request"], proofRef: pkg["proof"], ref: token, st(a, "intentHash"): intent, tr: transcript, br: body}) {
		if e = l.put("objects", k, x); e != nil {
			return nil, e
		}
	}
	if e = l.db.exec("INSERT INTO operations(audience,op,certRef,certificate,grantRef,intent,record,state,deadline) VALUES(?,?,?,?,?,?,?,'ISSUED',?)", aud, op, ref, token, grant, st(a, "intentHash"), record, strconv.FormatInt(exp, 10)); e != nil {
		return nil, deny("ATTEMPT_REPLAY")
	}
	if _, e = l.event("REQUEST_PROVED", "http6-agent", op, aud, M{"intentRef": a["intentHash"], "bodyRef": br, "transcriptRef": tr, "proofRef": proofRef, "requestRef": requestRef, "policyHash": a["policyHash"], "grantRef": grant}); e != nil {
		return nil, e
	}
	if _, e = l.event("CERTIFICATE_ISSUED", "ledger", op, aud, M{"certificateRef": ref, "exp": exp}); e != nil {
		return nil, e
	}
	return token, nil
}
func actualIntent(t M, wire M, channel string) (M, error) {
	i := copyMap(obj(obj(wire["body"])["intent"]))
	route := obj(obj(t["routes"])[st(i, "audience")])
	tuple := obj(obj(route["channels"])[channel])
	if tuple == nil {
		return nil, deny("UNKNOWN_CHANNEL")
	}
	for _, k := range []string{"resource", "action", "args", "releaseTo"} {
		if k == "args" && i["audience"] == "wallet" {
			args := copyMap(obj(tuple[k]))
			args["satoshis"] = obj(i[k])["satoshis"]
			i[k] = args
		} else {
			i[k] = tuple[k]
		}
	}
	return i, nil
}
func (l *ledger) callback(path string, r *http.Request, body M) (any, error) {
	role := r.Header.Get("Http6-Role")
	ctrl, ok := obj(l.trust["controls"])[role]
	if !ok {
		return nil, deny("UNKNOWN_CONTROL_ROLE")
	}
	proof, e := publicProof(M{"headers": M{"http6-proof": r.Header.Get("Http6-Proof")}})
	if e != nil {
		return nil, e
	}
	checked, e := l.verifier.call("control", M{"ledger": l.base, "role": role, "path": path, "body": body, "proof": proof})
	if e != nil {
		return nil, e
	}
	if r.Header.Get("Http6-Policy") != strconv.Quote(st(obj(proof["result"]), "policyAddress")) {
		return nil, deny("CONTROL_POLICY_ADDRESS")
	}
	if e = l.db.exec("INSERT INTO used VALUES(?)", role+"/"+st(body, "nonce")); e != nil {
		return nil, deny("CONTROL_REPLAY")
	}
	if e = l.put("objects", hash("proof", proof), proof); e != nil {
		return nil, e
	}
	if path == api+"failure-challenge" || path == api+"failure-commit" {
		if role != "broker" {
			return nil, deny("BROKER_REQUIRED")
		}
		return l.failureResponse(path, body)
	}
	if path == api+"record-refusal" {
		if role != "broker" {
			return nil, deny("BROKER_REQUIRED")
		}
		return l.recordRefusal(body, proof)
	}
	wire := obj(body["presentation"])
	grant := grantFor(obj(wire["body"]))
	f, e := l.get("families", grant)
	if e != nil {
		return nil, e
	}
	var cert M
	var ref, pres string
	if path == api+"outcome" || path == api+"confirm" || path == api+"response-challenge" || path == api+"response-commit" {
		// A committed outcome may be reported after the five-second execution window.
		ref = st(body, "certificateRef")
		tok, e := l.get("objects", ref)
		if e != nil {
			return nil, e
		}
		cert, e = readSigned(tok.(string), public(l.signer), "certificate")
		if e != nil {
			return nil, e
		}
		pres = st(body, "presentationRef")
	} else {
		v, e := l.verifier.call("wire", M{"family": f, "presentation": wire})
		if e != nil {
			return nil, e
		}
		info := obj(v)
		cert = obj(info["certificate"])
		ref = st(info, "certificateRef")
		pres = st(info, "presentationRef")
	}
	rows, e := l.db.query("SELECT * FROM operations WHERE certRef=?", ref)
	if e != nil || len(rows) != 1 {
		return nil, deny("UNKNOWN_CERTIFICATE")
	}
	row := rows[0]
	reqRef := st(cert, "requestRef")
	op := st(cert, "op")
	aud := st(cert, "audience")
	channel := st(body, "channel")
	if role != "broker" && role != aud {
		return nil, deny("WRONG_CUSTODIAN")
	}
	data := M{"certificateRef": ref, "presentationRef": pres, "proofRef": cert["proofRef"], "requestRef": reqRef, "policyHash": cert["policyHash"], "controlProofRef": obj(checked)["proofRef"], "proofVerified": true, "stateBefore": row["state"], "verifierNonce": body["nonce"]}
	decision := "ELIGIBLE"
	event := "CHECKED"
	extraDecision := M{}
	switch path {
	case api + "check", api + "redeem":
		actual, e := actualIntent(l.trust, wire, channel)
		if e != nil {
			return nil, e
		}
		_, policyErr := l.verifier.call("policy", M{"policy": obj(f)["policy"], "intent": actual})
		data["policyAllowed"] = policyErr == nil
		revoked, e := l.isRevoked(grant, st(cert, "rootRef"))
		if e != nil {
			return nil, e
		}
		switch {
		case row["state"] == "REJECTED":
			decision = "REJECTED"
		case row["state"] == "EXPIRED":
			decision = "EXPIRED"
		case row["state"] != "ISSUED" && row["state"] != "HELD":
			decision = "SPENT"
		case policyErr != nil:
			decision = "POLICY_DENIED"
			if e = l.db.exec("UPDATE operations SET state='REJECTED' WHERE certRef=?", ref); e != nil {
				return nil, e
			}
			data["stateAfter"] = "REJECTED"
		case !bytesEqual(actual, obj(obj(wire["body"])["intent"])):
			decision = "CHANNEL_MISMATCH"
		case revoked:
			decision = "REVOKED"
			if e = l.db.exec("UPDATE operations SET state='REJECTED' WHERE certRef=?", ref); e != nil {
				return nil, e
			}
			data["stateAfter"] = "REJECTED"

		}
		if path == api+"redeem" && decision == "ELIGIBLE" {
			if role != aud {
				return nil, deny("WRONG_REDEEMER")
			}
			id := st(body, "redemptionId")
			if len(id) != 64 {
				return nil, deny("REDEMPTION_ID")
			}
			if stamp() >= integer(cert, "exp") {
				return nil, deny("EXPIRED")
			}
			e = l.db.exec("UPDATE operations SET state='REDEEMED',redemption=?,presentation=? WHERE certRef=? AND state IN ('ISSUED','HELD')", id, pres, ref)
			if e != nil {
				return nil, e
			}
			decision = "REDEEMED"
			event = "REDEEMED"
			data["redemptionId"] = id
		} else if path == api+"redeem" && decision == "SPENT" && role == aud && st(row, "state") == "REDEEMED" && st(row, "redemption") == st(body, "redemptionId") && st(row, "presentation") == pres {
			decision = "REDEEMED"
			event = "RECOVERED_REDEMPTION"
			data["redemptionId"] = body["redemptionId"]
		}
	case api + "hold":
		if role != "broker" {
			return nil, deny("WRONG_HOLD_ROLE")
		}
		switch st(row, "state") {
		case "ISSUED", "HELD":
			if stamp() >= integer(cert, "exp") {
				return nil, deny("EXPIRED")
			}
			if e = l.db.exec("UPDATE operations SET state='HELD' WHERE certRef=?", ref); e != nil {
				return nil, e
			}
			decision = "HELD"
			event = "DELIVERY_HELD"
			data["deadline"] = cert["exp"]
			data["reason"] = "resource unavailable"
		case "REDEEMED", "COMMITTED":
			decision = "UNCERTAIN"
			event = "DELIVERY_UNCERTAIN"
			data["reason"] = "resource response unavailable after redemption"
		case "REJECTED":
			decision = "REJECTED"
		case "EXPIRED":
			decision = "EXPIRED"
		default:
			decision = "SPENT"
		}
	case api + "response-challenge":
		if role != aud || st(row, "state") != "COMMITTED" || st(row, "receipt") != st(body, "receipt") || pres != st(row, "presentation") {
			return nil, deny("RESPONSE_CHALLENGE_STATE")
		}
		receipt := st(row, "receipt")
		out, err := readSigned(receipt, controlKey(l.trust, aud), "outcome")
		if err != nil {
			return nil, err
		}
		events, err := l.db.query("SELECT ref FROM events WHERE event='CUSTODIAN_OUTCOME' AND op=? AND actor=? ORDER BY seq DESC LIMIT 1", op, aud)
		if err != nil || len(events) != 1 || st(events[0], "ref") != st(body, "outcomeEventRef") {
			return nil, deny("RESPONSE_OUTCOME_MISMATCH")
		}
		at := stamp()
		responseNonce := nonce()
		controlPolicy := obj(obj(obj(l.trust["controls"])[aud])["policy"])
		ctx := claims("response-context", M{"op": op, "audience": aud, "recipient": cert["key"], "requestRef": reqRef,
			"certificateRef": ref, "presentationRef": pres, "policyHash": cert["policyHash"], "policyAddress": cert["policyAddress"],
			"epoch": cert["epoch"], "resultHash": out["resultHash"], "receiptRef": sha([]byte(receipt)),
			"outcomeEventRef": body["outcomeEventRef"], "status": 200, "contentType": "application/json", "nonce": responseNonce,
			"iat": at, "exp": at + 20, "actorKey": controlPolicy["key"], "verifierKey": controlPolicy["responseVerifier"]})
		if e = l.db.exec("INSERT INTO response_challenges(nonce,certRef,contextHash,state,deadline) VALUES(?,?,?,'ISSUED',?)", responseNonce, ref, hash("response-context", ctx), strconv.FormatInt(at+20, 10)); e != nil {
			return nil, e
		}
		decision = "RESPONSE_CHALLENGED"
		event = "RESPONSE_CHALLENGED"
		data["responseContextRef"] = hash("response-context", ctx)
		data["responseNonce"] = responseNonce
		data["receiptRef"] = sha([]byte(receipt))
		extraDecision["responseContext"] = ctx
	case api + "response-commit":
		if role != aud || st(row, "state") != "COMMITTED" || pres != st(row, "presentation") {
			return nil, deny("RESPONSE_STATE")
		}
		response := obj(body["response"])
		ctx := obj(response["context"])
		if st(response, "receipt") != st(row, "receipt") || st(ctx, "certificateRef") != ref || st(ctx, "presentationRef") != pres {
			return nil, deny("RESPONSE_BINDING")
		}
		ch, err := l.db.query("SELECT * FROM response_challenges WHERE nonce=?", st(ctx, "nonce"))
		if err != nil || len(ch) != 1 {
			return nil, deny("RESPONSE_REPLAY_OR_EXPIRED")
		}
		deadline, err := strconv.ParseInt(st(ch[0], "deadline"), 10, 64)
		if err != nil || st(ch[0], "state") != "ISSUED" || st(ch[0], "certRef") != ref || st(ch[0], "challenge") != st(response, "challenge") || st(ch[0], "contextHash") != hash("response-context", ctx) || stamp() >= deadline {
			return nil, deny("RESPONSE_REPLAY_OR_EXPIRED")
		}
		prior, err := l.db.query("SELECT nonce FROM response_challenges WHERE certRef=? AND state='PROVED'", ref)
		if err != nil || len(prior) != 0 {
			return nil, deny("RESPONSE_ALREADY_PROVED")
		}
		v, err := l.verifier.call("response-verify", M{"response": response})
		if err != nil {
			return nil, err
		}
		proofRef := st(obj(v), "responseProofRef")
		contextRef := st(obj(v), "responseContextRef")
		challengeRef := st(obj(v), "responseChallengeRef")
		if e = l.put("objects", proofRef, response["proof"]); e != nil {
			return nil, e
		}
		if e = l.put("objects", contextRef, ctx); e != nil {
			return nil, e
		}
		if e = l.put("objects", challengeRef, response["challenge"]); e != nil {
			return nil, e
		}
		if e = l.db.exec("UPDATE response_challenges SET state='PROVED',proofRef=? WHERE nonce=? AND state='ISSUED'", proofRef, st(ctx, "nonce")); e != nil {
			return nil, e
		}
		decision = "RESPONSE_PROVED"
		event = "RESPONSE_PROVED"
		data["responseProofRef"] = proofRef
		data["responseContextRef"] = contextRef
		data["responseChallengeRef"] = challengeRef
		data["receiptRef"] = ctx["receiptRef"]
		data["resultHash"] = ctx["resultHash"]
		data["responseNonce"] = ctx["nonce"]
		extraDecision["responseProofRef"] = proofRef
		extraDecision["responseContextRef"] = contextRef
		extraDecision["responseChallengeRef"] = challengeRef
	case api + "outcome", api + "confirm":
		if path == api+"outcome" && role != aud || path == api+"confirm" && role != "broker" {
			return nil, deny("WRONG_OUTCOME_ROLE")
		}
		cust := obj(obj(l.trust["controls"])[aud])
		outKey := st(obj(cust["policy"]), "key")
		receipt := st(body, "receipt")
		out, e := readSigned(receipt, outKey, "outcome")
		if e != nil {
			return nil, e
		}
		if st(out, "certificateRef") != ref || st(out, "op") != op || st(out, "requestRef") != reqRef || st(out, "intentHash") != st(cert, "intentHash") || st(out, "redemptionId") != st(row, "redemption") || st(out, "presentationRef") != st(row, "presentation") || pres != st(row, "presentation") || st(out, "audience") != aud || st(out, "recipient") != st(cert, "key") || integer(out, "at") < integer(cert, "nbf") || integer(out, "at") >= integer(cert, "exp") {
			return nil, deny("OUTCOME_MISMATCH")
		}
		if path == api+"outcome" {
			if st(row, "state") != "REDEEMED" && !(st(row, "state") == "COMMITTED" && st(row, "receipt") == receipt) {
				return nil, deny("OUTCOME_STATE")
			}
			if e = l.db.exec("UPDATE operations SET state='COMMITTED',receipt=? WHERE certRef=?", receipt, ref); e != nil {
				return nil, e
			}
			if e = l.put("objects", sha([]byte(receipt)), receipt); e != nil {
				return nil, e
			}
			decision = "COMMITTED"
			event = "CUSTODIAN_OUTCOME"
		} else {
			if st(row, "state") != "COMMITTED" || st(row, "receipt") != receipt {
				return nil, deny("UNSETTLED")
			}
			proofs, err := l.db.query("SELECT proofRef,eventRef FROM response_challenges WHERE certRef=? AND state='PROVED'", ref)
			if err != nil || len(proofs) != 1 || st(proofs[0], "proofRef") != st(body, "responseProofRef") || st(proofs[0], "eventRef") != st(body, "responseEventRef") {
				return nil, deny("RESPONSE_NOT_PROVED")
			}
			data["responseProofRef"] = body["responseProofRef"]
			data["responseEventRef"] = body["responseEventRef"]
			event = "BROKER_CONFIRMED"
			decision = "CONFIRMED"
		}
		data["receiptRef"] = sha([]byte(receipt))
	default:
		return nil, errors.New("unknown callback")
	}
	_ = ctrl
	data["decision"] = decision
	eventRef, e := l.event(event, role, op, channel, data)
	if e != nil {
		return nil, e
	}
	decisionFields := M{"decision": decision, "nonce": body["nonce"], "caller": role, "channel": channel, "op": op, "certificateRef": ref, "presentationRef": pres, "requestRef": reqRef, "proofRef": cert["proofRef"], "policyHash": cert["policyHash"], "eventRef": eventRef, "redemptionId": body["redemptionId"], "iat": stamp(), "exp": stamp() + 5}
	for k, v := range extraDecision {
		decisionFields[k] = v
	}
	if decision == "RESPONSE_CHALLENGED" {
		decisionFields["exp"] = obj(extraDecision["responseContext"])["exp"]
	}
	token := signed(l.signer, claims("decision", decisionFields))
	if decision == "RESPONSE_CHALLENGED" {
		if e = l.db.exec("UPDATE response_challenges SET challenge=? WHERE nonce=?", token, st(obj(extraDecision["responseContext"]), "nonce")); e != nil {
			return nil, e
		}
	}
	if decision == "RESPONSE_PROVED" {
		if e = l.db.exec("UPDATE response_challenges SET eventRef=?,decision=? WHERE nonce=?", eventRef, token, st(obj(obj(body["response"])["context"]), "nonce")); e != nil {
			return nil, e
		}
	}
	return token, nil
}
func (l *ledger) revoke(b M) (any, error) {
	a, e := readSigned(st(b, "authorization"), st(l.trust, "operator"), "revoke")
	if e != nil {
		return nil, e
	}
	g := st(a, "grantRef")
	if integer(a, "exp") <= stamp() {
		return nil, deny("EXPIRED")
	}
	if _, e = l.get("families", g); e != nil {
		return nil, e
	}
	if e = l.db.exec("INSERT INTO revoked VALUES(?)", g); e != nil {
		return nil, e
	}
	return l.event("GRANT_REVOKED", "operator", "", "", M{"grantRef": g, "authorization": b["authorization"]})
}
func bytesEqual(a, b any) bool { return string(canon(a)) == string(canon(b)) }

func (l *ledger) catalog() (M, error) {
	result := M{}
	for _, k := range []string{"roots", "families", "policies", "objects"} {
		rows, e := l.db.query("SELECT ref FROM " + k + " ORDER BY ref")
		if e != nil {
			return nil, e
		}
		result[k] = rows
	}
	return result, nil
}
func (l *ledger) sweep(stop, done chan struct{}) {
	defer close(done)
	tick := time.NewTicker(75 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			l.mu.Lock()
			e := l.db.transaction(func() error {
				rows, e := l.db.query("SELECT audience,op,certRef,state,deadline FROM operations WHERE state IN ('HELD','ISSUED') AND deadline<=?", strconv.FormatInt(stamp(), 10))
				if e != nil {
					return e
				}
				for _, r := range rows {
					if e = l.db.exec("UPDATE operations SET state='EXPIRED' WHERE certRef=?", st(r, "certRef")); e != nil {
						return e
					}
					if _, e = l.event("EXPIRED", "ledger", st(r, "op"), st(r, "audience"), M{"certificateRef": r["certRef"], "stateBefore": r["state"], "deadline": r["deadline"]}); e != nil {
						return e
					}
				}
				return nil
			})
			l.mu.Unlock()
			if e != nil {
				fmt.Fprintln(os.Stderr, e)
			}
		}
	}
}
