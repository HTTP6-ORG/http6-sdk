package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ingressContextKey struct{}
type ingressSession struct {
	mu        sync.Mutex
	challenge string
	expiry    int64
}

func (s *ingressSession) issue() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.challenge = nonce()
	s.expiry = stamp() + 5
	return s.challenge
}
func (s *ingressSession) consume() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.challenge
	s.challenge = ""
	if stamp() >= s.expiry {
		return ""
	}
	return n
}

type front struct {
	lagMillis         atomic.Int64
	paused            atomic.Bool
	failAfterRedeem   atomic.Bool
	delayAfterRedeem  atomic.Int64
	role, bin         string
	verifier, control *guest
	trust             M
	client            *http.Client
	db                *database
	mu                sync.Mutex
}

func (f *front) init() error {
	if e := f.db.exec("CREATE TABLE checks(id INTEGER PRIMARY KEY, op TEXT, channel TEXT, decision TEXT, certificateRef TEXT, eventRef TEXT)"); e != nil {
		return e
	}
	if f.role == "broker" {
		return nil
	}
	if e := f.db.exec("CREATE TABLE effects(op TEXT PRIMARY KEY,channel TEXT,resource TEXT,state TEXT,redemption TEXT,validationRef TEXT,at TEXT,receipt TEXT,result TEXT)"); e != nil {
		return e
	}
	if f.role == "wallet" {
		if e := f.db.exec("CREATE TABLE funds(account TEXT PRIMARY KEY, sats INTEGER CHECK(sats>=0))"); e != nil {
			return e
		}
		if e := f.db.exec("INSERT INTO funds VALUES('fixture',10000)"); e != nil {
			return e
		}
		if e := f.db.exec("CREATE TABLE spends(op TEXT PRIMARY KEY,recipient TEXT,sats INTEGER)"); e != nil {
			return e
		}
	}
	if f.role == "database" {
		if e := f.db.exec("CREATE TABLE invoices(project TEXT,period TEXT,amount INTEGER,memo TEXT)"); e != nil {
			return e
		}
		for _, v := range [][]string{{"p7", "2026-10", "7", "sample A"}, {"p7", "2026-10", "11", "sample B"}, {"p8", "2026-10", "100", "other project"}} {
			if e := f.db.exec("INSERT INTO invoices VALUES(?,?,?,?)", v...); e != nil {
				return e
			}
		}
	}
	return nil
}
func (f *front) readPublic(base, kind, ref string) (any, error) {
	if len(ref) != 64 || strings.Trim(ref, "abcdef0123456789") != "" {
		return nil, deny("INVALID_LEDGER_REFERENCE")
	}
	v, e := exchange(f.client, "GET", base+api+kind+"/"+ref, nil, nil)
	if e != nil {
		var ae *apiError
		if !errors.As(e, &ae) {
			return nil, &apiError{503, "HELD_LEDGER"}
		}
	}
	return v, e
}
func (f *front) verify(wire M) (M, M, error) {
	aud := st(obj(obj(wire["body"])["intent"]), "audience")
	if f.role != "broker" && f.role != aud {
		return nil, nil, deny("WRONG_CUSTODIAN")
	}
	base := st(obj(obj(f.trust["routes"])[aud]), "ledger")
	if base == "" {
		return nil, nil, deny("UNKNOWN_AUDIENCE")
	}
	v, e := f.readPublic(base, "families", grantFor(obj(wire["body"])))
	if e != nil {
		return nil, nil, e
	}
	family := obj(v)
	verified, e := f.verifier.call("wire", M{"family": family, "presentation": wire})
	if e != nil {
		return nil, nil, e
	}
	info := obj(verified)
	cert := obj(info["certificate"])
	ph := st(cert, "policyHash")
	pol, e := f.readPublic(base, "policies", ph)
	if e != nil {
		return nil, nil, e
	}
	if hash("policy", pol) != ph || !bytesEqual(pol, family["policy"]) {
		return nil, nil, deny("LEDGER_POLICY_MISMATCH")
	}
	p, e := f.readPublic(base, "objects", st(cert, "proofRef"))
	if e != nil {
		return nil, nil, e
	}
	if !bytesEqual(p, info["proof"]) {
		return nil, nil, deny("LEDGER_PROOF_MISMATCH")
	}
	token, e := f.readPublic(base, "objects", st(info, "certificateRef"))
	if e != nil {
		return nil, nil, e
	}
	if !bytesEqual(strconv.Quote(fmt.Sprint(token)), obj(wire["headers"])["http6-certificate"]) {
		return nil, nil, deny("LEDGER_CERTIFICATE_MISMATCH")
	}
	return info, obj(pol), nil
}
func (f *front) callback(step, channel string, wire, info, extra M) (M, error) {
	path := api + step
	route := obj(obj(f.trust["routes"])[st(obj(info["certificate"]), "audience")])
	base := st(route, "ledger")
	body := M{"nonce": nonce(), "channel": channel, "presentation": wire, "certificateRef": info["certificateRef"], "presentationRef": info["presentationRef"]}
	for k, v := range extra {
		body[k] = v
	}
	p, e := f.control.call("prove", M{"ledger": base, "path": path, "body": body})
	if e != nil {
		return nil, e
	}
	hdr := M{"http6-role": f.role, "http6-proof": ":" + base64.StdEncoding.EncodeToString(canon(p)) + ":", "http6-policy": strconv.Quote(st(obj(obj(p)["result"]), "policyAddress"))}
	v, e := exchange(f.client, "POST", base+path, body, hdr)
	if e != nil {
		var ae *apiError
		if !errors.As(e, &ae) {
			return nil, &apiError{503, "HELD_LEDGER"}
		}
		return nil, e
	}
	token, _ := v.(string)
	d, e := readSigned(token, st(route, "ledgerKey"), "decision")
	if e != nil {
		return nil, e
	}
	cert := obj(info["certificate"])
	expected := M{"caller": f.role, "channel": channel, "op": info["op"], "nonce": body["nonce"], "requestRef": cert["requestRef"], "proofRef": cert["proofRef"], "policyHash": cert["policyHash"], "certificateRef": info["certificateRef"], "presentationRef": info["presentationRef"], "redemptionId": body["redemptionId"]}
	for k, v := range expected {
		if !bytesEqual(d[k], v) {
			return nil, deny("LEDGER_DECISION_MISMATCH")
		}
	}
	if integer(d, "iat") > stamp() || integer(d, "exp") <= stamp() || len(st(d, "eventRef")) != 64 {
		return nil, deny("STALE_DECISION")
	}
	if e = f.db.exec("INSERT INTO checks(op,channel,decision,certificateRef,eventRef) VALUES(?,?,?,?,?)", st(d, "op"), channel, st(d, "decision"), st(d, "certificateRef"), st(d, "eventRef")); e != nil {
		return nil, e
	}
	d["_token"] = token
	return d, nil
}
func needDecision(d M, value string) error {
	if st(d, "decision") != value {
		return deny(st(d, "decision"))
	}
	return nil
}
func controlKey(t M, role string) string {
	return st(obj(obj(obj(t["controls"])[role])["policy"]), "key")
}
func (f *front) authenticate(r *http.Request, wire, cert M) error {
	s := r.Context().Value(ingressContextKey{}).(*ingressSession)
	n := s.consume()
	if n == "" {
		return deny("FRESH_HOLDER_REQUIRED")
	}
	tokens := r.Header.Values("Http6-Ingress")
	if len(tokens) != 1 {
		return deny("FRESH_HOLDER_REQUIRED")
	}
	key := st(cert, "key")
	if f.role != "broker" && st(peek(tokens[0]), "signer") == controlKey(f.trust, "broker") {
		key = controlKey(f.trust, "broker")
	}
	d, e := readSigned(tokens[0], key, "ingress")
	if e != nil {
		return deny("FRESH_HOLDER_REQUIRED")
	}
	expected := claims("ingress", M{"nonce": n, "ingress": f.role, "signer": key, "wireHash": hash("wire", wire)})
	if !bytesEqual(d, expected) {
		return deny("FRESH_HOLDER_REQUIRED")
	}
	return nil
}

// A challenge belongs to this single keep-alive connection. Each call uses a private transport.
func deliver(c *http.Client, target, role string, wire M, signer *guest, key string, substitute string) (any, error) {
	u, e := url.Parse(target)
	if e != nil {
		return nil, e
	}
	tr := c.Transport.(*http.Transport).Clone()
	defer tr.CloseIdleConnections()
	hop := *c
	hop.Transport = tr
	if key != "" && role == "endpoint" && signer != nil {
		hop.Timeout = 1200 * time.Millisecond
	}
	challenge, e := exchange(&hop, "GET", u.Scheme+"://"+u.Host+api+"challenge", nil, nil)
	if e != nil {
		return nil, e
	}
	h := copyMap(obj(wire["headers"]))
	if signer != nil {
		cl := claims("ingress", M{"nonce": st(obj(challenge), "nonce"), "ingress": role, "signer": key, "wireHash": hash("wire", wire)})
		token, e := signer.call("ingress", M{"presentation": wire, "claims": cl})
		if e != nil {
			return nil, e
		}
		h["http6-ingress"] = token
	} else if substitute != "" {
		h["http6-ingress"] = substitute
	}
	return exchange(&hop, "POST", target, wire["body"], h)
}
func (f *front) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if f.paused.Load() {
		answer(w, nil, &apiError{503, "SERVICE_UNAVAILABLE"})
		return
	}
	if r.URL.RawQuery != "" || r.URL.EscapedPath() != r.URL.Path {
		answer(w, nil, deny("UNREGISTERED_TARGET"))
		return
	}
	if r.Method == "GET" && r.URL.Path == api+"challenge" {
		if lag := f.lagMillis.Swap(0); lag > 0 {
			select {
			case <-time.After(time.Duration(lag) * time.Millisecond):
			case <-r.Context().Done():
				return
			}
		}
		answer(w, M{"nonce": r.Context().Value(ingressContextKey{}).(*ingressSession).issue()}, nil)
		return
	}
	if r.Method != "POST" {
		answer(w, nil, deny("METHOD"))
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.role == "broker" && r.URL.Path == api+"review-wallet" {
		m, e := requestBody(r)
		if e != nil {
			answer(w, nil, e)
			return
		}
		v, e := f.reviewWallet(m)
		answer(w, v, e)
		return
	}
	var channel string
	switch {
	case f.role == "broker" && r.URL.Path == api+"dispatch":
		channel = "allowed"
	case f.role != "broker" && r.URL.Path == api+"operate":
		channel = "allowed"
	case f.role != "broker" && r.URL.Path == api+"secondary":
		channel = "restricted"
	default:
		answer(w, nil, deny("UNREGISTERED_TARGET"))
		return
	}
	wire, e := readWire(r)
	if e != nil {
		answer(w, nil, e)
		return
	}
	info, policy, e := f.verify(wire)
	if e != nil {
		answer(w, nil, e)
		return
	}
	cert := obj(info["certificate"])
	aud := st(cert, "audience")
	route := obj(obj(f.trust["routes"])[aud])
	if f.role != "broker" {
		u, _ := url.Parse(st(route, "target"))
		if f.role != aud || r.Host != u.Host {
			answer(w, nil, deny("WRONG_CUSTODIAN"))
			return
		}
	}
	if e = f.authenticate(r, wire, cert); e != nil {
		answer(w, nil, e)
		return
	}
	actual, e := actualIntent(f.trust, wire, channel)
	if e != nil {
		answer(w, nil, e)
		return
	}
	_, policyErr := f.verifier.call("policy", M{"policy": policy, "intent": actual})
	d, e := f.callback("check", channel, wire, info, nil)
	if e != nil {
		answer(w, nil, e)
		return
	}
	if st(d, "decision") == "REJECTED" || st(d, "decision") == "SPENT" || st(d, "decision") == "EXPIRED" {
		answer(w, nil, deny(st(d, "decision")))
		return
	}
	if policyErr != nil {
		if st(d, "decision") != "POLICY_DENIED" {
			answer(w, nil, deny("POLICY_DECISION_DISAGREEMENT"))
			return
		}
		answer(w, nil, deny("POLICY_DENIED"))
		return
	}
	if e = needDecision(d, "ELIGIBLE"); e != nil {
		answer(w, nil, e)
		return
	}
	if !bytesEqual(actual, obj(wire["body"])["intent"]) {
		answer(w, nil, deny("CHANNEL_MISMATCH"))
		return
	}
	if f.role == "endpoint" && st(peek(r.Header.Get("Http6-Ingress")), "signer") != controlKey(f.trust, "broker") {
		answer(w, nil, deny("BROKER_REQUIRED"))
		return
	}
	var v any
	if f.role == "broker" {
		v, e = f.forward(wire, info, route)
	} else {
		v, e = f.execute(channel, wire, info, actual)
	}
	answer(w, v, e)
}
func (f *front) forward(wire, info, route M) (value any, err error) {
	cert := obj(info["certificate"])
	aud := st(cert, "audience")
	v, e := deliver(f.client, st(route, "target"), aud, wire, f.control, controlKey(f.trust, "broker"), "")
	if e != nil {
		var ae *apiError
		if errors.As(e, &ae) && ae.Status != 503 {
			return nil, e
		}
		d, holdErr := f.callback("hold", "allowed", wire, info, nil)
		if holdErr != nil {
			return nil, &apiError{503, "UNCERTAIN_HOLD"}
		}
		if st(d, "decision") == "UNCERTAIN" {
			return nil, &apiError{503, "UNCERTAIN"}
		}
		if holdErr = needDecision(d, "HELD"); holdErr != nil {
			return nil, holdErr
		}
		return nil, &apiError{503, "HELD_RESOURCE"}
	}
	defer func() {
		if err != nil {
			err = &apiError{503, "UNCERTAIN_RESPONSE_VALIDATION"}
		}
	}()
	reply := obj(v)
	receipt := st(reply, "receipt")
	out, e := readSigned(receipt, controlKey(f.trust, aud), "outcome")
	if e != nil {
		return nil, e
	}
	for k, x := range (M{"op": info["op"], "certificateRef": info["certificateRef"], "presentationRef": info["presentationRef"], "requestRef": cert["requestRef"], "audience": aud, "recipient": cert["key"], "intentHash": cert["intentHash"], "resultHash": sha(canon(reply["result"]))}) {
		if !bytesEqual(out[k], x) {
			return nil, deny("RESOURCE_RECEIPT_MISMATCH")
		}
	}
	response := obj(reply["response"])
	checked, e := f.verifier.call("response-verify", M{"response": response})
	if e != nil {
		return nil, e
	}
	if st(obj(checked), "resultHash") != sha(canon(reply["result"])) || st(response, "receipt") != receipt {
		return nil, deny("RESPONSE_RESULT_MISMATCH")
	}
	decision, e := readSigned(st(reply, "responseDecision"), st(route, "ledgerKey"), "decision")
	if e != nil {
		return nil, e
	}
	for k, x := range (M{"decision": "RESPONSE_PROVED", "op": info["op"], "certificateRef": info["certificateRef"],
		"presentationRef": info["presentationRef"], "responseProofRef": obj(checked)["responseProofRef"],
		"responseContextRef": obj(checked)["responseContextRef"], "responseChallengeRef": obj(checked)["responseChallengeRef"], "eventRef": reply["responseEventRef"]}) {
		if !bytesEqual(decision[k], x) {
			return nil, deny("RESPONSE_LEDGER_DECISION_MISMATCH")
		}
	}
	if integer(decision, "iat") > stamp() || integer(decision, "exp") <= stamp() {
		return nil, deny("STALE_RESPONSE_DECISION")
	}
	confirm, e := f.callback("confirm", "allowed", wire, info, M{"receipt": receipt, "responseProofRef": obj(checked)["responseProofRef"], "responseEventRef": reply["responseEventRef"]})
	if e != nil {
		return nil, e
	}
	if e = needDecision(confirm, "CONFIRMED"); e != nil {
		return nil, e
	}
	reply["confirmationRef"] = confirm["eventRef"]
	return reply, nil
}
func (f *front) execute(channel string, wire, info, intent M) (value any, err error) {
	id := nonce()
	d, e := f.callback("redeem", channel, wire, info, M{"redemptionId": id})
	if e != nil {
		// A lost ledger reply cannot establish whether redemption was recorded.
		return nil, &apiError{503, "UNCERTAIN_REDEMPTION"}
	}
	if e = needDecision(d, "REDEEMED"); e != nil {
		return nil, e
	}
	defer func() {
		if err != nil {
			err = &apiError{503, "UNCERTAIN_AFTER_REDEMPTION"}
		}
	}()
	if f.failAfterRedeem.Swap(false) {
		if delay := f.delayAfterRedeem.Swap(0); delay > 0 {
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}
		return nil, &apiError{503, "TEST_AFTER_REDEMPTION"}
	}
	cert := obj(info["certificate"])
	op := st(cert, "op")
	at := stamp()
	if at >= integer(cert, "exp") {
		return nil, deny("EXPIRED")
	}
	if e = f.db.exec("INSERT INTO effects VALUES(?,?,?,'STARTED',?,?,?,'','')", op, channel, st(intent, "resource"), id, st(d, "eventRef"), strconv.FormatInt(at, 10)); e != nil {
		return nil, e
	}
	if stamp() >= integer(cert, "exp") {
		return nil, deny("EXPIRED")
	}
	var result M
	var receipt string
	commit := func() error {
		if stamp() >= integer(cert, "exp") {
			return deny("EXPIRED")
		}
		result, e = f.act(op, intent)
		if e != nil {
			return e
		}
		cl := claims("outcome", M{"op": op, "audience": f.role, "recipient": cert["key"], "intentHash": cert["intentHash"], "epoch": cert["epoch"], "certificateRef": info["certificateRef"], "presentationRef": info["presentationRef"], "requestRef": cert["requestRef"], "redemptionId": id, "at": at, "observation": st(intent, "resource"), "resultHash": sha(canon(result))})
		token, e := f.control.call("outcome", M{"claims": cl})
		if e != nil {
			return e
		}
		receipt = token.(string)
		if e = f.db.exec("UPDATE effects SET state='ACTED', receipt=?, result=? WHERE op=?", receipt, string(canon(result)), op); e != nil {
			return e
		}
		return nil
	}
	if f.role == "wallet" {
		e = f.db.transaction(commit)
	} else {
		e = commit()
	}
	if e != nil {
		return nil, e
	}
	d, e = f.callback("outcome", channel, wire, info, M{"receipt": receipt})
	if e != nil {
		return nil, e
	}
	if e = needDecision(d, "COMMITTED"); e != nil {
		return nil, e
	}
	outcomeRef := st(d, "eventRef")
	challenge, e := f.callback("response-challenge", channel, wire, info, M{"receipt": receipt, "outcomeEventRef": outcomeRef})
	if e != nil {
		return nil, e
	}
	if e = needDecision(challenge, "RESPONSE_CHALLENGED"); e != nil {
		return nil, e
	}
	ctx := obj(challenge["responseContext"])
	challengeToken := st(challenge, "_token")
	if _, e = f.verifier.call("response-open", M{"context": ctx, "challenge": challengeToken}); e != nil {
		return nil, e
	}
	witness, e := f.control.call("response-answer", M{"context": ctx, "challenge": challengeToken})
	if e != nil {
		return nil, e
	}
	responseProof, e := f.verifier.call("response-attest", M{"context": ctx, "witness": witness})
	if e != nil {
		return nil, e
	}
	certificate, e := strconv.Unquote(st(obj(wire["headers"]), "http6-certificate"))
	if e != nil {
		return nil, e
	}
	response := M{"context": ctx, "challenge": challengeToken, "proof": responseProof, "certificate": certificate, "receipt": receipt}
	if _, e = f.verifier.call("response-verify", M{"response": response}); e != nil {
		return nil, e
	}
	proved, e := f.callback("response-commit", channel, wire, info, M{"response": response})
	if e != nil {
		return nil, e
	}
	if e = needDecision(proved, "RESPONSE_PROVED"); e != nil {
		return nil, e
	}
	return M{"result": result, "receipt": receipt, "ledgerOutcomeRef": outcomeRef,
		"response": response, "responseDecision": proved["_token"], "responseEventRef": proved["eventRef"]}, nil
}
func (f *front) act(op string, i M) (M, error) {
	resource := st(i, "resource")
	args := obj(i["args"])
	switch f.role {
	case "endpoint":
		values := map[string]string{"public-status": "available", "admin-status": "maintenance-window"}
		value, ok := values[resource]
		if !ok {
			return nil, deny("UNKNOWN_ENDPOINT")
		}
		return M{"view": resource, "project": args["project"], "status": value}, nil
	case "process":
		exports := map[string]string{"sum": "sum", "product": "product"}
		export, ok := exports[resource]
		if !ok {
			return nil, deny("UNKNOWN_EXECUTABLE")
		}
		path := filepath.Join(f.bin, "work.wasm")
		data, e := os.ReadFile(path)
		if e != nil || sha(data) != st(obj(f.trust["manifest"]), "workerSHA256") {
			return nil, deny("WORKER_DIGEST")
		}
		left, right := st(args, "left"), st(args, "right")
		for _, v := range []string{left, right} {
			n, e := strconv.Atoi(v)
			if e != nil || n < 0 || n > 100 || strconv.Itoa(n) != v {
				return nil, deny("COMPUTE_LIMIT")
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		b, e := exec.CommandContext(ctx, "wasmer", "run", "--disable-cache", "--no-tty", "--invoke", export, path, left, right).Output()
		if e != nil {
			return nil, e
		}
		n, e := strconv.Atoi(strings.TrimSpace(string(b)))
		if e != nil {
			return nil, e
		}
		return M{"program": export, "value": n}, nil
	case "wallet":
		amount, e := strconv.ParseInt(st(args, "satoshis"), 10, 64)
		if e != nil || amount <= 0 || amount > 1000 || st(args, "network") != "regtest" {
			return nil, deny("WALLET_SCOPE")
		}
		recipient := st(args, "recipient")

		if e := f.db.exec("INSERT INTO spends VALUES(?,?,?)", op, recipient, strconv.FormatInt(amount, 10)); e != nil {
			return nil, e
		}
		e = f.db.exec("UPDATE funds SET sats=sats-? WHERE account='fixture'", strconv.FormatInt(amount, 10))
		if e != nil {
			return nil, e
		}
		return M{"asset": "synthetic-satoshi", "recipient": recipient, "amount": amount, "network": "regtest", "op": op}, nil
	case "database":
		var q string
		switch resource {
		case "monthly-total":
			q = "SELECT sum(amount) AS total FROM invoices WHERE project=? AND period=?"
		case "invoice-detail":
			q = "SELECT amount,memo FROM invoices WHERE project=? AND period=? ORDER BY rowid"
		default:
			return nil, deny("UNKNOWN_QUERY")
		}
		rows, e := f.db.query(q, st(args, "project"), st(args, "period"))
		if e != nil {
			return nil, e
		}
		return M{"query": resource, "rows": rows}, nil
	}
	return nil, deny("UNKNOWN_ADAPTER")
}
