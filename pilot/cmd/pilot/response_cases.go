package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// Exercised against the live synthetic endpoint, its signed response and its ledger.
func (l *lab) responseCases(role string, x invocation, reply M) {
	if _, e := verifyResponse(l.attestor, l.trust, x.wire, reply, ""); e != nil {
		require(e)
	}
	l.pass("independent native response and ledger verification", role, "RESPONSE_PROVED", M{"op": x.attempt["op"]})
	cases := []struct {
		name   string
		mutate func(M, M)
	}{
		{"changed response result", func(_ M, r M) { obj(r["result"])["status"] = "changed" }},
		{"changed response recipient", func(_ M, r M) { obj(obj(r["response"])["context"])["recipient"] = "changed" }},
		{"changed response request reference", func(_ M, r M) { obj(obj(r["response"])["context"])["requestRef"] = strings64("a") }},
		{"changed response challenge", func(_ M, r M) { obj(obj(r["response"])["context"])["nonce"] = strings64("b") }},
		{"changed response status", func(_ M, r M) { obj(obj(r["response"])["context"])["status"] = 201 }},
		{"changed response policy", func(_ M, r M) { obj(obj(r["response"])["context"])["policyHash"] = strings64("c") }},
		{"changed response audience", func(_ M, r M) { obj(obj(r["response"])["context"])["audience"] = "wallet" }},
		{"changed response receipt", func(_ M, r M) { obj(r["response"])["receipt"] = "invalid" }},
		{"missing response proof", func(_ M, r M) { delete(obj(r["response"]), "proof") }},
		{"changed response proof signature", func(_ M, r M) { obj(obj(r["response"])["proof"])["signature"] = "invalid" }},
		{"changed original presentation", func(w M, _ M) { obj(w["headers"])["signature"] = "changed" }},
		{"changed ledger decision", func(_ M, r M) { r["responseDecision"] = "invalid" }},
	}
	for _, tc := range cases {
		wire := copyMap(x.wire)
		changed := copyMap(reply)
		tc.mutate(wire, changed)
		if _, e := verifyResponse(l.attestor, l.trust, wire, changed, ""); e == nil {
			require(errors.New(tc.name + " accepted"))
		}
		l.pass(tc.name, role, "REJECTED", M{"op": x.attempt["op"]})
	}
	route := obj(obj(l.trust["routes"])[role])
	base := st(route, "ledger")
	value := must(exchange(l.client, "GET", base+api+"events", nil, nil))
	rows := value.([]any)
	var record M
	for _, v := range rows {
		row := obj(v)
		if st(row, "ref") == st(reply, "responseEventRef") {
			record = obj(must(parse([]byte(st(row, "data")))))
		}
	}
	ensure(record != nil, "response event unavailable")
	proof := must(exchange(l.client, "GET", base+api+"objects/"+st(record, "controlProofRef"), nil, nil))
	response := obj(reply["response"])
	ctx := obj(response["context"])
	body := M{"nonce": record["verifierNonce"], "channel": "allowed", "presentation": x.wire,
		"certificateRef": ctx["certificateRef"], "presentationRef": ctx["presentationRef"], "response": response}
	headers := M{"http6-role": role, "http6-proof": ":" + base64.StdEncoding.EncodeToString(canon(proof)) + ":",
		"http6-policy": strconv.Quote(st(obj(obj(proof)["result"]), "policyAddress"))}
	_, err := exchange(l.client, "POST", base+api+"response-commit", body, headers)
	ensure(err != nil && err.Error() == "CONTROL_REPLAY", fmt.Sprint("response callback replay: ", err))
	after := must(exchange(l.client, "GET", base+api+"events", nil, nil)).([]any)
	ensure(len(after) == len(rows), "replayed response created a ledger event")
	l.pass("replayed response commit", role, "CONTROL_REPLAY", M{"op": x.attempt["op"]})
	fresh, err := l.services[role].testResponseReplay(x.wire, response)
	ensure(err == nil && fresh == "RESPONSE_REPLAY_OR_EXPIRED", fmt.Sprint("fresh-control response replay: ", fresh, " ", err))
	afterFresh := must(exchange(l.client, "GET", base+api+"events", nil, nil)).([]any)
	ensure(len(afterFresh) == len(rows), "fresh-control replay created a ledger event")
	l.pass("response proof replay with fresh control proof", role, "RESPONSE_REPLAY_OR_EXPIRED", M{"op": x.attempt["op"]})
	var signedEvent string
	for _, v := range rows {
		row := obj(v)
		if st(row, "ref") == st(reply, "responseEventRef") {
			signedEvent = st(row, "signature")
		}
	}
	ensure(signedEvent != "", "signed response event missing")
	remaining := time.Until(time.Unix(integer(ctx, "exp"), 0))
	ensure(remaining >= 0 && remaining <= 21*time.Second, "unexpected response expiry interval")
	time.Sleep(remaining + 100*time.Millisecond)
	if _, err = verifyResponse(l.attestor, l.trust, x.wire, reply, ""); err == nil {
		require(errors.New("expired response accepted live"))
	}
	l.pass("expired response proof rejected for live verification", role, "EXPIRED", M{"op": x.attempt["op"]})
	if _, err = verifyResponse(l.attestor, l.trust, x.wire, reply, signedEvent); err != nil {
		require(err)
	}
	l.pass("historical proof verifies at signed ledger event time", role, "HISTORICAL_VERIFIED", M{"op": x.attempt["op"]})
}
func strings64(v string) string {
	out := ""
	for len(out) < 64 {
		out += v
	}
	return out[:64]
}
