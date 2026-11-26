package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type lab struct {
	localOnly                   bool
	bin, out                    string
	trust, builds, routes, root M
	operator                    ed25519.PrivateKey
	client                      *http.Client
	services                    map[string]*service
	mint, attestor              *guest
	children                    map[string]*guest
	families                    map[string]M
	results                     []M
	examples                    M
}
type testFailure struct{ err error }

func require(e error) {
	if e != nil {
		panic(testFailure{e})
	}
}
func must[T any](v T, e error) T { require(e); return v }
func ensure(ok bool, msg string) { require(assert(ok, msg)) }
func expect(err error, want string) string {
	if err == nil {
		panic(testFailure{fmt.Errorf("expected refusal %q, received success", want)})
	}
	ensure(strings.Contains(err.Error(), want), fmt.Sprintf("expected %q, received %q", want, err.Error()))
	return err.Error()
}
func (l *lab) pass(name, role, actual string, detail M) {
	if detail == nil {
		detail = M{}
	}
	detail["test"] = name
	detail["resource"] = role
	detail["observed"] = actual
	detail["pass"] = true
	if os.Getenv("HTTP6_PILOT_REPORT_DIR") != "" {
		detail["finishedMicros"] = time.Now().UnixMicro()
	}
	l.results = append(l.results, detail)
	fmt.Printf("PASS  %-15s %s (%s)\n", role, name, actual)
}
func (l *lab) call(g *guest, cmd string, m M) any {
	v, e := g.call(cmd, m)
	if e != nil {
		require(fmt.Errorf("%s: %w", cmd, e))
	}
	return v
}
func (l *lab) ledger(base, step string, m M) any {
	v, e := exchange(l.client, "POST", base+api+step, m, nil)
	if e != nil {
		require(fmt.Errorf("ledger %s: %w", step, e))
	}
	return v
}
func (l *lab) bootstrap(tmp string) {
	serviceRoles, resources := roles, audiences
	if l.localOnly {
		serviceRoles = []string{"local-ledger", "broker", "process", "database", "wallet"}
		resources = []string{"process", "database", "wallet"}
	}
	ca := must(newCA())
	sockets := map[string]string{}
	sockJSON := M{}
	for _, r := range serviceRoles {
		s := must(launch(l.bin, tmp, r))
		l.services[r] = s
		if unixRole(r) {
			sockets[r+".local:80"] = s.socket
			sockJSON[r+".local:80"] = s.socket
		}
	}
	l.client = postClient(ca.pem, sockets)
	mh := obj(l.call(l.mint, "hello", nil))
	vh := obj(l.call(l.attestor, "hello", nil))
	l.routes = M{}
	type pair struct {
		role, action, a, b string
		args               M
	}
	pairs := []pair{{"endpoint", "endpoint.get", "public-status", "admin-status", M{"project": "p7"}}, {"process", "job.run", "sum", "product", M{"left": "4", "right": "7"}}, {"database", "report.read", "monthly-total", "invoice-detail", M{"project": "p7", "period": "2026-10"}}}
	pairs = append(pairs, pair{"wallet", "wallet.spend", "merchant-payment", "alternate-payment", M{"network": "regtest", "recipient": "merchant-a", "satoshis": "1000"}})
	rules := []M{}
	for _, p := range pairs {
		if l.services[p.role] == nil {
			continue
		}
		channels := M{}
		for i, res := range []string{p.a, p.b} {
			rule := M{"action": p.action, "audience": p.role, "resource": res, "args": p.args, "releaseTo": p.role + "-worker"}
			if p.role == "wallet" && i == 1 {
				args := copyMap(p.args)
				args["recipient"] = "merchant-b"
				rule["args"] = args
			}
			channels[[]string{"allowed", "restricted"}[i]] = rule
			rules = append(rules, rule)
		}
		base := l.services[p.role].base
		state := l.services["local-ledger"]
		if p.role == "endpoint" {
			state = l.services["ledger"]
		}
		l.routes[p.role] = M{"ledger": state.base, "ledgerKey": state.key, "target": base + api + "operate", "alternate": base + api + "secondary", "channels": channels}
	}
	semantics := M{"profile": profile, "routes": l.routes, "workerSHA256": l.builds["work.wasm"], "pilotSHA256": l.builds["http6-pilot"], "computeDeadlineMs": 2000, "processMaxOperand": 100, "queryRegistry": "parameterized-sqlite-v1", "input": "empty", "certificateSeconds": 5}
	sh := hash("semantics", semantics)
	controls := M{}
	l.operator = generate()
	home := l.services["ledger"]
	if l.localOnly {
		home = l.services["local-ledger"]
	}
	ledgerURL := home.base
	for _, r := range append([]string{"broker"}, resources...) {
		paths := []string{api + "check", api + "redeem", api + "outcome", api + "response-challenge", api + "response-commit"}
		if r == "broker" {
			paths = []string{api + "check", api + "confirm", api + "hold", api + "record-refusal", api + "failure-challenge", api + "failure-commit"}
		}
		bases := []string{l.services["local-ledger"].base}
		if r == "endpoint" {
			bases = []string{ledgerURL}
		}
		if r == "broker" && !l.localOnly {
			bases = append(bases, ledgerURL)
		}
		p := M{"ledgers": bases, "v": profile, "key": l.services[r].key, "role": r, "paths": paths, "responseCircuit": l.services[r].responseCircuit, "responseVerifier": l.services[r].responseVerifier}
		cert := signed(l.operator, claims("control-origin", M{"key": p["key"], "role": r, "policyHash": hash("policy", p), "nbf": stamp(), "exp": stamp() + 900}))
		controls[r] = M{"policy": p, "cert": cert}
	}
	l.trust = M{"localLedger": l.services["local-ledger"].base, "localLedgerKey": l.services["local-ledger"].key, "operator": public(l.operator), "mint": mh["issuer"], "verifier": vh["key"], "ledgerKey": home.key, "ledger": ledgerURL, "mintBuild": l.builds["mint.wasm"], "childBuild": l.builds["child.wasm"], "semantics": sh, "manifest": semantics, "routes": l.routes, "controls": controls}
	l.trust["seal"] = signed(l.operator, claims("installation", M{"digest": hash("installation", l.trust)}))
	require(artifact(filepath.Join(l.out, "trust.json"), l.trust))
	require(artifact(filepath.Join(l.out, "builds.json"), l.builds))
	for _, r := range serviceRoles {
		cert, key := "", ""
		if !unixRole(r) {
			var e error
			cert, key, e = ca.issue(r)
			require(e)
		}
		accessible := M{}
		if r == "broker" {
			accessible = sockJSON
		} else if unixRole(r) && r != "local-ledger" {
			accessible["local-ledger.local:80"] = sockJSON["local-ledger.local:80"]
		}
		require(l.services[r].configure(M{"base": l.services[r].base, "trust": l.trust, "out": l.out, "ca": ca.pem, "sockets": accessible, "certificate": cert, "tlsKey": key}))
	}
	if !l.localOnly {
		web := postClient(ca.pem, nil)
		_, e := exchange(web, "GET", l.services["local-ledger"].base+api+"catalog", nil, nil)
		l.pass("web-only client cannot open host ledger", "local-ledger", expect(e, "private socket unavailable"), nil)
		catalog := must(exchange(web, "GET", ledgerURL+api+"catalog", nil, nil))
		ensure(obj(catalog)["objects"] != nil, "public catalog unavailable")
		l.pass("anonymous HTTPS client can enumerate public evidence", "ledger", "catalog available", nil)
	}
	l.call(l.attestor, "configure", M{"trust": l.trust})
	layer := M{"schema": "policy-1", "tenant": "lab", "purpose": "channel-test", "ttlSeconds": 900, "budget": M{"pool": "shared-family", "limit": 25, "per": 1, "unit": "calls"}, "delegation": M{"maxBirths": len(resources), "maxDepth": 1, "survive": false}, "rules": rules}
	rootPolicy := M{"v": profile, "semanticsHash": sh, "layers": []M{layer}}
	ph := hash("policy", rootPolicy)
	cert := signed(l.operator, claims("certified-origin", M{"key": mh["origin"], "issuer": mh["issuer"], "policyHash": ph, "ledger": ledgerURL, "semantics": sh, "nonce": nonce(), "mintBuild": l.trust["mintBuild"], "childBuild": l.trust["childBuild"], "nbf": stamp(), "exp": stamp() + 900}))
	l.root = obj(l.call(l.mint, "root", M{"manifest": semantics, "policy": rootPolicy, "originCert": cert, "operator": l.trust["operator"], "ledger": ledgerURL, "semantics": sh}))
	l.ledger(ledgerURL, "admit", l.root)
	if !l.localOnly {
		l.ledger(l.services["local-ledger"].base, "admit", l.root)
	}
	l.pass("policy bound and native root output signed", "root", "ROOT_ADMITTED", M{"rootRef": sha([]byte(st(l.root, "root"))), "policyHash": ph, "nativeOutputHash": obj(obj(l.root["rootProof"])["result"])["publicResponse"].(map[string]any)["outputHash"]})
	for _, r := range resources {
		g := must(newGuest(l.bin, "child"))
		l.children[r] = g
		key := st(obj(l.call(g, "hello", nil)), "key")
		allowed := l.rule(r, "allowed")
		leaf := copyMap(layer)
		limits := map[string]int{"endpoint": 12, "process": 4, "database": 4, "wallet": 5}
		leaf["rules"] = []M{allowed}
		leaf["ttlSeconds"] = 600
		leaf["budget"] = M{"pool": "shared-family", "limit": limits[r], "per": 1, "unit": "calls"}
		leaf["delegation"] = M{"maxBirths": 0, "maxDepth": 0, "survive": false}
		pol := M{"v": profile, "semanticsHash": sh, "layers": []M{layer, leaf}}
		terms := l.call(l.mint, "prepare-birth", M{"birthId": "birth-" + r, "holder": r + "-worker", "childKey": key, "policy": pol})
		join := l.call(g, "join", M{"terms": terms, "policy": pol})
		b := obj(l.call(l.mint, "birth", M{"join": join}))
		family := obj(b["family"])
		l.ledger(st(obj(l.routes[r]), "ledger"), "birth", family)
		provision := M{"family": family, "privateProvision": b["privateProvision"]}
		l.call(l.attestor, "enroll", provision)
		provision["trust"] = l.trust
		l.call(g, "activate", provision)
		l.families[r] = family
	}
	require(artifact(filepath.Join(l.out, "families.json"), l.families))
	ids := map[string]bool{}
	for _, f := range l.families {
		terms := obj(peek(st(f, "child"))["terms"])
		ids[st(terms, "circuitDigest")] = true
	}
	ensure(len(ids) == len(resources), "child native material repeated")
	l.pass("distinct attenuated child circuits", "root", fmt.Sprintf("%d unique circuit digests", len(resources)), nil)
}
func (l *lab) rule(role, ch string) M { return obj(obj(obj(l.routes[role])["channels"])[ch]) }
func (l *lab) intent(role, channel string) M {
	i := copyMap(l.rule(role, channel))
	for k, v := range (M{"v": profile, "tenant": "lab", "purpose": "channel-test", "rootRef": sha([]byte(st(l.root, "root"))), "inputHash": sha(nil), "units": 1}) {
		i[k] = v
	}
	return i
}

type invocation struct {
	wire, pkg, attempt   M
	witness, certificate string
}

func (l *lab) prepare(role, op string) invocation {
	return l.prepareIntent(role, op, l.intent(role, "allowed"), 5)
}
func (l *lab) prepareIntent(role, op string, i M, ttl int) invocation {
	g := l.children[role]
	a := obj(l.call(g, "prepare", M{"intent": i, "holdSeconds": ttl, "op": op}))
	ch := obj(l.call(l.attestor, "challenge", M{"intent": i, "attempt": a}))
	wit := l.call(g, "answer", ch).(string)
	pr := l.call(l.attestor, "attest", M{"attempt": a, "witness": wit})
	pkg := obj(l.call(g, "request", M{"proof": pr}))
	return invocation{pkg: pkg, attempt: a, witness: wit}
}
func (l *lab) issued(role, op string) invocation {
	x := l.prepare(role, op)
	return l.issuePrepared(role, x)
}
func (l *lab) issuePrepared(role string, x invocation) invocation {
	x.certificate = l.ledger(st(obj(l.routes[role]), "ledger"), "reserve", x.pkg).(string)
	x.wire = obj(l.call(l.children[role], "present", M{"package": x.pkg, "certificate": x.certificate}))
	return x
}
func (l *lab) send(role, targetRole, ch string, x invocation) (any, error) {
	target := l.services["broker"].base + api + "dispatch"
	if targetRole != "broker" {
		target = st(obj(l.routes[targetRole]), map[string]string{"allowed": "target", "restricted": "alternate"}[ch])
	}
	return deliver(l.client, target, targetRole, x.wire, l.children[role], st(x.attempt, "key"), "")
}
func (l *lab) effects(role string) []M {
	d := must(openDB(filepath.Join(l.out, role+".sqlite")))
	defer d.close()
	return must(d.query("SELECT * FROM effects ORDER BY rowid"))
}
func (l *lab) happy(role string, x invocation, label string) {
	v := obj(must(l.send(role, "broker", "allowed", x)))
	r := obj(v["result"])
	expected := map[string]M{"endpoint": {"view": "public-status", "project": "p7", "status": "available"}, "process": {"program": "sum", "value": 11}, "database": {"query": "monthly-total", "rows": []M{{"total": "18"}}}}
	expected["wallet"] = M{"asset": "synthetic-satoshi", "network": "regtest", "amount": integerFromString(st(obj(obj(obj(x.pkg["body"])["intent"])["args"]), "satoshis")), "recipient": "merchant-a", "op": x.attempt["op"]}
	ensure(bytesEqual(r, expected[role]), "unexpected actual resource result: "+string(canon(r)))
	ensure(len(st(v, "confirmationRef")) == 64, "missing broker confirmation")
	l.pass(label, role, "CONFIRMED", M{"op": x.attempt["op"], "proofRef": hash("proof", x.pkg["proof"]), "result": r, "confirmationRef": v["confirmationRef"]})
	if role == "endpoint" && label == "allowed channel acted" {
		l.responseCases(role, x, v)
	}
}
func (l *lab) exercise() {
	for _, r := range audiences {
		x := l.issued(r, r+"-happy")
		l.happy(r, x, "allowed channel acted")
		l.examples[r] = x.wire
	}
	for _, r := range audiences {
		x := l.issued(r, r+"-second-channel")
		before := len(l.effects(r))
		_, e := l.send(r, r, "restricted", x)
		code := expect(e, "POLICY_DENIED")
		ensure(len(l.effects(r)) == before, "restricted channel caused an effect")
		l.pass("live signed proof presented directly at restricted channel", r, code, M{"op": x.attempt["op"], "policyHash": x.attempt["policyHash"], "proofRef": hash("proof", x.pkg["proof"]), "effectsAdded": 0})
		_, e = l.send(r, "broker", "allowed", x)
		l.pass("previously rejected proof retried on allowed channel", r, expect(e, "REJECTED"), M{"effectsAdded": 0})
		x = l.issued(r, r+"-fresh")
		l.happy(r, x, "fresh proof for the allowed channel after rejection")
		_, e = l.send(r, "broker", "allowed", x)
		code = expect(e, "SPENT")
		ensure(len(l.effects(r)) == before+1, "replay repeated effect")
		l.pass("exact replay after use", r, code, M{"effectsAdded": 0})
		_, e = l.children[r].call("prepare", M{"intent": l.intent(r, "restricted"), "op": "rogue-" + r})
		l.pass("child sought fresh proof outside its policy", r, expect(e, "outside hereditary policy"), nil)
	}
	// These tests use a still-unspent certificate, so spend state cannot explain the denials.
	r := "endpoint"
	x := l.issued(r, "endpoint-before-use")
	route := obj(l.routes[r])
	before := len(l.effects(r))
	_, e := deliver(l.client, st(route, "target"), r, x.wire, nil, "", "")
	l.pass("complete unspent presentation copied to another connection", r, expect(e, "FRESH_HOLDER_REQUIRED"), nil)
	firstHop := obj(must(exchange(l.client, "GET", l.services[r].base+api+"challenge", nil, nil)))
	holder := st(x.attempt, "key")
	signedHop := l.call(l.children[r], "ingress", M{"presentation": x.wire, "claims": claims("ingress", M{"nonce": firstHop["nonce"], "ingress": r, "signer": holder, "wireHash": hash("wire", x.wire)})}).(string)
	_, e = deliver(l.client, st(route, "target"), r, x.wire, nil, "", signedHop)
	l.pass("copied unspent presentation and authentic hop signature on a new connection", r, expect(e, "FRESH_HOLDER_REQUIRED"), M{"effectsAdded": 0})
	h := copyMap(obj(x.wire["headers"]))
	delete(h, "signature")
	_, e = exchange(l.client, "POST", st(route, "target"), x.wire["body"], h)
	l.pass("public proof copied without holder signature", r, expect(e, "MISSING_OR_DUPLICATE_SIGNATURE_FIELD"), nil)
	h = copyMap(obj(x.wire["headers"]))
	h["http6-policy"] = strconv.Quote(st(l.trust, "ledger") + api + "policies/" + hash("policy", l.root["rootPolicy"]))
	_, e = exchange(l.client, "POST", st(route, "target"), x.wire["body"], h)
	l.pass("public root policy address substituted for child policy", r, expect(e, "HTTP signed field mismatch"), nil)
	b := copyMap(obj(x.wire["body"]))
	obj(obj(b["intent"])["args"])["project"] = "p8"
	_, e = exchange(l.client, "POST", st(route, "target"), b, obj(x.wire["headers"]))
	l.pass("request arguments changed after signature", r, expect(e, "outside hereditary policy"), nil)
	b = copyMap(obj(x.wire["body"]))
	b["input"] = "different"
	_, e = exchange(l.client, "POST", st(route, "target"), b, obj(x.wire["headers"]))
	l.pass("request payload changed after signature", r, expect(e, "body shape"), nil)
	p := copyMap(x.pkg)
	obj(obj(p["proof"])["result"])["policyHash"] = hash("policy", l.root["rootPolicy"])
	_, e = exchange(l.client, "POST", st(l.trust, "ledger")+api+"reserve", p, nil)
	l.pass("native proof policy hash edited", r, expect(e, "circuit proof binding"), nil)
	f := copyMap(l.families[r])
	layers := obj(f["policy"])["layers"].([]any)
	obj(layers[1])["rules"] = []M{l.rule(r, "restricted")}
	_, e = l.attestor.call("family", M{"family": f})
	l.pass("child policy rewritten under existing grant", r, expect(e, "child scope"), nil)
	f = copyMap(l.families[r])
	f["birthProof"] = l.families["database"]["birthProof"]
	_, e = l.attestor.call("family", M{"family": f})
	l.pass("sibling birth proof spliced into lineage", r, expect(e, "child birth proof"), nil)
	_, e = l.attestor.call("attest", M{"attempt": x.attempt, "witness": x.witness})
	l.pass("spent native challenge submitted again", r, expect(e, "challenge absent or spent"), nil)
	_, e = exchange(l.client, "POST", st(l.trust, "ledger")+api+"reserve", x.pkg, nil)
	l.pass("duplicate signed proof reservation", r, expect(e, "OPERATION_EXISTS"), nil)
	_, e = exchange(l.client, "POST", st(obj(l.routes["process"]), "target"), x.wire["body"], obj(x.wire["headers"]))
	l.pass("valid endpoint proof at process custodian", "process", expect(e, "WRONG_CUSTODIAN"), nil)
	_, e = exchange(l.client, "GET", st(route, "target"), nil, nil)
	l.pass("unsigned HTTP method at endpoint", r, expect(e, "METHOD"), nil)
	ensure(len(l.effects(r)) == before, "copied requests reached protected resource")
	l.happy(r, x, "holder acted after copied requests were refused")
	// Race a broker delivery and a direct delivery of precisely the same signed operation.
	x = l.issued(r, "endpoint-race")
	before = len(l.effects(r))
	var wg sync.WaitGroup
	codes := make(chan string, 2)
	for _, dst := range []string{"broker", "broker"} {
		wg.Add(1)
		go func(dst string) {
			defer wg.Done()
			_, err := l.send(r, dst, "allowed", x)
			if err != nil {
				codes <- err.Error()
			} else {
				codes <- "OK"
			}
		}(dst)
	}
	wg.Wait()
	close(codes)
	got := map[string]int{}
	for c := range codes {
		got[c]++
	}
	ensure(got["OK"] == 1 && got["SPENT"] == 1 && len(l.effects(r)) == before+1, fmt.Sprintf("race result %v", got))
	l.pass("concurrent broker deliveries of one instruction", r, "1 acted, 1 SPENT", M{"effectsAdded": 1, "op": x.attempt["op"]})
	for _, variant := range []struct {
		name, field string
		value       any
	}{{"wrong tenant", "tenant", "elsewhere"}, {"different purpose", "purpose", "maintenance"}, {"different release recipient", "releaseTo", "other-worker"}, {"unregistered intent extension", "unused", true}, {"extra computation units", "units", 2}} {
		i := l.intent("process", "allowed")
		i[variant.field] = variant.value
		_, e = l.children["process"].call("prepare", M{"intent": i, "op": "bad-scope"})
		why := "outside hereditary policy"
		if variant.field == "unused" || variant.field == "units" {
			why = "intent shape"
		}
		l.pass(variant.name, "process", expect(e, why), nil)
	}
	for _, action := range []string{"report.create", "report.update", "report.delete"} {
		i := l.intent("database", "allowed")
		i["action"] = action
		_, err := l.children["database"].call("prepare", M{"intent": i, "op": action})
		l.pass("read-only grant rejects "+action, "database", expect(err, "outside hereditary policy"), M{"intent": i, "stage": "child preparation"})
	}
	for _, variant := range []struct{ name, field, value string }{
		{"endpoint outside allowlist", "resource", "unlisted-endpoint"},
		{"release response to an unlisted worker", "releaseTo", "external-worker"},
	} {
		i := l.intent("endpoint", "allowed")
		i[variant.field] = variant.value
		_, err := l.children["endpoint"].call("prepare", M{"intent": i, "op": "scope-review"})
		l.pass(variant.name, "endpoint", expect(err, "outside hereditary policy"), M{"intent": i, "stage": "child preparation"})
	}
	f = copyMap(l.families["process"])
	obj(obj(f["policy"])["layers"].([]any)[1])["ttlSeconds"] = 901
	_, e = l.attestor.call("family", M{"family": f})
	l.pass("child lifetime expansion", "root", expect(e, "unsupported policy bounds"), nil)
	_, e = l.mint.call("prepare-birth", M{"birthId": "extra", "childKey": st(x.attempt, "key"), "holder": "extra", "policy": l.families["process"]["policy"]})
	l.pass("fifth birth under four-child root", "root", expect(e, "birth allowance exhausted"), nil)
	l.issued("database", "database-budget-fourth")
	over := l.prepare("database", "database-over-budget")
	_, e = exchange(l.client, "POST", st(l.trust, "localLedger")+api+"reserve", over.pkg, nil)
	l.pass("fifth reservation against four-call child allowance", "database", expect(e, "BUDGET"), nil)
	_, e = l.send(r, r, "allowed", l.issued(r, "endpoint-direct"))
	l.pass("direct remote execution requires local broker", r, expect(e, "BROKER_REQUIRED"), nil)
	for _, v := range []struct{ k, value string }{{"satoshis", "1001"}, {"satoshis", "0"}, {"recipient", "merchant-b"}, {"network", "mainnet"}} {
		i := l.intent("wallet", "allowed")
		obj(i["args"])[v.k] = v.value
		_, e = l.children["wallet"].call("prepare", M{"op": "untrusted-proposal", "intent": i})
		l.pass("wallet proposal with "+v.k+"="+v.value, "wallet", expect(e, "outside hereditary policy"), nil)
	}
	x = l.issued(r, "endpoint-outage-recovered")
	require(l.services[r].availability(false))
	_, e = l.send(r, "broker", "allowed", x)
	l.pass("temporary service outage holds the original proof", r, expect(e, "HELD_RESOURCE"), nil)
	require(l.services[r].availability(true))
	l.happy(r, x, "service restored before the original deadline")
	x = l.issued(r, "endpoint-lag-recovered")
	require(l.services[r].setFault(M{"cmd": "latency", "ms": 1600}))
	_, e = l.send(r, "broker", "allowed", x)
	l.pass("delayed HTTPS response holds one operation", r, expect(e, "HELD_RESOURCE"), nil)
	l.happy(r, x, "same proof delivered after network delay")
	x = l.issuePrepared(r, l.prepareIntent(r, "endpoint-expired", l.intent(r, "allowed"), 2))
	require(l.services[r].availability(false))
	_, e = l.send(r, "broker", "allowed", x)
	l.pass("agent sets a two-second service outage deadline", r, expect(e, "HELD_RESOURCE"), M{"agentTTL": 2})

	time.Sleep(time.Until(time.Unix(integer(peek(x.certificate), "exp"), 0)) + 150*time.Millisecond)
	require(l.services[r].availability(true))
	_, e = exchange(l.client, "POST", st(route, "target"), x.wire["body"], obj(x.wire["headers"]))
	l.pass("held request past its signed two-second window", r, expect(e, "expired or inactive"), nil)
	x = l.issued("process", "process-revoked")
	l.ledger(st(l.trust, "localLedger"), "revoke", M{"authorization": signed(l.operator, claims("revoke", M{"grantRef": x.attempt["grantRef"], "exp": stamp() + 30}))})
	_, e = l.send("process", "process", "allowed", x)
	l.pass("grant revoked after valid proof was issued", "process", expect(e, "REVOKED"), nil)
	_, e = l.send("process", "process", "allowed", x)
	l.pass("retry after a signed revocation refusal", "process", expect(e, "REJECTED"), nil)
	localBase := l.services["local-ledger"].base
	for _, ra := range []string{"process", "database", "wallet"} {
		p := obj(l.examples[ra])
		pr := must(publicProof(p))
		ref := hash("proof", pr)
		_, e = exchange(l.client, "GET", l.services["ledger"].base+api+"objects/"+ref, nil, nil)
		l.pass("local call proof absent from public ledger", ra, expect(e, "MISSING_PUBLIC_RECORD"), nil)
	}
	_, e = exchange(l.client, "POST", l.services["ledger"].base+api+"birth", l.families["wallet"], nil)
	l.pass("wallet grant submitted to external ledger", "wallet", expect(e, "WRONG_LEDGER"), nil)
	x = l.issued(r, "endpoint-ledger-offline")
	events := must(exchange(l.client, "GET", l.services["ledger"].base+api+"events", nil, nil))
	require(artifact(filepath.Join(l.out, "public-ledger.json"), events))
	l.services["ledger"].close()
	for _, dst := range []string{"broker", r} {
		_, e = l.send(r, dst, "allowed", x)
		var a *apiError
		ensure(errors.As(e, &a) && a.Status == 503, "outage must return 503")
		l.pass("external ledger disconnected before remote action", dst, expect(e, "HELD_LEDGER"), M{"effectsAdded": 0})
	}
	i := l.intent("wallet", "allowed")
	obj(i["args"])["satoshis"] = "250"
	payment := l.issuePrepared("wallet", l.prepareIntent("wallet", "wallet-offline-payment", i, 5))
	l.happy("wallet", payment, "250-satoshi local debit while the external ledger is offline")
	require(exportSpend(l.out, l.trust, l.families["wallet"], payment))
	l.pass("portable signed spend checked with local trust anchors", "wallet", "OFFLINE_VERIFIED", nil)
	bundle := obj(must(readArtifact(l.out, "spend-evidence.json")))
	changed := copyMap(bundle)
	obj(changed["result"])["amount"] = 999
	e = verifySpend(l.bin, changed, st(l.trust, "operator"), st(l.trust, "localLedgerKey"))
	l.pass("offline evidence with modified spend amount", "wallet", expect(e, "spend evidence binding mismatch"), nil)
	e = verifySpend(l.bin, bundle, st(l.trust, "operator"), st(l.trust, "ledgerKey"))
	l.pass("public ledger key substituted for local trust anchor", "wallet", expect(e, "untrusted installation"), nil)
	waiting := l.issued("wallet", "wallet-local-ledger-offline")
	events = must(exchange(l.client, "GET", localBase+api+"events", nil, nil))
	require(artifact(filepath.Join(l.out, "local-ledger.json"), events))
	l.services["local-ledger"].close()
	for _, dst := range []string{"broker", "wallet"} {
		_, e = l.send("wallet", dst, "allowed", waiting)
		var ae *apiError
		ensure(errors.As(e, &ae) && ae.Status == 503, "local ledger loss must hold")
		l.pass("local ledger disconnected before debit", dst, expect(e, "HELD_LEDGER"), M{"effectsAdded": 0})
	}
	require(artifact(filepath.Join(l.out, "presentations.json"), l.examples))
}
func runDemo(bin, out, runtimePath string) error { return runLab(bin, out, runtimePath, false) }
func runLab(bin, out, runtimePath string, localOnly bool) (err error) {
	if !localOnly {
		_ = os.Setenv("HTTP6_PILOT_RESPONSE_TEST", "1")
		defer os.Unsetenv("HTTP6_PILOT_RESPONSE_TEST")
	}
	defer func() {
		if x := recover(); x != nil {
			if f, ok := x.(testFailure); ok {
				err = f.err
			} else {
				panic(x)
			}
		}
	}()
	l := &lab{localOnly: localOnly, bin: bin, out: out, builds: must(manifest(bin)), services: map[string]*service{}, children: map[string]*guest{}, families: map[string]M{}, examples: M{}}
	tmp := must(os.MkdirTemp("", "http6-"))
	defer os.RemoveAll(tmp)
	require(os.MkdirAll(filepath.Dir(out), 0700))
	require(os.Mkdir(out, 0700))
	defer func() {
		for _, g := range l.children {
			g.close()
		}
		for _, s := range l.services {
			s.close()
		}
		if l.attestor != nil {
			l.attestor.close()
		}
		if l.mint != nil {
			l.mint.close()
		}
	}()
	if runtimePath == "" {
		l.mint = must(newGuest(bin, "mint"))
		l.attestor = must(newGuest(bin, "verifier"))
	} else {
		l.mint = must(attachGuest(runtimePath, "mint"))
		l.attestor = must(attachGuest(runtimePath, "verifier"))
	}
	l.bootstrap(tmp)
	if localOnly {
		return l.serveAgent(tmp)
	}
	l.exercise()
	for _, s := range l.services {
		s.close()
	}
	require(artifact(filepath.Join(out, "tests.json"), l.results))
	return audit(out, true)
}

func integerFromString(v string) int64 { n, _ := strconv.ParseInt(v, 10, 64); return n }
