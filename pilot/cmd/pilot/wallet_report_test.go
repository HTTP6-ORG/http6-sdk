package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

var traceEvidence = flag.String("trace-out", "", "a new private evidence directory")
var traceRelease = flag.String("trace-release", "", "verified HTTP6 release binary directory")

func TestWalletBrokerTrace(t *testing.T) {
	if *traceEvidence == "" || *traceRelease == "" {
		t.Skip("set -trace-out and -trace-release to capture a new run")
	}
	syscall.Umask(0077)
	require(os.Mkdir(*traceEvidence, 0700))
	socketDir := must(os.MkdirTemp("", "h6-wt-"))
	defer os.RemoveAll(socketDir)
	l := &lab{bin: *traceRelease, out: *traceEvidence, localOnly: true, builds: must(manifest(*traceRelease)), services: map[string]*service{}, children: map[string]*guest{}, families: map[string]M{}, examples: M{}}
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
	l.mint = must(newGuest(l.bin, "mint"))
	l.attestor = must(newGuest(l.bin, "verifier"))
	l.bootstrap(socketDir)
	agentDone := make(chan error, 1)
	go func() { agentDone <- l.serveAgent(socketDir) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, e := os.Stat(filepath.Join(l.out, "connections.json")); e == nil {
			break
		}
		select {
		case e := <-agentDone:
			t.Fatalf("agent exited at start: %v", e)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("agent startup timeout")
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer func() {
		require(syscall.Kill(os.Getpid(), syscall.SIGTERM))
		select {
		case e := <-agentDone:
			require(e)
		case <-time.After(9 * time.Second):
			t.Fatal("agent shutdown timeout")
		}
	}()
	funds := func() string {
		db := must(readDB(l.out, "wallet"))
		defer db.close()
		rows := must(db.query("SELECT sats FROM funds WHERE account='fixture'"))
		return st(rows[0], "sats")
	}
	before := funds()
	allowed := M{"op": "wallet-allowed-250", "audience": "wallet", "resource": "merchant-payment", "args": M{"network": "regtest", "recipient": "merchant-a", "satoshis": "250"}, "holdSeconds": 5}
	over := copyMap(allowed)
	over["op"] = "wallet-over-limit-1100"
	obj(over["args"])["satoshis"] = "1100"
	entries := []M{}
	cli := func(label string, proposal M, expected string) M {
		cmd := exec.Command(filepath.Join(l.bin, "http6-pilot"), "request", "--state", l.out, string(canon(proposal)))
		b, e := cmd.CombinedOutput()
		raw := strings.TrimSpace(string(b))
		item := M{"case": label, "proposal": proposal, "digest": hash("proposal", proposal), "exit": cmd.ProcessState.ExitCode()}
		var reply M
		if expected == "" {
			require(e)
			reply = obj(must(parse(b)))
			item["reply"] = reply
		} else {
			if e == nil || !strings.Contains(raw, expected) {
				t.Fatalf("%s: %s", label, raw)
			}
			item["reply"] = raw
		}
		entries = append(entries, item)
		return reply
	}
	paid := cli("allowed", allowed, "")
	if integer(obj(paid["result"]), "amount") != 250 {
		t.Fatal("wrong transfer")
	}
	cli("over-limit", over, "WALLET_AMOUNT_EXCEEDS_LIMIT")
	cli("repeat refused proposal", over, "REJECTED")
	cli("same proposal at agent", allowed, "SPENT")

	// Submit the original exported business presentation on a fresh authenticated connection.
	// This uses the same enrolled holder inside the run and the ordinary broker's dispatch path.
	bundle := obj(must(readArtifact(l.out, st(paid, "evidenceFile"))))
	wire := obj(bundle["presentation"])
	attempt := obj(peek(st(obj(wire["body"]), "request"))["attempt"])
	_, e := l.send("wallet", "broker", "allowed", invocation{wire: wire, attempt: attempt})
	var refusal *apiError
	if !errors.As(e, &refusal) || refusal.Status != 403 || refusal.Code != "SPENT" {
		t.Fatalf("expected signed-ledger replay refusal, got %v", e)
	}
	entries = append(entries, M{"case": "same signed presentation at broker", "op": attempt["op"], "httpStatus": refusal.Status, "reply": refusal.Code, "holderKey": attempt["key"], "wireHash": hash("wire", wire)})
	after := funds()
	if before != "10000" || after != "9750" {
		t.Fatalf("unexpected wallet balance %s to %s", before, after)
	}
	events := must(exchange(l.client, "GET", st(l.trust, "localLedger")+api+"events", nil, nil))
	require(artifact(filepath.Join(l.out, "ledger-entries.json"), events))
	require(artifact(filepath.Join(l.out, "submissions.json"), M{"proposals": entries, "openingBalance": before, "closingBalance": after, "evidenceFile": paid["evidenceFile"]}))
	fmt.Printf("Wallet funding %s -> %s; signed presentation replay HTTP %d %s\n", before, after, refusal.Status, refusal.Code)
}
