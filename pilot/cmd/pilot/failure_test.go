package main

import (
	"bytes"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestFailureProofEndToEnd(t *testing.T) {
	if *traceRelease == "" {
		t.Skip("set -trace-release to a built pilot")
	}
	t.Setenv("HTTP6_PILOT_RESPONSE_TEST", "1")
	out := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(out, 0700); err != nil {
		t.Fatal(err)
	}
	socketDir, err := os.MkdirTemp("/private/tmp", "h6-f-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(socketDir)
	l := &lab{bin: *traceRelease, out: out, localOnly: true, builds: must(manifest(*traceRelease)), services: map[string]*service{}, children: map[string]*guest{}, families: map[string]M{}, examples: M{}}
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
	db := must(openDB(filepath.Join(out, "agent.sqlite")))
	defer db.close()
	require(db.exec("CREATE TABLE proposals(id INTEGER PRIMARY KEY,op TEXT,audience TEXT,digest TEXT,verdict TEXT,at TEXT)"))
	agent := &agentServer{l: l, db: db, open: map[string]pendingCall{}}
	invoke := func(raw []byte, category string, status int, proved bool) M {
		t.Helper()
		req := httptest.NewRequest("POST", api+"propose", bytes.NewReader(raw))
		w := httptest.NewRecorder()
		agent.ServeHTTP(w, req)
		result := obj(must(parse(w.Body.Bytes())))
		if w.Code != status || st(result, "category") != category {
			t.Fatalf("%s got status %d result %s", category, w.Code, canon(result))
		}
		expected := "unavailable"
		if proved {
			expected = "ledger-recorded"
		}
		if st(result, "proofStatus") != expected {
			t.Fatalf("%s proof status: %s", category, canon(result))
		}
		if proved {
			b := obj(must(readArtifact(out, st(result, "failureEvidenceFile"))))
			if e := verifyFailureEvidence(l.bin, b, st(l.trust, "operator"), st(l.trust, "localLedgerKey"), sha(raw), int64(status)); e != nil {
				t.Fatalf("%s historical verification: %v", category, e)
			}
			if e := verifyFailureEvidence(l.bin, b, st(l.trust, "operator"), st(l.trust, "localLedgerKey"), sha([]byte("altered")), int64(status)); e == nil {
				t.Fatal("altered request accepted")
			}
			for _, field := range []string{"category", "status", "requestHash", "resultHash"} {
				altered := obj(must(parse(canon(b))))
				ctx := obj(obj(altered["failure"])["context"])
				if field == "status" {
					ctx[field] = 418
				} else {
					ctx[field] = "altered"
				}
				if e := verifyFailureEvidence(l.bin, altered, st(l.trust, "operator"), st(l.trust, "localLedgerKey"), sha(raw), int64(status)); e == nil {
					t.Fatalf("altered %s accepted", field)
				}
			}
			replay, e := l.services["broker"].testFailureReplay(obj(b["failure"]))
			if e != nil || replay != "FAILURE_REPLAY_OR_EXPIRED" {
				t.Fatalf("failure replay: %q %v", replay, e)
			}
			bad := copyMap(b)
			bad["failureEntry"] = ""
			if e := verifyFailureEvidence(l.bin, bad, st(l.trust, "operator"), st(l.trust, "localLedgerKey"), sha(raw), int64(status)); e == nil {
				t.Fatal("missing ledger entry accepted")
			}
		} else if result["failure"] != nil {
			t.Fatal("unrecorded proof returned")
		}
		return result
	}
	invoke([]byte("{bad"), "malformed", 400, true)
	p := M{"op": "deny-1100", "audience": "wallet", "resource": "merchant-payment", "args": M{"network": "regtest", "recipient": "merchant-a", "satoshis": "1100"}, "holdSeconds": 5}
	denied := invoke(canon(p), "denied", 403, true)
	if st(denied, "error") != "WALLET_AMOUNT_EXCEEDS_LIMIT" {
		t.Fatalf("wrong denial: %s", canon(denied))
	}
	p = M{"op": "held-100", "audience": "wallet", "resource": "merchant-payment", "args": M{"network": "regtest", "recipient": "merchant-a", "satoshis": "100"}, "holdSeconds": 5}
	require(l.services["wallet"].availability(false))
	held := invoke(canon(p), "held", 503, true)
	if st(held, "error") != "HELD_RESOURCE" {
		t.Fatalf("wrong hold: %s", canon(held))
	}
	require(l.services["wallet"].availability(true))
	require(l.services["wallet"].setFault(M{"cmd": "test-fail-after-redeem"}))
	p["op"] = "uncertain-100"
	uncertain := invoke(canon(p), "uncertain", 503, true)
	if st(uncertain, "error") != "UNCERTAIN" {
		t.Fatalf("wrong uncertain: %s", canon(uncertain))
	}
	// The reply arrives after the request certificate has expired, but redemption is still uncertain.
	require(l.services["wallet"].setFault(M{"cmd": "test-fail-after-redeem", "delayMillis": 2500}))
	p["op"] = "uncertain-expired"
	p["holdSeconds"] = 2
	expired := invoke(canon(p), "uncertain", 503, true)
	if st(expired, "error") != "UNCERTAIN_HOLD" {
		t.Fatalf("expired uncertain state: %s", canon(expired))
	}
	rows := must(readDB(out, "local-ledger"))
	defer rows.close()
	op := must(rows.query("SELECT state FROM operations WHERE op=?", "uncertain-100"))
	if len(op) != 1 || st(op[0], "state") != "REDEEMED" {
		t.Fatalf("uncertain state: %v", op)
	}
	l.services["local-ledger"].close()
	invoke([]byte("{offline"), "malformed", 400, false)
}
