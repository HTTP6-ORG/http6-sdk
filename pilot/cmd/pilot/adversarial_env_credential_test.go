package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// A readable environment file lets another local process reuse a remote
// service credential. The test endpoint is TLS-protected and loopback-only.
func TestAdversarialReadableEnvCredentialCanAuthorizeLocalService(t *testing.T) {
	credential := "SYNTHETIC-REMOTE-" + nonce()
	envPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envPath, []byte("HTTP6_TEST_REMOTE_API_KEY="+credential+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	readCredential := func() string {
		t.Helper()
		data, err := os.ReadFile(envPath)
		if err != nil {
			t.Fatal(err)
		}
		key, ok := strings.CutPrefix(strings.TrimSpace(string(data)), "HTTP6_TEST_REMOTE_API_KEY=")
		if !ok || key == "" {
			t.Fatal("synthetic environment credential missing")
		}
		return key
	}
	applicationCredential := readCredential()
	attackerCredential := readCredential()
	if applicationCredential != attackerCredential {
		t.Fatal("synthetic attacker did not read the same test credential")
	}

	ca := must(newCA())
	cert, key := mustPair(ca.issue("local-synthetic-service"))
	var effects atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+credential {
			answer(w, nil, &apiError{Status: http.StatusUnauthorized, Code: "INVALID_CREDENTIAL"})
			return
		}
		effects.Add(1)
		answer(w, M{"payload": M{"accepted": true}}, nil)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{must(tls.X509KeyPair([]byte(cert), []byte(key)))}}
	server.StartTLS()
	defer server.Close()

	client := postClient(ca.pem, nil)
	defer client.CloseIdleConnections()
	for _, credentialCopy := range []struct {
		caller string
		value  string
	}{{"application", applicationCredential}, {"local file reader", attackerCredential}} {
		response, err := exchange(client, "POST", server.URL, M{"operation": "sum"}, M{"Authorization": "Bearer " + credentialCopy.value})
		if err != nil || obj(obj(response)["payload"])["accepted"] != true {
			t.Fatalf("%s request rejected by local service: %v", credentialCopy.caller, err)
		}
	}
	if effects.Load() != 2 {
		t.Fatalf("expected two local service effects, got %d", effects.Load())
	}
	t.Log("OBSERVATION: a reader of a synthetic .env bearer secret reused it over validated local HTTPS")
}
