package main

import (
	"encoding/json"
	"fmt"
	h "github.com/HTTP6-ORG/http6-sdk/packages/go"
	"os"
	"path/filepath"
)

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func rejected(e error) {
	if e == nil {
		panic("expected rejection")
	}
}
func proposal(op, amount string) map[string]any {
	return map[string]any{"op": op, "audience": "wallet", "resource": "merchant-payment", "args": map[string]any{"network": "regtest", "recipient": "merchant-a", "satoshis": amount}, "holdSeconds": 4}
}
func main() {
	if len(os.Args) != 5 {
		panic("state binary operator ledger required")
	}
	state, binary, operator, ledger := os.Args[1], os.Args[2], os.Args[3], os.Args[4]
	c, e := h.Attach(state, binary)
	must(e)
	r, e := c.Invoke(proposal("go-sdk-ok", "100"))
	must(e)
	if r.Status != 200 {
		panic("expected success")
	}
	file := filepath.Join(state, r.Body["responseEvidenceFile"].(string))
	must(c.VerifyResponse(r, file, operator, ledger, "go-sdk-ok"))
	rejected(c.VerifyResponse(r, file, "0000000000000000000000000000000000000000000000000000000000000000", ledger, "go-sdk-ok"))
	rejected(c.VerifyResponse(r, file, operator, ledger, "different-op"))
	res := r.Body["result"].(map[string]any)
	old := res["amount"]
	res["amount"] = json.Number("101")
	rejected(c.VerifyResponse(r, file, operator, ledger, "go-sdk-ok"))
	res["amount"] = old
	f, e := c.Invoke(proposal("go-sdk-denied", "1100"))
	must(e)
	if f.Status != 403 {
		panic("expected denial")
	}
	ff := filepath.Join(state, f.Body["failureEvidenceFile"].(string))
	must(c.VerifyFailure(f, ff, operator, ledger))
	f.RequestBytes = []byte("altered")
	rejected(c.VerifyFailure(f, ff, operator, ledger))
	m, e := c.InvokeRaw([]byte("{invalid"))
	must(e)
	if m.Status != 400 {
		panic("expected malformed")
	}
	must(c.VerifyFailure(m, filepath.Join(state, m.Body["failureEvidenceFile"].(string)), operator, ledger))
	rows, e := c.Events()
	must(e)
	v, e := c.VerifyLedger(rows, ledger)
	must(e)
	if v["verified"] != true || v["latestHeadVerified"] != false {
		panic("wrong verification")
	}
	rows[0].(map[string]any)["event"] = "ALTERED"
	_, e = c.VerifyLedger(rows, ledger)
	rejected(e)
	fmt.Println(`{"language":"go","success":true,"denied":true,"malformed":true,"tamperingRejected":true,"ledgerVerified":true}`)
}
