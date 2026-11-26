package main

import (
	"fmt"
	"testing"
)

func TestVerifyLedgerRows(t *testing.T) {
	key := generate()
	data := M{"grantRef": "fixture"}
	prev := ""
	rows := []any{}
	for i := 1; i <= 2; i++ {
		entry := claims("ledger-entry", M{"seq": i, "prev": prev, "event": "ROOT_ADMITTED", "actor": "mint", "op": "", "channel": "fixture", "data": data, "at": 1})
		token := signed(key, entry)
		ref := sha([]byte(token))
		rows = append(rows, M{"seq": fmt.Sprint(i), "event": "ROOT_ADMITTED", "actor": "mint", "op": "", "channel": "fixture", "data": string(canon(data)), "signature": token, "ref": ref})
		prev = ref
	}
	result, e := verifyLedgerRows(rows, public(key))
	if e != nil || result["verified"] != true || result["latestHeadVerified"] != false {
		t.Fatalf("verify %v %v", result, e)
	}
	wrong := generate()
	if _, e = verifyLedgerRows(rows, public(wrong)); e == nil {
		t.Fatal("accepted wrong key")
	}
	row := copyMap(obj(rows[0]))
	row["event"] = "ALTERED"
	if _, e = verifyLedgerRows([]any{row, rows[1]}, public(key)); e == nil {
		t.Fatal("accepted changed metadata")
	}
	if _, e = verifyLedgerRows(rows[1:], public(key)); e == nil {
		t.Fatal("accepted missing first entry")
	}
	row = copyMap(obj(rows[1]))
	row["data"] = `{"grantRef":"changed"}`
	if _, e = verifyLedgerRows([]any{rows[0], row}, public(key)); e == nil {
		t.Fatal("accepted changed data")
	}
}
