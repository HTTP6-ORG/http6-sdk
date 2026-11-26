package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Verify only the returned signed rows. This cannot establish the latest head or external effects.
func verifyLedgerRows(value any, ledgerKey string) (M, error) {
	key, e := hex.DecodeString(ledgerKey)
	if e != nil || len(key) != 32 || strings.ToLower(ledgerKey) != ledgerKey {
		return nil, errors.New("ledger trust pin required")
	}
	rows, ok := value.([]any)
	if !ok {
		return nil, errors.New("ledger rows must be an array")
	}
	prev := ""
	for i, item := range rows {
		row := obj(item)
		if row == nil || len(row) != 8 {
			return nil, errors.New("invalid ledger row")
		}
		token := st(row, "signature")
		entry, e := readSigned(token, ledgerKey, "ledger-entry")
		if e != nil {
			return nil, e
		}
		raw := st(row, "data")
		data, e := parse([]byte(raw))
		if e != nil {
			return nil, e
		}
		if st(row, "seq") != strconv.Itoa(i+1) || integer(entry, "seq") != int64(i+1) || st(entry, "prev") != prev || st(row, "ref") != sha([]byte(token)) || !bytesEqual(data, entry["data"]) {
			return nil, errors.New("ledger chain or row mismatch")
		}
		for _, k := range []string{"actor", "channel", "event", "op"} {
			if st(row, k) != st(entry, k) {
				return nil, fmt.Errorf("ledger metadata mismatch: %s", k)
			}
		}
		prev = st(row, "ref")
	}
	var head any
	if prev != "" {
		head = prev
	}
	return M{"verified": true, "verifiedEntries": len(rows), "head": head, "latestHeadVerified": false, "resourceEffectsVerified": false, "eventSchemaValidated": false}, nil
}
