# Ledger chain tampering

The test verifies an original synthetic signed event chain, then changes event data and breaks linkage.

Run from the repository root:

~~~sh
cd pilot
go test ./cmd/pilot -run '^TestVerifyLedgerRows$' -count=1
~~~

Expected observation: the original chain verifies and altered rows or broken linkage are rejected. A valid partial chain does not prove that the latest ledger head was returned.

[Review the Go test source](../../pilot/cmd/pilot/ledger_inspect_test.go).
