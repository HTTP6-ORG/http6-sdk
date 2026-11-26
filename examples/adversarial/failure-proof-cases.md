# Failure response proofs

The failure test exercises denied, held, malformed, uncertain, and unavailable outcomes. It checks binding to the request and response, ledger references, and the absence of a recorded proof when the ledger is unavailable.

Run from the repository root:

~~~sh
cd pilot
go test ./cmd/pilot -run '^TestFailureProofEndToEnd$' -count=1
~~~

Expected observation: available failure evidence verifies, changed context and replay are rejected, and unavailable ledger state does not produce a recorded proof.

[Review the Go test source](../../pilot/cmd/pilot/failure_test.go).
