# Copied ledger signing key

This synthetic case copies a trusted ledger signing key and uses it to create a fabricated signed history.

Run from the repository root:

~~~sh
cd pilot
go test ./cmd/pilot -run '^TestAdversarialCopiedLedgerSigningKey$' -count=1
~~~

Expected observation: the fabricated entry verifies under the corresponding trusted public key. The result shows that a verifier cannot distinguish fabricated history if its trusted signing key is compromised. The generated key is test-only.

[Review the Go test source](../../pilot/cmd/pilot/adversarial_external_test.go).
