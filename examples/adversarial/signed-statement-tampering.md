# Signed statement tampering

The test accepts the original synthetic signed statement and changes claims, signature algorithm, signature, signer, token type, or JSON field uniqueness.

Run from the repository root:

~~~sh
cd pilot
go test ./cmd/pilot -run '^TestAdversarialSignedStatementManipulation$' -count=1
~~~

Expected observation: the original verifies and each altered statement is rejected.

[Review the Go test source](../../pilot/cmd/pilot/adversarial_external_test.go).
