# Copied bearer JWT

A bearer token can be replayed by anyone who obtains it while it remains valid. This is an intentionally bearer-only synthetic comparison.

Run from the repository root:

~~~sh
cd pilot
go test ./cmd/pilot -run '^TestAdversarialBearerCredentialCopy$' -count=1
~~~

Expected observation: both the original caller and a caller holding the copied synthetic token are accepted. This demonstrates the limitation of the bearer-only fixture, not a weakness in every JWT design.

[Review the Go test source](../../pilot/cmd/pilot/adversarial_external_test.go).
