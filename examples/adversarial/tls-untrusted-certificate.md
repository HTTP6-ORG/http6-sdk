# Untrusted TLS certificate

This compares a local service under the configured test CA with another local service under an unrelated test CA.

Run from the repository root:

~~~sh
cd pilot
go test ./cmd/pilot -run '^TestAdversarialFakeTLSEndpoint$' -count=1
~~~

Expected observation: the trusted local endpoint connects and the endpoint with an untrusted certificate is rejected. This test does not show TLS being broken.

[Review the Go test source](../../pilot/cmd/pilot/adversarial_external_test.go).
