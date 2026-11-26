# Explicitly trusted TLS interception

The synthetic client is configured to trust a local test interception CA. The endpoint can therefore read the bearer value inside the encrypted connection.

Run from the repository root:

~~~sh
cd pilot
go test ./cmd/pilot -run '^TestAdversarialTrustedTLSProxyCanCaptureBearerJWT$' -count=1
~~~

Expected observation: the trusted local endpoint sees the synthetic JWT. This is an explicit trust configuration, not a break of TLS.

[Review the Go test source](../../pilot/cmd/pilot/adversarial_proxy_boundary_test.go).
