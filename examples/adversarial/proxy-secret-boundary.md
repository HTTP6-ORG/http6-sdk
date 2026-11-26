# Proxy key, source, and binary boundary

The local pilot receives malformed text, prompt fields, guessed source and binary names, and string-key requests. It also receives one valid typed sum operation.

First assemble the compiled demonstration bundle, then run from the repository root:

~~~sh
./pilot/assemble-demo.sh /private/path/to/new-demo-bin
cd pilot
go test ./cmd/pilot -run '^TestAdversarialProxyRejectsKeyAndSourceRequests$' -count=1 -args -trace-release /private/path/to/new-demo-bin/http6-pilot
~~~

Expected observation: malformed text receives HTTP 400, unlisted source, binary, or key requests receive HTTP 403, and prompt fields receive HTTP 403. Rejected inputs cause no resource effect. A valid typed request returns only its bounded result payload. The test checks that responses do not contain raw or base64 guest module bytes.

This tests the published pilot API boundary. It does not inspect or attest a separate production ENI6MA binary or prove production key placement.

[Review the Go test source](../../pilot/cmd/pilot/adversarial_proxy_boundary_test.go).
