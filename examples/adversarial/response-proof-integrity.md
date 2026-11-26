# Response proof integrity

The test changes HTTP status, content type, content encoding, duplicate headers, and canonical response bytes.

Run from the repository root:

~~~sh
cd pilot
go test ./cmd/pilot -run '^TestResponseHTTPMetadataAndCanonicalBytes$' -count=1
~~~

Expected observation: only the expected status and canonical response are accepted. Each altered response is rejected.

[Review the Go test source](../../pilot/cmd/pilot/response_test.go).
