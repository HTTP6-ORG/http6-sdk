# Readable workspace credentials

The test creates a synthetic signing key in an environment variable and file. A test actor with access to either location copies the value and creates a valid synthetic signature. A second test creates a temporary .env bearer credential and reuses it against a loopback HTTPS control service.

Run from the repository root:

~~~sh
cd pilot
go test ./cmd/pilot -run '^(TestAdversarialSyntheticKeyStorage|TestAdversarialReadableEnvCredentialCanAuthorizeLocalService)$' -count=1
~~~

Expected observation: both copied credentials work in their deliberately exposed control cases. These tests use generated keys and local services only. Verbose test logs can contain generated private test material. Keep logs private.

[Review the key storage test](../../pilot/cmd/pilot/adversarial_external_test.go) and [the HTTPS .env test](../../pilot/cmd/pilot/adversarial_env_credential_test.go).
