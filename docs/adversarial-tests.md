# Synthetic adversarial comparison

This optional demonstration exercises a deliberately bearer-only JWT service and the compiled HTTP6 WASIX pilot using fresh synthetic state. It does not run against external systems. No circuit source, production credentials, model, or real payment network is involved. Review the [circuit notice](https://github.com/HTTP6-ORG/http6-sdk/blob/main/circuits/NOTICE.md) before running the compiled demonstration guests. Website cards and report pages are at [HTTP6.org adversarial demonstrations](https://www.http6.org/developers/adversarial-tests/).

For the matched test, the two services receive the same sum operation over local HTTP. Both use Ed25519-signed authorization artifacts. An actor possessing only a copied valid artifact submits it again. The bearer-only control accepts the copied EdDSA JWT and performs a second effect. A second control checks an RS256 JWT. The HTTP6 resource rejects a copied unspent presentation and a copied connection-bound signature without access to the holder; the holder then acts once and the used presentation is rejected. The bearer service intentionally has no holder binding or replay defense.

TLS tests reject an endpoint with an unrelated certificate authority and show that a locally trusted interception authority can read a synthetic bearer JWT. This models a trusted-root or proxy configuration compromise. It does not break TLS encryption or test public internet interception. Workspace exposure tests create disposable synthetic environment and file secrets, then show that a reader can copy them and forge a test signature. A separate `.env` test reuses its generated bearer value against a local HTTPS service. These tests do not read real workspace files or keys.

Proxy tests submit plain text asking for a key, a prompt-like proposal, source and binary resource names, and a string in a numeric operation argument. The local gateway rejects these requests without a protected effect. A valid typed sum request returns the expected result payload. This checks the gateway shape and response path for the compiled demonstration worker. It does not prove that an external ENI6MA binary contains a particular secret or that an LLM resists prompt injection. No LLM is connected. A deliberately copied synthetic ledger signing key successfully signs fabricated ledger evidence. This demonstrates a limit, not a defense against trusted signing-key compromise. The test does not extract a key from a circuit or test copying a holder's private key.

## Cases and source examples

The repeatable runner covers copied bearer tokens, TLS trust and interception, test key-file exposure, signed statement tampering, holder proof and replay, proxy key or source requests, prompt-like input, response framing, failure proofs, ledger chain edits, and trusted ledger-key compromise. Each website report links to its own runnable example note in `examples/adversarial/` and the matching Go test source. The example index and expected outcomes are listed in `examples/adversarial/README.md`.

## Run the comparison

You need Go, Python 3, CGO, SQLite headers, Wasmer 7.4.0, and the published compiled WASIX guests. Use a new directory for the assembled bundle and another new directory for the logs. The script refuses to reuse the log directory.

```sh
./pilot/assemble-demo.sh /private/path/to/new-demo-bin
python3 scripts/run-adversarial.py \
  --pilot-bin /private/path/to/new-demo-bin \
  --out /private/path/to/new-private-logs \
  --iterations 3
```

`go-test.jsonl` contains Go's timestamped test events and observations, `stderr.log` contains tool errors, and `summary.json` counts completed, failed, and skipped top-level cases. To demonstrate readable key storage, the log includes the exact value of a freshly generated synthetic key after reading it from a test-only environment variable and a temporary file. The script does not scan your filesystem or read your actual keys. A pass for the copied-ledger-key case means the limitation was reproduced, not that the attack was blocked. Keep logs and generated fixture state private until reviewed. The runner uses only synthetic data, but failures may include diagnostics from the local environment.

These tests do not intercept a real network, steal a real token, test a compromised endpoint or model, prove latest-ledger-head freshness, or establish production security. The holder key is not extracted or copied. Independent adversarial testing and a deployment-specific threat model remain necessary.
