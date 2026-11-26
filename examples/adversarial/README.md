# Adversarial test examples

Each case has its own runnable example note in this directory and a corresponding Go integration test in `pilot/cmd/pilot`. All endpoints bind to loopback or private Unix sockets. Keys, certificates, requests, and ledger rows are generated for the test. No production secrets or remote services are used.

Run the suite with fresh compiled demo guests and private logs:

```sh
./pilot/assemble-demo.sh /private/path/to/new-demo-bin
python3 scripts/run-adversarial.py \
  --pilot-bin /private/path/to/new-demo-bin \
  --out /private/path/to/new-private-logs \
  --iterations 3
```

| Attack or control | Example | Runnable test |
| --- | --- | --- |
| Reuse copied EdDSA and RS256 bearer JWTs, then compare the holder-bound presentation | [stolen-jwt.md](stolen-jwt.md) | `TestAdversarialBearerCredentialCopy`, `TestAdversarialStolenLivePresentation` |
| Alter signed claims, algorithm, signer, token kind, or JSON | [signed-statement-tampering.md](signed-statement-tampering.md) | `TestAdversarialSignedStatementManipulation` |
| Read a generated environment or file key, including a synthetic `.env` bearer | [workspace-key-extraction.md](workspace-key-extraction.md) | `TestAdversarialSyntheticKeyStorage`, `TestAdversarialReadableEnvCredentialCanAuthorizeLocalService` |
| Connect to a TLS endpoint under a different, untrusted test CA | [tls-untrusted-certificate.md](tls-untrusted-certificate.md) | `TestAdversarialFakeTLSEndpoint` |
| Let an explicitly trusted local interception certificate observe a JWT | [tls-trusted-interception.md](tls-trusted-interception.md) | `TestAdversarialTrustedTLSProxyCanCaptureBearerJWT` |
| Request key text, source, or a binary through the pilot proposal route | [proxy-secret-boundary.md](proxy-secret-boundary.md) | `TestAdversarialProxyRejectsKeyAndSourceRequests` |
| Submit prompt-like fields and guessed secret-export commands | [prompt-injection-boundary.md](prompt-injection-boundary.md) | `TestAdversarialPromptLikeKeyRequests` |
| Alter response status, headers, encoding, or canonical JSON bytes | [response-proof-integrity.md](response-proof-integrity.md) | `TestResponseHTTPMetadataAndCanonicalBytes` |
| Tamper with denied, held, malformed, uncertain, or unavailable failure evidence | [failure-proof-cases.md](failure-proof-cases.md) | `TestFailureProofEndToEnd` |
| Change a signed ledger row or break its chain | [ledger-chain-tampering.md](ledger-chain-tampering.md) | `TestVerifyLedgerRows` |
| Sign fabricated history with a copied synthetic ledger key | [ledger-key-compromise.md](ledger-key-compromise.md) | `TestAdversarialCopiedLedgerSigningKey` |

The matched bearer control accepts copied tokens because it intentionally has no sender binding or replay cache. The trusted TLS proxy test observes a bearer token because its root is deliberately trusted by the synthetic client. These are expected control results. The HTTP6 side checks a narrow local profile: malformed or unlisted operations are refused without a resource effect, while a valid typed operation returns a bounded result. The sample worker is generic. These tests do not inspect or attest a separate ENI6MA binary, prove a production proxy isolates executable memory or internal keys, or test an LLM.

The runner writes full Go test events to its new output directory. Some test events include generated private keys for the synthetic key-read case. Keep that directory private. `summary.json` omits generated keys and request payloads.
