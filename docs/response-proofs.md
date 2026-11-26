---
sidebar_position: 3
---

# Native WASIX response proofs

**Proposal and local pilot.** `http6-wasix-delegation-01` adds a fresh native proof for each committed successful resource response. It uses the existing request circuit and state ledger, a distinct response circuit for the resource, and a separately running designated verifier. The older `http6-wasix-delegation-00` profile remains unchanged. The profiles have different identifiers and hash domains and are not interchangeable.

The Go host integration is in [`pilot/`](https://github.com/HTTP6-ORG/http6-sdk/tree/main/pilot). Circuit and WASIX guest source are not published. The compiled 02 demonstration bundle is available with its notice and limited validation report; profile 01 artifacts must be obtained separately. [Response package JSON Schema](https://www.http6.org/developers/sdk/artifacts/wasix-response-01.schema.json) specifies the message shape; cryptographic, policy, state and byte checks are still required.

<figure className="http6-figure">
  <picture>
    <source media="(max-width: 54.99rem)" srcSet="https://www.http6.org/illustrations/sdk-response-proof-mobile.svg" type="image/svg+xml" />
    <img src="https://www.http6.org/illustrations/sdk-response-proof-desktop.svg" alt="The worker signs a request, the resource commits a synthetic result, a separate response proof binds the result to its context, and the verifier checks evidence using pinned keys." width="1200" loading="lazy" />
  </picture>
  <figcaption>Local synthetic pilot. Verification concerns historical recorded evidence.<br /> <a className="http6-wide" href="https://www.http6.org/illustrations/sdk-response-proof-desktop.svg" target="_blank" rel="noopener noreferrer">View larger SVG (opens in a new tab)</a> <a className="http6-narrow" href="https://www.http6.org/illustrations/sdk-response-proof-mobile.svg" target="_blank" rel="noopener noreferrer">View larger SVG (opens in a new tab)</a> · <a className="http6-wide" href="https://www.http6.org/illustrations/sdk-response-proof-desktop.png" download>Download PNG</a> <a className="http6-narrow" href="https://www.http6.org/illustrations/sdk-response-proof-mobile.png" download>Download PNG</a> </figcaption>
</figure>

## End-to-end flow

1. The holder signs a request with a fresh native request proof. The ledger verifies the lineage and policy and reserves one operation. The actual custodian checks and redeems it before acting.
2. The resource performs the allowed synthetic operation and signs its result digest and durable observation. The state ledger records `CUSTODIAN_OUTCOME` and marks the operation committed.
3. The resource makes an authenticated, policy-bound `response-challenge` control call. The ledger verifies the committed receipt, creates an unpredictable one-use nonce, records `RESPONSE_CHALLENGED`, and signs the exact response context.
4. The resource circuit answers that context-bound challenge. Its separate designated verifier checks the 12 native responses, consumes the local challenge, and signs the response result and its transcript commitments. The private circuit provision and unblinded responses stay in the local resource and verifier processes.
5. The resource submits the proof using an authenticated `response-commit` control call. The ledger verifies the challenge, proof, receipt and certificate, atomically consumes the challenge, stores the public proof and context, and records `RESPONSE_PROVED`. A repeated proof cannot be committed again, even under a fresh control proof.
6. The broker and agent independently verify the response proof, its signed ledger decision, the original presentation and the exact returned result before releasing it. The broker records `BROKER_CONFIRMED` only after the ledger has a matching response proof.

```text
REQUEST_PROVED -> CERTIFICATE_ISSUED -> CHECKED -> REDEEMED
-> CUSTODIAN_OUTCOME -> RESPONSE_CHALLENGED -> RESPONSE_PROVED
-> BROKER_CONFIRMED
```

The response context binds `op`, audience, recipient key, original request reference, certificate, original presentation, policy hash and address, epoch, SHA-256 result digest, signed receipt reference, outcome event, HTTP status, content type, ledger nonce, validity interval, resource key and designated verifier key. The proof signs `H("response-context", context)` and the ledger nonce. The final result is hashed before the proof is assembled, so the proof does not depend on a digest of a packet containing itself.

For this profile, `H(label, object)` is lowercase SHA-256 over ASCII `http6-wasix-delegation-01/`, the label, one zero byte and canonical JSON. The result digest is SHA-256 of the canonical JSON result bytes. A signed compact JWS reference is SHA-256 of the complete compact ASCII string. The challenge and proof use distinct references. The HTTP receiver checks the actual 200 status, single JSON content type, unencoded body and canonical response bytes.

## SDK verification

The SDK requires the exact response object and its corresponding private evidence file. It compares their proof, result and receipt fields, then invokes the compiled pilot's independent verifier using operator and ledger keys supplied from the caller's trust configuration.

```js
import {join} from 'node:path';

const proof = await client.verifyNativeResponseProof({
  response: reply,
  evidenceFile: join(stateDir, reply.responseEvidenceFile),
  operatorKey: independentlyPinnedOperatorKey,
  ledgerKey: independentlyPinnedLedgerKey
});
console.log(proof.verified, proof.currentAuthorityVerified);
```

The result verifies historical evidence at the time recorded in the signed ledger event. `currentAuthorityVerified` is false: this check does not establish that a grant remains active now. A response replay at a relying party also needs that party's own request correlation and replay handling. The ledger prevents the response proof from being committed twice.

For a running synthetic fixture, the same verification is available from the pilot:

```sh
./pilot/bin/http6-pilot verify-response \
  --operator-key "$OPERATOR_PUBLIC_KEY" --ledger-key "$LEDGER_PUBLIC_KEY" \
  /path/to/private/response-evidence.json
```

## Measured local checks

A [local synthetic qualification report](https://www.http6.org/developers/sdk/artifacts/wasix-response-01-qualification.json) records 98 passing checks across endpoint, process, database and wallet adapters. It recorded 167 signed ledger entries, 23 issued operations, 13 resource effects and zero restricted effects. The response tests rejected altered result, recipient, request reference, nonce, status, policy, audience, receipt, proof signature, original presentation and ledger decision; they also rejected missing proofs and replay with both the original and a fresh control proof. A live check rejects an expired response proof, while historical verification succeeds at the signed event time.

Separate SDK tests exercised direct minting and request proof validation, response evidence verification, a changed result, wrong trust pin, profile mismatch and a local synthetic bridge. The original 00 SDK path was also checked. These test runs used one operator.

## Current limits

- Profile 01 covers committed successful responses. Profile 02 separately supports broker-observed [failure response proofs](./failure-proofs.md) for denied, malformed, held and uncertain replies.
- The resource and designated verifier are separate WASIX processes on one host. The verifier receives a private provision; its signed public transcript does not make the native proof independently publicly verifiable or establish a zero-knowledge claim.
- A failed response proof or lost reply can occur after the effect commits. The pilot preserves the ledger record but does not yet provide a complete production inquiry and recovery protocol.
- The signed proof binds the canonical result bytes and response context. The pilot does not yet implement a complete RFC 9421 response signature profile for the whole final HTTP envelope.
- The pilot has synthetic identities and data. Real human admission, production key custody, independently operated checkpoints, broad host mediation, multi-host failover and external settlement remain future work.

[Review the SDK API](./sdk-api.md) and [open a GitHub issue](https://github.com/HTTP6-ORG/http6-sdk/issues) with questions or reproduction results.
