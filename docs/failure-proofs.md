---
sidebar_position: 4
---

# Native proofs for failure responses

**Proposed local pilot.** Profile `http6-wasix-delegation-02` adds a native designated-verifier proof for a gateway's denied, held, malformed or uncertain response. It retains the committed-success response flow, request circuits, policy checks and state ledger. [Review the implementation and contribute on GitHub](https://github.com/HTTP6-ORG/http6-sdk).

A failure proof is an authenticated **broker observation** of the request bytes received and the response core returned. It does not independently establish the identity of the caller, that a policy decision was correct, or whether an effect occurred. In particular, never infer that an uncertain operation had no effect or automatically retry it. A wallet refusal may also carry separate evidence about the wallet policy check; verify that evidence under the wallet's own rules.

| Category | HTTP status | Pilot meaning |
| --- | --- | --- |
| `malformed` | 400 | The bounded body cannot be parsed as the required canonical JSON object. No identity is inferred from it. |
| `denied` | 403 | The gateway reports a rejection, such as a policy refusal. |
| `held` | 503 | The gateway reports a temporary hold, including a resource unavailable before redemption. |
| `uncertain` | 503 | The gateway cannot establish a conclusive response or encounters an error after redemption. Inspect and reconcile state before any new action. |

The returned object includes `error`, `category`, `failureCore`, `failure`, `failureDecision`, `failureEventRef`, `failureEvidenceFile` and `proofStatus`. `failureCore` is the canonical JSON object of response fields before proof metadata is added. `failure.context.requestHash` is SHA-256 of the exact received request body bytes; `resultHash` is SHA-256 of canonical `failureCore`. The proof and its metadata are outside that core, avoiding a self-referential digest. The HTTP status, method, target, broker and designated-verifier keys, policy, random challenge and expiry are bound in the signed context. The proof does not cover every HTTP header or the final envelope bytes.

The [failure package schema](https://www.http6.org/developers/sdk/artifacts/wasix-failure-02.schema.json) documents the shape. Schema validation alone does not verify signatures, policy, state, freshness or replay. The profile uses `H(label, object) = SHA-256(ASCII("http6-wasix-delegation-02/" + label) || 0x00 || canonicalJSON(object))`, with lowercase hexadecimal encoding. Compact signed statement references hash the complete ASCII JWS.

## Issuance and ledger inspection

1. The private agent hashes the actual request body and assembles the response core. The authenticated broker requests a challenge through its native policy-bound control circuit.
2. The ledger signs a short-lived context and records `FAILURE_RESPONSE_CHALLENGED`. The broker's response circuit answers the challenge; its designated verifier checks the 12 rounds and signs its result.
3. The broker submits the proof through a second authenticated control call. The ledger verifies it, atomically consumes the one-use challenge, stores the public context and proof by digest, and records `FAILURE_RESPONSE_PROVED`. The gateway verifies the proof and ledger decision before returning `proofStatus: "ledger-recorded"`.
4. The private evidence file contains the signed ledger event, installation trust record and proof. Offline verification requires independently pinned operator and ledger public keys, the original request digest and actual response status.

Inspect the event chain using `client.events({pinnedLedgerKey})`, then retrieve public proof and context objects using `client.resolve('objects', ref)`. A valid event chain does not prove that the server returned its newest head. The failure event records hashes and category, not raw request bytes. Ledger assertions are observations made by the trusted local broker, not independent findings about effects.

## SDK example

```js
import {PilotClient, Http6Error, canonical} from '@http6-org/proposed-sdk';
import {join} from 'node:path';

const client = await PilotClient.attach({
  stateDir, pilotBinary, expectedProfile: 'http6-wasix-delegation-02'
});
const proposal = {op:'payment-over-limit', audience:'wallet',
  resource:'merchant-payment', args:{network:'regtest', recipient:'merchant-a',
  satoshis:'1100'}, holdSeconds:4};
const bytes = Buffer.from(canonical(proposal));
try {
  await client.invokeRaw(bytes);
} catch (error) {
  if (!(error instanceof Http6Error)) throw error;
  const response = error.detail.response;
  if (response?.proofStatus === 'ledger-recorded') {
    const verdict = await client.verifyFailureResponse({
      error, requestBytes:bytes,
      evidenceFile:join(stateDir, response.failureEvidenceFile),
      operatorKey:independentlyPinnedOperatorKey,
      ledgerKey:independentlyPinnedLedgerKey
    });
    console.log(verdict.verified, verdict.effectStateVerified);
  } else {
    // No ledger-recorded proof is available. Reconcile before taking action.
  }
}
```

For malformed bodies, pass their exact bytes to `invokeRaw`; do not reconstruct them from parsed JSON. `invoke` canonicalizes an object, so preserve `Buffer.from(canonical(proposal))` if it is used. Do not obtain trust pins from the same untrusted response being verified. `verifyFailureResponse` checks the actual error, status, core and evidence, then runs the independent compiled WASIX verifier against a private copy. It returns `callerIdentityVerified:false` and `effectStateVerified:false`.

## Local qualification

The [synthetic qualification report](https://www.http6.org/developers/sdk/artifacts/wasix-failure-02-qualification.json) records the final pilot binary hash and the local integration, tampering, replay, outage and compatibility checks. The separate existing pilot audit passed 98 checks. The hosted documentation workflow does not provision the vendor crates or run these WASIX integration tests.

## Availability and scope

If the ledger, broker, verifier or evidence export is unavailable, the agent returns `proofStatus: "unavailable"` and no failure proof. A body larger than 65,536 bytes also receives no proof because the complete body was not retained. Requests rejected before the agent can read the bounded body, including unknown routes and methods, do not receive this proof. Transport timeout without a received response is itself unproved and may be uncertain. Profile 01 does not issue failure proofs; profile 00 has neither native success nor failure response proofs. All profiles are experimental synthetic fixtures, not a production standard or public zero-knowledge verification system.
