---
sidebar_position: 2
---

# SDK integration

The proposed [Python, Rust, Go and C# SDKs](./multilanguage-sdks.md) provide basic proof and ledger verification. The proposed Node.js SDK connects to the local WASIX pilot through private agent and ledger sockets. Profiles `http6-wasix-delegation-01` and `http6-wasix-delegation-02` create and validates native proofs for committed successful responses, in addition to request proofs and resource-side enforcement. The earlier `http6-wasix-delegation-00` profile remains supported and has no native response proof. Profile 02 additionally records [failure response proofs](./failure-proofs.md). All use synthetic autonomous fixture origins and fixed children at agent startup.

<figure className="http6-figure">
  <picture>
    <source media="(max-width: 54.99rem)" srcSet="https://www.http6.org/illustrations/sdk-integration-mobile.svg" type="image/svg+xml" />
    <img src="https://www.http6.org/illustrations/sdk-integration-desktop.svg" alt="An application starts or attaches to the synthetic local pilot through the SDK. The resource checks policy and records the effect, and the application can review signed evidence." width="1200" loading="lazy" />
  </picture>
  <figcaption>Experimental SDK integration using a local synthetic fixture. It is not a production deployment.<br /> <a className="http6-wide" href="https://www.http6.org/illustrations/sdk-integration-desktop.svg" target="_blank" rel="noopener noreferrer">View larger SVG (opens in a new tab)</a> <a className="http6-narrow" href="https://www.http6.org/illustrations/sdk-integration-mobile.svg" target="_blank" rel="noopener noreferrer">View larger SVG (opens in a new tab)</a> · <a className="http6-wide" href="https://www.http6.org/illustrations/sdk-integration-desktop.png" download>Download PNG</a> <a className="http6-narrow" href="https://www.http6.org/illustrations/sdk-integration-mobile.png" download>Download PNG</a> </figcaption>
</figure>

From an application checkout, install the local package after cloning this repository:

```sh
npm install /path/to/http6-sdk/packages/sdk
```

```js
import {PilotClient} from '@http6-org/proposed-sdk';
import {join} from 'node:path';

const stateDir = '/private/path/to/a-new-state-directory';
const client = await PilotClient.startFixture({
  pilotBinary: '/path/to/pilot/bin/http6-pilot', stateDir,
  expectedProfile: 'http6-wasix-delegation-02'
});
try {
  console.log(client.capabilities());
  const receipt = await client.invoke({
    op: 'payment-1', audience: 'wallet', resource: 'merchant-payment',
    args: {network:'regtest', recipient:'merchant-a', satoshis:'250'}, holdSeconds:4
  });
  // In a deployment, provision trust pins independently of the socket and state directory.
  const ledger = await client.events({pinnedLedgerKey: independentlyPinnedLedgerKey});
  const responseProof = await client.verifyNativeResponseProof({
    response: receipt, evidenceFile: join(stateDir, receipt.responseEvidenceFile),
    operatorKey: independentlyPinnedOperatorKey, ledgerKey: independentlyPinnedLedgerKey
  });
  console.log(responseProof, ledger.verification);
} finally {
  await client.close();
}
```

`startFixture` is limited to a new state directory and creates the pilot's fixed fixture circuits. `attach` connects to an existing pilot without taking ownership of its lifecycle. `invoke` submits an operation to the pilot's policy gate. `catalog` and `resolve` read ledger objects. `events` verifies the returned signed event chain under an independently configured ledger key; it does not prove the server returned its latest head or that an external effect occurred. `verifySpend` invokes the pilot's separate historical wallet verifier with independently configured operator and ledger pins.

For profiles 01 and 02, `verifyNativeResponseProof` compares the supplied response to its evidence, then invokes the compiled verifier with independent operator and ledger pins. Its result is historical verification at the signed ledger-event time, not a finding that the grant is currently active. The method rejects profile 00. Profile selection is explicit; `attach` and `startFixture` reject an unexpected profile. General `mintChild()` is not exposed through the pilot agent API. Human approval, production key custody, multi-host recovery, and unrestricted OS mediation are not implemented.

## Direct mint and verifier integration

`WasixCircuits` starts the existing mint and verifier guests through Wasmer. The integrator supplies the root policy, route manifest, certified autonomous origin, operator pin, trust configuration and callbacks that register and verify root and child evidence with its state authority. `admitRoot` verifies the root through the designated verifier before registration. `mintChild` uses the existing mint and a distinct child guest, verifies the family, and provisions the child and verifier after the registration callback returns. `proveRequest` runs the existing prepare, challenge, answer, attest and signed-request sequence. `verifyRequest` asks the existing verifier to check the result.

```js
import {WasixCircuits} from '@http6-org/proposed-sdk';
const circuits = await WasixCircuits.start({binDir: '/path/to/wasix-delegation/bin'});
try {
  const identities = circuits.identities();
  // Construct and authenticate originCert and trust for these identities.
  await circuits.admitRoot({policy, manifest, originCert, operator, ledger,
    semantics, trust, registerRoot: verifyAndRegisterRoot});
  const child = await circuits.mintChild({birthId: 'birth-reader-1',
    holder: 'reader-1', policy: childPolicy, registerFamily: verifyAndRegisterFamily});
  const packet = await circuits.proveRequest({holder: child.holder, op: 'read-1', intent});
  await circuits.verifyRequest({holder: child.holder, package: packet});
} finally {
  await circuits.close();
}
```

These are local process adapters, not a sandbox or protected key store. The registration callbacks must contact the intended state authority and verify its durable acknowledgement; returning without doing so does not register anything. The direct-circuit test uses an in-memory callback only. If registration or activation fails after minting, the deployment must reconcile or quarantine the partially created grant. The current guest accepts a bounded policy vocabulary and certified autonomous fixture. This direct mint path does not implement human admission. The resource, ledger and response-proof workflow is supplied by the profile 01 and 02 pilot services.

## Separate request and response proof model

The repository's Python adapter loads the existing Rosario-Wang validation kit and executes its local request and response proof flow:

```sh
python3 reference/review_channel.py /path/to/HTTP6_RosarioWang_Validation_Kit
```

This adapter mints the kit's synthetic child, verifies a request and separate response, rejects response modification and replay, and inspects the kit's local ledger. It uses the review model's own proof and ledger formats, not the WASIX agent's format. No production network deployment or actual human approval is implied.

A second local bridge composes both paths for a synthetic wallet example. It places the complete WASIX proposal inside a review-model request proof, sends that proposal to the running pilot, verifies the pilot's signed wallet evidence using independently supplied operator and ledger keys, and places the actual pilot response inside a separate review-model response proof. It also tests a modified response.

```sh
python3 reference/pilot_bridge.py KIT_PATH STATE_DIR PILOT_BINARY OPERATOR_KEY LEDGER_KEY
```

The bridge is an optional trusted local integration with two separate verifiers and two ledgers. Profile 01 also supplies native response proofs directly, without this bridge. It does not make their wire profiles interoperable, provide an independent third-party verification of the review proof, or prove production payment settlement. It is intended for synthetic data only.

The [repository](https://github.com/HTTP6-ORG/http6-sdk) contains the SDK, tests, proposed schemas and source documents. Please [open an issue](https://github.com/HTTP6-ORG/http6-sdk/issues) with questions or implementation feedback.

## Proposed HTTP API contract

The [read-only API navigator](https://www.http6.org/developers/sdk/api-reference/) maps proposed control operations and their request and response schemas. Its example server is intentionally invalid and its unimplemented operations are not the existing WASIX pilot API. The [cross-runtime examples](./multilanguage-demo.md) exercise the actual local pilot.
