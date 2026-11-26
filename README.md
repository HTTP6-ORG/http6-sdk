# HTTP6 proposed SDK and developer guide

This repository contains an experimental SDK adapter, a navigable Docusaurus guide, the full draft source, a proposed schema and synthetic vectors. The developer site is designed for `https://www.http6.org/developers/sdk/` and is built from this repository. Questions and feedback are welcome through this repository's issues.

## Current capabilities

- A Node.js adapter starts or attaches to the original `http6-wasix-delegation-00` pilot or profiles `http6-wasix-delegation-01` and `http6-wasix-delegation-02`. All admit a synthetic autonomous root and mint fixed fixture children. Profiles 01 and 02 add native proofs for committed successful responses. Profile 02 adds ledger-recorded broker observations for denied, held, malformed and uncertain replies.
- Basic Python, Rust, Go and C# SDKs in `packages/` submit pilot requests and verify success proofs, failure proofs and signed ledger chains through a separately supplied verifier. See `docs/multilanguage-sdks.md`.
- The direct `WasixCircuits` adapter also connects to the existing mint, child and verifier guests. It can prepare a root, mint an attenuated child and produce and verify a native request proof when the integrator supplies configured trust and verified ledger-registration callbacks. Its direct-circuit test uses in-memory registration callbacks and does not establish ledger enrollment.
- The adapter reads the local ledger, verifies the signed chain under an independently provided key and can invoke the pilot's offline synthetic wallet verifier. A verified chain is not evidence that the newest head was returned or that an external effect occurred.
- A separate Python adapter runs the existing Rosario-Wang review model's native request and response proofs, local mint and ledger. This is a different implementation and proof format from the WASIX pilot.
- A local synthetic bridge binds a pilot wallet proposal and its actual verified receipt into the review model request and response proofs. It is a trusted local composition of two distinct implementations and ledgers, not a unified wire protocol or production cross-domain evidence.
- Human enrollment, arbitrary child minting through the pilot agent API, full production recovery and unrestricted host mediation remain unimplemented. The SDK reports profile capabilities explicitly.

The [read-only API navigator](https://www.http6.org/developers/sdk/api-reference/) defines the proposed guide contract. The five-language examples and Python/Rust WASIX test are documented in `docs/multilanguage-demo.md`.

This is a proposal and local experimental software, not a standard or production security product. Do not use the fixtures for real money, sensitive data or production authorization. See `docs/sdk-api.md` for usage and `source/developer-guide.md` for the complete draft.

## Develop and test

Requires Node 22. The pilot integration test requires a separately built local pilot and Wasmer. The public `pilot/` directory includes host integration source. Circuit and WASIX guest source are not distributed. Compiled demonstration guests, their notices, and bounded validation results are in `circuits/demo-wasix-02/`. The review adapter requires the separately provisioned public validation kit.

```sh
npm ci
npm test
HTTP6_TEST_PROFILE=http6-wasix-delegation-02 \
  HTTP6_PILOT_BINARY=/path/to/pilot/bin/http6-pilot \
  HTTP6_WASIX_BIN=/path/to/pilot/bin \
  HTTP6_REVIEW_KIT=/path/to/HTTP6_RosarioWang_Validation_Kit npm test
python3 reference/review_channel.py /path/to/HTTP6_RosarioWang_Validation_Kit
npm run build
```

The public CI runs the framework build and SDK tests available without the separately provisioned circuit crates. Tests requiring `HTTP6_PILOT_BINARY` and `HTTP6_WASIX_BIN` are skipped when those inputs are absent. The 98-check pilot qualification is a separately run local synthetic test.

A fixture start requires a new state directory. It never deletes an existing state directory. The SDK's `close` shuts down only the pilot process it started. Test code uses a new temporary directory and removes only that test directory after shutdown.

The website build turns the two Markdown documents in `source/` into individually navigable pages and publishes static schema and synthetic vectors from `static/artifacts/`. GitHub Pages is updated on changes to `main`; HTTP6.org's developers route is configured to serve those built pages. Update the source here rather than editing a rendered page on the website.

## Contribution and licensing

Report corrections, reproduction results and API proposals in GitHub issues. A license for this new repository has not yet been selected. Publication and the invitation to discuss do not grant an open-source license or resolve rights to separately distributed HTTP6, ENI6MA, third-party or validation-kit components. Do not submit material you cannot share. No private keys, device state, customer records or private ledger exports belong in issues or commits.

ENI6MA circuits are patent pending and protected by copyright. Commercial deployments require a license available only through ENI6MA and Rosario Cybernetics. For production or extended implementations and inquiries about proposed information-theoretic properties, contact President Frank Rosario through [Rosario Cybernetics](https://www.rosariocyber.com/contact) to discuss license options. The experimental tests are not proof of a production guarantee.

Nonprofit organizations and private entities may [contact Rosario Cybernetics](https://www.rosariocyber.com/contact) to request permission. Commercial use is strictly prohibited without a paid commercial license. See the [compiled circuit notice](circuits/NOTICE.md).
