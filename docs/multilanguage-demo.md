---
sidebar_position: 5
---

# SDK examples and cross-runtime demo

**Proposal and synthetic local pilot.** The [repository](https://github.com/HTTP6-ORG/http6-sdk) contains five minimal clients for the existing `http6-wasix-delegation-02` agent. They submit real fixture requests over its private Unix socket. The Node example uses the proposed SDK. These original Python, Rust, Go and C# clients demonstrate transport. Separate [basic SDKs](./multilanguage-sdks.md) now add response-proof and ledger verification.

| Client | Location | Requirements |
| --- | --- | --- |
| Node.js | `examples/languages/node/client.mjs` | Node.js 22 and the repository SDK |
| Python | `examples/languages/python/client.py` | Python 3 and its standard library |
| Rust | `examples/languages/rust/client.rs` | `rustc` and Unix sockets |
| Go | `examples/languages/go/client.go` | Go and Unix sockets |
| C# | `examples/languages/csharp/Program.cs` | .NET 8 and Unix sockets |

Each client accepts `SOCKET OP allowed|denied` and prints a JSON object with the actual status and response. The fixture spends synthetic regtest units; it does not connect to a payment network. The clients do not, by themselves, verify a proof. The test runner compares the returned objects to private evidence and invokes the separately compiled native verifier with the fixture's operator and ledger keys. A production relying party must provision its own trust pins independently.

## Demo circuit controls

The fixture uses separately provisioned Rust WASIX circuit and verifier guests, private local sockets, bounded request bodies, a fresh ledger challenge, one-use proof commitments, registered policy checks and signed ledger evidence. The tests verify response evidence and reject a changed request digest. These controls harden this specific demonstration path; they do not make the sample clients, single-host trust model, key custody or resource mediation production ready.

## Reproduce the full test

You need a Unix-like host, Node.js 22, Python 3, Rust, Go, .NET 8 and Wasmer. The [compiled demonstration guests](https://github.com/HTTP6-ORG/http6-sdk/tree/main/circuits/demo-wasix-02) are provided with their rights notice, checksums and limited test results. Circuit and guest source are not distributed. Follow [`pilot/README.md`](https://github.com/HTTP6-ORG/http6-sdk/tree/main/pilot) to assemble the matching public Go host and verify the manifest. The Python guest uses the versioned Wasmer Registry package `python/python@=3.13.18`; resolving it requires registry access. Obtain and verify runtime packages under your organization's supply-chain policy.

```sh
git clone https://github.com/HTTP6-ORG/http6-sdk.git
cd http6-sdk
npm ci
# Review the circuit notice and assemble a new private demo bundle.
./pilot/assemble-demo.sh /private/path/to/a-new-demo-bin
python3 examples/languages/run.py \
  --pilot /private/path/to/a-new-demo-bin/http6-pilot \
  --out /private/path/to/a-new-http6-test-directory \
  --dotnet dotnet --wasmer wasmer
```

Choose a parent directory that already exists. The runner refuses an existing output directory and retains the newly created fixture databases and evidence there. It compiles the language examples in that directory and starts a fresh agent per language. Keep the directory private. It shuts down only the agents it starts.

For each language the runner sends an allowed 100-unit operation and a separate denied 1,100-unit operation. It compares the response to the evidence file, verifies the successful and failure proofs through the pilot's native verifier, checks that a modified request digest fails, inspects signed response event presence, and checks the wallet has one synthetic effect. The failure proof is an authenticated broker observation, not proof that a policy decision was correct or an effect did not occur.

The runner also starts Python **inside** the Wasmer WASIX runtime. The Python guest canonicalizes a synthetic denied request and computes its SHA-256 digest. The host forwards those exact bytes to the local agent, where the existing Rust WASIX circuit and designated verifier create a native proof and the Go ledger records it. The test checks that the proof context binds the digest produced by the Python guest. The Python guest does not create an ENI6MA proof or directly invoke the circuit; the host and pilot perform those steps. This is a local composition, not independent cross-domain verification.

The [published synthetic test report](https://www.http6.org/developers/sdk/artifacts/multilanguage-02-qualification.json) gives the measured results and limits. The [failure-proof guide](./failure-proofs.md) covers held, malformed and uncertain responses and replay checks. The existing pilot audit covers the registered endpoint, process, database and wallet adapters. GitHub's default documentation workflow cannot run the WASIX tests without the separately provisioned circuit crates and toolchain.

## Inspect the proposal

Use the [SDK guide](./sdk-api.md) for minting and request, success-response and failure-response verification. The [API navigator](https://www.http6.org/developers/sdk/api-reference/) describes the separate `http6-guide-01` design, including request and response bodies for all listed operations. It is read-only and the example server is invalid. The proposed [message and ledger model](https://www.http6.org/developers/sdk/artifacts/schema.json) is distinct from the pilot's [ledger envelope](https://www.http6.org/developers/sdk/artifacts/wasix-ledger-02.schema.json), [success proof](https://www.http6.org/developers/sdk/artifacts/wasix-response-02.schema.json) and [failure proof](https://www.http6.org/developers/sdk/artifacts/wasix-failure-02.schema.json). The pilot ledger schema defines event-specific data for all 19 current event kinds.

## Circuit licensing and contact

ENI6MA circuits are patent pending and protected by copyright. Commercial deployments require a license available only through ENI6MA and Rosario Cybernetics. For production or extended implementations, including inquiries about the proposed information-theoretic properties of HTTP6 with embedded ENI6MA circuits, contact President Frank Rosario through [Rosario Cybernetics](https://www.rosariocyber.com/contact) to discuss licensing options.

The experimental demos and published information do not establish that a deployed system meets an information-theoretic guarantee. Such claims depend on a precise model, assumptions, implementation and independent assessment. No license to the separately distributed circuits is granted by this guide or its examples.

Nonprofit organizations and private entities may contact Rosario Cybernetics directly to request permission. Commercial use is strictly prohibited without a paid commercial license. The [circuit notice](https://github.com/HTTP6-ORG/http6-sdk/blob/main/circuits/NOTICE.md) describes enforcement and applicable legal limits.
