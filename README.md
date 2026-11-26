# HTTP6: proposed protocol, SDK, and demonstrations

HTTP6 explores how a person or authorized service can delegate bounded work to an agent, require proof for each protected request, enforce the grant at the resource that performs the action, and inspect evidence of the result.

This repository is the public entry point for the HTTP6 proposal, API and SDK code, schemas, examples, and compiled demonstration guests. It presents the platform architecture, current profile implementations, and planned milestones.

## Start here

- [HTTP6.org](https://www.http6.org/): project overview, architecture, research, and participation.
- [The ENI6MA Moonshot](https://www.http6.org/moonshot/): the mission for human-bound agent authority and human-usable, post-quantum information-theoretic security.
- [Moonshot mission on GitHub](docs/eni6ma-moonshot.md): a repository copy for readers who begin here.
- [HTTP6 theory](docs/http6-theory.md): the design rationale, proof model, agent authority, and long-term HTTPS/TLS and JWT migration goal.
- [HTTP6 developers](https://www.http6.org/developers/): API proposal, SDK guide, source links, and demonstrations.
- [Read-only API navigator](https://www.http6.org/developers/sdk/api-reference/): browse the proposed API operations.
- [Protocol roadmap](https://www.http6.org/roadmap/): staged path from signed requests over HTTPS to a possible native HTTP6 channel.
- [Full developer guide](https://www.http6.org/developers/sdk/): schemas, pseudocode, examples, and current implementation boundaries.
- [Adversarial demonstrations](https://www.http6.org/developers/adversarial-tests/): separate cards for controlled JWT, TLS, proxy, proof, and ledger cases.
- [GitHub Issues](https://github.com/HTTP6-ORG/http6-sdk/issues): report a problem, share a reproduction, or propose a change.

## What HTTP6 proposes

An ordinary bearer credential grants authority to whoever possesses it. HTTP6 explores a different application model: carry a bounded grant with a particular operation, bind the request proof to its recipient and contents, and have the receiving resource check the authority and one-use state before allowing the protected effect.

A proposed exchange has these parts:

1. **Approval and grant.** A person or configured origin defines the task, audience, resource, allowed actions, limits, and lifetime. An issuer can create narrower child grants that preserve those constraints.
2. **Request preparation.** An SDK constructs an exact request context, including the operation, target, arguments or payload digest, grant, and unique operation identifier.
3. **Proof and verification.** The configured proof provider produces evidence for the request. The resource checks the signer and grant chain, current policy, expiration or revocation, request binding, budget, and replay state.
4. **Enforcement and record.** The resource adapter checks the policy at the actual effect or disclosure point and records the outcome in ordered ledger events. A valid signature by itself does not authorize an effect.
5. **Response and inspection.** Depending on the profile, a client verifies a native response proof or a signed observation and inspects the available ledger chain. The current pilot cannot establish that a returned ledger prefix is the newest head without an independently trusted checkpoint.

The intended result is authority that follows the task through delegation, with resource-side enforcement and evidence that can be checked independently. The design does not automatically mediate every filesystem, network, database, queue, or privileged path. A deployment must connect and verify each path that can perform an action or disclose data.

## Architecture at a glance

| Part | Responsibility | Current status in this repository |
| --- | --- | --- |
| Protocol profiles and schemas | Define signed objects, request and response context, digests, status transitions, errors, and ledger events | Multiple profiles and proposals are kept separate. A proposed API guide is not wire compatible with every existing profile. |
| Origin and SDKs | Prepare requests, carry grants, call proof and resource adapters, verify responses, and inspect evidence | Node.js, Python, Rust, Go, and C# adapters are present. Their capabilities and setup differ. |
| Pilot host and resource adapters | Receive structured requests, enforce local policy, operate the demo resource, and record events | Public host integration source supports defined synthetic local profiles and registered resource adapters. |
| Proof provider | Produce or verify request and response evidence under a selected trust model | Implementations can use their own proof provider or a separately licensed ENI6MA / Pass+ integration. The public WASIX demonstration guests are compiled files. Circuit and guest source is not distributed. A verifier attestation must not be described as a public zero-knowledge proof unless that property is separately established. |
| Ledger and inspector | Record signed event history and let authorized clients verify signatures and chain continuity | The local pilot verifies returned rows. It does not prove that the server returned the latest ledger head or that an external effect occurred. |

## What is implemented and what remains proposed

Profile names identify different contracts. Do not assume that a capability or test result for one profile applies to another.

| Profile or material | What it contains | Status and boundary |
| --- | --- | --- |
| `http6-w1-00` | A bounded signed-request profile that runs over HTTPS, with reference cases for authorization, resource enforcement, shared budgets, replay, and recovery | Reference implementations and test material are available for the profile's defined cases. |
| `http6-wasix-delegation-00` | The original synthetic WASIX pilot with request proofs and local resource adapters | Local pilot profile with request proofs and local resource adapters. |
| `http6-wasix-delegation-01` | The pilot with native proofs for committed successful responses | Local pilot profile with native response proofs under its configured trust model. |
| `http6-wasix-delegation-02` | Profile 01 plus broker observations for denied, held, malformed, and uncertain replies | Local pilot profile with broker observations for denied, held, malformed, and uncertain responses. |
| `http6-guide-01` | A detailed API, schema, and end-to-end design example in the guide | Proposed API and schema profile, separate from the pilot wire profiles. |
| Rosario-Wang review model | A separate request and response proof model, with its own SDK and ledger | A separate implementation and proof format. |

The local demonstrations use generated synthetic credentials, local state, and bounded test resources. Each test reports the result produced by its fixture.

## Roadmap from HTTPS and JWT

The roadmap moves from signed, proof-bearing requests over HTTPS toward a native encrypted HTTP6 channel. At full migration, the native channel is intended to provide transport encryption and service authentication while request proofs replace reusable bearer JWTs for authorization on migrated routes. The milestones below describe the technical work and sequence.

| Stage | Goal | Status and exit gate |
| --- | --- | --- |
| 1. W1 signed requests over HTTPS | Bind authorization to each operation while keeping TLS for transport confidentiality and service authentication | Reference implementations are available. Prove route-level resource enforcement and replay behavior. |
| 2. Independent-operator interoperability | Exchange requests in both directions between separately administered domains | Next trial. Each operator must keep its own keys, policy, and ledger, and independently reconcile the same resource outcomes. A route may retire bearer JWT authorization only after every effect path enforces the request rule. |
| 3. W2 managed workspace | Bind the displayed approval to the running worker, its delegated tasks, and its resource access | Design stage. Demonstrate that navigation, downloads, background work, and worker replacement preserve or renew the approved authority. HTTPS can continue to carry the traffic. |
| 4. N1 native encrypted channel | Define an HTTP6-aware client and service that establish an authenticated encrypted channel with integrity, key rotation, downgrade protection, replay handling, and recovery | Research and controlled-pilot stage. Twelve technical decisions remain open. Independent implementations and a reviewed transport specification are required before migration. |
| 5. Application-wide migration | Move clients, APIs, assets, workers, queues, and recovery paths onto the validated native channel | Long-term goal. Only after every path and recovery flow is qualified could an operator retire HTTPS/TLS and bearer JWTs on those migrated routes. Partners that have not migrated would need a separately secured gateway. |

There are no promised completion dates. See the [public roadmap](https://www.http6.org/roadmap/) and [technical milestone gates](https://www.http6.org/specifications/status-and-precedence/#milestones) for the current sequence. Replacing HTTPS is more than replacing a token format: TLS currently supplies channel encryption and service authentication, and those jobs need a validated replacement before a route can leave HTTPS.

## Repository map

| Path | Contents |
| --- | --- |
| `source/` | Canonical long-form developer guide and original API proposal. |
| `docs/generated/` | Navigable guide and proposal pages generated from `source/`. Update the canonical source, not generated pages. |
| `docs/` | SDK integration, profile status, response and failure proof, adversarial test, and multi-language guides. |
| `packages/` | Node.js, Python, Rust, Go, and C# SDK adapters and proof verification code. |
| `pilot/` | Public host integration and local WASIX pilot source. This does not include circuit or guest source. |
| `examples/` | Language, cross-runtime, and adversarial demonstrations. |
| `circuits/demo-wasix-02/` | Compiled demonstration guests, notices, checksums, validation records, and dependency notices. Circuit source is not included. |
| `static/artifacts/` | Published schemas and synthetic vectors for the developer guide. |

The Docusaurus developer guide is generated from the canonical Markdown in `source/` and published from this repository. GitHub Pages updates when `main` changes, and the HTTP6.org developer SDK route is configured to serve the guide. Edit the canonical source, not generated pages.

## Build and explore locally

For the documentation site and package unit tests, use Node.js 22:

```sh
npm ci
npm test
npm run build
```

To assemble the local synthetic pilot and run the adversarial examples, you also need Go, Python 3, CGO, SQLite headers, and Wasmer 7.4.0. Use new, private output directories. The runner retains detailed logs, and some verbose synthetic tests print generated test-only keys.

```sh
./pilot/assemble-demo.sh /private/path/to/new-demo-bin
python3 scripts/run-adversarial.py \
  --pilot-bin /private/path/to/new-demo-bin \
  --out /private/path/to/new-private-logs \
  --iterations 3
```

The [adversarial guide](docs/adversarial-tests.md) explains the expected outcomes and limits. The [multi-language demo](docs/multilanguage-demo.md) documents the Node.js, Python, Rust, Go, and C# examples and cross-runtime run. End-to-end SDK runs that require an assembled pilot use a new output directory and remain synthetic.

## Production roadmap milestones

The production roadmap includes these milestones:

- Freeze and independently review profile contracts, canonical bytes, schemas, algorithms, key lifecycle, and proof statements.
- Complete human enrollment, trusted approval display, key custody, runtime identity, and resource-specific policy distribution.
- Test every direct, alternate, background, and privileged route at the actual effect and disclosure boundary.
- Implement transactional shared state, revocation propagation, independent ledger checkpoints, rollback resistance, and crash-safe recovery.
- Test request and response proofs across independent implementations and separately administered operators.
- Specify and independently review the native encrypted channel before claiming that it can replace TLS.
- Publish deployment-specific test evidence, assumptions, supported actions, versions, recovery behavior, and known limits.

Signatures and a hash chain do not by themselves prove current authority, complete mediation, the newest ledger state, or an external resource effect. The [production work checklist](docs/generated/guide/19-decisions-and-work-required-before-production.md) records additional open decisions.

## Contributing and use

Open [GitHub Issues](https://github.com/HTTP6-ORG/http6-sdk/issues) for corrections, proposals, and synthetic reproduction results. Keep private keys, customer data, device state, and private ledger exports out of issues and commits. Do not submit material you cannot share.

This repository does not currently select a top-level license. Public visibility does not grant rights to separately distributed circuit, validation-kit, or third-party material. Review the [compiled circuit notice](circuits/NOTICE.md) and the notice shipped with each demo before use. Circuit source is not published.

ENI6MA circuits are patent pending and protected by copyright. Commercial deployments of the separately licensed circuit integration require a paid license through ENI6MA or Rosario Cybernetics. Nonprofit organizations and private entities may [contact Rosario Cybernetics](https://www.rosariocyber.com/contact) to request permission. For production or extended implementation inquiries, contact President Frank Rosario through [Rosario Cybernetics](https://www.rosariocyber.com/contact).
