# HTTP6 Theory: From Bearer Authority to Proof-Carrying Operations

## HTTP6 within the ENI6MA program

HTTP6 is an application of a wider ENI6MA program whose long-range objective is human-accessible security grounded in information-theoretic analysis. The program considers identity, authorization, private proofs, communications, institutional access, and the resources on which digital operations depend. HTTP6 addresses one part of this system: it connects a person-origin grant to an agent’s request and to the service that can enforce it.

The underlying research starts by modeling geometric relationships among public partitions, private membership choices, proof responses, and an observer’s view. It asks how the distribution of released responses affects the observer’s probabilities over a credential. In the current per-message privacy model, fresh independent private randomness supports a result for a specified passive observer and stated assumptions. That result describes the model’s privacy property; each additional system property requires its own definition and evidence.

The long-range objective is to extend this foundation across practical security functions and replace computational-hardness-dependent patterns when an alternative has been proved, implemented, independently reviewed, and adopted. The HTTP6 API and SDK make this larger thesis reviewable through typed requests, schemas, examples, and test material. Cryptographic properties remain specific to each profile. W1, for example, uses Ed25519 signatures over HTTPS. Read the [ENI6MA mission](./eni6ma-moonshot.md) for the full program and review path.

HTTP6 starts from a change in the unit of security. Conventional web systems protect a connection and then often give an application or agent a reusable credential. HTTP6 aims to make each protected operation carry its own bounded authority and evidence, checked where the requested effect takes place.

The long-range objective is to replace reusable bearer JWT authorization and conventional HTTPS transport across fully migrated applications with a native HTTP6 model. That destination combines operation-level authority, resource-side enforcement, verifiable evidence, and an authenticated encrypted channel.

## The problem HTTP6 addresses

HTTPS protects traffic in transit. Modern HTTPS uses TLS, the successor to SSL. JWT is a token format that can carry signed claims. In many deployments, a JWT is a bearer credential: whoever obtains the token can present it until the system expires or revokes it.

Bearer credentials can spread through environment files, process settings, debug output, build logs, browser storage, copied workspaces, or support bundles. A script or compromised dependency can read and reuse a credential it can access. An AI agent can also misread a task, follow hostile instructions, or invent an action. If the agent has broad ambient credentials, a mistaken tool call can have authority beyond the user's intended task.

The underlying issue is reusable ambient authority. The application may know that a token is valid while having little information about which exact operation the user approved, whether that operation was already used, or whether a response corresponds to the same request.

JWT is not the source of every security problem. The key design question is whether a reusable bearer value alone is enough to exercise authority. HTTP6 aims to make authority narrower, bound to a specific operation, and checked at the resource that performs it.

## The HTTP6 principle

HTTP6 treats the operation as the central security object. A person or authorized origin grants a task with a defined audience, resource, action set, limits, and lifetime. A delegated child grant can narrow those terms. It cannot acquire authority outside its parent grant.

For each protected operation, the caller prepares a canonical request context. It identifies the grant, target resource, operation, payload or payload digest, recipient, and unique operation identifier. A configured proof provider produces evidence bound to that context. The receiving service verifies the grant chain, signer, policy, request binding, freshness, replay state, and available budget.

The resource adapter applies the decision at the point of effect or disclosure. A signature proves who signed a message under a key. It does not alone authorize a database write, file read, payment, process launch, or network call. Authorization combines the grant, request, policy, current state, and resource-side enforcement.

The exchange can be summarized as:

**Permit an effect = valid authority + valid delegation + request binding + fresh operation state + policy match + resource enforcement.**

The parts work together. A valid grant for one recipient does not authorize another recipient. A proof for one payload does not authorize a different payload. Replaying a consumed operation does not create a second effect. An agent's free-text claim of permission does not replace the required signed authority.

## Why this matters for AI agents

An AI model produces proposals, plans, and tool calls. Those outputs can be useful, mistaken, or influenced by hostile content. The model's text is not itself a source of authority in the HTTP6 model.

The agent can request a typed operation. The service checks that operation against the human or origin grant and the resource policy. If a prompt asks the agent to reveal a signing key, circuit source, or unrelated data, that text does not match an allowed operation and cannot enlarge the grant. The protected operation interface returns authorized results and evidence, not the private signing key used by a proof provider.

This separates reasoning from authorization. The model may suggest an action, while the resource decides whether the authenticated, bounded request is permitted. This lets an application use an agent without giving every prompt or tool call ambient access to all credentials available to the process.

## Request proofs, response proofs, and the ledger

A request proof associates the authorized caller and grant with the exact operation context. Depending on the profile, the evidence can include a signature, a native proof result, or both. The receiver verifies the bytes and context it actually received rather than relying on a natural-language description of the request.

A response proof or signed observation links the outcome to the request. Its context can bind the request digest, recipient, status, result digest, policy decision, challenge, and ledger event. This helps a client detect a substituted response, changed payload, replay, or mismatch between the requested operation and the recorded outcome.

The ledger records ordered state transitions such as grant admission, reservation, redemption, result, response proof, failure observation, closure, and recovery. Clients can inspect signed event data and verify chain continuity under configured keys. The ledger supports accountability and reconciliation. It is not a substitute for request authorization or for applying policy at the resource.

## The relationship to HTTPS, TLS, SSL, and JWT

HTTP6's long-term destination is to replace conventional HTTPS/TLS transport and reusable bearer JWT authorization across fully migrated applications. The transport and authorization roles are distinct:

| Concern | Conventional deployment | HTTP6 direction |
| --- | --- | --- |
| Traffic confidentiality and peer authentication | HTTPS with TLS | Native HTTP6 encrypted channel with authenticated peers |
| Application authorization | Often a reusable bearer token, including JWT-based designs | Bounded grants and request-bound proof checked for each operation |
| Agent authority | Credentials available to the process or tool environment | Authority constrained to the approved task and its delegated operations |
| Replay control | Endpoint-specific token lifetime and replay handling | Unique operation identity and stateful one-use checks at the enforcing resource |
| Outcome evidence | Application logs and response bodies | Response proof or signed observation associated with ledger events |

W1 begins with signed requests over HTTPS. That phase changes how authorization is bound to operations while retaining TLS for transport. Later milestones develop independent interoperability, managed workspace authority, and a native encrypted channel. Once an application has moved its clients, services, workers, assets, queues, and recovery paths to the native channel, the operator's objective is to retire TLS-based HTTPS and reusable bearer JWTs on those migrated routes.

An application can migrate in stages. A gateway can connect legacy HTTPS services to HTTP6-aware components while each route is converted. The destination is a native channel whose confidentiality, peer authentication, integrity, key rotation, downgrade protection, replay handling, and recovery are part of the protocol design, alongside request authority.

## The path from proposal to migration

The roadmap orders the work needed to move from current profiles to that destination:

| Milestone | Focus | Contribution to the destination |
| --- | --- | --- |
| W1 signed requests over HTTPS | Bind a scoped authorization to each operation and enforce it at the resource | Establishes request-bound authorization while TLS carries the connection |
| Independent-operator interoperability | Exchange and reconcile requests between separately administered domains | Shows that independent operators can verify the same authority and outcome |
| W2 managed workspace | Bind approval to the running worker, task, and resource access | Extends bounded authority across navigation, downloads, background work, and worker changes |
| N1 native encrypted channel | Define authenticated encryption, key rotation, downgrade control, replay handling, and recovery | Provides the transport foundation for moving beyond HTTPS/TLS |
| Application-wide migration | Move all protected application paths, services, assets, workers, queues, and recovery flows | Allows operators to retire HTTPS/TLS and reusable bearer JWTs on migrated routes |

The profile and SDK guides in this repository provide the schemas, examples, verification paths, and milestones behind this theory. The [repository README](https://github.com/HTTP6-ORG/http6-sdk#readme) links to the live HTTP6.org developer pages, API navigator, demonstrations, and roadmap.

## A concrete contrast

Consider an agent asked to summarize a report stored by a remote service.

With a broad bearer token, the application gives the agent or its runtime a reusable value such as a JWT. A process inspector, untrusted script, copied environment file, or prompt-injected tool may expose that value. Whoever obtains it can make requests allowed by the token until the server expires or revokes it.

With HTTP6, the origin grants a defined read operation for a specific resource and purpose. The SDK prepares a request bound to that operation. The resource checks the grant, recipient, payload context, expiry, replay state, and policy before reading the report. The response is bound to that request and recorded for verification. A new operation requires authority for that operation, and a request asking for a private signing key does not become valid merely because an agent was prompted to ask for it.

That is the central theory: replace ambient, reusable authority with narrow authority that travels with the operation, and move the decision to the resource that can enforce it.
