# HTTP6 API and SDK guide proposal

**Status:** Working proposal for author and implementer review, November 25, 2026. This document defines a proposed developer experience and identifies contracts to specify and test before release. Pseudocode and proposed endpoints are illustrative.

## 1. Objective and boundaries

Provide a coherent API and SDK through which a developer can establish an origin, mint bounded authority, construct and prove requests, enforce decisions at the resource, verify responses, inspect the ledger, and recover safely from failures. The same model should support an application developer, a resource operator, a circuit provider, and an independent auditor without giving each party another party's private keys or control privileges.

The SDK is an integration layer over explicit protocol profiles. It does not itself guarantee that every filesystem, network, process, database, wallet, queue, or privileged path is mediated. Those guarantees depend on the deployment and its actual resource adapters. Transport uses HTTPS with normal TLS authentication where an HTTP profile applies.

The design makes three distinctions:

| Layer | Purpose | Status in the source material |
| --- | --- | --- |
| Authority continuity | Human or certified origin, constrained delegation, instance identity, current state, and resource-side enforcement | Architecture and proposal. The W1 profile defines a human approval route. The WASIX proposal also describes a certified autonomous origin that does not assert human approval. |
| `http6-w1-00` | W1 signed control objects, narrowly defined credit operations, HTTP signatures, resource outcomes, shared budgets, revocation and recovery | Existing draft and external public vector corpus. Use its exact schema and bytes. It does not define a general circuit proof header or arbitrary payload vocabulary. |
| `http6-wasix-delegation-00` | Policy-bound circuit results, a signed request, certificate, proof and policy publication, live ledger checking and redemption | Local pilot and developer specification. Some host, response, recovery, human-enrollment and production contracts remain proposed. The local pilot is not the W1 wire format. |
| Full message proof extension, working name `http6-message-proof-01` | Explicit fresh native proofs for protected requests and responses, general payloads and other dependent messages | Proposal in this guide. No wire compatibility, security proof, or implementation is claimed. Freeze a separately reviewed specification before using the name as an interoperable profile. |

The earlier per-message review demonstrator models separate native request and response proofs. W1 instead authenticates a response using an HTTP signature and signed evidence. The current WASIX specification describes a circuit proof on the request and identifies fuller response binding as additional work. An SDK must report the actual capability of each profile and must never label a signed response as carrying a native circuit proof unless that separate proof was verified.

## 2. Participants and trust

| Participant | Responsibility | Trust and custody boundary |
| --- | --- | --- |
| Origin and approval presenter | Show the exact scope, destination, action set, delegation, limits and lifetime; obtain a fresh approval or validate the configured autonomous-origin certificate | Human authentication evidence and private enrollment material remain in the admission domain. An autonomous origin is identified as such. |
| Admission and delegation issuers | Admit roots, validate parent request and child possession, register lineage and issue grants | Only configured issuer keys may sign the relevant statements. A peer-supplied key is not a trust anchor. |
| Runtime and circuit provider | Keep instance keys and circuit secrets in protected custody; produce a proof for a particular challenge and context | Appraisal, native verification method, confidentiality and isolation depend on the platform. An attested verifier's assertion is not automatically a publicly verifiable zero-knowledge proof. |
| State authority and ledger | Order admissions, reservations, one-use claims, settlement and revocation; expose authorized evidence | State-changing operations require authenticated callers and durable transactions. A publicly readable object store is not itself proof of current authority. |
| Resource enforcement point | Independently verify the request and current resource policy, acquire the required execution right, and control the actual effect or disclosure | All effect-capable paths must be covered. A broker's signature alone does not establish downstream enforcement. |
| Checkpoint keeper and recovery authority | Retain independently protected checkpoints and authorize a verified recovery | Separate failure domain and registered keys. A signed stale checkpoint is insufficient. |
| Auditor | Verify available signatures, links, ledger continuity and resource evidence under an explicit trust policy | Read access and disclosure are authorized separately. An audit can establish only what its evidence supports. |

Every role uses configured trust roots, role assignments, allowed profile versions, service origins, key identifiers, policy vocabularies, clocks and revocation sources. Trust configuration is installed out of band or through an authenticated update process. Discovery can advertise capabilities; discovery alone never installs trust. Key rotation needs overlapping validity, role authorization, revocation handling and an auditable transition. Private signing and circuit keys must not appear in logs or SDK error objects.

## 3. Proposed SDK surface

The names below describe a consistent application interface, not a claim that these functions exist. A profile adapter must reject an operation that its profile cannot represent, instead of silently translating it to weaker semantics.

```typescript
interface HTTP6 {
  profiles: ProfileRegistry;       // choose exact version and capabilities
  trust: TrustStore;               // role-specific keys, origins and policy
  origins: OriginClient;           // prepare, approve, admit
  grants: GrantClient;             // inspect, mint child, revoke, rotate
  proofs: ProofClient;             // challenge, prove, verify under a profile
  operations: OperationClient;     // prepare, execute, inquire, reconcile
  resources: ResourceMiddleware;  // authenticate, authorize, commit, respond
  ledger: LedgerClient;            // inspect, check, redeem, evidence and audit
  recovery: RecoveryClient;        // checkpoint, reconcile, activate epoch
  codecs: ProfileCodecs;           // exact canonicalization, signatures, digests
}

interface Signer {
  keyId(): KeyId;
  sign(context: TypedSigningContext, exactBytes: Bytes): Promise<Bytes>;
}
interface ProofProvider {
  capabilities(): ProofCapabilities;
  prove(challenge: VerifiedChallenge, context: FrozenContext): Promise<Proof>;
}
```

A production `Signer` should enforce role and context restrictions in protected custody. Applications should use high-level operations rather than receive a general-purpose circuit signing key. `FrozenContext` is immutable after the first digest is calculated. `VerifiedChallenge` is bound to the expected verifier and is not just a caller-provided random string. Runtime configuration selects the approved cryptographic suite and proof provider. A successful SDK call returns typed evidence and its verification status, never a bare `true` that conflates signature validity, authorization and actual commitment.

### Application flow

```typescript
const h = HTTP6.connect({
  profile: "http6-wasix-delegation-00", // exact adapter, no auto-downgrade
  trust: configuredTrust,
  signer: protectedInstanceSigner,
  prover: registeredCircuitProvider,
  transport: tlsTransport
});

const pending = await h.origins.prepare({ policy: approvedPolicy, candidate: rootInstance });
const approval = await humanPresenter.approve(pending.display, pending.challenge);
const root = await h.origins.admit({ pending, approval });
const child = await h.grants.mintChild({
  parent: root, birthId: "birth-reader-01", candidate: readerInstance,
  restriction: restrictedReaderPolicy
});

const invocation = await h.operations.prepare({
  grant: child, op: "op-42", audience: "reports-db", action: "report.read",
  resource: "monthly-total-v1", args: { project: "p7", period: "2026-10" },
  input: bytes(""), releaseTo: "reader-1"
});
const response = await h.operations.execute(invocation);
const verified = await h.operations.verifyResponse({ invocation, response });
if (verified.effect.status === "committed") use(verified.authorizedResult);
else if (verified.effect.status === "uncertain") scheduleAuthorizedLookup(invocation);
```

Preparation must durably retain the operation ID, exact intent and input digest before transmission. Every new authorization attempt uses a fresh record and proof where the selected profile requires it. A delivery retry of an open WASIX certificate retains that certificate and proof and uses a fresh connection challenge; it does not mint a second effect. A new inquiry needs its own current authority. Callers must not treat `RESERVED`, `REDEEMED`, a timeout, or a signed assertion by itself as proof that the external effect occurred.

### Resource integration

```typescript
async function handleProtectedRequest(rawRequest, resource) {
  const received = await h.resources.parseAndVerify(rawRequest);
  // Includes signature, actual method and target, body, profile, chain and proof.
  const decision = await h.resources.authorize({
    received, currentResourcePolicy: await resource.policy()
  });
  if (!decision.allowed) return h.resources.refusal(decision);
  const claim = await h.resources.acquireExecutionRight(decision);
  // At the actual effect boundary, recheck time, policy and observed fence.
  const observation = await resource.commitOnce({
    operationKey: decision.operationKey,
    intent: decision.intent,
    claim,
    recheck: decision.commitGuard
  });
  return h.resources.finishAndRespond({ received, claim, observation });
}
```

The middleware requires an adapter that makes the effect and unique operation journal atomic, or uses the downstream system's durable idempotency and authoritative lookup. If an external system cannot determine whether a timed-out effect occurred, the outcome stays uncertain. Middleware must cover alternate routes, direct credentials, queues, background jobs and privileged adapters before claiming their effects are controlled. A queue receipt proves queue acceptance, not completion of the downstream work.

## 4. Model: objects, schemas and ownership

The tables define a **conceptual schema model**, not an alternative wire schema. Profile-specific closed JSON schemas govern exact names, required members, serialization, limits and signatures. Values such as `ProofRef` are typed in the SDK to prevent accidental interchange of unrelated 32-byte digests.

| Model | Required semantic contents | Issuer or owner | Use |
| --- | --- | --- | --- |
| `TrustConfiguration` | profile and version, trusted service origins, issuers and roles, algorithms, keys and validity, appraisal policy, policy vocabulary, state and checkpoint authorities | Each relying party | Establish independent trust and prevent origin or key substitution. |
| `OriginApproval` | origin type, challenge, subject or certified circuit, exact root terms and their digest, intended recipient, expiry | Human authenticator or configured autonomous-origin process | Bind the root to the actual approved terms. Never represent an autonomous certificate as a human signature. |
| `RootGrant` | root ID, subject or origin reference, holder, public key and generation, service, policy, scope, budget, validity, epoch and approval reference | Admission issuer | Establish initial bounded authority. |
| `ChildJoin` and `ParentRequest` | candidate key and instance, same proposed terms digest, parent, challenge, validity and proof of possession | Child and immediate parent, respectively | Prevent issuance of a child the parent did not authorize or that cannot prove its own key. |
| `ChildGrant` | root and parent references, child holder/key/generation, inherited policy, restrictions, expiry, delegation depth, shared pool, epoch | Delegation issuer | Maintain a verifiable root-to-leaf chain that can only narrow. |
| `Appraisal` | holder, instance key, generation, service, evaluator/policy, measurement or attestation reference, validity | Registered appraiser | Report instance eligibility under an explicit appraisal policy. |
| `Intent` | stable operation meaning: actor scope, destination, action, resource, arguments, input digest, recipient, units and purpose as supported by profile | Acting client | Bind the actual action. Its digest remains stable across an unchanged retry. |
| `Attempt` | operation ID, fresh record ID, intent digest, grant and policy references, actor and generation, method/target or local route, epoch, validity and challenge context | Acting client | Identify this authorization attempt and prevent substitution or replay. |
| `PublicProof` | proof type and version, verifier identity, challenge and context binding, result or witness evidence, verdict and signature | Circuit provider or registered verifier, depending on proof type | Bind the native verification to the context; expose only evidence qualified for that proof type. |
| `Permit` or `Certificate` | attempt, resource/audience, amount, actor, intent, expiry, epoch and fence, state authority signature | State authority | Reserve or authorize one bounded commitment. Exact semantics differ between W1 and WASIX. |
| `ResourceOutcome` or `Closure` | operation, claim, original intent, actor, resource observation, units, time and issuer | Resource | Attest to a durable effect or terminal no-effect closure. The resource journal remains the underlying evidence. |
| `Response` | status, intended recipient, request reference, result digest, outcome reference and response authentication | Resource | Bind the response to the intended request and recipient. A native response proof requires the proposed extension. |
| `LedgerEntry` and `Checkpoint` | sequenced event or state projection, object references, epoch, head and issuer; independent keeper acknowledgment where required | Ledger and checkpoint keeper | Inspect history, verify continuity, and support rollback-safe recovery. |

**Inheritance invariants:** each child preserves the root, applicable service/account/project/purpose, policy semantics, pool and epoch required by its profile; actions are a subset; time and limits do not expand; depth decreases; child holder and key are distinct as required; survival cannot be added if an ancestor forbids it. Validate at mint and again at use. A parent process exit, revocation, generation replacement and expiration have separate meanings and must follow the selected profile's survival and lineage rules.

### Exact W1 request and response model

These are W1 body shapes. Placeholder JWS strings are not valid test vectors. The order and indentation shown are for reading; actual W1 bytes must be canonical. Refer to the companion `schema.json` for all field types and the exact signed control objects.

```json
{
  "p": "http6-w1-00",
  "mode": "execute",
  "record": "record-42",
  "op": "op-42",
  "holder": "worker-1",
  "key": "worker-key-1",
  "gen": 1,
  "intent": {
    "root": "root-1",
    "service": "https://compute.example",
    "account": "account-1",
    "project": "p7",
    "purpose": "research",
    "action": "charge",
    "units": 6
  },
  "chain": ["<root-jws>", "<child-grant-jws>"],
  "appraisal": "<appraisal-jws>"
}
```

```json
{
  "p": "http6-w1-00",
  "code": "COMMITTED",
  "op": "op-42",
  "recipient": "worker-key-1",
  "requestRef": "<64-lowercase-hex-digits>",
  "evidence": "<resource-outcome-jws>"
}
```

The W1 schema has no fields for the arbitrary `args`, `input`, policy address or native proof shown in the WASIX model. Unknown fields are rejected. W1 uses `/w1/operate` and `/w1/status`; `/w1/backend` is a demonstration adapter. A retry retains the operation key and original intent, but gets a new record ID. The provider's operation key is `(service, account, op)` and changing its bound business terms is a conflict for an entitled caller. Disclosure of a prior result requires separate lookup authorization.

### W1 signed-object inventory

The following are the required members of each W1 payload, transcribed from the companion schema. Every signed payload has `p` and `kind`; `terms` is the embedded unsigned object. See the schema for types, value ranges, closed-object rules and relationships. The compact JWS protected header is a separate object.

| Object | Required members |
| --- | --- |
| `terms` | `account, actions, budget, depth, epoch, exp, gen, holder, id, key, limit, nbf, parent, per, policy, project, purpose, root, service, survive` |
| `approval` | `challenge, kind, p, subject, terms` |
| `join` | `exp, gen, holder, key, kind, nbf, p, service, termsHash` |
| `root` | `approvalHash, challenge, kind, p, subject, terms` |
| `request_grant` | `exp, gen, joinHash, key, kind, nbf, p, parent, service, termsHash` |
| `grant` | `kind, p, terms` |
| `appraisal` | `exp, gen, holder, key, kind, nbf, p, policy, service` |
| `permit` | `account, budget, epoch, exp, fence, gen, holder, iat, id, intentHash, key, kind, op, p, policy, project, root, service, units` |
| `outcome` | `account, at, epoch, holder, intentHash, kind, op, p, permit, project, root, row, service, units` |
| `closure` | `account, at, epoch, holder, intentHash, kind, op, p, permit, project, root, service, units` |
| `revocation` | `at, epoch, fence, kind, p, root` |
| `checkpoint` | `account, epoch, head, kind, p, root, seq, service` |
| `recovery` | `account, checkpointHash, kind, nextEpoch, p, root, service` |

### Exact WASIX request relationships

The developer specification describes the WASIX request body as `{v, intent, input, request}`. `request` is a holder-signed compact JWS containing an attempt and proof reference. The public proof is separate and is also transmitted in `HTTP6-Proof` for the specified HTTPS binding. `HTTP6-Policy` carries the trusted ledger policy address and `HTTP6-Certificate` carries the state authority certificate. The local pilot supports a bounded policy vocabulary and local fixtures; the wider specification and this SDK guide describe additional integration work. Check the current implementation and its tests before representing any particular route or proof function as available.

## 5. Digest and signature registry

Typed digest APIs must name the exact profile, data type, algorithm, input bytes and encoding. Never hash a JSON object by an implementation's default stringification and assume it matches another implementation. Preserve the exact received bytes needed for signature and forensic verification.

| Name | Exact input and output | Purpose |
| --- | --- | --- |
| W1 terms hash | SHA-256 of canonical W1 terms JSON, lowercase hex | Bind approval, join and grant request to the same terms. |
| W1 intent hash | SHA-256 of canonical W1 intent JSON, lowercase hex | Preserve business intent across attempts. |
| W1 signed-object hash | SHA-256 of the complete compact JWS ASCII bytes, including signature, lowercase hex | Reference that exact signed object. |
| W1 request `Content-Digest` | SHA-256 over exact transmitted body octets, padded standard Base64 in the `sha-256=:...:` field syntax | Bind the received body, including its record ID. |
| W1 `requestRef` | SHA-256 hex of the ASCII request `Signature` field **value**, from `w1=:` through its ending colon, with no field name or surrounding whitespace | Link the resource response to that exact signed request. This is not the body digest or JWS digest. |
| WASIX `H(label, object)` | SHA-256 hex of ASCII `http6-wasix-delegation-00/` + ASCII label + one `0x00` byte + canonical JSON bytes | Domain-separated policy, intent, attempt, proof and circuit-result digests. |
| WASIX `S(jws)` | SHA-256 hex of the complete compact JWS ASCII bytes | Exact signed request, certificate or grant reference where specified. |
| WASIX input hash | SHA-256 hex of exact input octets, including the empty byte string | Bind bytes actually supplied to an action. |
| WASIX circuit result | `resultHash = H("circuit-result", result)`; verifier signs the **32 decoded digest bytes**, then `proofRef = H("proof", publicProof)` | Bind the signed verifier result and complete public proof. |
| Proposed response content and context | Exact response bytes, status, recipient, request and outcome references, sender, direction, nonce and lifetime under a separately versioned format | Support a separately verified native response proof without reusing a request proof. Exact wire rules remain to be frozen. |

W1 uses restricted RFC 8785 canonical JSON: printable ASCII strings and object names, booleans, null, arrays and unsigned integers; timestamps and other integers have the ranges in the draft. Reject duplicate or unknown members, noncanonical bytes, out-of-range numbers and unsupported values. W1 compact JWS protected headers contain exactly `alg`, `kid`, `typ`, with `Ed25519` and `http6-w1+jws`; the protected header and payload are canonical. Compact JWS segments are unpadded base64url. HTTP `Content-Digest` and HTTP signature byte sequences use standard padded Base64 in their specified structured-field encoding. They are not interchangeable encodings.

W1 limits are 65,536 body octets, 16,384 header octets, 8,192 characters per compact object, and nine chain objects including the root. Permissions contain one to eight unique identifiers in ascending ASCII order. Validity is inclusive at the start and exclusive at the end. Configure an uncertainty budget for clocks and reject ambiguous expiry. The WASIX profile's implementation has its own closed schemas and resource limits; test its exact serializer against profile-specific vectors before interchange.

### Dependency map

The arrows mean that the target references or authenticates the source under the relevant profile; each arrow is checked independently. The two branches are distinct, and the extension's response steps are future work.

```text
W1:
terms -> approval + join -> root -> parent request + child join -> grant chain
intent -> intentHash -> permit -> resource outcome / closure
request body -> Content-Digest -> request HTTP signature -> requestRef
requestRef + outcome + response body -> response Content-Digest -> response HTTP signature

WASIX:
policy -> policyHash -> root and child grants -> attempt
input bytes -> inputHash -> intent -> intentHash -> attempt -> attemptHash
attemptHash + challenge -> circuit result -> resultHash -> signed public proof -> proofRef
attempt + proofRef -> signed request -> requestRef -> certificate
body + proof + policy address + certificate -> holder HTTP signature -> presentationRef
presentation + references -> check -> designated redemption -> resource observation -> receipt

Proposed response proof:
result bytes -> payloadDigest -> response context + challenge -> native response proof
result + context + proof -> final envelope digest -> response HTTP signature
```

This is a dependency map, not a serialization template. A resource receipt or proof verifier's signature states what that signer attests; the recorded observation and trust in the resource determine what can be concluded about a real effect.

### Signing W1 HTTP messages

W1 signs the following components in exactly this order with a single `w1` label and parameters `created`, `expires`, `keyid`, `alg`, `tag`, in that order. The HTTP tag is `http6-w1-00`, algorithm `ed25519`. A request or response signature interval is at most 30 seconds.

```text
Request:  "@method" "@target-uri" "content-type" "content-digest"
Response: "@status" "content-type" "content-digest" "@method";req
          "@target-uri";req "content-digest";req
```

The response signer is the trusted resource key. The client verifies the response's own time interval, associated request context, recipient, operation, status and evidence. The WASIX `dg` component list is different and covers proof, policy and certificate fields as well. Select one profile explicitly and reconstruct its exact signature base; never mix `w1` and `dg` rules. Reject duplicate fields, unauthorized redirects, changed target, transformations and conflicting framing. W1 excludes state-changing early data, content/transfer codings, trailers and unverified streaming effects.

## 6. From admission to a protected response

The following sequence is a **proposed general orchestration**. Each step must be mapped to the actual profile. W1 uses its defined signatures and control records; it does not acquire new circuit-message fields merely by following this sequence.

1. **Establish trust and capabilities.** Choose the exact profile, configured origin, resource, issuers, appraiser, state authority and proof method. Compare advertised capabilities against local policy. Fail closed on unknown versions and unsupported semantics.
2. **Prepare root.** Generate a fresh unpredictable single-use challenge and candidate key. Canonicalize the exact root terms and show the person the destination, action set, purpose, delegation right, lifetime and ceilings. For an autonomous origin, verify its configured certificate and clearly identify its origin type.
3. **Admit.** Verify the approval or origin certificate, candidate possession, appraisal, exact terms and current policy. Consume the challenge and register the signed root in one authoritative decision. A changed key or policy needs a new appropriate authorization.
4. **Mint child.** Form restricted terms. Verify the current parent's signed request and the new child's signed join over the same terms. Validate all ancestors, appraisal, budgets and issuance idempotency. Sign and register the child before enabling its handle.
5. **Prepare intent.** Construct typed intent from the actual resource, operation, arguments, input octets, audience, recipient and expected unit cost. Compute the profile-specific input and intent digests. Retain stable operation identity before sending.
6. **Prove and sign.** Construct the fresh attempt and obtain an authenticated, unpredictable challenge where the profile requires it. The circuit and verifier bind the exact attempt, actor, policy, audience, expiry and challenge. The holder signs the prescribed request. Publish only the permitted proof and policy evidence.
7. **Reserve or acquire certificate.** The state authority authenticates the request, checks active lineage and policy, and atomically orders available units and operation uniqueness. Obtain the profile's short-lived permit or certificate. A signed statement that does not match the actual request cannot authorize it.
8. **Present and independently check.** Deliver the exact request with profile-specific signed HTTP components or a protected local envelope. The receiver verifies its own trust, signatures, exact body and route, lineage, proof where applicable, and live current state. WASIX `check` does not spend the certificate. A custodian's control call is separately authenticated under its control policy and terminates at the ledger without recursive callbacks.
9. **Enforce and commit.** At the real resource boundary, recheck the resource policy, current fence, time and claim. For WASIX the designated custodian redeems as specified; a retry of the winning redemption ID returns the original decision. Apply one effect and durable observation atomically, or use equivalent downstream idempotency. A redemption is an execution claim, not the effect itself.
10. **Respond and settle.** The resource signs the actual durable observation or no-effect closure and sends the profile's response bound to the original request. Verify the response before release to the caller. Settle once on matching evidence. If no effect can be proven or excluded, keep the reservation uncertain. A timeout does not release it.
11. **Inspect, inquire, revoke or recover.** Use separately authorized inspection and lookup. Order revocation at the state authority and enforce observed fences. After restore, hold new effects until latest independent checkpoint, authority history and resource journals reconcile; activate exactly the authorized next epoch, retaining spent and revoked state.

A response might arrive after a grant is revoked. The resource evidence is still an assertion about the earlier actual effect; disclosure to a later reader requires its own authority. Do not equate late acknowledgment time with commit time.

## 7. Proposed request and response proof extension

This section proposes a path to the full per-message model. It is not a W1 field definition and is not a released WASIX response format. A profile revision must specify the full schema, byte encodings, limits, transport mapping, trust and verification rules, test vectors, and privacy model.

### Message context

```typescript
// Conceptual required semantics, not an approved wire schema.
type MessageContext = {
  profile: ProfileId;
  messageType: "request" | "response" | "ledger-control";
  direction: "client-to-resource" | "resource-to-client" | "service-to-ledger";
  sender: InstanceRef; recipient: InstanceRef;
  authorityRef: GrantRef; policyRef: PolicyRef;
  operationId: OperationId; recordId: RecordId;
  requestRef?: RequestPresentationRef; // required for a response
  status?: Integer;                   // required for an HTTP response
  target: ExactTarget; contentType: MediaType;
  payloadDigest: TypedDigest; outcomeRef?: OutcomeRef;
  challenge: ChallengeRef; issuedAt: Time; expiresAt: Time;
};
```

Require explicit rules for which fields are mandatory in each direction, how sender and recipient are authenticated, and how a result's actual bytes are bound. Response proof challenge ownership, expiry, replay storage and who can verify must be specified. A malicious or repeated challenge must not cause unsafe reuse of a native witness or private mask.

### Construction order without a circular hash

1. Freeze the application result bytes, HTTP status, recipient, original request reference, and durable outcome reference. Compute `payloadDigest` over the exact result bytes.
2. Construct and canonicalize the response `MessageContext` without any response proof, final envelope signature, or digest of an envelope that contains itself. Bind the payload digest, request reference and resource observation.
3. Verify a fresh challenge for this context. Produce and verify the response proof under the resource's registered circuit and verifier policy. The proof states precisely whether its native relation is publicly verifiable or is an attestation from a trusted designated verifier.
4. Assemble a response envelope containing the frozen result, context and proof or stable proof reference. Calculate its body digest over the final envelope. Sign the response status, exact final body digest and associated request components under the profile's defined HTTP signature base.
5. The receiver verifies the HTTP association, recipient and exact body; independently checks context and payload digest; validates and consumes the response proof under the right verifier and challenge; checks the signed outcome and resource evidence; then permits release. If proof resolution or the authoritative verifier is unavailable, return an authenticated hold or indeterminate result rather than asserting proof success.

This ordering avoids making the proof depend on a digest of the envelope that contains the proof. The specification still needs to choose whether to embed payload and proof or transmit detached bytes, define the signed content type and failure behavior, and handle privacy-preserving retention. Do not assume a response signature is a native response proof, or that a native proof alone proves an actual external effect.

A request-side design can use the same separation: hash the immutable application payload, place its digest in an attempt context, obtain a challenge and proof for that context, construct the envelope, and finally sign the exact transmitted HTTP representation. W1 and WASIX maintain their own existing construction orders unless revised through new profile versions.

## 8. Proposed service API and inspection

These routes illustrate a future service API; they are **not** a claim that a generic HTTP6 server implements them. Keep control, resource and inspection permissions separate. All mutation and protected inspection calls require authenticated, scoped callers; responses include request correlation and a profile-defined authenticated result. An implementation can expose equivalent local APIs without a public network endpoint.

| Purpose | Proposed operation | Input and result |
| --- | --- | --- |
| Discover supported profiles | `GET /http6/api/v1/capabilities` | Supported versions, limits and methods. Advertisement is not a trust anchor. |
| Prepare and admit origin | `POST /http6/api/v1/origins/challenges`, `POST /http6/api/v1/origins/admissions` | Exact proposed terms and candidate; authenticated challenge, then approval, join and appraisal; signed root and receipt. |
| Mint child | `POST /http6/api/v1/grants` | Parent request, child join, restricted terms, proof/appraisal, stable birth ID; signed child or conflict. |
| Resolve grant or policy | `GET /http6/api/v1/grants/{ref}`, `GET /http6/api/v1/policies/{ref}` | Authorized public or private object, exact bytes, profile and digest; caller verifies against configured trust. |
| Challenge and verify proof | `POST /http6/api/v1/proofs/challenges`, `POST /http6/api/v1/proofs/verify` | Authenticated context-bound challenge; proof and context; signed accepted, denied or indeterminate decision. Verification alone grants no execution. |
| Reserve, check and redeem | `POST /http6/api/v1/operations/reservations`, `/checks`, `/redemptions` | Intent and evidence; scoped signed claim or check; designated redemption with durable idempotency key. Exact semantics depend on profile. |
| Submit outcome or closure | `POST /http6/api/v1/operations/outcomes`, `/closures` | Resource-authenticated observation or terminal no-effect evidence; settle once. |
| Inquire | `POST /http6/api/v1/operations/status` | Fresh authorized request with original operation and intent; original evidence, pending/uncertain, or nondisclosing denial. |
| Inspect | `POST /http6/api/v1/ledger/queries`, `POST /http6/api/v1/ledger/evidence-bundles` | Authorized bounded filters, cursor and snapshot; event/object evidence, ledger head and optional checkpoint chain. |
| Revoke and recover | `POST /http6/api/v1/authority/revocations`, `/recovery-plans`, `/recovery-activations` | Role-authorized request and proof, ordered fence or recovery receipt. Activation requires reconciled state and external checkpoint. |

Existing pilot routes are different: its Go ledger handles `GET /http6/v0/catalog`, `/events`, and object, root, policy and family paths, plus `POST /http6/v0/admit`, `/birth`, `/reserve`, `/check`, `/redeem`, `/outcome`, `/confirm`, `/hold`, `/record-refusal` and `/revoke`. Their existence does not make the proposed `/http6/api/v1` routes available. The pilot's deployment and access controls govern what its actual ledger exposes.

### Inspection workflow

```typescript
const bundle = await h.ledger.evidenceBundle({
  operation: { service: "reports-db", op: "op-42" },
  include: ["lineage", "policy", "attempts", "claims", "outcomes", "checkpoint"]
});
const audit = await h.ledger.verifyBundle(bundle, {
  trust: auditorTrust, at: "recorded-event-time", requireCurrentStatus: false
});
// report separately: valid historical signatures, complete links, state freshness,
// checkpoint continuity, resource observation and any unavailable evidence.
```

Historical verification at the recorded event time is distinct from whether the grant is valid now. Ledger snapshots must bind the query range and head, establish sequence continuity and include proof of the latest independently retained checkpoint where required. A hash chain or inclusion proof does not alone establish that no later entries exist or that the queried view is complete. Absence claims require an authenticated snapshot and explicit completeness mechanism. Support cursor pagination without mixing snapshot heads; restrict queries, rate limit and redact disclosure according to the reader's policy. Public hashes can still leak correlatable or low-entropy data.

## 9. State transitions and failure handling

Treat these as conceptual states. Each profile defines its own actual fields, states and ordering.

```text
Draft -> Admitted -> Active -> Revoked / Expired / Retired
Operation: Prepared -> Reserved -> Claimed -> Committed -> Settled
                                \-> Closed without effect -> Released
                                \-> Uncertain -> Reconciled to committed or closed
```

`Claimed` represents a WASIX-style redemption where applicable; W1 has its own permit and resource commitment model. A failed or rejected request must not create a protected effect. Concurrent siblings draw against a single authoritative shared budget: settled units plus all outstanding reservations, including uncertain ones, stay within every applicable inherited ceiling. Idempotency must bind the operation key to the original actor, intent, audience and policy; a reused key with changed meaning conflicts for an authorized caller. Fresh transmission records prevent replay and do not redefine the business operation.

| Condition | Required handling |
| --- | --- |
| Unknown signer, profile, field, algorithm, policy or destination | Reject; never fall back silently. A generic error need not be a signed profile response. |
| Bad proof, body digest, signature, context or challenge | Reject before effect; consume identifiers only according to the profile's authenticated eligibility rules. |
| Budget exhausted, expired grant, observed revocation, invalid lineage | Deny or hold as specified; disclose no protected outcome to an unauthorized caller. |
| State authority unavailable or stale | Hold new operations requiring fresh authority. A previously issued permit during partition follows its profile's bounded lifetime, fence, local policy and clock rules. |
| Lost reply after possible effect | Retain reservation as uncertain. An authorized lookup obtains the original result; never retry as a new business operation or release on timeout alone. |
| Terminal no-effect closure | Release only after matching authenticated evidence establishes that a prior effect cannot later commit. Settlement and closure must be mutually exclusive and idempotent. |
| Restored old database | Hold. Verify latest independent checkpoint, reconcile authority and resource histories, retire old runtime bindings, and activate the exactly authorized next epoch. Missing or unverifiable evidence maintains the hold. |
| Invalid or unavailable response proof | Do not report proof verification or release a protected payload under a policy that requires it. Distinguish invalid from indeterminate. |

For W1, the signed response codes are `COMMITTED`, `RECONCILED`, `CLOSED`, `RESERVED`, `UNCERTAIN`, `DENIED`, `CONFLICT`, `REPLAY`, `BUDGET` and `HELD`, with the exact HTTP status and evidence rules in the W1 draft. `INVALID` is a harness label for malformed or unauthenticated exchanges, not a required signed W1 response. APIs should surface transport failure, profile denial, proof failure, uncertain effect and confirmed commitment as distinct results.

## 10. Implementation plan and release evidence

1. **Freeze contracts.** Publish separate versioned JSON Schemas for every signed payload, public proof, request/response, ledger callback, policy, trust configuration, outcome and checkpoint. Define semantic constraints beyond JSON Schema, canonical bytes, all signature bases and digest domains, challenge lifecycle, size/time limits, and unknown-field behavior. Preserve W1 schema and vectors unchanged.
2. **Deliver a profile core.** Implement strict encoders/decoders, typed digests, role-aware signature verification, current trust and clock evaluation, and no-downgrade profile selection. Publish public synthetic keys and reproducible exact byte vectors, including malformed and noncanonical inputs. Test two independently written encoders.
3. **Integrate origin, minting and proof providers.** Implement actual human enrollment or clearly identified autonomous origin, trusted display, key custody, parent authorization, child possession and appraisal. Specify each circuit proof's statement, witness, public inputs, verifier and security assumptions. Prove and test any stronger cryptographic claim separately.
4. **Build the state service and adapters.** Provide transactional unique operation records, shared allowance, reservation and reconciliation, independent resource commitment, resource-side policy, revocation and authorized inspection. Exercise direct and alternate access paths at the real effect and disclosure sinks.
5. **Add response proof profile.** Resolve the design choices in section 7, implement sender and receiver independently, and publish request, response and dependent control-message vectors with every intermediate digest and signature base. Cover replay, substituted recipient, status, payload, outcome and original request.
6. **Qualify operational recovery and independent exchange.** Test crashes before and after each state transition, simultaneous claims, lost replies, stale restores, clock uncertainty, key rotation, partition and recovery against independently retained checkpoints and resource journals. Run both directions between separately administered domains and record actual origins, builds and resource observations.

**Conformance evidence** should include exact input bytes and expected intermediate hashes, signatures and output bytes; positive and negative schema cases; proof substitution and replay tests; changed payload, method, target, status and recipient; expansion of scope and budget; concurrent shared-budget spending; one winning commit; zero unauthorized disclosures through alternate paths; independent lookup authorization; checkpoint rollback refusal; response proof availability and challenge handling; and privacy review of exported evidence. Run W1's existing 11 public cases as W1, and a separate suite for the WASIX and proposed message-proof profiles. Do not count local fixtures as a two-operator deployment.

### Decisions before a stable public SDK

- Which profiles are mandatory for the first SDK release, and which language and runtime bindings are supported first?
- Which native circuit formats support independent public verification, and which rely on a registered designated verifier? What precise security and privacy claims are supported for each?
- What is the authoritative method for obtaining human consent, protecting keys and appraising runtime instances on each target platform?
- How will multi-ledger budget allocation, revocation propagation, checkpoint independence, resource recovery and key rotation be implemented and tested?
- Which actions, argument types, content encodings, output disclosures and streaming or chunk semantics will each profile support?
- Which policy and result evidence is public, tenant-restricted or private, and what retention and deletion obligations apply?
- What response challenge exchange, proof transport, replay semantics, failure codes and version negotiation will the new message-proof profile adopt?

The remaining sections identify profile choices, API contracts, and the verification agenda for this design.

## 11. Source map

- [HTTP6 packet README](README.md): platform overview, document roles and milestones.
- [Authority continuity draft](01-ietf/draft-rosario-http6-authority-continuity-00.md): origins, delegation, resource commitment, revocation and recovery.
- [W1 profile](01-ietf/draft-rosario-http6-w1-profile-00.md): W1 schemas, byte rules, signatures, request/response and conformance cases.
- [WASIX delegation developer specification](HTTP6-WASIX-Delegation-Developer-Spec.md): proposed developer API, policy, native proof, callback and request bindings.
- [WASIX implementation plan](HTTP6-WASIX-Delegation-Implementation-Plan.md): local pilot boundaries, evidence and remaining production work.
- [WASIX local operating guide](wasix-delegation/README.md) and [protocol source](wasix-delegation/src/protocol.rs): implementation-specific behavior and digest construction.
- [Per-message proof review](02-nist-markdown/HTTP6_Per_Message_Proof_NIST_Review_White_Paper.md): separate request/response proof model and limitations of the demonstrated construction.
- The W1 draft references the companion corpus at `../IETF/http6/w1-public-vectors-00/`, including `schema.json`, exact public fixtures and 11 cases. That directory is outside this packet and must accompany any standalone distribution of the vectors.
