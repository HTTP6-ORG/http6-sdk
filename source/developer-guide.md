# HTTP6 API and SDK developer guide

**Draft design and synthetic examples, November 25, 2026**

This guide describes how an application, authority service, circuit verifier, resource owner, and ledger can cooperate to establish bounded authority and carry a protected operation through to a verifiable response. It includes detailed contracts, pseudocode, an exact proposed data model, and a reproducible synthetic exchange. It is for implementation review and profile development.

**Status:** The existing `http6-w1-00` and `http6-wasix-delegation-00` profiles retain their own contracts. The local `http6-wasix-delegation-01` pilot adds ledger-recorded native proofs for committed successful responses. Profile `http6-wasix-delegation-02` adds broker-observed failure response proofs for denied, held, malformed, and uncertain responses. The worked profile in this guide is a new design called `http6-guide-01`, with schemas and examples for the proposed API. Its remaining specifications and independent testing milestones are listed in section 19.

**Implementation update:** The proposed SDK supports WASIX profiles 00, 01 and 02. In 01, the resource and a separate designated verifier produce a native proof for a committed successful response after a one-use ledger challenge. The SDK verifies matching response evidence at the signed ledger-event time. A separate Rosario-Wang review model and optional synthetic bridge remain available. The different formats, verifiers and ledgers remain separate. See the SDK integration and native response proof pages for exact capabilities and limits.

## Where HTTP6 fits in the ENI6MA mission

HTTP6 is one network application within ENI6MA’s moonshot: replace cryptographic primitives whose security depends on computational assumptions with the ENI6MA and Rosario-Wang information-theoretic proof architecture. If a primitive depends on computational hardness, it belongs on the replacement path. The larger destination spans human identity, bounded authority, private proofs, communications, institutional access, and other consequential digital systems. Its mathematical starting point is a geometric model of public partitions, private membership choices, response dictionaries, fresh masking, and the information available to an observer. The research asks whether the released response distribution changes that observer’s probabilities over a credential.

The mission is to replace the computational assumptions beneath cryptography and carry information-theoretic proofs into working systems, one primitive class and deployment path at a time. This guide defines the HTTP6 API contribution through profiles, schemas, examples, and evidence. It does not assign a single cryptographic property to every profile. W1 uses Ed25519 over HTTPS and retains computational assumptions, while the native-channel and broader information-theoretic work follow separate research and implementation paths. Read the [ENI6MA mission](https://github.com/HTTP6-ORG/http6-sdk/blob/main/docs/eni6ma-moonshot.md) for the program’s full scope and review path.

The companion files are:

- [JSON Schema for the proposed guide profile](http6-sdk-guide/schema.json), with 37 reusable definitions.
- [Synthetic end-to-end vectors](http6-sdk-guide/synthetic-vectors.json), including public test keys, signatures, messages and digests.
- [Vector generator and consistency checks](http6-sdk-guide/build-vectors.mjs), runnable with Node.js.
- [Earlier API and SDK proposal](HTTP6-API-SDK-Guide-Proposal.md), including a W1 signed-object inventory and comparison with the existing material.

The examples use real Ed25519 signatures over public deterministic test keys. The human approval, circuit-verifier verdicts, ledger decisions, and resource effect are **simulated data**. No native circuit is run by the vector generator, no person approves its terms, and no service or production ledger is contacted.

## 1. What a developer builds

An HTTP6 integration has five cooperating pieces:

1. **Origin and issuer:** present bounded authority for approval, verify the origin, admit a root, and mint narrower descendants.
2. **Instance and proof adapter:** protect each instance's key and circuit material, obtain a context-bound challenge, and produce or verify the appropriate request or response evidence.
3. **State authority:** order one-use challenges, grants, reservations, redemptions, revocation and settlement using durable, transactional state.
4. **Resource enforcement point:** independently verify the request and current policy at the actual disclosure or effect boundary, then commit once and produce a resource observation.
5. **Client and auditor:** verify a response against the exact request and inspect authorized ledger evidence, including the limits of what that evidence proves.

A valid signature answers who signed particular bytes under a trusted key. A valid proof result answers the question defined by its proof provider and verifier policy. Neither alone authorizes the requested effect. Authorization also depends on the registered chain, current status, inherited and resource policies, operation identity, resource-specific claim, and actual enforcement.

### Profiles and compatibility

| Profile | Use in this guide | Important difference |
| --- | --- | --- |
| `http6-w1-00` | Existing W1 draft and vectors | Uses compact JWS, W1 request and response bodies, RFC 9421 HTTP signatures and defined credit operations. It does not define the guide profile's proof objects or general-purpose payload model. |
| `http6-wasix-delegation-00` | Existing local pilot and broader developer specification | Uses its own compact JWS, domain-separated hashes, `dg` HTTP signature and a proof, policy address and state certificate on the request. Some production, response and recovery features remain planned. |
| `http6-wasix-delegation-01` | New local pilot in this repository | Adds a distinct resource response circuit, designated verifier, ledger-issued one-use challenge, signed response evidence and SDK verification for committed successful responses. Failure response proofs are added in profile 02. |
| `http6-wasix-delegation-02` | Local pilot and proposed SDK | Retains native successful response proofs and adds ledger-recorded broker observations for denied, held, malformed and uncertain responses. The observation does not establish caller identity or effect state. |
| `http6-guide-01` | New, bounded example contract in this guide | Uses the signed JSON envelope below, separate request and response proof attestations, explicit packet and ledger models, and synthetic vectors. It must not be sent to a W1 or WASIX verifier as if it were their format. |

The SDK selects the exact profile and reports its capabilities. No automatic fallback is permitted when a required response proof, current-state check, algorithm or policy cannot be honored.

## 2. Before an application starts

Configure each relying party with its own trusted material. A request's embedded identifier is only a lookup key into that configuration.

```typescript
const config: TrustConfiguration = {
  profile: "http6-guide-01",
  resourceOrigin: "https://reports.example",
  target: "https://reports.example/operate",
  issuers: { admission: ["issuer-key"], delegation: ["issuer-key"] },
  approvers: { "human-1": ["human-key"] },
  appraisers: ["appraiser-key"],
  proofVerifiers: ["verifier-key"],
  stateAuthorities: ["state-key"],
  resources: { "reports-db": ["resource-key"] },
  checkpointKeepers: ["keeper-key"],
  permittedAppraisalPolicies: ["appraisal-1"],
  algorithms: ["Ed25519", "SHA-256"],
  maxClockUncertaintySeconds: 1,
  allowedActions: ["report-read"]
};
```

This is SDK configuration pseudocode, not a serialized trust schema. Provision public keys, role bindings, permitted origins, certificate validation, evaluator policies, validity and rotation rules through an authenticated administrative channel. Do not import a key or authorize a ledger merely because a request names it. Resource and state authorities remain independently responsible for their decisions. An SDK should provide protected key handles rather than expose private bytes to application code.

The worked guide profile uses a human-origin example. An autonomous origin requires a separately specified origin certificate and admission policy. It must not be reported as human approval. The example's human key is a public synthetic fixture.

## 3. Installable SDK shape

The following surface describes the intended SDK; it is not an existing package or callable interface.

```typescript
interface Http6Client {
  origins: {
    prepareRoot(input: RootProposal): Promise<RootCeremony>;
    admit(input: AdmissionEvidence): Promise<RegisteredGrant>;
  };
  grants: {
    prepareChild(input: ChildProposal): Promise<ChildCeremony>;
    mintChild(input: ChildEvidence): Promise<RegisteredGrant>;
    inspect(ref: GrantRef): Promise<VerifiedGrant>;
    revoke(input: RevocationRequest): Promise<SignedRevocation>;
  };
  operations: {
    prepare(input: OperationInput): Promise<FrozenOperation>;
    prove(input: FrozenOperation): Promise<ProvenRequest>;
    reserve(input: ProvenRequest): Promise<Permit>;
    execute(input: ProvenRequest, permit: Permit): Promise<RawResponse>;
    verifyResponse(input: ResponseVerificationInput): Promise<VerifiedResponse>;
    status(input: StatusRequest): Promise<OperationStatus>;
  };
  ledger: {
    check(input: LedgerControl): Promise<SignedDecision>;
    redeem(input: LedgerControl): Promise<SignedDecision>;
    inspect(query: AuthorizedQuery): Promise<EvidenceBundle>;
    verifyBundle(bundle: EvidenceBundle, trust: TrustConfiguration): AuditResult;
  };
}
```

Implement client, issuer, verifier, state and resource packages separately so that installing the client does not grant issuer or ledger authority. Signing and proof generation should accept typed, frozen contexts and role-restricted key handles. Return typed results such as `Committed`, `Reserved`, `Uncertain`, `Denied`, `Held`, and `Invalid`; do not expose a single ambiguous success flag.

## 4. Guide profile encoding and cryptography

This section specifies the proposed `http6-guide-01` encoding used by its companion schema and vectors. It does not alter W1 or WASIX.

### Canonical JSON and bounds

- Encode JSON as UTF-8, without a byte-order mark. Use RFC 8785 canonical JSON restricted to printable ASCII strings and property names, booleans, null, arrays and nonnegative integers. Sort object member names in ASCII order. Preserve array order. Reject duplicate object members, unknown members, floating-point values, noncanonical wire representations and invalid UTF-8.
- Identifiers contain 1 to 64 lowercase ASCII letters, digits and hyphens, beginning with a letter or digit. Hashes and nonces are 64 lowercase hex digits. Ed25519 signatures are 128 lowercase hex digits. `keyId` is a configured identifier, not raw trust material.
- Time is whole Unix seconds. Time intervals include `nbf` or `iat` and exclude `exp`. The schema limits timestamps to `253402300799` and other counts to `2147483647`. Timestamps, signature freshness and the uncertain clock interval all have to fit within the relevant grant, appraisal, challenge and permit bounds.
- For this design, reject JSON packets larger than 65,536 bytes and chains longer than nine grants. Fields and rules have the additional limits in the schema. Hex encoding expands binary data: large inputs, streaming and chunk proofs require a different profile.
- The URI pattern is intentionally narrow: configured HTTPS URI, restricted ASCII path, no query or fragment. Compare the exact configured target to the actual route seen at enforcement. Disable redirects, state-changing early data and content transformation. Do not derive the trusted target from an untrusted `Host` field.

A JSON Schema validator works on parsed values. It cannot by itself detect duplicate keys, noncanonical received bytes, key-role trust, replay or an unauthorized effect. Parse defensively, retain the raw received bytes, reserialize canonically and compare bytes before validating semantics.

### Hashing and signing

Let `C(x)` be canonical JSON bytes, and let `0x00` be one zero byte:

```text
frame(label, x) = ASCII("http6-guide-01/" + label) || 0x00 || C(x)
H(label, x)     = lowercase_hex(SHA-256(frame(label, x)))
rawHash(bytes)  = lowercase_hex(SHA-256(bytes))
```

This domain separation is specific to the guide profile. It is different from W1's canonical-object hashes and from the WASIX profile's prefix.

A signed object is:

```json
{
  "payload": {"v": "http6-guide-01", "kind": "..."},
  "signature": {"alg": "Ed25519", "keyId": "...", "value": "<128-hex-digits>"}
}
```

The signing input is `frame("signature", {"alg":"Ed25519", "keyId": keyId, "payload": payload})`. Sign those bytes with ordinary Ed25519. `value` is the signature's raw 64 bytes encoded as lowercase hex. The algorithm and key identifier are therefore signed along with the payload. Check the configured role and the expected payload kind, key, audience, context and time before accepting it. Its reference is `H("signed", signedObject)`, over the complete envelope including the signature.

### Typed digest registry

| Name | Exact input | Who checks it |
| --- | --- | --- |
| `policyRef` | `H("policy", policy)` | Issuer, state authority and resource |
| `termsRef` | `H("terms", terms)` | Approver, prospective instance and issuer |
| `intentRef` | `H("intent", intent)` | Holder, state authority and resource |
| `attemptRef` | `H("attempt", attempt)` | Holder, proof verifier, state and resource |
| Signed grant, challenge, request, permit, outcome, event or checkpoint reference | `H("signed", completeSignedEnvelope)` | The relying party for that role and kind |
| `proofRef` | `H("proof", {challenge, result})`, with both complete signed envelopes | Request/response signer and relying party |
| Input/result digest | `rawHash(exactInputBytes)` or `rawHash(exactResultBytes)` | Resource or recipient before using bytes |
| `presentationRef` | `H("request-packet", completeRequestPacket)` | Custodian and state authority for the same presented packet |
| Response context | `H("response-context", responseContext)` | Proof verifier, resource signer and recipient |
| Response packet | `H("response-packet", completeResponsePacket)` | Optional archival identification; it is not the response proof context |
| Checkpoint state | `H("state", canonicalStateProjection)` | State authority and independent keeper under an agreed projection |

Do not place a digest of the final response packet inside the context that generates its own proof. Section 11 gives a noncircular construction order. A standalone digest of low-entropy input is not confidential; public evidence needs privacy review.

## 5. Data model and schema reference

The companion [schema](http6-sdk-guide/schema.json) is a draft 2020-12 JSON Schema. All listed object properties are required and `additionalProperties` is false. The schema supports syntactic validation; the semantic constraints below must also be implemented. A `signed` wrapper can contain several payload kinds, so every endpoint additionally verifies that its expected payload kind and signer role match.

| Definition | Required fields beyond `v` and `kind`, unless noted | Semantics |
| --- | --- | --- |
| `policy` | `id, tenant, purpose, rules, unit, pool, limit, per, maxDepth, survive` | One to eight exact action rules; each rule has `action, resource, audience, releaseTo, args`. The unit and pool define shared accounting. |
| `terms` | `id, rootId, parentGrantRef, origin, holder, keyId, gen, service, policyRef, depth, limit, per, epoch, nbf, exp` | Embedded object, no `v` or `kind`. Root has `parentGrantRef: null`; child names the signed parent. |
| `challenge` | `id, nonce, purpose, contextRef, actorKeyId, recipient, iat, exp` | Signed by a configured challenge issuer. Purposes are `root-approval`, `join`, `request-proof`, `response-proof`, `ledger-control`. |
| `approval` | `challengeRef, subject, termsRef, nbf, exp` | Signed by the configured human key over the exact root terms and challenge. |
| `join` | `challengeRef, holder, keyId, gen, termsRef, nbf, exp` | Candidate signs to prove possession for the exact terms and issued join challenge. |
| `parent-request` | `parentGrantRef, childTermsRef, joinRef, nbf, exp` | Immediate parent signs this specific child birth request. |
| `grant` | `terms, approvalRef, parentRequestRef, joinRef, appraisalRef` | Issuer-signed root or child. Root uses an approval reference and null parent request; child does the reverse. Referenced admission evidence must remain retrievable. |
| `appraisal` | `holder, keyId, gen, service, appraisalPolicy, measurement, nbf, exp` | Trusted appraiser's statement about this instance under configured appraisal policy. |
| `intent` | `rootId, tenant, purpose, audience, action, resource, args, inputHash, releaseTo, units` | Complete stable business action for this bounded vocabulary. `args` values are printable ASCII strings. |
| `attempt` | `op, record, intentRef, grantRef, policyRef, holder, keyId, gen, method, target, epoch, iat, exp` | A particular signed attempt. `op` persists across an unchanged retry; `record` is fresh per new attempt. |
| `proof-result` | `proofType, direction, contextRef, challengeRef, actorKeyId, policyRef, witnessCommitment, verdict, iat, exp` | A designated verifier's signed attestation. Here `proofType` is `designated-verifier-attestation`; `verdict` is `accepted`. It is not an independently verifiable native witness. |
| `proof` | `challenge, result` | Embedded object, no `v` or `kind`; both members are signed envelopes. A real provider must define the challenge and native response validation. |
| `request` | `attemptRef, proofRef` | Holder-signed statement. The attempt names the exact target, grant, intent, actor and policy. |
| `requestPacket` | `intent, input, attempt, proof, request, grantChain, policies, appraisal` | Embedded transport object, no `v` or `kind`. `input` is lowercase hex of exact input bytes. Policies correspond one-for-one with the root-to-leaf grant chain. |
| `permit` | `id, op, record, intentRef, requestRef, proofRef, grantRef, policyRef, holder, keyId, audience, units, epoch, fence, iat, exp` | State authority's short-lived reservation for one exact request and audience. |
| `outcome` | `op, permitRef, requestRef, intentRef, audience, row, resultHash, units, epoch, at` | Resource assertion about a unique durable operation row and the exact result bytes. |
| `closure` | `op, permitRef, requestRef, intentRef, audience, epoch, at` | Resource attests a terminal no-effect result. It must be mutually exclusive with an outcome for the same permit. |
| `response-context` | `op, record, requestRef, recipientKeyId, resourceKeyId, policyRef, status, contentType, resultHash, outcomeRef, iat, exp` | Binds the response's content, status, recipient, actual resource identity and original signed request. |
| `response` | `contextRef, proofRef` | Resource-signed statement over the context and response proof. |
| `responsePacket` | `context, result, proof, outcome, response` | Embedded transport object; `result` is lowercase hex of exact result bytes. |
| `ledger-control` | `action, requestRef, permitRef, presentationRef, caller, nonce, idempotencyKey, iat, exp` | Signed control action: `check`, `redeem`, `settle`, `close` or `inspect`. If a control proof is required, carry it separately and bind it to the control payload's context digest. |
| `ledger-decision` | `controlRef, requestRef, permitRef, caller, nonce, decision, sequence, epoch, fence, iat, exp` | State-signed decision bound to the caller's exact control request and fresh nonce. |
| `ledger-event` | `ledger, sequence, prev, event, actor, op, objectRef, at` | Signed event. `prev` is null at genesis and otherwise the previous signed event reference. |
| `checkpoint` | `ledger, sequence, head, stateHash, epoch, at` | Independently retained keeper signature over the log head and a specified complete state projection. |
| `revocation` | `rootId, epoch, fence, at` | State-signed advancement of a lineage fence. |
| `recovery` | `ledger, rootId, checkpointRef, nextEpoch, at` | Authorized recovery for the exact trusted checkpoint and next epoch. |

The `responsePacket` schema models a committed response and requires an outcome. A denial, hold, closure, status response, and general error envelope need separate versioned schemas before they can be exchanged under this profile. This is a deliberate limitation of the worked contract; do not fill an `outcome` with invented evidence for a failed request.

### Relationships beyond schema

- `terms.nbf < terms.exp`; parent interval contains child interval. A proof, challenge, permit and response have nonempty intervals and cannot authorize outside their own or their controlling authority's intervals. Current eligibility uses a clock uncertainty interval, not an unchecked local timestamp.
- Each grant's `terms.policyRef` equals its corresponding `H("policy", policy)`. Policies preserve tenant, purpose, pool and unit. Every child rule is an exact permitted parent rule; child's `limit`, `per`, `maxDepth`, `depth` and lifetime never expand; `survive` cannot change from false to true. These exact-match rules are a starting vocabulary, not a general policy language.
- A grant is issuer-signed, registered, uniquely identified and current. At use, the chain is root first, each `parentGrantRef` equals the preceding signed grant reference, root and epoch are consistent, key and holder bindings are valid, depth strictly decreases, and each ancestor is valid and not revoked.
- A challenge's `purpose`, `contextRef`, `actorKeyId`, `recipient` and interval match the pending ceremony or message. Its unpredictable nonce comes from a cryptographic random generator; its identifier and nonce are consumed atomically at the authoritative verifier. The fixed fixture nonces are deterministic test values.
- Every proof result is signed by a configured verifier for its proof type; it matches its signed challenge, context, actor, direction and policy. The verifier must actually perform its defined native checks before signing. A digest of a witness is not by itself a proof.
- The operation key in this guide is `(configured service, tenant, audience, op)`. Its first eligible reservation binds original root, holder, intent, resource and accounting meaning. A changed intent or actor under the same key is a conflict for an entitled caller. A transmission record is scoped to service, direction, actor key and generation.
- `units > 0`, `units <= per`, and settled plus outstanding reservations, including uncertain amounts, do not exceed the pool or inherited ceilings. State changes need a single transactional ordering point for that pool.

## 6. An end-to-end example at a glance

A human approves a root for the `month-close` purpose. Its policy permits reading `monthly-total` for project `p7`, permits a total of ten credits, and permits at most six credits per operation. The root delegates a narrower six-credit, depth-zero policy to `reader-1`. That reader requests operation `op-42`. The resource reserves six credits, redeems the permit, records one result row, and returns `{"total":42}` with a separately challenged response proof.

```text
Human -> approval -> admission issuer -> root grant
Root -> parent request + child join -> delegation issuer -> child grant
Reader -> intent + attempt -> request challenge -> request proof -> signed request
State authority -> permit -> resource verification -> redemption -> one resource row
Resource -> outcome + result -> response challenge -> response proof -> signed response
Client -> verify response and result -> use result
Auditor -> signed events + independently retained checkpoint -> qualified audit
```

The vectors present all objects in this order under named keys. Use only their public fixtures in tests:

```sh
node examples/build-vectors.mjs
```

The program writes `examples/synthetic-vectors.json` and checks its own 24 Ed25519 signatures and selected digest links, including modified signed context and changed response bytes. It does not run a native circuit, enforce a real policy, operate a service, persist a ledger, or exercise concurrent transactions. Re-running the generator deterministically overwrites only its own synthetic vector file.

## 7. Root admission and child minting

### Root policy and terms

The readable policy below corresponds to `rootPolicy` in the vector file. `policyRef = H("policy", rootPolicy)` is placed in the root terms.

```json
{
  "v": "http6-guide-01",
  "kind": "policy",
  "id": "policy-root",
  "tenant": "lab",
  "purpose": "month-close",
  "rules": [{
    "action": "report-read",
    "resource": "monthly-total",
    "audience": "reports-db",
    "releaseTo": "reader-1",
    "args": {"period": "2026-10", "project": "p7"}
  }],
  "unit": "credits",
  "pool": "pool-p7",
  "limit": 10,
  "per": 6,
  "maxDepth": 1,
  "survive": false
}
```

Before signing, the human presenter must render the actual policy and terms, including destination, action, recipient, input scope, limits, expiry and delegation right. This is a requirement on a real admission implementation, not something the fixture performs.

```typescript
async function admitRoot(proposal, trustedDisplay, admissionIssuer) {
  assertValidPolicy(proposal.policy);
  const terms = freeze(proposal.terms.withPolicyRef(H("policy", proposal.policy)));
  const approvalChallenge = await verifier.issueChallenge({
    purpose: "root-approval", contextRef: H("terms", terms),
    actorKeyId: proposal.humanKeyId, recipient: "admission"
  });
  const approval = await trustedDisplay.showAndApprove({terms, policy: proposal.policy,
    challenge: approvalChallenge});
  const joinChallenge = await verifier.issueChallenge({
    purpose: "join", contextRef: H("terms", terms),
    actorKeyId: terms.keyId, recipient: "admission"
  });
  const join = await candidate.proveKeyPossession(joinChallenge, terms);
  const appraisal = await appraiser.assess(candidate, terms.service);
  return admissionIssuer.transaction(async state => {
    verifyApprovalAndJoin(approval, join, approvalChallenge, joinChallenge, terms);
    verifyAppraisal(appraisal, terms, configuredTrust);
    state.consumeChallengesExactlyOnce([approvalChallenge, joinChallenge]);
    const root = signAsIssuer(grantForRoot(terms, approval, join, appraisal));
    state.registerGrantAndEvidence(root, proposal.policy, approval, join, appraisal);
    return root;
  });
}
```

Challenge creation, validation and consumption need a coordinated authoritative store. If the verifier and issuer are separate services, use a durable transactional protocol with explicit ownership and crash recovery, not two independent `consume` flags that can disagree.

### Child birth

The child independently signs a join over `H("terms", childTerms)`. The parent signs the parent request over the same child terms and the signed child join reference. The child policy's rules are a subset of the parent policy, with `limit: 6`, `per: 6`, `maxDepth: 0` and `survive: false` in the vectors.

```typescript
async function mintChild(parent, childTerms, childPolicy, birthId) {
  const current = await registry.currentLineage(parent);
  verifyLineage(current, {now: trustedClock.interval()});
  require(attenuates(childPolicy, current.effectivePolicy));
  require(childTerms.parentGrantRef === ref(parent));
  require(childTerms.policyRef === H("policy", childPolicy));
  require(childTerms.depth < parent.terms.depth);
  const join = await child.signJoin(await joinChallenge(childTerms), childTerms);
  const parentRequest = await parent.signBirth({childTermsRef: H("terms", childTerms),
    joinRef: ref(join)});
  return state.transaction(tx => {
    tx.requireCurrentParent(parent);
    tx.requireUnusedOrMatchingBirth(parent, birthId, H("terms", childTerms));
    verifyJoinAndParentRequest(join, parentRequest, childTerms, parent);
    const childGrant = signAsDelegationIssuer(grantForChild(childTerms, join,
      parentRequest, currentChildAppraisal()));
    tx.registerBirthAndEvidence(birthId, childGrant, childPolicy, join, parentRequest);
    return childGrant;
  });
}
```

A birth identifier and birth registry are proposed service state, not fields in the guide profile's `grant` schema. A real minting service must specify its authenticated admission API and atomic idempotency record. A duplicate birth with identical authorized terms can return its original outcome; changed terms conflict. A process restart requires an authorized new generation and appraisal rather than silently reusing a retired key.

## 8. Prepare, prove and sign a request

### Construct the exact intent

The fixture's input is the empty byte string, whose SHA-256 is `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`. The fixture intent is:

```json
{
  "v": "http6-guide-01",
  "kind": "intent",
  "rootId": "root-1",
  "tenant": "lab",
  "purpose": "month-close",
  "audience": "reports-db",
  "action": "report-read",
  "resource": "monthly-total",
  "args": {"period": "2026-10", "project": "p7"},
  "inputHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "releaseTo": "reader-1",
  "units": 6
}
```

A real adapter must bind every effect-changing input. For a database query this includes the registered query, complete typed arguments and recipient; for a wallet it includes network, amount and beneficiary. A vocabulary that cannot represent one of these must reject the action or use a new profile. Model text or an LLM tool suggestion is not authority to enlarge the rule.

### Challenge and prove

The holder freezes an `attempt` containing the intent reference, leaf grant, policy, identity and generation, `POST`, the exact target URI, epoch, operation and fresh record IDs. The verifier issues a fresh signed `request-proof` challenge over `H("attempt", attempt)`. The holder and circuit respond under a real, separately specified native proof contract. The registered designated verifier validates the native response and emits a signed `proof-result` containing the same challenge, actor, context, direction and policy.

```typescript
async function proveRequest(frozenIntent, actualInput, leaf, target) {
  require(rawHash(actualInput) === frozenIntent.inputHash);
  const attempt = freeze(makeAttempt({
    op: stableOperationId(), record: freshRecordId(),
    intentRef: H("intent", frozenIntent), grantRef: ref(leaf.grant),
    policyRef: H("policy", leaf.policy), holder: leaf.holder,
    keyId: leaf.keyId, gen: leaf.gen, method: "POST", target,
    epoch: leaf.epoch, iat: clock.now(), exp: boundedDeadline()
  }));
  const challenge = await trustedVerifier.issue({purpose: "request-proof",
    contextRef: H("attempt", attempt), actorKeyId: leaf.keyId, recipient: "resource"});
  verifyChallenge(challenge, attempt, configuredTrust);
  const nativeResponse = await protectedCircuit.answer(challenge, attempt);
  const result = await trustedVerifier.validateAndConsume(challenge, nativeResponse);
  verifyProofResult(result, challenge, attempt, "request", configuredTrust);
  const proof = freeze({challenge, result});
  const request = await leaf.sign({v: "http6-guide-01", kind: "request",
    attemptRef: H("attempt", attempt), proofRef: H("proof", proof)});
  return freeze({intent: frozenIntent, input: hex(actualInput), attempt, proof, request,
    grantChain: leaf.chain, policies: leaf.policies, appraisal: leaf.appraisal});
}
```

The placeholder `nativeResponse` is private provider-specific material. The example's `witnessCommitment` is a public synthetic digest and is not a native proof. Production proof documentation must identify the native statement and witness, who verifies what, privacy assumptions, soundness and replay guarantees, and public evidence that can safely be disclosed. The SDK must not call an attestation publicly verifiable proof of knowledge unless a suitable independent verifier and security definition exist.

### HTTP carrier

The guide profile proposes `POST` over authenticated TLS to the exact `attempt.target`. The body is the canonical UTF-8 `requestPacket`. The holder-signed request binds the attempt and proof, which bind the actual method, target, intent and input digest. The resource recomputes `H("request-packet", requestPacket)` for ledger callbacks. A reservation request carries this packet to the state authority through an authenticated control interface, and the resource receives the state-signed permit with the packet. The present draft does not define a finalized wire container or HTTP header for the permit; implementations must agree one before interoperation. HTTPS protects transport, while the profile signatures and resource checks authorize the operation.

The existing W1 HTTP binding and WASIX `HTTP6-Proof`, `HTTP6-Policy`, `HTTP6-Certificate` fields are different. Do not add these guide fields to a W1 packet or claim the guide packet is a W1 signed HTTP message.

## 9. Reservation, live checking and enforcement

```typescript
function reserve(packet, state) {
  strictParseSchemaAndCanonicalBytes(packet);
  const {intent, attempt, proof, request, grantChain, policies, appraisal} = packet;
  verifyChainAndAppraisal(grantChain, policies, appraisal, configuredTrust);
  require(rawHash(unhex(packet.input)) === intent.inputHash);
  require(attempt.intentRef === H("intent", intent));
  require(attempt.grantRef === ref(last(grantChain)));
  require(attempt.policyRef === H("policy", last(policies)));
  verifyProof(proof, H("attempt", attempt), "request", attempt.keyId);
  verifySignedRoleAndKind(request, attempt.keyId, "request");
  require(request.payload.attemptRef === H("attempt", attempt));
  require(request.payload.proofRef === H("proof", proof));
  require(matchesEveryInheritedPolicy(intent, policies));
  return state.serializableTransaction(tx => {
    tx.requireCurrentLineageEpochAndFence(grantChain, attempt.epoch);
    tx.consumeFreshRecord(attempt.keyId, attempt.gen, attempt.record);
    const old = tx.findOperation(service, intent.tenant, intent.audience, attempt.op);
    if (old) return tx.reconcileOrConflict(old, intent, attempt.holder);
    tx.requirePoolAndAncestorAvailability(intent.units, policies);
    const permit = tx.reserveAndSignPermit(packet, boundedExpiry(attempt));
    return permit;
  });
}
```

An implementation must validate signatures, freshness, appraisal, record and policy before letting an unauthenticated request consume a record position or reservation. Concurrency requires one ordering point per shared allowance. For example, two concurrent six-credit requests on ten remaining credits produce at most one six-credit reservation, regardless of which worker wins.

### Resource boundary

The resource verifies the packet and permit independently using its own trust configuration. It validates the actual request method and target, exact input and all action arguments, then checks its **current** policy. A live state check alone does not consume the permit. The designated custodian signs a `ledger-control` redemption with fresh nonce and stable idempotency key; the state authority returns a signed `ledger-decision` binding the control reference, caller, nonce, permit, epoch, fence and deadline.

```typescript
async function executeAtResource(packet, permit, actualRoute) {
  verifyPacketAndPermit(packet, permit, actualRoute, resourceTrust);
  require(await resourcePolicy.permits(packet.intent));
  const redemption = await ledger.redeem(await custodian.signControl({
    action: "redeem", requestRef: ref(packet.request), permitRef: ref(permit),
    presentationRef: H("request-packet", packet), caller: "reports-db",
    nonce: random256(), idempotencyKey: stableRedemptionId(),
    iat: clock.now(), exp: boundedDeadline()
  }));
  verifyStateDecision(redemption, "redeemed", permit, packet);
  return resource.transaction(async tx => {
    await tx.recheckPolicyFenceAndDeadline(packet, permit, redemption);
    const existing = await tx.findOperation(operationKey(packet));
    if (existing) return existing.requireMatchingIntent(packet.intent);
    const result = await tx.performAllowedOperation(packet.intent, unhex(packet.input));
    return tx.insertUniqueObservation(operationKey(packet), result, permit);
  });
}
```

The same transaction must protect the effect and unique journal row where possible. If the downstream sink supplies only idempotency and authoritative lookup, bind and persist its idempotency key and reconcile with it. A network or process effect without those guarantees may remain uncertain. Issuance of a permit and redemption of it are not proof of resource commitment.

Control calls can have their own fresh native proof when the deployment requires it. The control context is `H("ledger-control", ledgerControlPayload)`, and its proof challenge uses purpose `ledger-control`, direction `control`, and the custodian's authorized policy. The ledger checks it locally against configured control authority. This draft still needs a closed control-packet schema and proof transport; the synthetic control example includes a signature and signed decision, not a native control proof.

## 10. Produce the outcome and settle

After the resource commits, it signs an `outcome` over the operation, exact permit and request references, intent, resource audience, journal row, units, epoch, commit time and SHA-256 of result bytes. Its signing key must be configured for that resource. Persist the actual journal with the effect.

```typescript
const observation = await executeAtResource(packet, permit, actualRoute);
const outcome = await resourceSigner.sign({
  v: "http6-guide-01", kind: "outcome", op: packet.attempt.op,
  permitRef: ref(permit), requestRef: ref(packet.request),
  intentRef: H("intent", packet.intent), audience: packet.intent.audience,
  row: observation.rowId, resultHash: rawHash(observation.resultBytes),
  units: packet.intent.units, epoch: permit.payload.epoch, at: observation.commitTime
});
await ledger.settleOnce({permit, outcome, resourceJournalRef: observation.rowId});
```

Settlement verifies the resource's signature and all bindings, then converts the corresponding reservation to spent once. If delivery fails after commit, the state remains reserved or uncertain until the outcome is reconciled. A no-effect closure may release funds only after the resource has durably excluded both an earlier effect and any later commitment for that permit. The schema's `closure` is an assertion; the mutual exclusion must be enforced transactionally.

## 11. Construct and verify a response proof

A separately authenticated response protects the recipient against a substituted result, status, outcome or request association. The guide profile requires a distinct verifier challenge and a separate resource proof attestation for its committed response.

### Noncircular construction

1. Freeze the exact application result bytes and durable signed outcome. Compute `resultHash = rawHash(resultBytes)`.
2. Create `response-context`, including the original **signed request reference**, operation, recipient key, resource key, status, policy, result hash, signed outcome reference, fresh record and deadline.
3. Obtain and authenticate a `response-proof` challenge whose `contextRef` is `H("response-context", context)`, and whose actor is the resource key. The resource's circuit answers the challenge under its own configured credentials. The verifier validates the response and consumes the challenge.
4. Set `proof = {challenge, result}` and have the resource sign a `response` payload containing `contextRef` and `H("proof", proof)`.
5. Transmit the `responsePacket`: context, exact result bytes encoded as hex, proof, signed outcome and signed response. Its archival packet digest can be computed after assembly. It is not included in the context that the proof signs.

```typescript
async function makeResponse(packet, permit, observation, outcome) {
  const context = freeze({v: "http6-guide-01", kind: "response-context",
    op: packet.attempt.op, record: freshResponseRecord(), requestRef: ref(packet.request),
    recipientKeyId: packet.attempt.keyId, resourceKeyId: resourceSigner.keyId(),
    policyRef: packet.attempt.policyRef, status: 200, contentType: "application/json",
    resultHash: rawHash(observation.resultBytes), outcomeRef: ref(outcome),
    iat: clock.now(), exp: responseDeadline()});
  const challenge = await verifier.issue({purpose: "response-proof",
    contextRef: H("response-context", context), actorKeyId: context.resourceKeyId,
    recipient: "client"});
  const nativeResponse = await resourceCircuit.answer(challenge, context);
  const result = await verifier.validateAndConsume(challenge, nativeResponse);
  const proof = {challenge, result};
  const response = await resourceSigner.sign({v: "http6-guide-01", kind: "response",
    contextRef: H("response-context", context), proofRef: H("proof", proof)});
  return {context, result: hex(observation.resultBytes), proof, outcome, response};
}
```

A response proof can fail or be unavailable after a real effect has committed. The caller must retain an uncertain delivery state and use separately authorized inquiry; failure to deliver or verify the response does not undo the effect or authorize another one.

### Receiver checklist

1. Authenticate the TLS endpoint and reject malformed, noncanonical, oversized or unexpected packet types. Independently identify the resource and the pending operation.
2. Verify the resource's response signature, configured role and its `contextRef` and `proofRef`. Check `status`, content type, current response interval and actual recipient key.
3. Recompute the exact result-byte hash. Compare operation, policy, original request reference, target context and intended recipient to the retained verified request. A response for a different attempt is not interchangeable even if the operation is the same.
4. Verify the signed response challenge and designated verifier result, including challenge freshness and one-use handling, response direction, resource actor, context, policy and verifier's authorized role. The verifier's attestation is trusted only under the client's configured proof policy.
5. Verify the resource-signed outcome and its request, permit, intent, audience, result digest, units, epoch and row. Match the outcome to trusted resource evidence as required by the application. Independently evaluate evidence freshness and disclosure authorization.
6. Return `Committed` and release the result only if all required checks succeed. Report a verified signature, verified proof attestation and resource-observation status as separate fields in the result.

If the request was sent before revocation but the response arrives later, verify what occurred at the actual commit time and separately authorize disclosure to the reader. A later acknowledgment timestamp is not the commit time.

## 12. Ledger inspection and evidence

The ledger is an authority and evidence service, not a promise that every external effect happened. An inspector starts with a configured ledger key and keeper key, a scoped query permission, and an independently obtained trusted checkpoint. For the fixture, the logical sequence is:

```text
sequence 1: redeemed -> signed ledger decision reference
sequence 2: committed -> signed resource outcome reference, prev = ref(sequence 1)
checkpoint: sequence 2, head = ref(sequence 2), stateHash = H("state", projection)
```

The fixture projection contains `epoch`, `fence`, `rootId`, `spent`, `reserved`, and `revoked`. It is only an illustrative projection. A production checkpoint projection must also cover every piece of security state needed to reconstruct consumed challenges and record IDs, registered grants and instance generations, reservations, settlements, closures, revocations, resource outcomes and state transitions. All parties must agree on its schema, ordering and digest rules before relying on it for recovery.

```typescript
function inspect(bundle, trustedCheckpoint, trust) {
  verifySignedRoleAndKind(trustedCheckpoint, trust.keeperKeys, "checkpoint");
  require(bundle.ledger === trustedCheckpoint.payload.ledger);
  let previous = bundle.trustedStartRef; let sequence = bundle.trustedStartSequence;
  for (const event of bundle.events) {
    verifySignedRoleAndKind(event, trust.stateKeys, "ledger-event");
    require(event.payload.sequence === sequence + 1 && event.payload.prev === previous);
    verifyReferencedObjectWhenAvailable(event.payload.objectRef, bundle.objects, trust);
    previous = ref(event); sequence++;
  }
  require(sequence === trustedCheckpoint.payload.sequence);
  require(previous === trustedCheckpoint.payload.head);
  require(H("state", bundle.reconstructedState) === trustedCheckpoint.payload.stateHash);
  return reportSeparateFindings(bundle, {verifiedHistory: true,
    independentCheckpoint: true, observedResourceEffect: bundle.resourceEvidenceStatus});
}
```

A valid checkpoint signature proves the keeper signed that checkpoint. It does not prove it is the keeper's latest. The inspector must obtain a freshness assertion or latest sequence from the independent keeper through an authenticated channel and compare it with its own previously retained state. A chain or inclusion proof alone cannot prove an omitted later event does not exist. An evidence bundle needs an authenticated, stable snapshot boundary and an explicit completeness mechanism. Pagination must remain anchored to the same snapshot.

Restrict ledger inspection by tenant, purpose, role, query range and disclosure policy. A public object store may expose designated nonsecret objects, but raw prompts, inputs, private enrollment evidence, secrets, full database results and low-entropy data are not automatically safe to publish. Separate historical verification at a recorded time from the question of whether a grant is valid now.

## 13. Revocation, uncertainty and recovery

### Revocation

The state authority orders a `revocation` and advances the root's minimum fence. Once ordered, it refuses new permits under the revoked lineage. A resource that has observed the higher fence rejects an older permit. During a partition, whether an already issued permit can commit depends on the chosen profile, its unexpired deadline, local policy, actual clock uncertainty and the most recent observed fence. Use very short permits where this residual window is unacceptable. The guide profile still needs a complete distributed revocation and fence-propagation contract.

### Retry and status

A timeout does not demonstrate a failed effect. Keep the original operation ID and intent. An authorized lookup must use current lookup rights, fresh request authentication and disclosure policy. It may return the original outcome, a terminal closure, or `Uncertain`; it cannot start a second effect. Exact replay of a consumed transmission is rejected, while a new eligible attempt uses a fresh record and the original operation identity. For previously redeemed but indeterminate calls, do not release reserved units or issue a conflicting permit without terminal evidence.

The guide schema currently lacks a committed status and denial wire format. A production profile must define those bodies, signatures, read authorization, and non-disclosing responses before offering status interoperability. The W1 profile already defines its own status and response semantics.

### Recovery

1. Put new effects and issuance on hold.
2. Authenticate the latest independently retained keeper checkpoint and compare it to any previously accepted head.
3. Reconcile authority state, consumed identifiers, pending reservations, spent balances, revocations, generation registrations and resource journals to that checkpoint. Missing evidence or an unverifiable suffix keeps the hold.
4. Verify the recovery authority's signed `recovery`, exact `checkpointRef`, root and `nextEpoch`; the next epoch is the checkpoint epoch plus one.
5. Atomically retire old runtime bindings and prior-epoch issuance, preserve spent and revoked authority and unresolved operations, then activate the new epoch. Old permits and old descendants cannot regain authority merely because a backup was restored.

The fixture checkpoint and event chain are static signed examples. They do not demonstrate durable storage, independent retention, rollback safety or recovery.

## 14. API contract proposal

These API calls are design targets, not currently implemented routes. Each state-changing call authenticates the caller and enforces its role. In the table, `signed<T>` is the signed envelope described in section 4. Transport errors and generic unauthenticated errors must be distinguishable from authenticated decisions.

| Operation | Request | Successful result | Primary checks |
| --- | --- | --- | --- |
| `origins.prepareRoot` | root terms, policy, candidate metadata | challenge and display material | configured origin, supported profile, intended destination |
| `origins.admit` | policy, terms, signed approval, signed join, challenges, signed appraisal | signed root grant and durable registration receipt | exact hashes, trusted human and candidate, one-use challenge, appraisal |
| `grants.mintChild` | parent chain, child policy/terms, signed parent request, child join, appraisal, birth ID | signed child grant and registration receipt | current parent, distinct child key, narrowing, birth idempotency |
| `proofs.challenge` | purpose, context digest, actor, intended verifier/recipient | signed challenge | authorized issuance and fresh random nonce |
| `proofs.verify` | signed challenge, private native response, public context | signed proof result | exact native verifier policy, replay, context and expiry |
| `operations.reserve` | complete signed request packet | signed permit or authenticated denial/hold | chain, proof, actual intent, budget, uniqueness, epoch and fence |
| `ledger.check` | signed control and presentation evidence | signed decision with caller nonce | current state; no consumption |
| `ledger.redeem` | signed control and presentation evidence | signed winning redemption or nondisclosing refusal | designated custodian, same packet and permit, one winner |
| `resource.execute` | request packet and permit through agreed transport | committed response packet | independent policy, proof, actual route and atomic effect |
| `operations.settle` | signed outcome or terminal closure | authenticated settlement decision | correct resource issuer, matching scope, exclusive terminal state |
| `operations.status` | fresh signed authorized inquiry | matching original outcome, terminal closure or uncertain state | separate lookup authority and non-disclosure rules |
| `ledger.inspect` | signed scoped query and snapshot cursor | events, referenced objects and checkpoint evidence | query authorization, stable snapshot, pagination, privacy |
| `authority.revoke` | authorized root and current epoch | signed higher fence | authorized operator and ordered state transition |
| `recovery.activate` | recovery authorization, latest checkpoint and reconciled state | signed activation receipt | independent latest checkpoint, complete reconciliation, next epoch |

Control packet transport, issuance registration receipts, discovery, status responses, authenticated pagination and native proof material still need their own closed schemas. The table identifies these contracts for implementers; it does not silently supply the missing wire definitions.

## 15. Error, replay and retry behavior

| Condition | Result to expose | Effect and state rule |
| --- | --- | --- |
| Malformed JSON, duplicate field, invalid signature, untrusted key or unknown profile | `Invalid` or generic unauthenticated error | No effect and no authenticated claim about the caller. |
| Valid identity but action or disclosure outside inherited or resource policy | `Denied` | No protected disclosure or effect. Do not reveal an unrelated operation's existence. |
| Reused consumed record or challenge | `Replay` | No new reservation or effect. |
| Same operation ID with changed intent or actor | `Conflict` to an otherwise entitled caller | Preserve original operation; unrelated callers get nondisclosing denial. |
| Shared budget unavailable | `Budget` | No reservation; avoid leaking other participants' data. |
| Required trusted state, proof verifier or clock confidence unavailable | `Held` | No new effect requiring fresh authority. |
| Permit redeemed or reply lost and effect cannot be determined | `Uncertain` | Keep reservation and reconcile. Do not automatically issue a new effect. |
| Matching durable signed outcome | `Committed` or `Reconciled` | Settle once; verify response proof if the selected policy requires one. |
| Matching terminal no-effect closure | `Closed` | Release once only after future effect is excluded. |

These are proposed SDK categories. W1 has its own exact response status and code table. Treat an HTTP error, state response, transport timeout and client-side verification error as different things.

## 16. Test the implementation

The included vector generator is useful for reproducing bytes and basic link checks. A complete implementation needs independent tests at each boundary.

| Category | Required evidence |
| --- | --- |
| Codec and schema | Valid and malformed packets, duplicate JSON names, noncanonical bytes, unknown fields, invalid integer and size bounds, unsupported algorithms and wrong signer role. At least two independent encoders reproduce identical canonical bytes, references and signatures. |
| Admission and minting | Changed displayed terms, wrong human, mismatched join, reused challenge, retired parent, changed child key, wider rule, increased budget/depth/lifetime and unauthorized survival all fail before activation. |
| Request proof and payload | Changed request, actual target, input bytes, args, recipient, policy, actor, generation, challenge or proof result fails. A simulated attestation is never accepted as a native production proof. |
| Response proof | Changed result byte, HTTP status, recipient, original request, outcome, signer, challenge or context fails. Wrong direction, expired or replayed response proof fails. |
| Enforcement | Direct, queued, background and privileged resource paths are tested at the actual effect and disclosure sinks. A signed check alone cannot count as a protected effect. |
| Concurrency and retry | Two six-unit requests against ten available cannot both win. Duplicate redemption and settlement are idempotent. Lost reply returns original outcome to an authorized reader and preserves uncertainty otherwise. |
| Revocation and recovery | Test boundaries around permit expiry, clock uncertainty, fence propagation and partition. Restore an older snapshot against a newer independent checkpoint; no spent or revoked authority reappears. |
| Ledger and privacy | Verify signatures, sequence, links, snapshots and trusted latest checkpoint; detect omitted or altered evidence. Inspect public outputs for secrets and sensitive data. |
| Independent exchange | Two separately administered implementations exchange both request and response in both directions, record builds, origins, clocks, actual resource journals and independent results. |

Run the W1 public corpus as W1, the WASIX pilot's own suite as WASIX, and a separate conformance suite for the guide profile. Passing one does not establish conformance to another.

## 17. Mapping back to existing HTTP6 work

| Requirement | Existing source | Guide profile contribution |
| --- | --- | --- |
| Human approval and hereditary authority | [Authority continuity draft](01-ietf/draft-rosario-http6-authority-continuity-00.md) and [W1 draft](01-ietf/draft-rosario-http6-w1-profile-00.md) | Concrete proposed SDK objects, schemas and minting sequence. |
| Request and response association | W1 signs HTTP request and response components and binds `requestRef` to its request `Signature` field value. | A different signed JSON envelope and separate response proof context. Never substitute digest definitions between profiles. |
| Circuit-bound request and ledger check | [WASIX developer specification](HTTP6-WASIX-Delegation-Developer-Spec.md) and [local operating guide](wasix-delegation/README.md) | An illustrative general model for challenge, proof result, request, permit and response. The pilot's actual header and callback rules stay authoritative for the pilot. |
| Fresh native response proof | [Per-message proof review](02-nist-markdown/HTTP6_Per_Message_Proof_NIST_Review_White_Paper.md) describes a separate local demonstrator for request and response proofs. | The local WASIX 01 pilot adds a distinct native response proof; the guide profile remains a separate proposed attestation envelope. |
| Ledger and recovery | Authority continuity draft and WASIX plan distinguish local behavior from full deployment work. | Inspection pseudocode, explicit evidence semantics and recovery requirements. |

For exact W1 schemas, use the W1 draft's companion `schema.json` and vectors at `../IETF/http6/w1-public-vectors-00/`; that external folder must be included separately in any standalone distribution. For the WASIX hash function and signed objects, use its current implementation and specification rather than the guide profile's helpers.

## 18. Reproducing the synthetic example

From the workspace root:

```sh
node examples/build-vectors.mjs
python3 -m json.tool static/artifacts/schema.json > /dev/null
python3 -m json.tool static/artifacts/synthetic-vectors.json > /dev/null
```

The JSON Schema can also be checked using a draft 2020-12 validator. To validate a particular object independently, use a schema whose root is `{"$ref":"#/$defs/requestPacket", "$defs": ...}` or the corresponding definition. Then perform all signature, canonical-byte, policy and state checks separately. The vector fixture timestamps, nonces, signing seeds and keys are deliberately public and fixed.

The generator serializes the full synthetic exchange as readable JSON and records exact digest values in its `digests` object. It reconstructs canonical bytes internally. This validates only its own deterministic construction; it is not an independent implementation or a production conformance report.

## 19. Decisions and work required before production

This guide supplies a complete conceptual lifecycle and a concrete worked profile subset. It does not yet supply a production-ready protocol for every possible HTTP6 operation. The following are explicit remaining dependencies:

- Publish a reviewed native circuit interface and security model for each proof type, including challenge issuance, private state, witness reuse, active attacks, publicly verifiable versus designated-verifier claims, and evidence privacy.
- Freeze closed schemas and authenticated transport for admission calls, permits in transit, control proofs, denial and hold responses, authorized status lookup, issuance receipts, inspection queries, pagination, latest-checkpoint assertions and full recovery state.
- Specify authenticated profile negotiation, URI and proxy handling, HTTP field and body binding if RFC 9421 is adopted, key provisioning and rotation, runtime appraisal, human display and platform key custody.
- Define the complete transactional state model for distributed grants, shared budgets, multi-ledger allocation, redemption, downstream commitment, revocation propagation and cross-domain recovery. Specify time uncertainty and all failure boundaries.
- Define additional action vocabularies, nonempty and large payload transport, streaming/chunking, result disclosure, audit completeness and privacy-preserving evidence retention.
- Production assurance milestones include independent code and cryptographic reviews, interoperability vectors from separate implementations, real resource-path tests, and separately administered deployment evidence.

A deployment should publish its selected profile, exact versions, supported actions and proof method, trust assumptions, enforcement coverage, recovery policy, and the evidence it can actually provide.

## 20. Navigator, example clients and circuit licensing

The [read-only Swagger API navigator](https://www.http6.org/developers/sdk/api-reference/) renders the proposed `http6-guide-01` control API with request, response and error schemas for the listed operations. Its invalid example server and disabled request controls keep the navigator read-only. The [message and ledger schema](https://www.http6.org/developers/sdk/artifacts/schema.json) defines the guide profile's objects.

The [five-language and cross-runtime guide](https://www.http6.org/developers/sdk/multilanguage-demo/) describes Node.js, Python, Rust, Go and C# examples against the separate local WASIX 02 pilot. The Node example uses the SDK; the other examples demonstrate socket transport. A Python WASIX guest synthesizes request bytes that are forwarded to the Rust WASIX circuit and ledger by the local host. Verification checks the recorded proof and matching bytes within the local pilot. The [pilot ledger schema](https://www.http6.org/developers/sdk/artifacts/wasix-ledger-02.schema.json) defines event data for all 19 current event kinds. Separate [basic SDKs](https://www.http6.org/developers/sdk/multilanguage-sdks/) for Python, Rust, Go and C# verify response evidence and the returned signed ledger chain using an independently supplied pilot verifier.

ENI6MA circuits are patent pending and protected by copyright. Commercial deployments require a license available only through ENI6MA and Rosario Cybernetics. For production or extended implementations and inquiries about the proposed information-theoretic properties of HTTP6 with embedded ENI6MA circuits, contact President Frank Rosario through [Rosario Cybernetics](https://www.rosariocyber.com/contact) to discuss license options. This guide and its examples do not grant a circuit license.

Nonprofit organizations and private entities may contact Rosario Cybernetics directly to request permission. Commercial use is strictly prohibited without a paid commercial license. The [compiled circuit notice](https://github.com/HTTP6-ORG/http6-sdk/blob/main/circuits/NOTICE.md) describes enforcement and applicable legal limits.
