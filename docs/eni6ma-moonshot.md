# The ENI6MA mission: replace cryptography’s computational foundations

ENI6MA’s moonshot is to replace cryptographic primitives whose security depends on computational assumptions with the ENI6MA and Rosario-Wang information-theoretic proof architecture. If a primitive depends on a computational problem remaining infeasible, it belongs on the replacement path. The intended destination is a different foundation for identity, communication, authorization, and control across the digital world. HTTP6 is an early network application of that mission.

This is a world-scale objective. Its completion would change the mathematical basis on which people, institutions, devices, and software establish identity, protect communications, authorize consequential actions, and keep control as systems become more autonomous. The program intends to replace the computational assumptions beneath cryptographic security, primitive by primitive, and to carry the replacement into the systems that use them. HTTP6 begins with human authority over AI agents and web operations; the mission extends across cybersecurity and the industries that depend on it.

The destination is categorical. The work proceeds through explicit proof statements, working implementations, academic review, cybersecurity evaluation, and developer adoption. The current HTTP6 W1 profile is an initial application: it uses Ed25519 signatures over HTTPS and therefore retains computational assumptions. It demonstrates operation-bound authority in an existing web stack. The completed information-theoretic replacement architecture remains the program’s longer-range objective.

## Connect a person’s decision to an agent’s action

An autonomous agent can read files, call APIs, update records, send messages, deploy software, and move money. A prompt, model output, or tool response can influence the next action, but none of those objects establishes that a person authorized the action. A process that also holds a reusable bearer token or broad API key can act with the authority attached to that credential, even when the particular operation exceeds the human’s intent.

ENI6MA begins its application work by asking how an operation can retain an accountable human origin while passing through a machine process. The system must be able to identify the person or organization that granted authority, distinguish the running agent from that authority source, and decide whether the exact destination, resource, operation, data, and limits remain within the grant. Authority should narrow as work is delegated, expire or be revoked under defined rules, and remain inspectable after execution.

Human-bound identity refers to the authority chain used by participating services. It does not require that a person’s identity be broadcast to every observer. A service can verify the relevant identity and disclose only the attributes required by the task and policy. This distinction allows accountability for protected operations to coexist with privacy for people using the system.

The same design question appears when an agent follows hostile instructions, misreads a task, or produces an unintended tool call. The model can propose an operation; the resource that owns the data or effect must evaluate the operation against the human-origin grant and its current policy before acting. The goal is to bind cryptographic evidence to that decision and preserve a record that an authorized reviewer can examine.

## A new program meets several distinct traditions

The modern cryptographic literature contains work on different technical problems. [Whitfield Diffie and Martin Hellman’s 1976 paper](https://www.itsoc.org/publications/papers/new-directions-in-cryptography) developed public-key methods for establishing secret communication. [Rivest, Shamir, and Adleman’s 1978 paper](https://people.csail.mit.edu/rivest/pubs/RSA78.pdf) presented a public-key cryptosystem with applications to encryption and digital signatures. [Satoshi Nakamoto’s paper on peer-to-peer electronic cash](https://bitcoin.org/bitcoin.pdf) addressed electronic payments and double spending through a distributed record and proof of work. [Shafi Goldwasser, Silvio Micali, and Charles Rackoff’s work on interactive proof systems](https://doi.org/10.1145/22145.22178) developed the concept of zero knowledge, in which a proof can establish a statement while limiting what the verifier learns.

These contributions have different purposes and assumptions. Key agreement, public-key encryption, signatures, distributed cash, and zero-knowledge proofs establish different capabilities under different models. An application that composes them still has to specify how a particular human’s intention becomes bounded permission at every resource an agent can reach. A complete system connects identity, proof, policy, execution, and the consequences recorded by the service.

The ENI6MA thesis sets a more fundamental destination: replace the security primitives whose guarantees depend on computational hardness with an information-theoretic proof architecture. The program recognizes the distinct achievements of earlier cryptography while rejecting computational infeasibility as the final basis for digital security. It asks how geometry, explicit observer models, and proof can establish security properties without requiring an adversary to lack enough time, hardware, or algorithmic insight. That foundation must then connect a cryptographic proof to the responsible human, the approved purpose, the service policy, and the actual resource effect.

## Begin with geometry and the information an observer receives

Conventional cryptographic designs commonly define a problem that an attacker is assumed to be unable to solve within a specified computational budget. ENI6MA’s stated starting point is different. Its research begins with the geometric relationships among public partitions, secret membership choices, a private response dictionary, fresh masking, and the observer’s view, then studies the probability distribution those released responses induce over the hidden credential.

For the current per-message privacy model, the construction uses fresh independent private randomness to mask responses. Under the defined passive-observer model and its stated assumptions, the released transcript preserves the observer’s prior probabilities over the credential. The privacy claim therefore concerns what the modeled observation reveals, rather than how many operations an observer can afford. The [information-theoretic tradition associated with Claude Shannon’s work on secrecy systems](https://doi.org/10.1002/j.1538-7305.1949.tb00928.x) provides the language for expressing such claims precisely.

This is a model-specific privacy result, and its scope matters. Credential privacy does not, by itself, authenticate a person, authorize a database write, protect a network channel, stop a compromised runtime, or establish that a ledger contains the newest state. Those are separate system properties with their own models and evidence. The wider objective is to build a coherent architecture in which human authentication, private proofs, request authorization, communications, enforcement, and recovery are designed together and each claimed property can be reviewed on its own terms.

The far horizon is the replacement of computational-assumption-based cryptography with security primitives whose guarantees are stated and proved in information-theoretic terms, including perfect secrecy for specified messages and observers where the construction supports it. The work will establish a corresponding proof and deployment path for each primitive class, then subject it to mathematical scrutiny, independent implementation, cybersecurity evaluation, and adoption. The ambition is to change the foundation on which the digital world secures identity, communications, institutions, and machine action. HTTP6 is one network track in that larger transformation.

## HTTP6 carries authority to the resource

HTTP6 applies the human-authority problem to web operations. Its proposed request model connects an issuer’s grant to a particular worker, recipient, operation, payload, limits, and one-use identifier. The service checks that authority against current policy and state at the point where it can disclose data or cause an effect, then records the outcome for later inspection. In this way, the protocol addresses one critical seam in the larger program: how an agent’s network request is tied to an identifiable source of permission.

The first profile, W1, uses Ed25519-signed requests over HTTPS. It gives developers a way to test request-bound authority using existing web infrastructure, while retaining computationally based signatures and TLS. The proposed native HTTP6 channel is a later research and implementation stage addressing confidentiality, peer authentication, integrity, key changes, replay, downgrade, and recovery. HTTP6’s long-term role is to replace HTTPS transport and reusable bearer JWT authorization on fully migrated routes, as one concrete part of ENI6MA’s wider replacement of computationally based security primitives.

HTTP6 is one implementation track within ENI6MA. Its API, proof formats, and ledger describe the network exchange and operation authority. They do not define every form of human authentication, every communications technology, or every industry-specific resource. The wider program will require additional implementations, each with a protected object, an explicit verification procedure, and evidence that can be independently examined.

## Mathematical review and developer adoption

A change in cryptographic foundations requires a public, demanding route from mathematical claim to deployed system. Academic researchers need definitions, assumptions, derivations, and examples they can inspect and reproduce. Developers need stable schemas, readable APIs, test vectors, reference implementations, and ways to compare independent implementations. Cybersecurity practitioners need to examine threat models, identity and key custody, resource enforcement, operations, recovery, and compatibility with existing systems. The mission depends on all three communities, because a proof that cannot be independently examined or implemented cannot replace the primitives used across the world.

These forms of review answer different questions. A mathematical argument establishes a property under its hypotheses. An implementation test reports the behavior of identified code in an identified environment. A security assessment examines whether a deployment and its operating practices satisfy the model. Developer adoption shows whether the interfaces can support real integration and interoperability. The project will need evidence at each level before a broader application can rely on the result.

HTTP6’s current proposal materials invite review through the IETF and NIST discussion tracks, public SDK source, examples, and the project’s feedback channels. The purpose is to make the technical work open to correction and implementation experience as the program expands beyond the first protocol track.

- [Read the ENI6MA mission on HTTP6.org](https://www.http6.org/moonshot/)
- [Explore Rosario-Wang research](https://www.http6.org/research/rosario-wang/)
- [Review the HTTP6 protocol roadmap](https://www.http6.org/roadmap/)
- [Review IETF proposal material](https://www.http6.org/standards/ietf/)
- [Read the NIST discussion](https://www.http6.org/standards/nist/)
- [Inspect the public SDK repository](https://github.com/HTTP6-ORG/http6-sdk)
- [Contribute feedback on GitHub](https://github.com/HTTP6-ORG/http6-sdk/issues)
