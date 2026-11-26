# A global moonshot for identity privacy and cybersecurity

## The global problem

Every person should be able to establish identity, keep private life private, communicate securely, and control actions taken in their name. Today, identity is fragmented across accounts, credentials, databases, and institutions. A stolen secret can grant authority that is difficult to contain, and computational assumptions sit beneath cryptographic guarantees used by public services, commerce, and personal communications.

The consequences are already profound. The FBI’s Internet Crime Complaint Center recorded 1,008,597 complaints and $20.877 billion in reported losses during 2025. These figures cover many forms of cyber-enabled crime and do not isolate cryptographic failures. They document human costs that include exposed information, impersonation, extortion, financial loss, and disrupted services. [Read the FBI 2025 IC3 report](https://www.ic3.gov/AnnualReport/Reports/2025_IC3Report.pdf).

Those harms have many causes, including deception, stolen credentials, compromised systems, and failures of policy or operations. A deeper structural risk lies in computationally based cryptography: a security guarantee holds while a difficult problem remains infeasible for an adversary to solve. If that assumption fails, the effects can spread across every system that relies on it, exposing identity, communications, records, financial assets, public services, and automated decisions.

## The destination

The moonshot is identity privacy and cybersecurity for every person on Earth, with systems designed for a world of 10 billion people. Its destination is information-theoretic security as the foundation of future cryptography and cybersecurity. Every primitive whose guarantee depends on computational hardness is on the path to replacement. The thesis is to make privacy and security rest on explicit proof and information models rather than on the expectation that an adversary cannot compute enough.

This proposed transition is comparable in scope to the way public-key cryptography and public-key infrastructure became a foundation for Internet identity and trust. [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) defines a widely used Internet certificate infrastructure. The ambition here is to make information-theoretic security practical for identity privacy and cybersecurity worldwide.

## The technology and its roles

Rosario-Wang names the mathematical technology at the center of this work. Its formulation brings together geometric ciphers, proof, and commitment to define security through the information available to an observer. ENI6MA is the commercialization and licensing arm for this technology. The company name is an homage to the British nickname “Enigma” for a historical cipher machine; that historical reference is separate from Rosario-Wang. HTTP6 is one early application of Rosario-Wang to network requests and delegated authority for AI agents. The global challenge and its beneficiaries are humanity; the company supports licensing and commercial access.

The broader route proceeds through explicit proof statements, working implementations, academic review, cybersecurity evaluation, and developer adoption. The current HTTP6 W1 profile is an initial application: it uses Ed25519 signatures over HTTPS and therefore retains computational assumptions. It demonstrates operation-bound authority in an existing web stack. The completed information-theoretic replacement architecture remains a longer-range objective.

## Connect a person’s decision to an agent’s action

An autonomous agent can read files, call APIs, update records, send messages, deploy software, and move money. A prompt, model output, or tool response can influence the next action, but none of those objects establishes that a person authorized the action. A process that also holds a reusable bearer token or broad API key can act with the authority attached to that credential, even when the particular operation exceeds the human’s intent.

The first application question is how an operation can retain an accountable human origin while passing through a machine process. The system must be able to identify the person or organization that granted authority, distinguish the running agent from that authority source, and decide whether the exact destination, resource, operation, data, and limits remain within the grant. Authority should narrow as work is delegated, expire or be revoked under defined rules, and remain inspectable after execution.

Human-bound identity refers to the authority chain used by participating services. It does not require that a person’s identity be broadcast to every observer. A service can verify the relevant identity and disclose only the attributes required by the task and policy. This distinction allows accountability for protected operations to coexist with privacy for people using the system.

The same design question appears when an agent follows hostile instructions, misreads a task, or produces an unintended tool call. The model can propose an operation; the resource that owns the data or effect must evaluate the operation against the human-origin grant and its current policy before acting. The goal is to bind cryptographic evidence to that decision and preserve a record that an authorized reviewer can examine.

## From public-key infrastructure to information-theoretic security

The modern cryptographic literature contains work on different technical problems. [Whitfield Diffie and Martin Hellman’s 1976 paper](https://www.itsoc.org/publications/papers/new-directions-in-cryptography) developed public-key methods for establishing secret communication. [Rivest, Shamir, and Adleman’s 1978 paper](https://people.csail.mit.edu/rivest/pubs/RSA78.pdf) presented a public-key cryptosystem with applications to encryption and digital signatures. [Satoshi Nakamoto’s paper on peer-to-peer electronic cash](https://bitcoin.org/bitcoin.pdf) addressed electronic payments and double spending through a distributed record and proof of work. [Shafi Goldwasser, Silvio Micali, and Charles Rackoff’s work on interactive proof systems](https://doi.org/10.1145/22145.22178) developed the concept of zero knowledge, in which a proof can establish a statement while limiting what the verifier learns.

These contributions have different purposes and assumptions. Key agreement, public-key encryption, signatures, distributed cash, and zero-knowledge proofs establish different capabilities under different models. An application that composes them still has to specify how a particular human’s intention becomes bounded permission at every resource an agent can reach. A complete system connects identity, proof, policy, execution, and the consequences recorded by the service.

Public-key cryptography became an operational foundation for network identity through standards and infrastructure such as Internet X.509 PKI. The ambition for Rosario-Wang is comparable in scope: make information-theoretic security a practical foundation for identity privacy and cybersecurity worldwide. The goal is to give people and institutions security whose central guarantee comes from an explicit proof and information model.

The Rosario-Wang thesis sets a different foundation: replace security primitives whose guarantees depend on computational hardness with an information-theoretic proof architecture. It recognizes the distinct achievements of earlier cryptography while proposing a future in which computational infeasibility is no longer the basis for digital security. It asks how geometry, explicit observer models, and proof can establish security properties without relying on an adversary’s limited time, hardware, or algorithmic insight. That foundation must connect a cryptographic proof to the responsible human, the approved purpose, the service policy, and the actual resource effect.

## The Rosario-Wang formulation: geometry, ciphers, proof, and commitment

Rosario-Wang is the mathematical formulation at the center of the proposed future. It uses geometric ciphers and commitment within a proof architecture that models public partitions, secret membership choices, a private response dictionary, fresh masking, and the observer’s view. The analysis studies the probability distribution that released responses induce over a hidden credential.

The formulation studies what information the proof and its released responses make available to an observer. The resulting security claim depends on the defined construction, assumptions, and observer model.

For the current per-message privacy model, the construction uses fresh independent private randomness to mask responses. Under the defined passive-observer model and its stated assumptions, the released transcript preserves the observer’s prior probabilities over the credential. The privacy claim therefore concerns what the modeled observation reveals, rather than how many operations an observer can afford. The [information-theoretic tradition associated with Claude Shannon’s work on secrecy systems](https://doi.org/10.1002/j.1538-7305.1949.tb00928.x) provides the language for expressing such claims precisely.

This is a model-specific privacy result, and its scope matters. Credential privacy does not, by itself, authenticate a person, authorize a database write, protect a network channel, stop a compromised runtime, or establish that a ledger contains the newest state. Those are separate system properties with their own models and evidence. The wider objective is to build a coherent architecture in which human authentication, private proofs, request authorization, communications, enforcement, and recovery are designed together and each claimed property can be reviewed on its own terms.

The destination is the replacement of computational-assumption-based cryptography with security primitives whose guarantees are stated and proved in information-theoretic terms, including perfect secrecy for specified messages and observers where the construction supports it. Each primitive class needs a corresponding proof and deployment path, followed by mathematical scrutiny, independent implementation, cybersecurity evaluation, and adoption. The ambition is to change the foundation on which the digital world secures identity, communications, institutions, and machine action. HTTP6 is one network track in that transformation.

## HTTP6 carries authority to the resource

HTTP6 applies the human-authority problem to web operations. Its proposed request model connects an issuer’s grant to a particular worker, recipient, operation, payload, limits, and one-use identifier. The service checks that authority against current policy and state at the point where it can disclose data or cause an effect, then records the outcome for later inspection. In this way, the protocol addresses one critical seam in the larger program: how an agent’s network request is tied to an identifiable source of permission.

The first profile, W1, uses Ed25519-signed requests over HTTPS. It gives developers a way to test request-bound authority using existing web infrastructure, while retaining computationally based signatures and TLS. The proposed native HTTP6 channel is a later research and implementation stage addressing confidentiality, peer authentication, integrity, key changes, replay, downgrade, and recovery. HTTP6’s long-term role is to replace HTTPS transport and reusable bearer JWT authorization on fully migrated routes, as one concrete part of the worldwide transition to information-theoretic security.

HTTP6 is one early network application of the Rosario-Wang technology. Its API, proof formats, and ledger describe the network exchange and operation authority. The worldwide effort will require additional implementations for human identity, communications, institutional access, and industry-specific resources, each with explicit verification procedures and evidence that can be independently examined.

## Mathematical review and developer adoption

A change in cryptographic foundations requires a public, demanding route from mathematical claim to deployed system. Academic researchers need definitions, assumptions, derivations, and examples they can inspect and reproduce. Developers need stable schemas, readable APIs, test vectors, reference implementations, and ways to compare independent implementations. Cybersecurity practitioners need to examine threat models, identity and key custody, resource enforcement, operations, recovery, and compatibility with existing systems. The mission depends on all three communities, because a proof that cannot be independently examined or implemented cannot replace the primitives used across the world.

These forms of review answer different questions. A mathematical argument establishes a property under its hypotheses. An implementation test reports the behavior of identified code in an identified environment. A security assessment examines whether a deployment and its operating practices satisfy the model. Developer adoption shows whether the interfaces can support real integration and interoperability. The project will need evidence at each level before a broader application can rely on the result.

HTTP6’s current proposal materials invite review through the IETF and NIST discussion tracks, public SDK source, examples, and the project’s feedback channels. The purpose is to make the technical work open to correction and implementation experience as the program expands beyond the first protocol track.

- [Read the global security moonshot on HTTP6.org](https://www.http6.org/moonshot/)
- [Explore Rosario-Wang research](https://www.http6.org/research/rosario-wang/)
- [Review the HTTP6 protocol roadmap](https://www.http6.org/roadmap/)
- [Review IETF proposal material](https://www.http6.org/standards/ietf/)
- [Read the NIST discussion](https://www.http6.org/standards/nist/)
- [Inspect the public SDK repository](https://github.com/HTTP6-ORG/http6-sdk)
- [Contribute feedback on GitHub](https://github.com/HTTP6-ORG/http6-sdk/issues)
