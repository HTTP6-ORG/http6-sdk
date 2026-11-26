# The ENI6MA Moonshot

**Give every consequential action an accountable human origin. Then build a human-usable foundation for security that can move beyond computational hardness, one protocol pattern at a time.**

ENI6MA is pursuing a multi-industry, multi-technology mission to change how people establish identity, delegate authority, protect information, and verify what systems did. HTTP6 is one of the first steps: a proposed way for a service to check the human authority behind an autonomous agent before the agent performs a protected action.

## Autonomous agents need human-bound authority

Autonomous language-model agents can call tools, read files, change records, send messages, deploy software, and move money at machine speed. A mistaken, manipulated, or compromised agent can turn a prompt into a series of real operations. A broad credential stored in an environment file or workspace can make possession of that string enough to act as its owner.

The mission is to make every protected operation answer three questions: **which person or organization authorized the work, which agent is acting, and does this exact action fit the authority that was granted?** The authorization chain should lead to an accountable human or organization, while each agent receives only a bounded task and a distinct identity.

Human-bound identity is not a demand to expose a person’s identity to every service or observer. It is a verifiable chain of authority for the systems responsible for admission and enforcement, with disclosure limited to what the task and policy require. Within a protected workflow, an anonymous request or a prompt alone must not create authority.

A prompt injection or rogue instruction may still cause an agent to ask for an action. The design objective is that the request reaches a resource gate that checks the approved destination, operation, data, limits, time, and one-use state before it can take effect. Identity, policy, proof, enforcement, and a reviewable record work together.

## HTTP6 carries the approval to the point of action

HTTP6 is designed to connect a person’s approval to the worker making a request and to the resource that can carry it out. In the proposed pattern, a request identifies its authority chain, recipient, operation, payload digest, limits, and unique operation identifier. The receiving service checks that evidence against policy and current ledger state, enforces the decision at the actual effect or disclosure point, and records what happened.

1. **A person scopes the task.** The approval identifies the purpose, permitted actions, destinations, limits, and duration.
2. **An agent receives bounded authority.** Its identity and delegation remain tied to the original approval.
3. **The service checks each protected request.** The resource verifies the request, policy, freshness, recipient, and replay state before acting.
4. **The outcome can be inspected.** Response evidence and ledger records let an authorized reviewer follow the decision and its result.

The first HTTP6 profile uses signed requests over HTTPS, allowing teams to work with existing web infrastructure. The long-term protocol path adds independent-operator interoperability, a managed workspace, and research toward a native HTTP6 channel. On routes that complete a full, reviewed migration, HTTP6 aims to replace HTTPS and reusable bearer JWT authorization with a native channel and request-bound authority.

- [Explore the HTTP6 architecture](https://www.http6.org/architecture/)
- [Follow the HTTP6 roadmap](https://www.http6.org/roadmap/)
- [Open the HTTP6 developer section](https://www.http6.org/developers/)

## Make strong cryptography understandable and usable by people

The ENI6MA and Rosario-Wang research program aims to make post-quantum, information-theoretic secrecy usable in everyday systems and workflows. The ambition is to pair mathematical guarantees with interfaces that let people enroll, approve a task, understand what it permits, revoke authority, recover safely, and inspect the record without needing to become cryptographers.

Information-theoretic secrecy is a precise claim about what a defined observation can reveal under stated assumptions. For the project’s current per-message privacy research, fresh independent private randomness supports a credential-privacy result for a specified passive observer model. That research is a foundation for the mission. Extending such guarantees across identity, request integrity, transport, runtime, storage, recovery, and enforcement requires each property to be specified and established for its own model.

The target is not simply to label a system “quantum safe.” It is to define which information is protected, which observer is considered, what assumptions the construction uses, how the service authenticates and authorizes an action, and how a deployment preserves those properties through failures and recovery. The moonshot includes making formally defined perfect-secrecy properties practical and legible at human scale. [Claude Shannon’s 1949 treatment of secrecy systems](https://doi.org/10.1002/j.1538-7305.1949.tb00928.x) provides a foundational reference for information-theoretic secrecy.

At the far horizon is a definitive transition in cryptography: establish a foundational family of patterns that makes information-theoretic security usable by people and progressively retires security roles built on computational hardness. The mission aims for a complete shift in that foundation, working through encryption, identity, authorization, transport, and recovery one pattern at a time, with each transition earned through mathematical proof, interoperable implementations, and adoption.

- [Read the security and deployment model](https://www.http6.org/architecture/security-and-deployment/)
- [Explore Rosario-Wang research](https://www.http6.org/research/rosario-wang/)
- [Read the theory collection](https://www.http6.org/research/ieee-theory/)

## Build on cryptography’s foundations, then replace patterns one by one

[Diffie and Hellman’s work on public-key cryptography](https://www.itsoc.org/publications/papers/new-directions-in-cryptography) and [the RSA paper by Rivest, Shamir, and Adleman](https://people.csail.mit.edu/rivest/pubs/RSA78.pdf) helped establish the modern network security landscape. ENI6MA’s mission respects that contribution while taking on a larger question: can security systems rely less on assumptions about how much computation an attacker can afford, and more on constructions whose stated properties hold independently of that computational budget?

The long-range ambition is to examine each role in the existing stack, from identity and key establishment to encryption, authorization, session continuity, and recovery. Where an alternative is mathematically specified, implementable, independently reviewed, and interoperable, the goal is to replace the corresponding legacy pattern on qualified routes. The work advances pattern by pattern, with evidence for the property each replacement is meant to provide.

This mission begins with the web and autonomous agents, then extends to other industries and technologies where accountable identity and high-assurance secrecy matter. Financial services, healthcare, public infrastructure, industrial systems, and machine-to-machine networks each bring distinct requirements that must shape their own implementations.

## A sequence of concrete steps

1. **Bind authority to an accountable origin.** Identify the person or organization that approves a task, the agent that carries it out, and the constraints that apply.
2. **Check every protected action.** Bind proofs to the request and recipient, enforce policy at the resource, prevent duplicate effects, and record outcomes.
3. **Prove operation across organizations.** Demonstrate that separately administered services can verify grants, enforce shared limits, and reconcile evidence.
4. **Build a human-centered workspace and native channel.** Keep the displayed approval aligned with the running agent, then develop and evaluate an HTTP6 transport that can take over the jobs HTTPS performs today.
5. **Revisit cryptographic patterns.** Define, prove, implement, and test alternatives to computational-hardness-dependent patterns where the research supports a replacement.
6. **Extend across sectors.** Adapt the identity, privacy, policy, and recovery model to the needs of each participating industry and technology.

Each step creates a concrete review surface for engineers, researchers, operators, and standards participants. The project is at the proposal and community-feedback stage, and contributions can help shape the problem definition, protocol choices, and milestones.

## Help shape the mission

Read the research and protocol material, run the public examples, and share technical feedback. The HTTP6 SDK repository is the public place to review code, open issues, and contribute implementation feedback.

- [Browse the HTTP6 SDK on GitHub](https://github.com/HTTP6-ORG/http6-sdk)
- [Share feedback or open an issue](https://github.com/HTTP6-ORG/http6-sdk/issues)
- [Review the IETF drafts](https://www.http6.org/standards/ietf/)
- [Read the NIST discussion material](https://www.http6.org/standards/nist/)
- [Send feedback through HTTP6.org](https://www.http6.org/participate/feedback/)
