# Architecture Collision Review

Use this review to find parallel changes that merge cleanly in Git but independently solve the same domain problem or establish incompatible foundations. Treat architectural convergence as a first-class integration risk.

## Contents

- [Build a capability map](#build-a-capability-map)
- [Recognize architecture collisions](#recognize-architecture-collisions)
- [Make the DDD boundary decision](#make-the-ddd-boundary-decision)
- [Apply the hexagonal design test](#apply-the-hexagonal-design-test)
- [Resume and checkpoint pattern](#resume-and-checkpoint-pattern)
- [Rate and mitigate](#rate-and-mitigate)

## Build a capability map

Map the current branch and every candidate before deciding that paths are unrelated:

| Question | Evidence to capture |
| --- | --- |
| Business outcome | What user or operational capability becomes possible? |
| Ubiquitous language | Which domain nouns, verbs, states, and events appear? |
| State and lifecycle | Which transitions, checkpoints, retries, cursors, or completion rules change? |
| Invariants and policy | What must remain true, and who decides? |
| Application use case | Which command/query or orchestration flow is added? |
| Boundary dependencies | Which persistence, queue, clock, runtime, or external service is required? |
| Bounded context | Which model owns the meaning and lifecycle? |
| Public commitment | Which API, schema, storage format, event, or extension point becomes hard to change? |

Use PR titles and changed paths for the first pass. Retrieve the body, files, commits, and relevant diffs for any candidate sharing business language, lifecycle concepts, state management, or an adjacent extension point. Do not skip a candidate merely because its file intersection is empty.

## Recognize architecture collisions

Investigate when parallel work does any of the following:

- Models the same business verb or lifecycle in separate modules.
- Introduces competing state machines, checkpoint formats, status enums, cursors, retry policies, or resume entry points.
- Creates multiple domain services or repository interfaces around the same capability.
- Adds separate orchestration frameworks for sibling workflows.
- Establishes incompatible APIs, events, schemas, migration ordering, or persistence representations.
- Generalizes locally in a way that a concurrent PR will soon need to bypass or duplicate.
- Solves a shared domain need inside infrastructure code, making the business policy hard to reuse.
- Uses the same technical mechanism for different domain meanings and is therefore at risk of a misleading shared abstraction.

Similar words alone are weak evidence. Confirm shared meaning, invariants, lifecycle, and ownership before recommending reuse.

## Make the DDD boundary decision

Ask in order:

1. Do both changes belong to the same bounded context?
2. Do the important terms have the same meaning and invariants in both use cases?
3. Does one model own the lifecycle, or are the teams coordinating distinct models?
4. Is the proposed shared contract stable enough to couple both changes now?

Choose deliberately:

- **Same context, same meaning:** prefer one domain concept, value object, aggregate behavior, domain service, specification, or policy with explicit ownership.
- **Different contexts, stable shared language:** consider a small published language or, only with conscious joint ownership, a small shared kernel.
- **Different contexts or meanings:** keep separate models and translate through an anti-corruption layer or adapter. Duplication can be safer than false unification.
- **Shared technical mechanism, distinct domain semantics:** share an application/infrastructure mechanism behind a narrow port while keeping domain policies separate.

Do not default to a generic utility, inheritance hierarchy, or broad `Manager`/`Service` abstraction. A common architecture can instead be a shared vocabulary, a minimal protocol, an event contract, a prerequisite PR, or an agreed extension point.

## Apply the hexagonal design test

For a justified common capability, identify:

- **Domain:** state, invariants, policies, and decisions that remain valid without a database, queue, CLI, or framework.
- **Application:** use cases that coordinate the domain, such as start, pause, checkpoint, resume, retry, or complete.
- **Inbound ports:** commands or use-case interfaces through which callers request the capability.
- **Outbound ports:** capabilities the application/domain needs, such as loading checkpoints, saving progress, obtaining time, or scheduling work.
- **Adapters:** storage, runtime, transport, CLI, API, or framework-specific implementations.

Put a port at the boundary that owns the need. Keep serialization and runtime details out of domain objects. Check that the abstraction can be tested with an in-memory adapter and that each bounded context can preserve its own language.

## Resume and checkpoint pattern

When one PR resumes Source Hunt and another resumes iterative steps or a different workflow, treat them as a likely architecture collision even if their files do not overlap.

Different checkpoint granularity does not remove the collision. A stage-handoff snapshot and an immutable completed-work record may be distinct domain concepts, but both can still compete for session identity, resume policy, compatibility rules, durable envelopes, fingerprints, atomic persistence, locking, CLI language, and ownership of the execution lifecycle. Decide explicitly whether they belong to one session/execution model, remain separate concepts behind one persistence protocol, or live in different bounded contexts with translation between them.

Investigate:

- What identity is resumed: a run, hunt, workflow, step, iteration, or task?
- Is a checkpoint a domain fact, an application snapshot, or merely a storage record?
- Which state is durable, versioned, idempotent, and safe to replay?
- Which invariants govern partial results, completed steps, cancellation, retries, and exactly-once effects?
- Who decides whether a checkpoint is compatible with current code and configuration?
- Does resumption continue the same aggregate lifecycle or start a new one from prior state?

Possible outcomes:

- If both use cases share meaning and invariants in one context, extract a small checkpoint/resume domain model and application use cases, then place storage behind an outbound port.
- If a platform execution context owns generic run progress while Source Hunt owns hunt semantics, define a stable published contract or port and let Source Hunt adapt its domain state to it.
- If the semantics differ, retain separate domain models and share only a narrow persistence or scheduling mechanism where useful.

Avoid designing a universal `Resumable` hierarchy from two superficial examples. Prefer the smallest stable contract supported by concrete invariants, and record what evidence would justify broader generalization later.

## Rate and mitigate

- **ARCH-BLOCKER:** Parallel PRs establish incompatible foundational domain models, public contracts, or durable formats in the same capability. Resolve ownership and architecture before either merges.
- **ARCH-HIGH:** The same or strongly adjacent capability is being implemented twice, or both PRs create extension points that should be designed together. Hold submission or readiness until investigated and sequenced.
- **ARCH-MEDIUM:** A plausible shared capability or future convergence point exists, but evidence is not yet sufficient. Record questions, owner, and follow-up before dismissing it.
- **ARCH-NONE:** Evidence supports separate bounded contexts/meanings or no material convergence. State that evidence; do not infer this from a clean merge alone.

Prefer mitigations that reduce irreversible commitments:

- Agree on ubiquitous language and ownership first.
- Extract a prerequisite contract/model PR when the shared concept is stable.
- Sequence PRs and adapt the second to the agreed extension point.
- Keep models separate behind an adapter when meanings differ.
- Add an architecture decision record when the boundary or durable contract affects future work.

Report each finding with this shape:

```text
Architecture severity:
Parallel capability:
Evidence:
Bounded-context decision:
Proposed domain/application/ports/adapters:
Why this is not premature abstraction:
Sequencing or coordination:
Open owner questions:
```
