# Sourcehunt Improvement: Proof-Carrying Vulnerability Hunting

**Status:** Proposed

## Summary

Clearwing's sourcehunt capability currently depends heavily on a model's
ability to perform a long, stateful investigation inside its context
window. A hunter must choose code to inspect, understand the relevant
program behavior, form a vulnerability hypothesis, trace it across
functions, identify defenses, construct a trigger, validate the result,
and finally reconstruct the evidence as a report.

Observed end-to-end success is approximately 60% with frontier models and
30% with lower-cost or locally served models. These numbers are
preliminary, but the gap is consistent with an architecture that asks one
model invocation loop to perform several different kinds of reasoning
while also maintaining the authoritative investigation state.

This document proposes replacing that model-centric hunt with a
proof-oriented investigation system. Clearwing should:

- Extract durable facts from the repository and execution environment.
- Generate typed vulnerability candidates from suspected invariant
  violations.
- Attach an explicit threat model and bug-class-specific proof plan.
- Represent the investigation as a versioned graph of claims, evidence,
  assumptions, and proof obligations.
- Select bounded experiments according to their expected information
  value and cost.
- Preserve positive, negative, conflicting, and incomplete evidence.
- Require an independent falsification pass before accepting a finding.
- Compile reports from machine-auditable evidence rather than model
  recollection.
- Retain a bounded exploratory lane for novel vulnerability mechanisms.

The intended product is a **proof-carrying vulnerability finding**: a
security conclusion bundled with a machine-auditable chain of evidence,
explicit assumptions, reproducible artifacts, and preserved uncertainty.
A disproven candidate should produce an equally durable rejection
certificate.

## Motivation

### Current model burden

The current sourcehunt pipeline already contains useful mechanical
components: preprocessing, file ranking, callgraph construction,
reachability propagation, Semgrep hints, limited taint analysis, harness
generation, sandbox execution, verification, and reporting. However, the
per-file hunter still performs most of the important synthesis.

A single hunter is effectively responsible for:

1. Selecting relevant code and deciding which neighboring files to read.
2. Recovering types, control flow, dataflow, ownership, and configuration.
3. Choosing a security invariant that may be violated.
4. Forming and revising a vulnerability hypothesis.
5. Establishing entry-point and attacker reachability.
6. Finding guards, sanitizers, and call-site constraints.
7. Constructing a trigger or proof of harmful behavior.
8. Interpreting runtime or static-analysis output.
9. Distinguishing a security boundary violation from a correctness bug.
10. Reassembling the authoritative trace and writing the final finding.

These are different cognitive tasks. Combining them creates a
long-horizon, partially observed investigation whose state exists mainly
in conversation history. Frontier models sometimes compensate for
missing orchestration with stronger planning and working memory. Smaller
models are more likely to lose an edge, overlook a guard, choose an
unproductive tool, or fail while converting a real observation into the
required reporting structure.

### What the performance gap does and does not establish

The observed 60% versus 30% end-to-end gap is evidence of model
sensitivity, but it does not identify the failing stage. A smaller model
may:

- Fail to rank the target code.
- Find the correct function but not the relevant invariant.
- Generate the right hypothesis but miss a caller or guard.
- Complete the trace but fail to build the harness.
- Reproduce the behavior but misclassify the threat model.
- Produce a valid investigation but fail the reporting schema.
- Be correct while a later verifier rejects the finding.

The proposed architecture therefore begins with stage-level
instrumentation. Improving prompts without locating the failure funnel
would risk optimizing the wrong component.

## Goals

The design has the following goals:

- Raise absolute vulnerability-discovery and validation success.
- Reduce the performance gap between frontier and local models.
- Make investigations resumable, inspectable, and reproducible.
- Make model calls small, typed, and independently evaluable.
- Separate observed program behavior from security conclusions.
- Preserve uncertainty instead of forcing premature binary decisions.
- Make rejection evidence reusable across scans and code changes.
- Route expensive models only to explicitly unresolved ambiguities.
- Improve incremental rescanning by invalidating only affected proofs.
- Measure causal understanding through counterfactual evaluation.
- Continue discovering unfamiliar vulnerability mechanisms.

## Non-goals

This proposal does not attempt to:

- Build a sound and complete static analyzer for every supported language.
- Eliminate language models from sourcehunt.
- Prove the absence of all vulnerabilities in a repository.
- Treat every crash, undefined behavior report, or static warning as a
  security vulnerability.
- Require dynamic reproduction for vulnerability classes where a
  different form of proof is more appropriate.
- Replace human review for disclosure, severity, or remediation decisions.
- Introduce an unbounded swarm of agents performing duplicate hunts.

## Design principles

### System state is authoritative

Repository facts, evidence, assumptions, claims, obligations, tool
outputs, and decisions must live in typed storage. Conversation history is
working context, not the source of truth.

### Models resolve bounded ambiguity

A model should answer a focused question over a deliberately constructed
context packet. It should not be responsible for remembering the whole
investigation or deciding silently what evidence is missing.

### Unknown is not absent

Unresolved indirect calls, missing build variants, incomplete alias
analysis, and unavailable runtime environments must remain explicit.
Unknown edges must never silently become absent edges.

### Claims are scoped

Every claim is valid only for a particular repository snapshot, analysis
configuration, threat model, and set of assumptions. A claim such as
"all callers enforce the bound" is meaningless without that scope.

### Security requires a boundary

Observed unsafe behavior is not automatically a vulnerability. A finding
must identify an attacker principal, protected asset, trust boundary,
capability gained, and violated security property.

### Evidence supports typed claims

Evidence that proves one claim type cannot automatically prove another. A
sanitizer crash may establish an out-of-bounds access in a harness. It
does not, by itself, establish remote reachability or code execution.

### Falsification precedes acceptance

The system must actively look for counterevidence before issuing a
finding. Confirmation and falsification should operate on atomic claims,
not competing free-form narratives.

### Mechanization must preserve exploration

Most resources should go to structured investigation, but a bounded
exploratory lane must search outside the current candidate ontology.
Novel discoveries should be distilled into reusable invariants, proof
plans, and candidate generators.

## Target architecture

The proposed system has six primary layers and two cross-cutting systems:

~~~text
1. Fact extraction
   Symbols, types, calls, dataflow, control flow, configuration, tests

2. Hypothesis generation
   Candidates based on invariant violations, contrasts, and anomalies

3. Investigation planning
   Threat model, proof-plan selection, and obligation instantiation

4. Evidence acquisition
   Static tools, bounded model judgments, compilation, fuzzing, execution

5. Adversarial resolution
   Falsification, conflict resolution, and residual-uncertainty assessment

6. Finding compilation
   Evidence-linked report, reproduction package, or rejection certificate

Cross-cutting:
   Budget and value-of-information scheduler
   Learning, calibration, and evaluation loop
~~~

The high-level flow is:

~~~text
Repository snapshot
        |
        v
Normalized facts and provenance
        |
        v
Invariant-oriented candidate hypotheses
        |
        v
Threat model + bug-class proof plan
        |
        v
Versioned claim/evidence/obligation graph
        |
        v
Bounded evidence-acquisition actions
        |
        v
Independent falsification and conflict resolution
        |
        +----------------------+
        |                      |
        v                      v
Finding certificate      Rejection certificate
        |                      |
        +----------+-----------+
                   v
         Incremental learning and rescanning
~~~

## Core data model

The data model is the architectural center of the proposal. Exact storage
technology is an implementation choice; semantic ownership is not.

### RepositorySnapshot

A snapshot identifies the code and analysis environment to which evidence
applies.

~~~yaml
id: snapshot:abc123:linux-default
commit: abc123
dirty_tree_digest: null
build_configuration: linux-default
compiler: clang-19
feature_flags:
  tls: true
  experimental_decoder: false
analysis_tool_versions:
  callgraph: clearwing-tree-sitter-v2
  semgrep: 1.x
created_at: 2026-07-14T00:00:00Z
~~~

Dirty worktrees must include a content digest so evidence cannot be
mistakenly attributed to the checked-in commit.

### Fact

A fact is an immutable extracted observation. Examples include a symbol
definition, call edge, control-flow dominator, assignment, cast,
allocation, bound check, configuration value, or test target.

~~~yaml
id: fact:F-104
snapshot_id: snapshot:abc123:linux-default
kind: allocation
subject: symbol:parse_packet.buffer
properties:
  expression: payload_length + 8
location:
  file: src/parser.c
  line: 118
provenance:
  producer: clang-ast-adapter
  producer_version: 1.0
  source_digest: sha256:...
~~~

Facts should not contain model conclusions. A model-derived observation
is stored as evidence or a claim with its own provenance.

### Evidence

Evidence is an artifact that supports or contradicts one or more claims.
It may be static, dynamic, model-produced, or human-supplied.

~~~yaml
id: evidence:E-55
snapshot_id: snapshot:abc123:linux-default
kind: sanitizer_run
artifact_uri: artifacts/runs/R-19/asan.json
observations:
  - heap-buffer-overflow
  - write_of_size: 4096
  - allocation_size: 264
provenance:
  command: ./packet_harness crash.bin
  environment_digest: sha256:...
  exit_code: 1
  stdout_digest: sha256:...
  stderr_digest: sha256:...
reliability:
  deterministic_replays: 3
  total_replays: 3
~~~

Evidence is immutable. Corrections produce new evidence and supersession
links rather than overwriting the original artifact.

### Claim

A claim is a typed assertion derived from facts, evidence, assumptions,
or other claims.

~~~yaml
id: claim:C-17
type: attacker_controls_value
subject: symbol:parse_packet.payload_length
scope:
  snapshot_id: snapshot:abc123:linux-default
  entry_points:
    - symbol:network_receive
assumptions:
  - assumption:A-2
status: proven
supporting_evidence:
  - evidence:E-4
  - evidence:E-9
contradicting_evidence: []
derivation: derivation:D-12
validity:
  established_at: 2026-07-14T00:00:00Z
  invalidated_at: null
~~~

Claims should use a controlled predicate vocabulary. Free-form
explanation can accompany a claim but must not replace its typed meaning.

### Assumption

An assumption is an explicit condition not yet established as a fact.

~~~yaml
id: assumption:A-2
type: deployment
statement: network listener is enabled in the default server profile
status: unverified
scope:
  configuration: linux-default
required_by:
  - claim:C-17
~~~

Assumptions can later become proven, disproven, or configuration-specific.
Dependent claims must be updated accordingly.

### Candidate

A candidate is a suspected invariant violation, not yet a finding.

~~~yaml
id: candidate:CAND-104
snapshot_id: snapshot:abc123:linux-default
invariant_family: spatial_safety
suspected_mechanism: narrowing_conversion_before_allocation
source:
  symbol:parse_packet.payload_length
  fact_ids:
    - fact:F-91
transformations:
  - fact:F-97
sink:
  symbol:copy_payload.memcpy
  fact_ids:
    - fact:F-108
suspected_invariant:
  predicate: accessed_region_subset_of_allocated_region
relevant_guards:
  - fact:F-99
threat_model_id: threat:TM-8
proof_plan_id: proof-plan:memory-write-v1
open_questions:
  - obligation:O-21
  - obligation:O-22
generator:
  name: allocation-write-size-contrast
  version: 1
~~~

Candidates may share evidence and obligations. Duplicate candidates should
be merged through explicit equivalence links rather than silently
discarded.

### Obligation

An obligation is an atomic question required by a proof plan.

~~~yaml
id: obligation:O-21
candidate_id: candidate:CAND-104
claim_template: no_effective_guard_on_path
dependencies:
  - obligation:O-18
status: unknown
resolution:
  supporting_claims: []
  contradicting_claims: []
  blocked_reason: null
available_actions:
  - action-template:compute-dominators
  - action-template:classify-guard
  - action-template:expand-caller-slice
~~~

Supported obligation states are:

- **proven**: evidence establishes the required claim within scope.
- **disproven**: evidence establishes the claim's negation.
- **unknown**: not enough evidence has been collected.
- **blocked**: a required action cannot currently run.
- **conflicting_evidence**: credible supporting and contradicting
  evidence coexist.
- **stale**: a dependency, assumption, snapshot, or analysis scope
  changed after resolution.
- **not_applicable**: the selected proof plan no longer requires this
  obligation.

Confidence and obligation state are separate. A claim is not "proven at
60%." Probabilistic estimates may guide scheduling, while proof status
describes whether predefined evidentiary requirements were met.

### Action

An action is a bounded experiment intended to resolve one or more
obligations.

~~~yaml
id: action:ACT-31
template: compile-and-run-asan-harness
targets:
  - obligation:O-29
inputs:
  context_packet: packet:P-44
  harness: artifact:H-3
preconditions:
  - claim:build_target_available
estimated:
  cost_seconds: 90
  token_cost: 0
  information_gain: 0.72
status: completed
outputs:
  - evidence:E-55
~~~

Every action has bounded inputs, permitted tools, resource limits,
termination conditions, and typed outputs.

### Derivation

A derivation records why particular evidence establishes a claim.

~~~yaml
id: derivation:D-12
rule: direct-parameter-dataflow-v2
premises:
  - fact:F-11
  - fact:F-12
  - evidence:E-4
conclusion:
  - claim:C-17
limitations:
  - indirect aliases not considered
validator: deterministic
~~~

Model-produced derivations must include the model, prompt template,
context packet, structured output, and any adjudication result.

### Certificate

A certificate is the durable terminal product of an investigation:

- A **finding certificate** establishes the proof plan's acceptance
  conditions.
- A **rejection certificate** establishes why the candidate is not a
  vulnerability within the stated scope.
- An **incomplete certificate** records material progress and residual
  uncertainty when work stops without a conclusion.

Certificates reference claims and evidence; they do not copy evidence
without provenance.

## Versioned graph semantics

Within one snapshot and proof-plan instance, obligation dependencies
should be acyclic. Across time, however, investigations can revisit prior
conclusions. The implementation should therefore behave like a versioned
truth-maintenance system rather than a permanently fixed DAG.

Examples:

- A newly resolved indirect caller invalidates an earlier claim that all
  callers enforce a bound.
- A configuration scan reveals that an allegedly internal endpoint is
  enabled by default.
- Alias analysis finds that a suspected write targets a different object.
- A code change removes the guard supporting a rejection certificate.
- A new dynamic run conflicts with a previous deterministic observation.

Facts and evidence remain immutable. Claims, obligations, and
certificates receive new versions or become stale. Invalidation propagates
only through recorded dependencies.

## Threat model

Every candidate must include or reference a threat model before it can
become a reportable vulnerability.

Required fields are:

~~~yaml
id: threat:TM-8
attacker_principal: unauthenticated_remote_client
attacker_capabilities:
  - send_arbitrary_protocol_frames
trust_boundary:
  - network_to_server_process
protected_assets:
  - process_memory_integrity
  - service_availability
required_privileges: none
deployment_assumptions:
  - default_listener_enabled
capability_gained:
  - out_of_bounds_write_in_server_process
security_property_violated:
  - memory_integrity
~~~

Threat-model fields can initially be unknown, but they must produce
obligations. Severity and report language must change when attacker
capabilities or deployment assumptions change.

The same unsafe operation may be:

- Critical when remotely reachable before authentication.
- Moderate when triggered only by a local unprivileged user.
- Not security-relevant when reachable exclusively through a trusted
  internal interface.
- A correctness defect when it cannot cross a trust boundary.

## Invariant-oriented candidate generation

Candidate generation should be organized around security invariants
rather than an ever-growing list of bug names. Bug mechanisms remain
useful as generators, but the proof target is the violated invariant.

### Spatial safety

~~~text
accessed_region is a subset of allocated_region
~~~

Possible mechanisms include truncation, overflow, incorrect element size,
parser length disagreement, stale capacity, missing terminator space, and
incorrect object selection.

### Temporal safety

~~~text
object is live and owned appropriately at every access
~~~

Possible mechanisms include use-after-free, double free, borrowed-pointer
escape, invalid iterator, reference-count imbalance, and asynchronous
lifetime mismatch.

### Parser safety

~~~text
cursor + requested_length <= validated_boundary
~~~

Candidate generators should model nested boundaries, encoded versus
decoded lengths, integer domains, remaining input, and state-dependent
field interpretation.

### Authority safety

~~~text
requested_operation is permitted for principal and resource
~~~

Generators should compare sibling routes, read/write variants, policy
enforcement locations, object ownership checks, tenancy boundaries, and
confused-deputy flows.

### State-machine safety

~~~text
transition is permitted from the current authenticated and initialized state
~~~

Generators should look for missing prerequisites, reordered protocol
messages, error-path transitions, replay, partial initialization, and
state shared across principals.

### Cryptographic safety

~~~text
the required secrecy, authenticity, uniqueness, freshness, and domain
separation properties hold under the API's preconditions
~~~

Generators should reason about properties and API contracts, not merely
flag cryptographic function names.

### Additional invariant families

The framework should allow additional families, including:

- Resource accounting and denial-of-service bounds.
- Isolation and sandbox-boundary integrity.
- Concurrency and atomicity.
- Confidentiality and unintended information flow.
- Deserialization and object-construction safety.
- Command, path, query, and template interpretation boundaries.

## Candidate generators

Candidate generators consume normalized facts and emit candidates with
provenance. They may be deterministic, analyzer-backed, model-assisted,
or contrastive.

Initial generator families should include:

- Allocation size versus subsequent write or access size.
- Narrowing, signedness, and overflow transformations.
- Parser cursor versus validated boundary.
- Allocation, transfer, free, and dereference lifetime mismatches.
- Attacker-controlled values reaching dangerous interpreters.
- Missing policy enforcement on a sibling path.
- Checked and unchecked variants of equivalent operations.
- State transitions without required predecessor states.
- Cryptographic calls with violated preconditions.
- Error paths that bypass validation, cleanup, or state restoration.

Candidate generation should use bidirectional search:

- Forward propagation from untrusted entry points and attacker-controlled
  values.
- Backward propagation from high-impact sinks and protected operations.
- Candidate creation where the searches meet or nearly meet.

A model may help label an ambiguous edge or infer a likely invariant, but
the emitted candidate must use the same typed schema and preserve the
model's provenance.

## Bug-class-specific proof plans

A proof plan defines the obligations required to confirm or reject a
candidate. Plans are versioned and selected by invariant family,
mechanism, language, and available validation backends.

### Memory corruption

~~~text
attacker control
  -> reachable dataflow
  -> violated size or lifetime invariant
  -> no effective guard
  -> concrete malformed input or state
  -> observed unsafe behavior
  -> realistic execution context
  -> security consequence
~~~

Dynamic sanitizer evidence is highly valuable but does not replace
attacker-control, reachability, or threat-model obligations.

### Authorization

~~~text
attacker identity
  -> protected object or operation
  -> expected policy
  -> actual enforcement path
  -> missing or inconsistent decision
  -> allowed-versus-denied differential test
  -> unauthorized capability gained
~~~

The preferred dynamic evidence is often a differential integration test,
not a crash.

### Cryptographic misuse

~~~text
required security property
  -> construction or API used
  -> violated precondition
  -> attacker observation or control
  -> concrete reuse, distinction, forgery, or disclosure consequence
~~~

A weak-looking primitive is not sufficient evidence without a violated
property in the actual construction.

### State-machine vulnerability

~~~text
expected transition graph
  -> reachable illegal transition
  -> required input sequence
  -> resulting inconsistent state
  -> attacker capability gained
~~~

Model checking, protocol replay, or a generated transition test may be a
better backend than fuzzing.

### Proof-plan composition

Some findings require multiple plans. For example, an authorization
bypass may expose a parser that then causes memory corruption. The graph
should share claims and evidence while preserving the separate security
properties and consequences.

## Context packets

Models and bounded analysis actions receive deterministic context
packets. A packet should contain only the material relevant to a specific
obligation:

- Candidate and target obligation.
- Relevant function bodies and source locations.
- Direct callers and callees.
- Type and constant definitions.
- Macro expansions when applicable.
- Control-flow dominators and relevant branches.
- Data dependencies and known aliases.
- Entry-point and configuration reachability.
- Existing tests, fuzz targets, and build commands.
- Supporting and contradicting evidence.
- Explicit unknowns.
- One or more permitted output schemas.

### Completeness manifest

Every packet includes a machine-generated completeness manifest:

~~~yaml
packet_id: packet:P-44
snapshot_id: snapshot:abc123:linux-default
target_obligation: obligation:O-21
included:
  direct_callers:
    status: complete
    basis: clang-callgraph
    scope: statically_resolved_calls
  direct_callees:
    status: complete
    basis: clang-callgraph
  type_definitions:
    status: complete
    basis: clang-ast
  macro_expansions:
    status: complete
    basis: compile_commands
  control_dominators:
    status: complete
    basis: llvm-cfg
  data_dependencies:
    status: partial
    limitations:
      - field-sensitive aliases unavailable
  indirect_calls:
    status: unresolved
    missing:
      - decoder->write
  configuration_variants:
    status: partial
    analyzed: 2
    known_total: 5
~~~

A model may return an **insufficient_context** result naming the missing
fact and explaining why it could alter the conclusion. That response is a
successful bounded judgment, not a model failure.

Context packet IDs make model comparisons reproducible: different models
can receive the identical question and evidence.

## Evidence acquisition actions

The system should offer small, typed actions such as:

- Expand the slice by one caller or callee edge.
- Resolve an indirect call target.
- Extract all control-flow dominators for a sink.
- Identify range checks affecting one value.
- Compute one bounded taint path.
- Classify whether a particular guard establishes a particular predicate.
- Compare two sibling functions or routes.
- Compile an existing test target.
- Generate a harness from a known signature template.
- Repair one compiler error.
- Run a sanitizer-backed test.
- Fuzz for a bounded duration.
- Execute a differential authorization test.
- Explore a bounded state machine.
- Test a configuration variant.
- Ask a stronger model to resolve one ambiguous relation.

Each action must declare:

- Required inputs and preconditions.
- Tools and model tier permitted.
- Time, token, and execution budgets.
- Expected output types.
- Termination conditions.
- Artifact-retention requirements.
- Which obligations it may resolve.

## Value-of-information scheduling

Once work is decomposed into obligations, the scheduler chooses the next
action rather than processing candidates in a fixed sequence.

A conceptual priority function is:

~~~text
priority =
    security_impact
    * expected_decision_relevance
    * expected_information_gain
    / expected_cost
~~~

The exact formula should be learned and calibrated from evaluation runs.
Model self-reported probabilities must not be treated as calibrated
probabilities.

The scheduler should consider:

- Potential security impact under the current threat model.
- Probability that the action resolves the target ambiguity.
- Expected reduction in unresolved proof obligations.
- Token, wall-clock, sandbox, and human-review cost.
- Candidate age and starvation prevention.
- Availability of cheaper deterministic actions.
- Whether the result can be reused by multiple candidates.
- Whether an action can disprove an expensive false positive.
- Remaining run-wide budget.

Required policy safeguards include:

- A severity floor for potentially high-impact candidates.
- A fixed exploration allocation.
- Candidate aging or fairness.
- Per-action and per-candidate limits.
- Explicit stopping with an incomplete certificate.
- Calibration reports by action type, model, language, and bug class.

Useful operational metrics include:

- Evidence gained per token.
- Evidence gained per execution minute.
- Obligations resolved per action type.
- Confirmation probability before and after an action.
- Percentage of frontier calls that resolve the stated ambiguity.
- Time spent blocked, unknown, or in conflict.
- Reusable evidence generated per run.

## Model roles and routing

Models should be selected by obligation difficulty rather than assigning
one model to an entire file.

Smaller or local models should handle:

- Source, sink, and guard classification.
- One-hop call or dataflow questions.
- Invariant extraction from a bounded function.
- Comparison of sibling paths.
- Explanation of a specific tool result.
- One compiler-error repair.
- Structured summaries of stored evidence.

Stronger models should handle:

- Ambiguous multi-hop flows that survive mechanical analysis.
- Complex alias, ownership, or cross-configuration reasoning.
- Novel invariant hypotheses.
- Architectural trust-boundary analysis.
- Conflicts that deterministic rules and smaller models cannot resolve.

Escalation requests must state the unresolved obligation, known evidence,
missing information, and required output schema. A stronger model should
not repeat the whole hunt.

Redundancy should be applied to atomic decisions. Voting or
disagreement-based escalation is useful for guard classification or
policy comparison; running several unconstrained hunters over the same
file mainly multiplies the same long-horizon failure mode.

## Independent falsification

Before a candidate becomes a finding, an independent falsifier attempts
to disprove the required claims.

The falsifier receives:

- Atomic claims.
- Evidence references and raw artifacts where necessary.
- Threat-model assumptions.
- Context completeness manifests.
- A finite bug-class-specific falsification checklist.

It should not receive persuasive report prose, prosecutor confidence, or
unsupported conclusions. This reduces anchoring.

Typical falsification obligations include finding:

- A missed dominating guard.
- An unreachable entry point.
- A caller-enforced precondition.
- A hidden type or ownership invariant.
- An alias that makes the suspected access safe.
- A configuration assumption that is unrealistic or disabled by default.
- A harness behavior that cannot occur in production.
- A dynamic artifact caused by the harness itself.
- A crash without meaningful attacker capability gain.
- A safer interpretation of ambiguous runtime evidence.

The falsifier must either provide concrete counterevidence, identify a
blocked question, or explicitly fail to find a counterexample within its
bounded scope. "No counterexample found" is not itself proof.

## Exploratory lane

A structured system risks ontology lock-in: it may become excellent at
finding vulnerability mechanisms already encoded in its generators while
missing unfamiliar interactions.

Sourcehunt should reserve a configurable portion of the run budget,
initially in the range of 5% to 15%, for exploratory investigation.

Exploratory tasks may:

- Search for unusual trust transitions.
- Compare architectural assumptions with implementation behavior.
- Inspect interactions between individually safe subsystems.
- Find code ignored by existing source and sink taxonomies.
- Identify new invariant, guard, source, or sink categories.
- Explore anomalous ownership, state, or error-handling patterns.

Exploratory output is still not directly reportable. A promising
observation must be converted into a candidate, threat model, and proof
plan, then pass through structured evidence acquisition and falsification.

Confirmed novel discoveries should undergo a structured retrospective:

~~~text
novel discovery
    -> mechanism and invariant extraction
    -> reusable candidate generator
    -> proof-plan or obligation-template update
    -> counterfactual regression cases
    -> future local-model coverage
~~~

This creates a learning flywheel without allowing unconstrained model
output to bypass evidentiary requirements.

## Dynamic validation backends

Dynamic validation should route according to the candidate and proof
plan. Supported backends may include:

- Sanitizer-assisted execution.
- Coverage-guided fuzzing.
- Differential testing.
- Symbolic or concolic execution.
- Bounded model checking.
- Authorization integration tests.
- Fault injection for error paths.
- Race detectors and schedule perturbation.
- Protocol replay.
- Configuration matrix testing.
- Patch differential testing.

The model's role is primarily to:

- Choose among permitted validation actions.
- Fill a small missing harness component.
- Repair one compiler or runtime failure at a time.
- Interpret structured output.
- Propose the next bounded experiment.

### Harness generation

Harness synthesis should prefer mechanical reuse:

1. Reuse existing tests and fuzz targets.
2. Extract signatures and build commands from compiler databases.
3. Select a language- and API-specific harness template.
4. Populate typed arguments mechanically.
5. Ask a model only for small unresolved setup or repair work.
6. Preserve every compile and execution attempt as an artifact.

A failed harness does not disprove the candidate. It blocks or leaves
unknown the reproduction obligation unless the failure itself establishes
a relevant fact.

## Rejection certificates and incremental rescanning

Negative evidence is a first-class result. A rejection certificate
records why the system considers a candidate safe within a defined scope.

~~~yaml
certificate_id: rejection:RC-104
candidate: candidate:CAND-104
decision: disproven
reason: bounded_by_dominating_guard
supporting_claims:
  - claim:C-81
guard_evidence:
  - evidence:E-55
dominated_operations:
  - fact:F-56
  - fact:F-57
validated_callers:
  - symbol:parse_tcp
  - symbol:parse_file
assumptions:
  - MAX_PACKET_SIZE == 4096
scope:
  snapshot_id: snapshot:abc123:linux-default
dependencies:
  files:
    - src/parser.c
    - include/packet.h
  symbols:
    - parse_tcp
    - parse_file
    - copy_payload
~~~

Benefits include:

- Avoiding repeated investigation of the same false positive.
- Distinguishing "proved safe in scope" from "ran out of budget."
- Creating high-quality negative evaluation and training examples.
- Reopening only affected candidates when relevant code changes.
- Detecting regressions when a guard or assumption disappears.

Incremental invalidation should operate on semantic dependencies when
possible. A removed guard or new caller reopens relevant obligations; a
comment or unrelated function change should not invalidate the
certificate.

## Evidence-constrained reporting

The report compiler must enforce a no-unsupported-claims policy.

Requirements include:

- Every factual statement references one or more evidence or claim IDs.
- Every trace edge has stored provenance.
- Every impact statement references threat-model facts or observations.
- Every reproduction statement points to a specific run artifact.
- Every assumption is labeled as an assumption.
- Every unresolved uncertainty remains visible.
- Evidence can be cited only for compatible claim types.
- Severity is derived from supported reachability, capability, asset, and
  deployment claims.

For example:

~~~text
Evidence: ASan reports an out-of-bounds write in the harness.

Supported claim:
  An out-of-bounds write occurred in this harnessed execution.

Not supported without additional evidence:
  An unauthenticated remote attacker can achieve code execution.
~~~

The final report may use model-generated prose, but the compiler validates
the prose's structured claims against the proof graph. Unsupported
sentences must be rejected, weakened, or marked as hypotheses.

A finding package should include:

- Human-readable summary.
- Threat model and security property violated.
- Versioned vulnerability trace.
- Supporting and contradicting evidence.
- Reproduction commands and retained artifacts.
- Completeness manifests.
- Assumptions and residual uncertainty.
- Falsification result.
- Remediation guidance.
- Machine-readable finding certificate.

## Evaluation strategy

### Stage-level failure funnel

Each evaluation case should identify expected intermediate artifacts when
ground truth permits:

- Target file and function.
- Entry point.
- Source and sink.
- Relevant transformation.
- Expected invariant.
- Effective or missing guard.
- Trigger constraints.
- Reproduction behavior.
- Threat model and security consequence.

Track whether each stage succeeds:

1. Target code appears in the ranked working set.
2. Relevant facts are extracted.
3. A candidate covering the true mechanism is generated.
4. The correct proof plan is selected.
5. Reachability and dataflow obligations resolve correctly.
6. Guards and counterevidence are handled correctly.
7. A trigger or validation plan is constructed.
8. Dynamic or static validation produces the expected evidence.
9. The threat model is classified correctly.
10. The finding or rejection certificate is compiled correctly.

This separates discovery failures from reporting and verification
failures.

### Staged model ablations

For each known vulnerability, run progressively easier variants:

1. Repository only.
2. Target file supplied.
3. Target function supplied.
4. Source and sink supplied.
5. Invariant and suspected path supplied.
6. Complete trace supplied.
7. Trigger supplied; the model only explains and reports.

Run identical context packets across model tiers. The differences locate
which reasoning task causes the frontier/local performance gap.

### Counterfactual repositories

Each evaluation case should include counterfactual variants where
practical:

- Patched repository.
- Vulnerability moved to a different file.
- Symbols and variables renamed.
- Equivalent code expressed with different syntax.
- Similar-looking decoy path added.
- Guard moved into a caller.
- Vulnerable code made unreachable.
- Same crash retained while security impact is removed.
- Threat model changed through authentication or configuration.
- A second unrelated bug introduced.

Transformations fall into three useful categories:

- **Invariant-preserving:** names, layout, or syntax change while the
  security property remains the same.
- **Invariant-repairing:** the actual vulnerability is removed.
- **Threat-model-changing:** technical behavior remains, but attacker
  capability, reachability, or severity changes.

Corresponding metrics are:

- **Representation invariance:** findings survive superficial changes.
- **Causal sensitivity:** findings disappear or weaken when the defect is
  repaired.
- **Threat-model sensitivity:** severity and conclusions change correctly
  when attacker assumptions change.

### Core metrics

End-to-end discovery remains important, but it should be accompanied by:

- Target recall at K.
- Candidate recall and candidates per true finding.
- Candidate precision after each proof stage.
- Source/sink and invariant classification accuracy.
- Path-completion accuracy.
- Guard-analysis accuracy.
- Context insufficiency detection accuracy.
- Harness compilation and reproduction rates.
- Threat-model and impact accuracy.
- Falsifier true-positive and false-rejection rates.
- Counterfactual consistency.
- Finding-certificate correctness.
- Rejection-certificate correctness.
- Unsupported-claim rate.
- Cost, latency, and frontier-escalation rate.
- Local-only completion rate.
- Percentage of runs ending with useful incomplete certificates.

### Calibration

Scheduler estimates and model confidence should be calibrated by:

- Model and model version.
- Language and framework.
- Invariant and proof-plan family.
- Action and obligation type.
- Context completeness.
- Evidence type.

Calibration data should influence routing, not redefine proof
requirements.

## Integration with the current sourcehunt pipeline

The proposal is an evolution of existing components rather than a full
rewrite.

| Current component | Proposed responsibility |
|---|---|
| Preprocessor | Emit normalized facts with provenance |
| Static patterns, Semgrep, taint | Emit evidence and typed candidates |
| Callgraph and reachability | Populate facts, claims, and completeness manifests |
| Ranker | Prioritize fact extraction and candidate-generation scope |
| HunterPool | Schedule candidate obligations and actions rather than whole-file hunts |
| NativeHunter | Become a bounded obligation resolver and exploratory worker |
| Hunter tools | Return typed evidence artifacts |
| Trace recording | Persist authoritative evidence and graph edges immediately |
| Harness generator | Select templates, reuse tests, and run compile-repair actions |
| Verifier | Become proof-plan adjudication plus independent falsification |
| Validator | Execute class-specific evidence gates rather than a single broad judgment |
| Mechanism memory | Store invariant, generator, proof-plan, and falsifier lessons |
| Variant hunter | Generate structurally related candidates sharing evidence |
| Reporter | Compile evidence-constrained finding and rejection certificates |

Existing file ranking remains useful for controlling how much of a large
repository receives expensive preprocessing. It should no longer decide
the unit of cognitive work after candidates exist.

## FFmpeg H.264 proof-flow migration scenario

The existing [FFmpeg H.264 sourcehunt walkthrough](FFmpeg.md) is a useful
end-to-end benchmark for this design. It describes a blind hunt for a
slice-counter vulnerability at FFmpeg commit
**795bccdaf57772b1803914dee2f32d52776518e2**, with public fix commit
**39e1969303a0b9ec5fb5f5eb643bf7a5b69c0a89** reserved as a post-run
oracle.

The proof-oriented flow is now available behind `--flow proof`, and the
walkthrough has been updated as described in this section. The vulnerable and fixed commits,
blindness requirements, sanitizer build, and post-discovery oracle remain
useful. What changes is the unit of work and the meaning of a successful
run.

The current scenario largely asks several agents to inspect highly ranked
files, keep their own investigation state, and emit findings. The updated
scenario should demonstrate that Clearwing can:

1. Discover a representation-domain collision without knowing the fix.
2. Convert that observation into a typed candidate.
3. Instantiate a threat model and composed proof plan.
4. Resolve independent obligations with mechanical tools and bounded
   model judgments.
5. Preserve incomplete or conflicting evidence.
6. Reproduce the unsafe behavior when a suitable runtime backend is
   available.
7. Run a finite falsification plan.
8. Emit a proof-carrying finding for the vulnerable snapshot.
9. Emit a rejection certificate, or invalidate the vulnerable proof, for
   the fixed snapshot.
10. Remain causally consistent under renamed, moved, guarded, unreachable,
    and decoy counterfactuals.

### Why this case is architecturally useful

The FFmpeg case is not merely a familiar integer-overflow pattern. Its
important invariant crosses representation, parser state, and memory
safety:

- Macroblock ownership is represented in a 16-bit slice table.
- The all-ones value **0xFFFF** represents "no owning slice."
- A wider slice counter can reach a value that aliases the reserved
  sentinel when represented in the table.
- Neighbor and same-slice logic can then interpret an unowned or padding
  location as belonging to the current slice.
- The deblocking path can use that false state relation in a way that
  reaches an out-of-bounds heap write.

The root invariant is therefore not simply "an integer must not overflow."
It is:

~~~text
valid_slice_identifier_domain does not intersect reserved_sentinel_domain
~~~

That representation invariant composes with:

~~~text
neighbor ownership decisions reflect real decoded ownership

and

accessed_region is a subset of allocated_region
~~~

A successful system must connect those layers. This makes the case a
strong test of whether the obligation architecture can decompose a
cross-function vulnerability without losing the causal chain.

### Scenario modes

The updated walkthrough should define four distinct modes and never mix
their evidence.

#### Blind structured discovery

Clearwing receives only the vulnerable repository snapshot and build
environment. It may use generic invariant generators and standard
mechanism knowledge, depending on the benchmark policy, but it receives
no FFmpeg-specific hint, H.264-specific campaign hint, CVE description,
patch, pull request, or fix-derived rule.

This is the primary discovery measurement.

#### Blind exploratory discovery

A fixed minority of the budget is assigned to the exploratory lane. It
receives the same blind snapshot and may propose novel invariants or
architectural anomalies. Any observation must enter the same structured
candidate and proof flow before it can become a finding.

This measures whether the system can escape its existing generator
ontology.

#### Assisted diagnostic controls

Target-file, target-function, source/sink, invariant, and trace hints are
introduced one at a time. These runs are not discovery successes. They
locate the exact stage at which a model or tool fails.

Generic CVE seeding and a campaign hint such as "integer overflows and
type mismatches in media codec parsers" belong in this control category,
not in the strict blind baseline.

#### Post-discovery oracle

Only after the blind run is sealed may Clearwing inspect the public fix.
The fixed commit, patch differential, and retro-hunt results are
counterfactual evidence. They test causal consistency and variant
detection but must not be added retroactively to the blind certificate.

### Blindness and contamination controls

The updated scenario should retain the current checkout isolation and add
artifact-level provenance:

- Pin the vulnerable snapshot exactly.
- Record the repository object ID and dirty-tree digest.
- Use a fresh Clearwing home and artifact directory.
- Disable mechanism memory for the strict baseline, or use a
  benchmark-frozen generic mechanism store whose contents are published.
- Do not enable CVE-log seeding in the strict blind baseline.
- Do not provide a vulnerability-class campaign hint in the strict blind
  baseline.
- Do not expose the fix commit, fix subject, pull request, CVE text, or
  this walkthrough to any discovery model.
- Record every prompt template, context packet, model identifier, tool
  version, and environment digest.
- Seal the blind run manifest before fetching the fix.
- Label all later evidence with the fixed or oracle snapshot rather than
  the blind snapshot.

These rules make it possible to distinguish true discovery from
patch-shaped recognition.

### Shipped invocation

The implemented migration interface is:

~~~bash
clearwing sourcehunt "$FFMPEG_DIR" \
  --flow proof \
  --compile-commands compile_commands.json \
  --build-configuration asan-debug \
  --depth deep \
  --model-routing local-first \
  --structured-budget 90% \
  --exploration-budget 10% \
  --proof-plan auto \
  --proof-max-actions 200 \
  --proof-max-model-calls 40 \
  --proof-max-dynamic-actions 20 \
  --retain-incomplete-certificates \
  --emit-rejection-certificates \
  --falsify \
  --no-mechanism-memory \
  --gvisor \
  --output-dir "$CASE_DIR/results-proof-blind" \
  --format all
~~~

For C/C++, `compile_commands.json` and a sandbox are hard prerequisites.
Dynamic validation is optional and is supplied with
`--validation-manifest <path>`; every entry is tied to one candidate
mechanism, obligation predicate, action type, bounded command, repetition
requirement, and success condition. No host-execution fallback exists.

The proof flow changes the meaning of several current tuning controls:

| Current walkthrough concept | Proof-flow replacement |
|---|---|
| Per-file hunter | Candidate and obligation work queue |
| Entry-point shard | Reachability fact scope and bounded context packet |
| Three independent agents per file | Redundancy on selected atomic obligations |
| Tier A/B/C model budget | Value-of-information action scheduling |
| Campaign hint | Optional assisted-control input or exploratory prompt |
| CVE seed context | Optional contaminated-control input |
| Hunter trace | Authoritative evidence and derivation graph |
| Adversarial verifier | Proof-plan adjudication plus bounded falsifier |
| Four broad validation axes | Typed obligations for reality, reachability, impact, and generality |
| Repeated independent passes | Reproducible packet replay plus selected decision redundancy |
| Search report text for success | Query the candidate and certificate graph |

The old and new flows may coexist temporarily. A migration run should
record which engine produced each finding so their results are not
mistakenly pooled.

### Expected run artifacts

In addition to the existing human-readable, JSON, and SARIF reports, the
proof-flow scenario should produce:

~~~text
<session>/
  manifest.json
  snapshots/
    snapshots.jsonl
  facts/
    facts.jsonl
    extraction-coverage.json
  candidates/
    candidates.jsonl
    duplicates.json
  threats/
    threat-models.jsonl
  proof-graphs/
    <candidate-id>.json
  context-packets/
    packets.jsonl
  actions/
    action-log.jsonl
  evidence/
    evidence.jsonl
  artifacts/
    index.jsonl
    sha256/...
  certificates/
    findings/
    rejections/
    incomplete/
  falsification/
    <candidate-id>.json
  metrics/
    run-metrics.json
  spend-ledger.jsonl
  spend-summary.json
  report.md
  findings.json
  findings.sarif
~~~

The final manifest must identify the blind boundary and atomically merge the
proof snapshot with the run-wide spend summary and output index. The ledger
checkpoints to `spend-summary.json` during proof execution, so an interrupted
provider call cannot replace the proof manifest. Physical model calls in
`spend-ledger.jsonl` carry stable proof action, candidate, and
obligation identifiers. `metrics/run-metrics.json` joins those calls back to
the proof graph and reports cost, tokens, evidence yield, terminal obligation
states, and unlinked calls by action template, model route, and predicate.
Oracle artifacts obtained
after inspecting the fix must live in a separate session or a clearly
separate post-discovery namespace.

### Phase A: snapshot and fact extraction

The first phase creates a normalized snapshot without making a
vulnerability claim.

For this case, relevant facts may include:

- Definitions and widths of the slice counter and table element type.
- The initialization value used for unowned slice-table entries.
- Assignments from the wider counter into the table representation.
- Comparisons that interpret table values as slice identities.
- Counter increments and any upper bounds.
- Parser entry points capable of advancing the slice counter.
- Calls from slice decoding into neighbor and deblocking logic.
- Allocation and padding facts for the affected data structures.
- Compile-time and runtime conditions enabling H.264 decoding and
  deblocking.
- Existing H.264 tests, corpus inputs, decoder binaries, and build
  commands.

The extractor should not be required to know in advance that these facts
belong to one vulnerability. Facts retain source locations and producer
provenance.

An extraction coverage record should explicitly name limitations such as:

~~~yaml
types:
  status: complete
  basis: clang-ast
macro_expansions:
  status: complete
  basis: ffmpeg-compile-database
direct_calls:
  status: complete
  basis: llvm-cfg
indirect_calls:
  status: partial
  unresolved:
    - architecture-specific H.264 DSP dispatch
configuration_variants:
  status: partial
  analyzed:
    - default-debug
    - asan-debug
  omitted:
    - hardware-accelerated decoders
~~~

Hardware-specific paths remaining unresolved must not silently become
evidence that no alternative guard or behavior exists.

### Phase B: invariant-oriented candidate generation

Several generators may independently contribute to the same candidate:

- A reserved-sentinel/domain generator notices that a live identifier can
  occupy the sentinel value.
- A narrowing or representation generator notices that a wider counter is
  stored or compared in a 16-bit domain.
- A state-contrast generator notices inconsistent meanings for the same
  numeric value.
- A spatial-safety generator links the resulting neighbor decision to an
  unsafe access candidate.
- An exploratory worker may identify the sentinel collision even if no
  structured generator recognizes it.

These observations should merge into a composed candidate instead of
becoming duplicate reports:

~~~yaml
id: candidate:ffmpeg-slice-sentinel
snapshot_id: snapshot:795bccd:asan-debug
invariant_families:
  - representation_domain_safety
  - state_machine_safety
  - spatial_safety
suspected_mechanism: live_identifier_aliases_reserved_sentinel
source:
  concept: attacker-influenced decoded slice count
transformations:
  - wider counter advances across decoded slices
  - counter value is represented in a 16-bit ownership table
state_sink:
  concept: slice-table ownership and same-slice decision
impact_sink:
  concept: deblocking neighbor memory access
suspected_invariants:
  - valid slice identifiers must not equal 0xFFFF
  - ownership comparisons must not classify sentinel entries as owned
  - deblocking accesses must remain inside valid neighbor storage
proof_plans:
  - representation-domain-collision-v1
  - memory-write-v1
open_questions:
  - can untrusted input drive the counter to the reserved value?
  - does a dominating upper-bound guard exist?
  - where is narrowing or equality semantics applied?
  - does the collision change a neighbor decision?
  - can that decision reach the suspected write in a production path?
  - can the behavior be reproduced in a supported build?
~~~

The exact symbol and evidence IDs are filled from extraction. The
candidate description uses concepts where a relationship remains
unresolved rather than fabricating a concrete edge.

### Phase C: threat-model construction

The initial threat model should be explicit and revisable:

~~~yaml
attacker_principal: untrusted_media_supplier
attacker_capabilities:
  - provide a crafted H.264 bitstream
trust_boundary:
  - encoded media input to decoder process
protected_assets:
  - decoder process memory integrity
  - host application availability
required_privileges: none within the decoding interface
deployment_assumptions:
  - software H.264 decoder is enabled
  - input reaches the affected slice and deblocking path
capability_gained:
  - initially unknown
security_properties_under_test:
  - memory integrity
  - memory safety
~~~

"Remote unauthenticated attacker" should not be asserted unless an
application deployment and network entry point establish that stronger
principal. The generic FFmpeg library case can prove that untrusted media
crosses a decoder trust boundary without overstating the deployment.

Threat-model obligations include:

- Is the affected decoder enabled in the analyzed build?
- Can a user-controlled bitstream reach the software path?
- Are the slice count and required decoder state controllable through
  valid or sufficiently parsed input?
- Does the resulting behavior cross memory integrity or only terminate
  decoding safely?
- Which applications or transports, if any, make the input remotely
  reachable?

### Phase D: composed proof plan

This case should instantiate a representation-domain proof plan and then
compose it with the memory-write proof plan.

The representation-domain plan requires:

~~~text
P1. A numeric or symbolic value is reserved as a sentinel.
P2. Live identifiers share the same representation domain.
P3. A reachable execution can generate the reserved value as a live ID.
P4. No effective guard prevents that value.
P5. At least one consumer cannot distinguish live ID from sentinel.
P6. The ambiguity changes a security-relevant state decision.
~~~

The spatial-safety continuation requires:

~~~text
M1. The incorrect state decision reaches a memory access.
M2. The selected address or extent violates the live object boundary.
M3. A concrete input or symbolic witness satisfies the path constraints.
M4. The behavior occurs in a realistic decoder configuration.
M5. Runtime or equivalently strong evidence confirms the unsafe access.
M6. The threat model establishes a protected security boundary.
~~~

The resulting obligation graph is not a single fixed sequence:

~~~text
reserved sentinel established ─────┐
live identifier domain established ├─> domain overlap established
counter range established ─────────┘             |
                                                  v
attacker influence ────────────────> reserved value reachable
upper-bound guards enumerated ─────> no effective guard
                                                  |
                                                  v
table representation + comparisons ─> semantic collision
                                                  |
                         ┌────────────────────────┘
                         v
neighbor decision changes
        |
        +──────────────> deblocking path reachable
                               |
object bounds established ─────┼─> unsafe access constraints satisfied
                               |
trigger constructed ───────────┘
        |
        v
runtime behavior reproduced
        |
        +────────> realistic configuration
        +────────> security boundary crossed
        |
        v
reportable finding
~~~

If runtime reproduction is blocked, the static obligations may still
produce a valuable incomplete certificate. Failure to compile a harness
does not disprove the domain collision.

### Phase E: value-of-information investigation

The scheduler should prefer reusable, inexpensive questions before
launching a large model or long fuzzing job.

An expected action sequence is:

1. **Extract table width, counter width, and sentinel value.**
   AST and constant analysis emit reusable representation facts.
2. **Enumerate assignments and comparisons involving the table.**
   Dataflow and query tools emit candidate edges.
3. **Compute the counter's reachable range and update sites.**
   Range analysis, followed by a local model only if needed, emits a
   bounded range claim.
4. **Enumerate dominating and caller-side upper bounds.**
   CFG, callgraph, and bounded guard classification emit guard claims.
5. **Establish parser entry-point influence.**
   Reachability and taint analysis emit an attacker-control claim.
6. **Explain how the collision changes ownership semantics.**
   A local model receives a bounded packet and emits a state-transition
   derivation.
7. **Trace the changed decision into deblocking access.**
   The slicer and static tools emit impact-path claims. A stronger model
   handles only unresolved hops.
8. **Solve or synthesize the required input constraints.**
   Constraint tools and harness templates emit a trigger artifact.
9. **Build and run the decoder with sanitizers.**
   The FFmpeg build backend emits retained runtime evidence.
10. **Run the finite falsification obligations.**
    Independent resolvers emit counterevidence or a scoped falsifier
    result.

This sequence is illustrative, not mandatory. If an existing FFmpeg test
or corpus input provides high-value dynamic evidence early, the scheduler
may run it before completing every static edge. The graph records which
obligations remain unresolved.

The scheduler should reuse facts across all H.264 candidates. It should
not repeatedly ask separate agents to rediscover the table width,
sentinel, callers, or build configuration.

### Phase F: bounded context packets

The important model question is not "audit H.264 for vulnerabilities."
Examples of appropriate packets are:

#### Sentinel-domain packet

~~~text
Question:
  Can a live slice identifier equal the value representing an unowned
  slice-table entry?

Included:
  counter declaration and update sites
  slice-table element type
  sentinel initialization
  assignments into the table
  all discovered upper-bound guards

Permitted answers:
  proven_possible
  proven_impossible
  insufficient_context
  conflicting_evidence
~~~

#### Guard packet

~~~text
Question:
  Does any included guard dominate every path that assigns the next slice
  identifier, and does it establish slice_num < 0xFFFF?

Included:
  control dominators
  direct and resolved indirect callers
  relevant macros and constants
  configuration scope

Required output:
  guard ID
  dominated operations
  established predicate
  uncovered paths
  missing context
~~~

#### Semantic-consequence packet

~~~text
Question:
  If the current live slice identifier equals 0xFFFF, which ownership
  comparison changes meaning, and what downstream branch does that alter?

Included:
  table initialization and writes
  same-slice or neighbor comparisons
  bounded callers and callees
  table padding facts

Required output:
  exact comparison
  normal interpretation
  collision interpretation
  changed branch
  evidence references
~~~

#### Memory-access packet

~~~text
Question:
  Under the changed branch, identify the first access whose selected
  object or extent can fall outside the valid neighbor region.

Included:
  deblocking slice
  object layout and padding
  address expressions
  relevant range constraints
  unresolved aliases

Permitted result:
  an exact evidence-linked edge
  a concrete safety proof
  a named missing alias or call target
~~~

Each packet includes a completeness manifest. A smaller model's
"insufficient context: unresolved architecture-specific DSP callback"
response should schedule a callback-resolution action rather than count
as a failed hunt.

### Phase G: dynamic validation

The preferred dynamic path is to reuse FFmpeg's actual build, decoder, and
test infrastructure rather than isolate a complex H.264 function in an
unrealistic standalone harness.

The validation backend should:

1. Recover or generate the FFmpeg build configuration.
2. Build the vulnerable snapshot with ASan and UBSan.
3. Reuse an existing H.264 parser, decoder test, or fuzz target when
   possible.
4. Generate or mutate a bitstream that advances the relevant slice state
   while satisfying necessary parser constraints.
5. Record coverage of the counter update, collision, changed decision, and
   suspected deblocking access.
6. Run the input in fresh containers enough times to characterize
   stability.
7. Preserve the input, command, build manifest, coverage, sanitizer
   output, exit status, and environment digest.

Dynamic evidence should be attached to individual claims:

- Coverage of the counter update supports reachability.
- Observing **0xFFFF** as a live identifier supports domain collision.
- A changed ownership branch supports the semantic-consequence claim.
- ASan output supports the out-of-bounds access claim.
- Repetition supports stability, not attacker reachability.

If generating 65,535 or more relevant slices is expensive, the scheduler
may use a staged plan:

- Static or symbolic range proof.
- A state-injection harness that tests the downstream collision
  consequence.
- A production-faithful bitstream attempt.

The state-injection harness can establish downstream behavior but cannot
by itself prove that a real bitstream reaches that state. The report must
keep those claims separate until both obligations resolve.

### Phase H: finite falsification plan

The FFmpeg falsifier should try to establish at least one of the following:

- The counter cannot reach **0xFFFF** through parsed input.
- A dominating local or caller-side guard prevents the value.
- The table stores a transformed value that does not collide with the
  sentinel.
- All consumers distinguish the live identifier from the sentinel through
  additional state.
- The apparent neighbor branch is unreachable in the affected
  configuration.
- Padding or allocation layout makes the suspected access valid.
- The ASan result is introduced by the generated harness.
- The input is rejected before the affected state in a production decoder.
- Hardware or alternate decoder paths are being confused with the
  vulnerable software path.
- The behavior produces no security-relevant capability under the stated
  threat model.

The falsifier receives atomic claims and evidence, not the candidate's
persuasive narrative. Each counterclaim must cite concrete evidence or
remain unknown.

### Phase I: proof-carrying output

A strong vulnerable-snapshot finding certificate should establish
separate claims for:

- The reserved meaning and representation of **0xFFFF**.
- The domain and reachable range of live slice identifiers.
- Attacker influence over the decoding progression.
- Absence of an effective upper-bound guard.
- Collision between a live identifier and the sentinel.
- The ownership or neighbor decision changed by that collision.
- The path from that decision to an unsafe deblocking access.
- The observed or otherwise strongly established memory-safety violation.
- The realistic decoder configuration.
- The security boundary and capability affected.

The certificate should preserve any weaker conclusion. For example, if
the evidence proves a heap out-of-bounds write but not practical code
execution, the report must stop at the supported memory-integrity claim.

A useful incomplete certificate may instead say:

~~~text
Proven:
  live identifier can collide with the reserved table sentinel
  no discovered guard prevents the collision
  the collision changes a neighbor-ownership decision

Unknown:
  production-faithful bitstream reaching the required count
  exact out-of-bounds address under all supported architectures

Blocked:
  sanitizer build unavailable in the current environment
~~~

That artifact is materially better than losing the investigation because
the hunter could not finish a PoC.

### Phase J: fixed-commit counterfactual

After sealing the blind result, run the same fact extractors, candidate
generators, proof plans, and context-packet templates against fix commit
**39e1969303a0b9ec5fb5f5eb643bf7a5b69c0a89**.

The public fix should introduce evidence for an upper-bound obligation
that prevents a live slice identifier from reaching the reserved value.
The expected result is:

- The original vulnerable certificate becomes invalid for the new
  snapshot.
- The representation-domain candidate is regenerated or carried forward
  for comparison.
- Its reachability or no-effective-guard obligation becomes disproven.
- Dynamic reproduction no longer reaches the collision or unsafe path.
- Clearwing emits a rejection certificate scoped to the fixed snapshot.

An illustrative rejection certificate is:

~~~yaml
candidate: candidate:ffmpeg-slice-sentinel
snapshot_id: snapshot:39e1969:asan-debug
decision: disproven
reason: reserved_value_rejected_by_dominating_guard
established_predicate: next_slice_identifier < 0xFFFF
invalidated_vulnerable_claims:
  - reserved_value_reachable
  - no_effective_guard
preserved_claims:
  - slice_table_uses_0xFFFF_sentinel
  - table_element_width_is_16_bits
dynamic_control:
  result: trigger_rejected_before_collision
scope:
  decoder: software_h264
  configuration: asan-debug
~~~

The fix diff may explain why the behavior changed, but causal consistency
comes from rerunning the same proof obligations on both snapshots.

### Phase K: FFmpeg counterfactual suite

The migrated scenario should add generated or maintained variants:

| Variant | Expected behavior |
|---|---|
| Vulnerable parent | Finding certificate or evidence-rich incomplete certificate |
| Public fixed commit | Rejection certificate for the original mechanism |
| Symbols renamed | Same conclusion and proof structure |
| Relevant function moved | Same conclusion after graph reconstruction |
| Harmless **0xFFFF** decoy added | No extra confirmed finding |
| Guard moved into every caller | Candidate rejected by caller-side evidence |
| One unguarded caller retained | Finding remains, scoped to that caller |
| Deblocking path made unreachable | Domain collision may remain, memory-impact claim weakens |
| Table representation widened with a distinct sentinel | Original collision claim disappears |
| Harness-only crash introduced | Falsifier rejects production-impact claim |
| Hardware decoder only | Software-path finding becomes not applicable to that configuration |

These variants measure representation invariance, causal sensitivity,
context completeness, and threat-model sensitivity. They should not all
be used as training cases before the corresponding held-out evaluation.

### Phase L: local-versus-frontier evaluation

The FFmpeg case should be replayed as identical obligation packets across
model tiers.

Suggested staged packets are:

1. Repository-only blind discovery.
2. Relevant fact cluster supplied.
3. Candidate source and state sink supplied.
4. Reserved-domain invariant supplied.
5. Collision proof supplied; ask for semantic consequence.
6. Consequence supplied; ask for the memory-access path.
7. Full static graph supplied; ask only for a validation plan.
8. Runtime evidence supplied; ask only for evidence-constrained reporting.

For every packet, measure:

- Correct typed decision.
- Correct evidence references.
- Appropriate use of insufficient-context output.
- Unsupported claims.
- Tokens, latency, and retries.
- Whether stronger-model escalation resolves the stated ambiguity.

The objective is not merely to make a local model emit the final CVE
description. It is to determine how much of the proof graph local models
can resolve reliably and where a frontier model adds measurable value.

### Updated scenario success criteria

The migrated FFmpeg walkthrough should report several success levels:

#### Discovery success

A blind generator or exploratory worker creates a candidate containing
the live-identifier/sentinel collision without fix-derived input.

#### Mechanism success

The graph establishes the reserved-domain collision and its effect on
slice ownership semantics.

#### Static impact success

The graph connects the changed ownership decision to a concrete unsafe
memory-access condition with no unresolved safety guard.

#### Dynamic success

A retained input and production-representative build reproduce the unsafe
access with coverage and sanitizer evidence.

#### Security success

The threat model establishes attacker influence, realistic configuration,
protected asset, and capability gained without overstating exploitability.

#### Counterfactual success

The same process rejects the fixed snapshot, survives representation-only
changes, and changes its conclusion correctly when reachability or threat
assumptions change.

#### Efficiency success

Most fact extraction and atomic obligations are resolved mechanically or
by local models. Frontier calls are limited to named ambiguities and
produce measurable information gain.

This level-based evaluation preserves useful partial progress and makes
the frontier/local gap diagnosable.

### Documentation migration

The implemented **docs/FFmpeg.md** migration follows this checklist:

1. Retain case metadata, vulnerable checkout, fixed checkout, blindness
   rules, ASan build guidance, and sandbox safety guidance.
2. Replace the broad blind-discovery command with the supported proof-flow
   command and explain each new option.
3. Move **--seed-cves** and **--campaign-hint** into a clearly labeled
   assisted-control section.
4. Replace repeated whole-run passes with obligation-packet replay and
   bounded decision redundancy.
5. Replace report-text grep as the primary success check with candidate,
   obligation, evidence, and certificate queries.
6. Add examples for inspecting completeness manifests, unresolved
   obligations, action history, and falsifier results.
7. Add the vulnerable-versus-fixed rejection-certificate comparison.
8. Add counterfactual consistency results.
9. Preserve the current report, SARIF, disclosure, and patch workflows as
   downstream consumers of a finding certificate.
10. Clearly label old-engine commands during any transition period.

The walkthrough now uses the proof command as its strict blind baseline,
labels the old file-agent workflow as a legacy control, documents the
append-only graph queries, and includes vulnerable-versus-fixed and optional
manifest-driven runtime validation flows. This section remains the acceptance
scenario and migration contract for final replacement of the legacy default.

## Implementation plan

### Implementation status (July 2026)

The migration implementation is now present behind `--flow proof`:

**Phase 0 implementation: 100%. Phase 1 implementation: 100%. Phase 2
implementation: 100%. Phase 3 implementation: 100%. Phase 4 implementation:
100%. Phase 5 implementation: 100%.** These percentages describe repository
implementation and fixture-level acceptance coverage, not a claim that an
unrun paid-model or FFmpeg campaign produced measurements. Empirical campaign
reports remain separately versioned artifacts, and the baseline,
counterfactual, and learning-coverage compilers keep those measurements
separate from implementation status.

- Strict snapshot, fact, evidence, claim, assumption, threat-model,
  candidate, obligation, action, derivation, context-packet, and certificate
  schemas.
- Append-only JSONL state, immutable content-addressed artifacts, materialized
  obligation DAGs, revision history, and dependency invalidation.
- Required sandboxed Clang plus `compile_commands.json` for C/C++, syntax
  adapters for all eleven first-class language families, and reusable
  tree-sitter callgraph and taint facts where grammars exist.
- Invariant-oriented deterministic generators and versioned proof plans for
  representation/spatial, parser, authorization, temporal, state-machine,
  cryptographic, injection, concurrency, and resource safety.
- Completeness-aware bounded packets containing the threat model, prior atomic
  claims, evidence summaries, and only cited repository facts.
- A global value-of-information scheduler with shared run-wide action, model,
  dynamic, exploration, and falsification accounting; local judgments receive
  one bounded frontier escalation.
- A bounded exploratory lane, finite independent falsifier, strict
  manifest-driven sandbox validation, evidence-class gates, rejection and
  incomplete certificates, and unsupported-claim auditing.
- Markdown, JSON, and SARIF finding compilation, stage-aware evaluation,
  counterfactual scoring, explicit cutover gates, an FFmpeg evaluation runner,
  and the migrated `docs/FFmpeg.md` scenario.
- Authoritative streamed legacy hunter traces, so evidence state is persisted
  when observed rather than reconstructed at report time.
- Action-attributed model-call telemetry, calibration-ready run metrics,
  finalized falsification views, and a combined proof/spend manifest that
  cannot be overwritten by ledger checkpointing.
- Session-local legacy instrumentation with stable run, work-item, model-call,
  tool-action, trajectory-event, and finding joins; per-stage file/symbol
  inventories; and separately retained reporting failures.
- A strict five-case intermediate-ground-truth manifest, seven-level ablation
  planner, resumable local/frontier campaign executor, session scorer, and
  completeness-gated precision/recall/cost/failure-stage baseline compiler.
- Live assumption records in candidate graphs, bounded packets, falsifier
  packets, certificates, and reports. Assumption revisions now stale dependent
  claims and obligations and persist stale certificate successor revisions.
- Versioned canonical allocation, access, length, cast, guard, and call facts;
  allocation-versus-access spatial candidates; explicit attacker-reachability
  and bounds obligations; and deterministic safe-containment and dominating-
  guard rejection paths.
- Reusable manifest-declared libFuzzer/ASan/UBSan harness templates that are
  materialized and compiled inside the sandbox, with build and runtime
  artifacts retained separately.
- Manifest-driven vulnerable, fixed, renamed, moved, guarded, unreachable,
  decoy, and widened-domain counterfactual scoring with exact-matrix
  validation.
- Portable scheduler-calibration artifacts compiled from observed action yield
  and spend, enforced structured/exploratory allocation, candidate starvation
  prevention, explicit local/frontier model identities, and escalation audit
  telemetry.
- Bug-class-specific Phase 4 resolvers, completeness dimensions, falsification
  checklists, and decisive dynamic evidence gates for parser, authorization,
  temporal, state-machine, cryptographic, injection, concurrency, and resource
  investigations. An incidental guard, encoder, lock, or limit marker cannot
  prove safety without effectiveness or complete supporting analysis.
- Typed exploratory retrospectives, explicit reviewed promotion into a
  content-addressed learning registry, mechanical promoted-mechanism candidate
  generation, reviewed bindings to installed proof plans, mandatory rejection
  and counterfactual regression specifications, and before/after local-model
  coverage reports.

This is a migration release, not an evidence-free default flip. `legacy`
remains the default until measured frontier recall is no worse than legacy,
local recall improves by at least ten percentage points, precision does not
regress, and mean cost remains within 1.25x. Real FFmpeg vulnerable/fixed runs,
retained runtime triggers, and the broader counterfactual corpus are campaign
artifacts that must be produced by evaluation infrastructure; the repository
contains the runner, schemas, fixture-level tests, and gate evaluator needed
to measure them. A missing harness, tool, model route, indirect edge, or build
configuration remains explicit `blocked` or `unknown` state and never becomes
an accepted finding.

### Phase 0: Instrument the current funnel

- [x] Assign stable IDs to runs, work items, model calls, tool actions, and
  findings.
- [x] Record which files and symbols enter each stage.
- [x] Preserve hunter trajectories and reporting failures.
- [x] Add intermediate ground truth to representative CVE evaluations.
- [x] Provide and test a resumable staged-ablation runner that executes
  identical hint packets across frontier and local models.
- [x] Establish a completeness-gated baseline compiler for precision, recall,
  cost, unsupported claims, report failures, and first-failure-stage metrics.

This phase determines where mechanization will yield the largest return.

The ground truth lives in
`evaluations/sourcehunt_ground_truth.yaml`. A reproducible campaign uses:

~~~bash
clearwing eval sourcehunt-plan \
  --ground-truth evaluations/sourcehunt_ground_truth.yaml \
  --local-model LOCAL_MODEL \
  --frontier-model FRONTIER_MODEL \
  --output results/sourcehunt-eval/plan.json

clearwing eval sourcehunt-run \
  --plan results/sourcehunt-eval/plan.json \
  --ground-truth evaluations/sourcehunt_ground_truth.yaml \
  --checkout CASE_ID=/path/to/vulnerable/checkout \
  --budget-per-run 10 \
  --output-dir results/sourcehunt-eval/sessions \
  --checkpoint results/sourcehunt-eval/observations.json

clearwing eval sourcehunt-baseline \
  --plan results/sourcehunt-eval/plan.json \
  --observations results/sourcehunt-eval/observations.json \
  --output results/sourcehunt-eval/baseline.json

clearwing eval sourcehunt-calibrate \
  --observations results/sourcehunt-eval/observations.json \
  --output results/sourcehunt-eval/scheduler-calibration.json
~~~

`sourcehunt-run` verifies that each supplied checkout is at the manifest's
vulnerable commit before dispatch. It requires a positive per-run budget,
rejects tracked checkout changes, checkpoints atomically after every arm, and
automatically resumes the checkpoint by stable run ID. C/C++ cases also
require a per-case `--compile-commands CASE_ID=PATH`; runtime evidence can be
provided with `--validation-manifest CASE_ID=PATH`. Level 1 supplies no oracle
hint. Levels 2–7 reveal only their declared cumulative information. Each
local/frontier pair receives the exact same serialized hint packet. Assisted
hints are recorded in the proof manifest and packets but are never accepted as
evidence. `sourcehunt-baseline` validates every observation against its plan
and fails closed when any planned arm is missing unless `--allow-incomplete`
is explicitly requested, in which case the report is visibly marked
incomplete.

The calibration command derives per-action information yield, cost, and time
from completed proof sessions. A later proof run consumes the artifact with
`--scheduler-calibration`; it never treats a model's self-reported confidence
as calibration data. Counterfactual sessions are scored as one complete,
causally related matrix:

~~~bash
clearwing eval sourcehunt-counterfactual \
  --manifest evaluations/ffmpeg_proof.yaml \
  --session vulnerable=/path/to/vulnerable/session \
  --session fixed=/path/to/fixed/session \
  --session renamed=/path/to/renamed/session \
  --session moved=/path/to/moved/session \
  --session guarded=/path/to/guarded/session \
  --session unreachable=/path/to/unreachable/session \
  --session decoy=/path/to/decoy/session \
  --session widened-domain=/path/to/widened/session \
  --output results/sourcehunt-eval/ffmpeg-counterfactual.json
~~~

### Phase 1: Proof substrate

- [x] Implement snapshot, fact, evidence, claim, assumption, obligation,
  action, derivation, and certificate schemas.
- [x] Add immutable artifact storage and provenance.
- [x] Make trace steps authoritative rather than conversation-only.
- [x] Allow findings to reference evidence IDs.
- [x] Implement dependency invalidation and stale-state propagation, including
  durable stale certificate revisions for file, symbol, evidence, and
  assumption changes.
- [x] Emit incomplete certificates when a run exhausts its budget.

This phase should initially coexist with the current hunter.

### Phase 2: Spatial-memory-safety vertical slice

- [x] Normalize allocation, access, length, cast, guard, and callgraph facts.
- [x] Implement allocation-versus-access candidate generators.
- [x] Add the memory-write proof plan.
- [x] Build completeness-aware context packets.
- [x] Add bounded guard, reachability, and attacker-control resolvers.
- [x] Reuse or template sanitizer harnesses.
- [x] Implement the memory-safety falsifier.
- [x] Emit finding and rejection certificates.
- [x] Add patched, renamed, moved, unreachable, and decoy counterfactuals.

This vertical slice exercises nearly every architectural concept while
remaining narrow enough for rigorous evaluation.

Phase 2 completion means each mechanism exists as a typed, provenance-carrying
repository feature with positive, rejection, incomplete-context, and
counterfactual fixtures. It does not mean the full FFmpeg counterfactual
checkout matrix or retained real-world trigger corpus has already been run.

### Phase 3: Scheduling and model routing

- [x] Replace file-level hunter assignments with candidate/action scheduling.
- [x] Add value-of-information estimates and action budgets.
- [x] Route deterministic actions before model calls.
- [x] Route small typed judgments to local models.
- [x] Escalate explicit unresolved obligations to stronger models.
- [x] Calibrate action utility using evaluation results.
- [x] Add starvation prevention and exploration allocation.

Phase 3 completion means those policies are enforced and audited in the proof
engine. Their production thresholds remain empirical: rollout still depends
on the complete local/frontier campaign meeting the cutover gates above.

### Phase 4: Additional proof plans

Proof plans and validation backends are implemented in measured order:

- [x] Parser and integer-domain safety.
- [x] Authorization and tenancy isolation.
- [x] Temporal memory safety.
- [x] State-machine and protocol safety.
- [x] Cryptographic property violations.
- [x] Injection, path, command, and deserialization boundaries.
- [x] Concurrency and resource-exhaustion classes.

Each plan has typed obligations, at least one decisive rejection path, hard
runtime-evidence gates where appropriate, a finite falsification checklist,
and positive, negative, rename, and move counterfactual fixtures. Validation
manifests can route sanitizer, fuzzing, symbolic, model-checking, differential,
protocol, race, schedule, load, fault-injection, configuration-matrix, and
patch-differential actions through the same sandboxed evidence boundary.

Phase 4 completion is repository and fixture completion. Production recall,
precision, and backend yield for each bug class remain empirical campaign
results and must not be inferred from the implementation percentage.

### Phase 5: Exploration and learning flywheel

- [x] Add bounded exploratory tasks and budget accounting.
- [x] Add structured retrospectives for novel discoveries.
- [x] Promote validated mechanisms into candidate generators and proof-plan
  profiles.
- [x] Generate rejection and counterfactual regression specifications.
- [x] Measure whether exploratory discoveries improve future local-model
  coverage.

Exploratory output never becomes policy directly. Only an exploratory
candidate with a finding certificate, audited evidence, evidence-linked report
claims, a reusable structural fact signature, and completed falsification is
eligible. Promotion is an explicit operator action:

~~~bash
clearwing eval sourcehunt-promote \
  --retrospectives results/proof-session/learning/retrospectives.json \
  --output results/sourcehunt-learning/registry.json
~~~

The registry stores content-addressed generator seeds, reviewed bindings to
installed typed proof plans, and the required original, guarded/policy,
renamed, moved, unreachable, and decoy regression matrix. Unknown plan IDs
fail preflight. A later run applies the structural seed mechanically:

~~~bash
clearwing sourcehunt /path/to/repository \
  --flow proof \
  --proof-learning-registry results/sourcehunt-learning/registry.json \
  --output-dir results/proof-learned
~~~

Supplying a learning registry makes a run assisted and unseals the strict
blind-evaluation boundary. The registry and digest are retained as immutable
run artifacts. Compare actual before/after sessions with:

~~~bash
clearwing eval sourcehunt-learning-coverage \
  --registry results/sourcehunt-learning/registry.json \
  --before-session results/before/session-id \
  --after-session results/after/session-id \
  --output results/sourcehunt-learning/coverage.json
~~~

The report measures structured rediscovery, terminal local-only obligation
completion, and frontier actions for promoted mechanisms only. It reports
improvement only when structured rediscovery and the count of local-only
resolved obligations both increase without a regression in the local-only
completion rate. These are observed session measurements, not model
self-assessment.

## Initial vertical-slice acceptance criteria

The spatial-memory-safety vertical slice is ready for broader rollout
when:

- Every candidate has a snapshot, invariant, threat model, and proof plan.
- Every accepted finding has a complete evidence-linked certificate.
- Every rejected candidate distinguishes disproven from incomplete.
- A sanitizer crash cannot independently establish remote reachability or
  security impact.
- Missing indirect calls or configurations appear as explicit unknowns.
- Removing a supporting guard invalidates the relevant rejection
  certificate.
- Renaming symbols does not materially change conclusions.
- Applying the real fix removes or weakens the finding.
- Local models can resolve a meaningful majority of bounded obligations.
- Frontier calls predominantly address explicit ambiguities rather than
  repeat repository exploration.
- Unsupported factual claims in compiled reports are rejected or marked.
- Run-wide budget exhaustion produces usable residual investigation state.

Exact numeric thresholds should be set after Phase 0 establishes the
baseline distributions.

## Risks and mitigations

### Ontology lock-in

**Risk:** The system finds only mechanisms encoded by existing
generators.

**Mitigation:** Preserve a bounded exploratory lane and require novel
finding retrospectives that expand the structured ontology.

### False confidence from incomplete context

**Risk:** A precise-looking packet omits a caller, macro, alias, or
configuration.

**Mitigation:** Attach scoped completeness manifests and treat
insufficient context as a valid result.

### Graph and storage complexity

**Risk:** Provenance and invalidation machinery becomes more complex than
the hunt itself.

**Mitigation:** Begin with a narrow schema and one proof plan. Prefer
append-only artifacts and simple dependency edges before adopting a
specialized graph database.

### Rule proliferation

**Risk:** Candidate generators become a brittle list of bug signatures.

**Mitigation:** Organize generators around invariant families and require
each generator to identify the invariant it suspects.

### Scheduler miscalibration

**Risk:** Value estimates starve difficult or novel candidates.

**Mitigation:** Add exploration, severity floors, aging, and retrospective
calibration. Preserve incomplete certificates instead of silently
dropping work.

### Model-generated false precision

**Risk:** Structured output gives an unsupported conclusion the
appearance of rigor.

**Mitigation:** Require provenance, evidence compatibility rules,
independent falsification, and explicit derivations.

### Dynamic validation artifacts

**Risk:** Harness behavior differs from production or creates the
observed failure.

**Mitigation:** Record environment and harness provenance, compare
production call paths, rerun deterministically, and include harness
validity in falsification.

### Excessive cost

**Risk:** Detailed evidence acquisition costs more than existing hunts.

**Mitigation:** Reuse facts and evidence across candidates, run cheap
mechanical actions first, invalidate incrementally, and escalate models
only for explicit unknowns.

## Open design questions

- Which storage representation provides sufficient versioning and query
  capability without premature infrastructure complexity?
- What is the minimum controlled vocabulary for claims and evidence?
- Which claims require deterministic derivations versus adjudicated model
  judgments?
- How should equivalent or overlapping candidates be merged?
- How should proof plans compose when one vulnerability depends on
  another?
- Which context-completeness properties can be measured reliably for each
  supported language?
- How should scheduler utility balance confirmation, rejection, reusable
  evidence, and novelty?
- What evidence is sufficient for different impact and severity claims?
- When should a blocked investigation be preserved indefinitely versus
  retired?
- How should human-supplied evidence and decisions enter the graph?
- Which counterfactual transformations can be automated without changing
  unrelated semantics?

These should be answered experimentally during the vertical slice rather
than entirely in advance.

## End-to-end example

Consider a parser that reads a 32-bit payload length, narrows it to 16
bits for allocation, then copies the original length.

### Fact extraction

The front end records:

- Network input controls the 32-bit length field.
- The value is cast to 16 bits.
- Allocation uses the narrowed value plus a header.
- A later copy uses the original 32-bit value.
- A local guard checks only a minimum length.
- One indirect callback target is unresolved.

### Candidate generation

The allocation-versus-access generator emits a spatial-safety candidate:

~~~text
suspected invariant:
  copied payload must fit within the allocated payload region

suspected mechanism:
  narrowing conversion before allocation

open obligations:
  attacker control
  entry-point reachability
  source-to-copy dataflow
  allocation/access inequality
  effective guards
  callback behavior
  concrete trigger
  observed unsafe write
  security consequence
~~~

### Planning

The memory-write proof plan instantiates the obligation graph. The threat
model initially assumes an unauthenticated network client, but default
listener configuration remains unverified.

### Evidence acquisition

The scheduler first chooses cheap deterministic actions:

1. Confirm direct dataflow from the input field to both expressions.
2. Compute control dominators and enumerate range guards.
3. Resolve configured callback targets.
4. Verify the default listener configuration.

A local model receives a packet asking only whether a specific guard
implies the allocation/access inequality. It returns that the guard does
not constrain the upper bound, with references to the included
expressions.

The harness system reuses an existing parser test, supplies a boundary
value, compiles with ASan, and records a reproducible out-of-bounds write.

### Falsification

The falsifier checks for:

- Caller-side maximum-size enforcement.
- Alternate callback behavior.
- Harness-only state.
- Disabled production configuration.
- A type invariant constraining the decoded value.

It finds no production guard, but discovers that one optional build
profile disables the listener. The primary default configuration remains
reachable, while the certificate scopes the conclusion appropriately.

### Compilation

The report compiler emits a finding whose claims separately establish:

- Attacker control.
- Default entry-point reachability.
- Narrowed allocation.
- Original-width copy.
- Missing effective upper-bound guard.
- Reproduced out-of-bounds write.
- Process memory-integrity violation.

It does not claim code execution unless additional evidence supports that
consequence.

If a later patch adds a dominating maximum-length guard, the affected
claims become stale. Reanalysis can then produce a rejection certificate
without repeating unrelated repository exploration.

## Long-term framing

Clearwing should not imitate an expert auditor by placing an entire
repository and investigation inside a model's context. It should operate
more like a scientific instrument:

1. Generate explicit hypotheses.
2. Select informative, bounded experiments.
3. Preserve every observation and its provenance.
4. Track assumptions and missing information.
5. Seek concrete counterexamples.
6. Revise conclusions when dependencies change.
7. Report only claims supported by the required evidence.

The model remains important, especially for interpreting ambiguous code
and recognizing novel mechanisms. The architecture should ensure that
model intelligence is applied to those irreducibly ambiguous questions,
not spent maintaining state and reconstructing evidence that the system
can manage mechanically.
