# VVAH pattern review

This review compares Clearwing with the Visa Vulnerability Agentic Harness
(VVAH) 1.1.0 checkout. The goal is to adopt the strongest ideas where they
improve Clearwing, while retaining Clearwing's stronger proof, sandbox, and
multi-surface architecture.

## Adopted in this pass

| VVAH pattern | Clearwing integration |
|---|---|
| Output-boundary secret and PII redaction | Sourcehunt tool output is redacted before model dispatch; prompts, trajectories, checkpoints, cross-run stores, disclosure bundles/databases, Markdown, JSON, SARIF, manifests, rejected-finding output, spend metadata, and general scan reports redact likely credentials, private keys, payment cards, and SSNs without mutating live evidence. |
| Markdown/report injection defense | Untrusted inline fields, table cells, paths, and code fences are rendered with context-specific escaping. General HTML reports now HTML-escape every dynamic value. |
| Balanced model JSON recovery | Model output parsing now uses a bounded, string-aware JSON scanner. It handles prose, fences, nested structures, braces inside strings, later valid payloads, and common invalid backslashes. Sourcehunt parsers share it instead of using greedy regular expressions. |
| Host-independent path confinement | Finding-controlled paths reject traversal, absolute paths, Windows drive paths, UNC paths, NULs, and symlink escapes. Patch-oracle file reads and sandbox replay use the same normalization, and shell arguments are quoted or passed as argv. |
| Auditable run provenance | The sourcehunt manifest now records a schema/tool version, UTC timing, effective configuration and its SHA-256, resolved model roles, target Git SHA/branch/dirty state, spend, stage health, and output index. |

## Clearwing already meets or exceeds the pattern

| Area | Clearwing position |
|---|---|
| Execution isolation | Per-hunter no-network Docker containers, read-only source mounts, writable scratch space, dropped capabilities, PID/memory/CPU limits, sanitizer variants, and optional gVisor are a materially stronger execution boundary than an in-process read/glob/grep jail. |
| Evidence discipline | The evidence ladder, proof obligations, falsifier, rejection and incomplete certificates, crash reproduction, stability runs, and patch oracle preserve uncertainty more explicitly than a binary finding lifecycle. |
| Budget enforcement | Clearwing reserves worst-case request cost before dispatch and settles actual provider usage through a concurrency-safe ledger. This is stronger than post-call stage accounting alone. |
| Discovery density | Entry-point sharding, tiered budget rollover, callgraph/taint ranking, sanitizer fuzzing, mechanism memory, retro-hunts, and the iterative variant loop already cover or exceed VVAH's decomposition and specialist passes. |
| Provider routing | Clearwing already supports per-task model/provider routes and independent hunter/verifier tiers through `ProviderManager`. |
| Observability | Append-only instrumentation, stable work IDs, per-stage file/symbol coverage, spend joins, and degraded-stage status provide richer run telemetry. |

## Recommended next integrations

1. **Standalone remediation DTO lifecycle.** Separate proposed fixes from the
   working tree, persist one typed DTO per finding, and make apply/report-only
   an explicit operator choice. Preserve Clearwing's sandboxed patch oracle as
   the dynamic-evidence gate.
2. **Adversarial fix-quality panel.** Add independent root-cause, coverage,
   regression/new-vulnerability, and security-practice gates. Compute the host
   verdict fail-closed; do not let a model directly select the terminal state.
3. **Remediation policy and kill switch.** Add forbidden-path rules, CWE-based
   allow/deny policy, a post-diff gate, automatic rollback, and an environment
   plus sentinel-file emergency disable.
4. **Standard-flow checkpoint store and garbage collection.** The proof flow
   and campaigns checkpoint today, but the legacy sourcehunt pipeline should
   gain validated external JSON/SQLite checkpoints, stable resume semantics,
   and a dry-run-capable pruning command.
5. **Explicit legacy threat-model stage.** Proof flow already carries threat
   models. The standard flow should persist assets, trust boundaries, attacker
   capabilities, deployment assumptions, and expected high-risk coverage
   before ranking files.
6. **Pre-scan estimate and coverage plan.** Provide a zero-spend estimate of
   files, LOC, languages, likely sandbox builds, model calls, and cost range,
   plus an auditable exclusion list. Any AI-proposed exclusions should require
   explicit display and be easy to disable.
7. **Batch application context.** Add collision-safe application/repository
   identity, optional CMDB context, contextual severity, and grouped summaries
   for multi-repository programs.

The first three next integrations form one coherent remediation milestone.
Checkpointing and threat modeling should follow as a separate orchestration
milestone so scan-state changes do not get entangled with write-policy changes.
