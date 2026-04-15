# API reference

Auto-generated from docstrings via `mkdocstrings`. The objects
documented here are the ones downstream code is expected to import
directly — internal helpers (`_`-prefixed) are excluded.

## `clearwing.findings`

The canonical unified-finding type plus the converters that bridge
between it and legacy shapes (CICDRunner dicts, SourceAnalyzer
dataclass).

::: clearwing.findings

### The `Finding` dataclass

::: clearwing.findings.types.Finding
    options:
      show_bases: true
      members_order: source

### Converters

::: clearwing.findings.types.from_cicd_dict
::: clearwing.findings.types.to_cicd_dict
::: clearwing.findings.types.from_analysis_finding

## `clearwing.capabilities`

Runtime probing of optional subsystems (guardrails, memory,
telemetry, events, audit, knowledge). The network-pentest graph
calls `capabilities.has(name)` to decide whether to instantiate
each subsystem.

::: clearwing.capabilities
    options:
      members:
        - Capabilities
        - capabilities

## `clearwing.agent.graph`

::: clearwing.agent.graph.build_react_graph
::: clearwing.agent.graph.create_agent
::: clearwing.agent.graph.detect_flags

## `clearwing.agent.tools`

The network-agent tool registry. `get_all_tools()` composes the
63-tool bind-list consumed by `build_react_graph`.

::: clearwing.agent.tools.get_all_tools
::: clearwing.agent.tools.get_custom_tools

### Per-domain tool builders

The seven subpackages each expose their own builders for callers
that want a narrower tool set than the full network-agent bind-list.

::: clearwing.agent.tools.hunt.build_hunter_tools
::: clearwing.agent.tools.hunt.build_propagation_auditor_tools
::: clearwing.agent.tools.hunt.sandbox.HunterContext

## `clearwing.sourcehunt`

### The runner

::: clearwing.sourcehunt.runner.SourceHuntRunner
    options:
      members_order: source
      filters:
        - "!^_"

### Evidence ladder

::: clearwing.sourcehunt.state.EvidenceLevel
::: clearwing.sourcehunt.state.evidence_at_or_above
::: clearwing.sourcehunt.state.evidence_compare
::: clearwing.sourcehunt.state.filter_by_evidence

### Preprocessor + ranker

::: clearwing.sourcehunt.preprocessor.Preprocessor
::: clearwing.sourcehunt.ranker.Ranker

### Hunter pool

::: clearwing.sourcehunt.pool.HunterPool
::: clearwing.sourcehunt.pool.HuntPoolConfig

### Verifier + patch oracle

::: clearwing.sourcehunt.verifier.Verifier
::: clearwing.sourcehunt.verifier.apply_verifier_result
::: clearwing.sourcehunt.patcher.AutoPatcher
::: clearwing.sourcehunt.patcher.apply_patch_attempt

### Mechanism memory

::: clearwing.sourcehunt.mechanism_memory.MechanismStore
::: clearwing.sourcehunt.mechanism_memory.Mechanism
::: clearwing.sourcehunt.mechanism_memory.MechanismExtractor

### Variant loop

::: clearwing.sourcehunt.variant_loop.VariantLoop
::: clearwing.sourcehunt.variant_loop.VariantPatternGenerator
