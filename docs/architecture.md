# Architecture

Clearwing is organized around two complementary pipelines that share
a common Finding type, sandboxing layer, knowledge graph, and event
bus.

```
┌───────────────────────────────────────────────────────────────────┐
│                         clearwing.cli                              │
│  (scan, sourcehunt, interactive, operate, mcp, parallel, webui)   │
└─────────────────┬───────────────────────────────┬─────────────────┘
                  │                               │
                  ▼                               ▼
┌─────────────────────────┐      ┌────────────────────────────────┐
│  Network-pentest agent  │      │   Source-code hunter (Overwing)│
│  clearwing.agent.graph  │      │   clearwing.sourcehunt.runner  │
│                         │      │                                │
│  build_react_graph      │      │  Preprocessor → Ranker → Pool  │
│    ├── ToolNode         │      │   → Hunter (per-file ReAct)   │
│    ├── input guardrail  │      │   → Adversarial Verifier      │
│    ├── output guardrail │      │   → Exploiter → Auto-Patcher  │
│    └── flag detector    │      │   → Variant Loop → Reporter   │
└────────┬────────────────┘      └───────┬────────────────────────┘
         │                                │
         │    ┌───────────────────────────┘
         │    │
         ▼    ▼
┌───────────────────────────────────────────────────────────────────┐
│                       Shared substrate                            │
├───────────────────────────────────────────────────────────────────┤
│  clearwing.findings.Finding  — the one canonical finding type     │
│  clearwing.capabilities      — runtime subsystem detection        │
│  clearwing.sandbox           — Docker-based sanitizer containers  │
│  clearwing.data.knowledge    — attack-graph + finding-graph DB    │
│  clearwing.data.memory       — episodic + session memory          │
│  clearwing.core.events       — process-wide pub/sub event bus     │
│  clearwing.observability     — cost tracker + Prometheus metrics  │
│  clearwing.safety            — guardrails, audit log, scoring     │
└───────────────────────────────────────────────────────────────────┘
```

## The network-pentest agent (`clearwing.agent.graph`)

A LangGraph ReAct loop with 63 bind-tools. The graph has two nodes:

- **`assistant`** — invokes the LLM with the current state and the
  full tool registry. Emits an AIMessage; detects CTF-style flags in
  the content; records cost + token usage; triggers the audit logger
  and context summarizer when the respective subsystems are loaded.
- **`guarded_tools_node`** — intercepts every tool call before it
  reaches the actual tool implementation:
  - **Output guardrail** — checks `kali_execute` commands against a
    denylist (`rm -rf /`, raw disk writes, etc.) and emits a warning
    event if blocked.
  - **Input guardrail** — validates tool arguments on the inbound
    side for scanners (`scan_ports`, `scan_vulnerabilities`,
    `detect_services`, `detect_os`) so a hallucinated `target=` can't
    blast a production host.
  - Executes the tool via `ToolNode`, then feeds each ToolMessage
    through the episodic-memory recorder, the knowledge-graph
    populator, and the state updater.

The loop terminates via the standard LangGraph `tools_condition` —
when the assistant returns no tool_calls, the graph ends.

### Capability gating

`clearwing/capabilities.py` probes each of the six optional subsystems
(`guardrails`, `memory`, `telemetry`, `events`, `audit`, `knowledge`)
at import time and exposes `capabilities.has(name)`. The graph's
init block decides whether to instantiate each subsystem based on
a user flag AND the capability being present — so a stripped install
degrades gracefully instead of crashing on first use.

## The source-code hunter (`clearwing.sourcehunt`)

The sourcehunt pipeline is staged, not looped. Each stage produces
input for the next:

1. **Preprocess** — clone, enumerate source files, static-scan with
   regex/AST patterns, tag files by concern (`memory_unsafe`,
   `parser`, `crypto`, `auth_boundary`, `syscall_entry`, `fuzzable`),
   build a tree-sitter callgraph, propagate attacker-reachability,
   optionally run a Semgrep sidecar, and run an intra-procedural
   taint analyzer that traces source→sink paths in C/Python.
2. **Rank** — score each file on three axes (`surface * 0.5 +
   influence * 0.2 + reachability * 0.3`). The influence axis exists
   specifically to catch "boring" files whose definitions propagate
   across many callers — the case a single-axis ranker drops.
3. **Harness generator** (`--depth deep` only) — for every rank-4+
   parser/fuzzable C/C++ file, ask the LLM to write a libFuzzer
   harness, compile it in the sandbox with ASan, run for a per-file
   budget, capture any crashes. Hunters for fuzzed files then get
   the easier "explain this crash" prompt instead of cold-reading.
4. **Tiered hunt** (`clearwing.sourcehunt.pool.HunterPool`) — files
   split into Tier A/B/C by priority. Budget allocated 70/25/5 with
   rollover. Tier C files get a narrower `build_propagation_auditor_tools(ctx)`
   set (no compile/run, just grep/read/record) to stay cheap.
   Hunters dispatch to one of six specialists based on tags +
   language: `kernel_syscall`, `crypto_primitive`, `web_framework`,
   `memory_safety`, `logic_auth`, `general`.
5. **Adversarial verify** — a second-pass `Verifier` agent with
   independent context steel-mans BOTH sides (pro-vuln AND
   counter-argument) and finds tie-breaker evidence. Gated on
   `evidence_level >= static_corroboration` by default to avoid
   burning budget on suspicion-only findings.
6. **Patch oracle** — writes a minimal defensive fix, recompiles in
   the sandbox, re-runs the PoC. Crash gone → causally validated,
   bump to `root_cause_explained`. Crash survives → theory suspect.
7. **Mechanism memory** — extracts abstract mechanisms from verified
   findings ("length field trusted before alloc; size_t wrapping")
   and persists them to a cross-run JSONL store. On subsequent runs,
   mechanism recall (pure-Python TF-IDF or optional chromadb
   embeddings) injects hint context into hunter prompts.
8. **Variant hunter loop** (up to 3 iterations) — for each verified
   finding, generate a grep regex + semantic description, search the
   codebase for structural matches, surface each as a variant finding.
   Runs until fixpoint — each pass's new seeds feed the next pass's
   pattern generation, compounding finding density inside one run.
9. **Exploit triage** — only on findings with sanitizer crash
   evidence (`>= crash_reproduced`). Successful PoC bumps severity
   to critical.
10. **Auto-patch** (opt-in) — on verified critical/high findings
    with `>= root_cause_explained`, write a minimal fix, recompile,
    re-run the PoC. Only validated patches (PoC stops crashing after
    apply) are included in the report. Optional `--auto-pr` opens
    draft PRs via the `gh` CLI.
11. **Report** — SARIF + markdown + JSON, findings sorted by
    evidence level descending. Optional `--export-disclosures`
    writes pre-filled MITRE CVE-request and HackerOne templates for
    every verified finding `>= root_cause_explained`.

The `openglass.md` deep dive walks through each stage with concrete
examples.

## The shared Finding type

`clearwing.findings.Finding` is the single canonical finding
dataclass. It's a strict superset of every legacy shape:

- sourcehunt hits (file, line_number, cwe, evidence_level, crash_evidence, ...)
- CICDRunner network findings (target, port, protocol, cve, cvss, ...)
- SourceAnalyzer static hits (file_path, line_number, severity, ...)

Converters in `clearwing.findings.types` bridge between `Finding`
and the two external shapes that still need dict form:
`from_cicd_dict` / `to_cicd_dict` and `from_analysis_finding`. The
old `SourceFinding` TypedDict was unified into `Finding` in Phase 3.

The `Finding` class carries a small dict-style access shim
(`__getitem__`, `__setitem__`, `get()`, `__contains__`) that lets
the `apply_verifier_result` / `apply_exploiter_result` /
`apply_patch_attempt` merge functions accept either a `Finding`
dataclass or a plain dict. Test fixtures lean on this heavily.

## The sandbox layer

`clearwing.sandbox` wraps the Docker SDK to provide per-hunter
disposable containers with sanitizer images (ASan+UBSan primary,
MSan variant, optional LSan/TSan). Each `HunterContext`
(`clearwing.agent.tools.hunt.sandbox.HunterContext`) owns:

- A primary `SandboxContainer` attached at hunt start.
- A `sandbox_manager` reference for spawning sanitizer-variant
  containers on demand (e.g., an MSan run for a specific finding).
- A cache of variant containers that tears down in `cleanup_variants()`
  when the hunter finishes.

The sandbox is read-only under `/workspace` (the cloned repo is
mounted there) and read-write under `/scratch` (where the hunter's
`write_test_case`, `compile_file`, and `fuzz_harness` tools emit
artifacts). Exec timeout, memory limit, and the workspace mount are
all configured per-container.

## The knowledge graph

`clearwing.data.knowledge.KnowledgeGraph` is a networkx-backed
attack graph that persists to `~/.clearwing/knowledge_graph.json`.
The network-pentest agent populates it with Target / Port / Service
/ Vulnerability / Exploit entities and the relationships between
them (`HAS_PORT`, `RUNS_SERVICE`, `AFFECTED_BY`, `EXPLOITED_WITH`).
The source-hunt pipeline adds File / Finding / CVE entities with
`HAS_FILE`, `HAS_FINDING`, `VARIANT_OF`, `RELATED_TO_CVE`.

Across sessions, this gives the interactive agent a memory of what's
been found — ask "what did we learn about 10.0.0.5" and the loader
pulls back the relevant subgraph.

## Tool organization

After Phase 4b, the agent tool set lives in seven domain subdirs:

```
clearwing/agent/tools/
├── scan/        # scanner_tools — port, service, vuln, os
├── exploit/     # exploit_tools, exploit_search, payload_tools
├── hunt/        # sandbox, discovery, analysis, reporting — for
│                  the source-hunt ReAct hunters, not the network agent
├── recon/       # browser_tools, proxy_tools, pivot_tools
├── ops/         # kali_docker_tool, mcp_tools, dynamic_tool_creator, skill_tools
├── data/        # knowledge_tools, memory_tools, analysis_tools
└── meta/        # utility_tools, remediation_tools, reporting_tools,
                   sourcehunt_tools, wargame_tools, ot_tools
```

`clearwing.agent.tools.__init__.get_all_tools()` is a pure aggregator
that composes the network-agent's 63-tool bind-list. The
sourcehunt pipeline uses its own tool factory in
`clearwing.agent.tools.hunt.__init__.build_hunter_tools(ctx)` — a
different lineage that never appears in `get_all_tools()`.
