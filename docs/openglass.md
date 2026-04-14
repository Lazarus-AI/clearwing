Overwing: Source-Code Vulnerability Hunting Pipeline                                                                                                                      
                                                                                                                                                                         
 Context

 The user wants to integrate Anthropic's Project Glasswing methodology (spec at docs/openglass.md, named Overwing here) into the clearwing project. Overwing is a
 file-parallel, agent-driven vulnerability discovery pipeline: rank source files by attack surface → fan out per-file ReAct hunter agents → use crash oracles (ASan/UBSan)
  as ground truth → verify findings with a second-pass independent agent → optionally generate exploits for severity triage → emit SARIF/markdown reports.

 The existing project is a network-target pentest agent, but closer inspection reveals it already has most of the substrate Overwing needs:

 - clearwing/analysis/source_analyzer.py — already clones repos, walks source trees, has a Finding dataclass with file_path/line_number/cwe, runs regex+AST static
 analysis. This is ~60% of the preprocessor.
 - clearwing/providers/manager.py — already supports model-per-role routing (ModelRoute(task, provider, model)). Adding ranker/hunter/verifier routes is configuration,
 not code.
 - clearwing/agent/graph.py::create_agent() — already parameterized by custom_tools, base_url, session_id. The guarded_tools_node is generic and reuses
 CostTracker/AuditLogger/EpisodicMemory — all of which are target-IP-agnostic.
 - clearwing/runners/cicd/runner.py — runner pattern is clean. SARIFGenerator is finding-agnostic; extending it for file-level locations is ~15 lines.
 - clearwing/agent/specialists/ — sub-graph pattern (e.g. recon_agent.py:24) is the template for the new hunter/verifier specialists.
 - clearwing/ui/commands/__init__.py — CLI auto-discovers any module in ALL_COMMANDS; new subcommand is ~50 lines.

 The goal is to reuse aggressively, refactor narrowly, add a new package — not fork the agent stack.

 ---
 Scope: three phases

 The plan is structured as three milestones. v0.1 is the one we build now — the rest is scoped here so we don't paint ourselves into corners.

 - v0.1 Walking (this implementation plan): Clone + two-axis ranker (LLM-only influence) + tiered pool + sandboxed hunter/verifier/exploiter + SARIF/markdown +
 interactive-agent @tool wrapper. Ships as one coherent feature.
 - v0.2 Running: Tree-sitter callgraph in preprocessor (upgrades the influence axis with real data), Harness Generator node (auto-libFuzzer for rank-4+ parsers,
 crash-seeded hunter prompts), UBSan/MSan alongside ASan, blast-radius analysis.
 - v0.3 Flying: Commit Monitor graph entry point, CVE Retro-Hunt graph entry point (CVE-ID → patch-diff → pattern query → variant hunt), cross-run vector-store memory
 keyed on code patterns, Auto-Patch mode (recompile+re-run verification).
 - v1.0+ (not scoped here): DPO fine-tuning on verified findings, distributed Ray execution across multiple machines, community finding database. Real but premature.

 Architectural stance: ReAct all the way. No planner-executor rewrite — the rigidity of a pre-planned DAG doesn't buy enough to justify the complexity. The existing
 build_react_graph() refactor (R1) is the substrate for every agent in every phase.

 The rest of this plan details v0.1 exhaustively and sketches v0.2/v0.3 with enough shape to keep the v0.1 interfaces future-compatible.

 ---
 Architecture

 ENTRY POINTS (v0.1)                                ENTRY POINTS (v0.3)
   sourcehunt <repo>                                  sourcehunt watch <repo>      (Commit Monitor)
   @tool hunt_source_code                             sourcehunt retro-hunt <CVE>  (CVE Retro-Hunt)
         │
         └─────────────────┬────────────────────────────────┘
                           ▼
                   SourceHuntRunner
                           │
                           ▼
    ┌─── Preprocessor ─────────────────────────────────────────────────────┐
    │  • clone + enumerate (SourceAnalyzer wrapper)                        │
    │  • file tagging: parser, memory_unsafe, crypto, auth_boundary,       │
    │      syscall_entry, fuzzable, attacker_reachable  (heuristics + 1    │
    │      cheap LLM pass)                          [v0.1 stub → v0.2 full]│
    │  • Semgrep sidecar (one tool, security rulesets)         [v0.2]      │
    │  • tree-sitter callgraph builder                          [v0.2]     │
    │  • reachability propagation through callgraph             [v0.2]     │
    │  • fuzz-corpus auto-detect (OSS-Fuzz, project harnesses)  [v0.2]     │
    └──────────────────────┬───────────────────────────────────────────────┘
                           ▼
                    HunterSandbox  (build once)  [v0.1: ASan/UBSan; v0.2: +MSan]
                           │
                           ▼
                     Ranker Agent (3 axes)
                        surface * 0.5
                        + influence * 0.2
                        + reachability * 0.3      [v0.1: reach=3 default; v0.2: real]
                           │
         ┌─────────────────┴─────────────────┐
         ▼ [v0.2: crash-first ordering]      ▼
    Harness Generator                  Tier assignment (A/B/C)
    • generate libFuzzer harness for         │
      rank-4+ parsers/entry points           │
    • compile + run in background            │
    • crashes → seeded findings              │
         │                                   │
         └─────────────────┬─────────────────┘
                           ▼
                     HunterPool  (parallel fan-out, tiered 70/25/5 budget)
                           │
         ┌─────────────────┼─────────────────┐
         ▼                 ▼                 ▼
   Memory-Safety       Logic/Auth       Propagation
   Hunter [v0.2]       Hunter [v0.2]    Auditor (Tier C)
   (file_tags:         (file_tags:      (TIER_C_PROPAGATION
    parser, memory_     auth_boundary,   _AUDIT_PROMPT)
    unsafe, fuzzable)   crypto, logic)
         │                 │                 │
         │  v0.1: single GeneralHunter     │
         │  (specialist split lands in v0.2)│
         └─────────────────┬─────────────────┘
                           ▼
                   Findings Collector
                   • dedup, normalize
                   • inject crash evidence from Harness Generator
                   • inject Semgrep hints                   [v0.2]
                   • query mechanism memory store           [v0.3]
                           │
                           ▼
                   Verifier Agent (adversarial)
                   • independent context (no hunter messages)
                   • steel-man the negative                 [v0.2]
                   • patch-oracle truth test                [v0.3]
                   •   try minimal fix → recompile → re-run PoC
                   •   crash gone = causally validated
                   •   crash survives = bounce back to hunter
                   • output: pro-arg, counter-arg, tie-breaker evidence
                           │
                           ▼
             ┌─── Variant Hunter Loop ──────┐  [v0.3]
             │  for each verified finding:  │
             │   • generate grep query      │
             │   • generate AST pattern     │
             │   • generate semantic desc   │
             │   • search whole repo        │
             │   • re-feed matches into     │
             │     HunterPool as seeded     │
             │     hypotheses               │
             └──────────────┬───────────────┘
                           ▼
                   Exploiter Agent
                   • only on findings with evidence_level >= crash_reproduced
                   • sandboxed PoC execution
                           │
                           ▼
                   Auto-Patcher Agent  [v0.3]
                   • spawn patcher, write minimal fix
                   • recompile + re-run PoC in sandbox
                   • include in report only if crash disappears
                   • optional --auto-pr opens draft PR
                           │
                           ▼
                   Reporter
                   • SARIF + markdown + JSON
                   • findings sorted by evidence_level
                   • persist mechanisms to memory store      [v0.3]

 Evidence ladder (gates budget allocation throughout):
 suspicion → static_corroboration → crash_reproduced → root_cause_explained → exploit_demonstrated → patch_validated

 The Exploiter only runs on findings ≥ crash_reproduced. The Auto-Patcher only runs on findings ≥ root_cause_explained. Findings reaching patch_validated are the gold
 standard in the report.

 Every new node is additive. v0.1 ships a working pipeline (preprocess → rank → tiered hunters → verifier → exploiter → reporter) with file_tags=[], reachability=3
 default, single GeneralHunter, non-adversarial verifier, no harness generator, no variant loop, no patch-oracle, no Semgrep, no cross-run memory. The interfaces
 (Finding.evidence_level, FileTarget.tags, FileTarget.reachability, Verifier output schema) are designed in v0.1 so v0.2/v0.3 plug in at defined seams without
 refactoring.

 State flows through a new SourceHuntState TypedDict. The existing AgentState is left untouched — hunter/verifier agents use SourceHuntState as their schema, which keeps
 the network-pentest state clean.

 ---
 New package: clearwing/sourcehunt/

 clearwing/sourcehunt/
 ├── __init__.py
 ├── state.py          # SourceHuntState TypedDict, FileTarget dataclass
 ├── preprocessor.py   # wraps SourceAnalyzer for clone + enumerate + static pre-scan
 ├── ranker.py         # single LLM call; batched for large repos
 ├── hunter.py         # per-file ReAct agent builder
 ├── verifier.py       # verifier agent builder (independent context)
 ├── exploiter.py      # exploit-triage agent (runs on verified critical/high only)
 ├── pool.py           # HunterPool — bounded parallel fan-out with budget tracking
 ├── runner.py         # SourceHuntRunner — public entry point, analog of CICDRunner
 └── reporter.py       # file-aware SARIF/markdown/JSON emitter

 state.py

 # Evidence ladder — gates budget allocation throughout the pipeline
 EvidenceLevel = Literal[
     "suspicion",                # ranker said this might be interesting
     "static_corroboration",     # Semgrep / SourceAnalyzer regex-AST hit
     "crash_reproduced",         # fuzzer crashed OR PoC ran with crash evidence
     "root_cause_explained",     # hunter wrote a coherent explanation
     "exploit_demonstrated",     # exploiter built a working PoC
     "patch_validated",          # auto-patcher fixed it; PoC stops crashing
 ]

 # File tags — drive specialist routing, oracle suite, fuzz harness gen, rank boost
 FileTag = Literal[
     "memory_unsafe",       # C/C++/unsafe Rust, manual memory management
     "parser",              # parses external/untrusted input
     "crypto",              # implements or wraps cryptographic primitives
     "auth_boundary",       # auth check, permission gate, session validation
     "syscall_entry",       # ioctl, sysfs, netlink, kernel boundary
     "fuzzable",            # has a clear (data: bytes) entry point
     "attacker_reachable",  # transitively reachable from a known entry point
 ]

 class FileTarget(TypedDict):
     path: str            # relative to repo root
     absolute_path: str
     surface: int         # 1-5 — direct vulnerability likelihood
     influence: int       # 1-5 — downstream danger if this file is wrong
     reachability: int    # 1-5 — attacker-reachability through callgraph
                          # v0.1: defaults to 3 (unknown); v0.2: real propagation
     priority: float      # surface*0.5 + influence*0.2 + reachability*0.3
     tier: Literal["A", "B", "C"]      # assigned from priority — see pool.py
     tags: list[FileTag]  # v0.1: empty by default; v0.2: populated by tagger
     language: str
     loc: int
     surface_rationale: str
     influence_rationale: str
     reachability_rationale: str
     static_hint: int     # count of SourceAnalyzer regex hits → surface boost
     semgrep_hint: int    # v0.2: count of Semgrep findings → surface boost + hint
     imports_by: int      # v0.1 cheap influence signal
     transitive_callers: int   # v0.2: from tree-sitter callgraph (better influence)
     defines_constants: bool   # influence boost for header/config files
     has_fuzz_entry_point: bool   # v0.2: detected by tagger
     fuzz_harness_path: str | None  # v0.2: filled by Harness Generator

 class SourceFinding(TypedDict):
     id: str
     file: str
     line_number: int
     end_line: int | None
     finding_type: str          # sql_injection, memory_safety, propagation_buffer_size, etc.
     cwe: str
     severity: Literal["critical", "high", "medium", "low", "info"]
     confidence: Literal["high", "medium", "low"]
     description: str
     code_snippet: str
     crash_evidence: str | None         # parsed ASan/UBSan/MSan report if available
     poc: str | None                    # input that triggers the bug
     evidence_level: EvidenceLevel      # gates downstream budget — see pipeline
     discovered_by: str                 # "hunter:memory_safety" | "harness_generator"
                                        # | "variant_loop" | "semgrep" | "source_analyzer"
     related_finding_id: str | None     # for variant_loop matches, the original finding
     related_cve: str | None            # for retro-hunt findings
     seeded_from_crash: bool            # True if hunter saw crash evidence first
     verified: bool
     severity_verified: str | None
     verifier_pro_argument: str | None  # v0.2: verifier's strongest pro-vuln case
     verifier_counter_argument: str | None  # v0.2: verifier's steel-manned counter
     verifier_tie_breaker: str | None   # v0.2: what evidence resolves it
     patch_oracle_passed: bool | None   # v0.3: minimal-fix recompile killed crash
     exploit: str | None
     exploit_success: bool | None
     auto_patch: str | None             # v0.3: minimal fix diff, None if rejected
     auto_patch_validated: bool | None  # v0.3: PoC stopped crashing after patch
     hunter_session_id: str
     verifier_session_id: str | None

 class SourceHuntState(TypedDict):
     messages: Annotated[list[BaseMessage], add_messages]
     repo_url: str
     repo_path: str
     branch: str
     files: list[FileTarget]
     files_scanned: list[str]
     current_file: Optional[str]
     callgraph: dict | None             # v0.2: tree-sitter callgraph
     semgrep_findings: list[dict]       # v0.2: pre-scan hits used as hints
     fuzz_corpora: list[dict]           # v0.2: detected OSS-Fuzz / project corpora
     seeded_crashes: list[dict]         # v0.2: harness generator output
     findings: list[SourceFinding]
     verified_findings: list[SourceFinding]
     variant_seeds: list[dict]          # v0.3: hypotheses from variant hunter loop
     exploited_findings: list[SourceFinding]
     patch_attempts: list[dict]         # v0.3: auto-patcher output (validated or not)
     budget_usd: float
     spent_usd: float
     spent_per_tier: dict[str, float]   # {"A": ..., "B": ..., "C": ...}
     total_tokens: int
     phase: Literal[
         "preprocess", "tag", "rank", "fuzz", "hunt", "verify", "variant_loop",
         "exploit", "auto_patch", "report"
     ]
     session_id: Optional[str]
     flags_found: list[dict]

 preprocessor.py

 Pure code (mostly). Delegates to clearwing.analysis.SourceAnalyzer for v0.1 and exposes seams for tree-sitter, Semgrep, file tagging, reachability propagation, and
 fuzz-corpus auto-detection in v0.2:

 @dataclass
 class PreprocessResult:
     repo_path: str
     file_targets: list[FileTarget]
     static_findings: list[Finding]              # from SourceAnalyzer regex/AST
     semgrep_findings: list[dict] = []           # v0.2: Semgrep sidecar output
     callgraph: CallGraph | None = None          # v0.1: None; v0.2: tree-sitter-built
     fuzz_corpora: list[FuzzCorpus] = []         # v0.1: []; v0.2: auto-detected

 class Preprocessor:
     def __init__(self, repo_url: str, branch: str = "main",
                  local_path: str | None = None,
                  build_callgraph: bool = False,    # v0.1 off; v0.2 on
                  run_semgrep: bool = False,        # v0.1 off; v0.2 on
                  tag_files: bool = True,           # v0.1: cheap heuristics only
                  propagate_reachability: bool = False,  # v0.1 off; v0.2 on
                  ingest_fuzz_corpora: bool = False):
         ...

     def run(self) -> PreprocessResult:
         """Steps:
         1. Clone via SourceAnalyzer.clone() if repo_url is a git URL.
         2. Enumerate source files via SourceAnalyzer._iter_source_files().
         3. Run SourceAnalyzer.analyze() → static_hint field on each FileTarget.
         4. Count imports_by (cheap grep over #include/import/require statements).
         5. [v0.1 cheap pass] File tagging via heuristics:
            - extension-based: .c/.cpp/.h → memory_unsafe candidate
            - filename-based: parse_*, decode_*, deserialize_* → parser
            - directory-based: */crypto/*, */auth/*, */security/* → crypto/auth_boundary
            - signature-based: contains LLVMFuzzerTestOneInput → fuzzable
            Tags are stored in FileTarget.tags. v0.1 ships with this minimal set.
         6. [v0.2] If build_callgraph: invoke CallGraphBuilder (tree-sitter)
            to build caller/callee relationships. Each FileTarget gains
            `transitive_callers` which becomes the primary influence signal.
         7. [v0.2] If propagate_reachability: identify entry points (network
            handlers, file parsers, CLI arg processors, RPC handlers, IPC
            receivers via signature heuristics + tag), propagate
            "attacker-reachable" through the callgraph one hop at a time.
            Each FileTarget gains a `reachability` score (1-5).
         8. [v0.2] If run_semgrep: invoke Semgrep with security rulesets.
            Findings stored in semgrep_findings; per-file count fed into
            FileTarget.semgrep_hint as a surface boost AND injected as hints
            into hunter prompts at hunt time. NEVER treated as ground truth.
         9. [v0.2] If ingest_fuzz_corpora: scan for OSS-Fuzz build scripts
            (projects/<name>/Dockerfile, build.sh), project-local libFuzzer
            entrypoints, AFL/honggfuzz dirs. Files matching get the `fuzzable`
            tag. Corpora are passed downstream to the Harness Generator as
            seed inputs.
        10. [v0.2 LLM polish pass — optional] Single cheap LLM call per ~150
            files to refine the tag set (e.g. "is this file actually doing
            crypto or just calling sha256?"). Skipped if budget is tight.
        11. Count LOC, detect language, finalize FileTarget list.
         """

 Key reuse: SourceAnalyzer.clone() at source_analyzer.py:230, _iter_source_files() at :309, LANGUAGE_MAP at :70, analyze() at :256. No duplication.

 v0.1 minimum viable file-tagger: Pure heuristics, no LLM call. Tags parser, crypto, auth_boundary, memory_unsafe, fuzzable only. attacker_reachable requires the
 callgraph and is left empty in v0.1. syscall_entry is left empty until v0.2 when the LLM polish pass can identify ioctl/sysfs/netlink boundaries reliably.

 v0.2 seams: CallGraph, FuzzCorpus, and SemgrepRunner are defined as optional dataclasses/interfaces in v0.1 (just the shape — no implementation). The v0.1 ranker treats
 callgraph=None and reachability=3 as "no data, use defaults." This keeps v0.1 shipping while reserving slots for v0.2 without refactoring downstream consumers.

 ranker.py — three-axis ranking

 The ranker scores each file on three independent axes, not a single rank:

 - Surface (1–5): likelihood the file itself contains an exploitable vulnerability. "Does this code parse untrusted input, handle auth, manage memory, implement crypto?"
 This is the Glasswing spec's rank.
 - Influence (1–5): downstream danger if this file is wrong. "If this file defines something (a constant, a type, a default, a macro), how many callers/consumers depend
 on that definition being correct?" A constants.h with MAX_AUTH_BYTES = 400 used in 50 memcpy calls has surface=1, influence=5.
 - Reachability (1–5): how easily attacker-controlled input can reach this file's code. v0.1 defaults to 3 (unknown) for everything because we don't have a callgraph yet.
  v0.2 fills it in via callgraph propagation from tagged entry points.

 Priority formula (used by tier assignment in pool.py):

 priority = surface * 0.5 + influence * 0.2 + reachability * 0.3

 Surface dominates (it's the strongest signal), reachability is the second-largest weight (a beautiful bug in unreachable code is worth less than a sloppy one in a
 network handler), influence is the smallest weight but never zero (the FFmpeg-style propagation case).

 In v0.1, with reachability defaulted to 3, the formula collapses to roughly surface * 0.5 + influence * 0.2 + 0.9, which still produces a useful ordering — just one with
  no reachability discrimination. v0.2 unlocks the third axis with no plan changes.

 A single cheap LLM call per chunk of ~150 files returns both scores plus rationales. The ranker also computes cheap static features before the LLM call that it includes
 in the prompt context:

 - static_hint: count of regex-based vulnerability hits from SourceAnalyzer.analyze() — feeds surface.
 - imports_by (v0.1): grep count of files with #include/import/require/use referencing this file — feeds influence. This is the cheap-and-wrong signal that the LLM can
 correct.
 - transitive_callers_count (v0.2): count of all files that transitively call any function defined in this file, from the tree-sitter callgraph. When available, this
 replaces imports_by as the primary influence signal and the LLM correction becomes less important.
 - defines_constants: does this file declare top-level #define, const, type, or module-level constant? — feeds influence.

 In v0.1, the LLM does most of the influence inference (with imports_by as a weak hint). In v0.2, the tree-sitter callgraph gives it real numbers, and the LLM call is
 mostly there to explain WHY a high-influence file matters.

 @dataclass
 class RankerConfig:
     chunk_size: int = 150        # smaller than before to fit both-axis rationales
     include_static_hints: bool = True

 class Ranker:
     def __init__(self, llm: BaseChatModel, config: RankerConfig = RankerConfig()):
         self.llm = llm
         self.config = config

     def rank(self, files: list[FileTarget], repo_path: str) -> list[FileTarget]:
         """Single LLM call per chunk. Fills surface and influence on each file.

         Uses the `ranker` task from ProviderManager.get_llm("ranker") — cheap
         model (default haiku). Promotes files where static_hint > 0 by surface +1
         (regex pre-scan is a strong signal). Files with imports_by > 10 OR
         defines_constants=True get an influence floor of 3 even if the LLM
         scores lower — downstream reach is hard for the LLM to see.

         Returns the same FileTargets with surface/influence/tier filled in.
         Tier assignment: see _assign_tier() (lives in pool.py, not ranker).
         """

 Ranker prompt

 RANKER_PROMPT = """You are a security researcher triaging files in a project
 for vulnerability hunting. For each file listed below, return TWO independent
 scores from 1 to 5:

 1. SURFACE — how likely this file *itself* contains an exploitable vulnerability:
    1 = Constants, type definitions, pure data, no logic
    2 = Internal utility code, no external input
    3 = Handles internal data with some complexity
    4 = Processes external data with validation
    5 = Parses raw untrusted input, handles auth, manages memory, or
        implements crypto

 2. INFLUENCE — how dangerous this file is DOWNSTREAM if it contains a bug:
    1 = Isolated, only called in one place
    2 = Used by a handful of files in the same module
    3 = Used across the codebase but only in non-critical paths
    4 = Defines behavior used in security-critical paths (e.g. a hash comparison
        helper, a buffer size constant used in memcpy calls)
    5 = Defines a type, constant, macro, or default that is used EVERYWHERE
        and whose correctness is load-bearing — a bug here propagates to
        many callers. (A constants.h with MAX_AUTH_BYTES used in 50 memcpys
        is a 5, even though the file itself has no vulnerability.)

 A file can score HIGH on influence and LOW on surface. That combination
 is what you're looking for — bugs in boring files that propagate widely.

 Hints (from static analysis — use these as guidance, not ground truth):
 {static_hints_block}

 Imports-of-this-file counts (how many files depend on each):
 {imports_by_block}

 Return JSON array:
 [
   {{
     "path": "...",
     "surface": N,
     "influence": N,
     "surface_rationale": "one short sentence",
     "influence_rationale": "one short sentence"
   }},
   ...
 ]
 """

 Why the FFmpeg case works: A hypothetical bug in libavcodec/common.h defining a sentinel byte value used across 30+ codecs would score surface≈1 (it's just a constant)
 but influence=5 (every codec's memset call relies on the sentinel not colliding with valid data). With a single-axis ranker it gets cut at rank 1. With two axes,
 max(surface, influence) = 5 — it goes in Tier A.

 Even if the ranker whiffs, the tiered budget in pool.py guarantees Tier C spot-checks catch stragglers with a different prompt (see below).

 hunter.py

 The core of Phase 1. Rather than copy-pasting create_agent(), we extract a reusable factory:

 Refactor: Split clearwing/agent/graph.py::create_agent() into:

 def build_react_graph(
     llm_with_tools,
     tools: list,
     system_prompt_fn: Callable[[dict], str],
     state_schema: type = AgentState,
     enable_guardrails: bool = True,
     enable_knowledge_graph: bool = True,
     enable_cost_tracker: bool = True,
     enable_audit: bool = True,
     session_id: str | None = None,
 ) -> CompiledGraph:
     """Core ReAct graph builder. Parameterized by tools + prompt + state schema."""

 Existing create_agent() becomes a thin wrapper around build_react_graph() with the pentest defaults. The new hunter.py is another wrapper:

 def build_hunter_agent(file_target: FileTarget, repo_path: str,
                       sandbox: SandboxContainer, llm: BaseChatModel,
                       session_id: str,
                       specialist: str = "general",   # v0.1: "general"
                                                      # v0.2: "memory_safety"|"logic_auth"
                       seeded_crash: dict | None = None,  # v0.2: from Harness Generator
                       semgrep_hints: list[dict] = None,  # v0.2: from preprocessor
                       variant_seed: dict | None = None,  # v0.3: from variant loop
                       ) -> CompiledGraph:
     """Per-file ReAct agent, scoped to one file. Dispatches by tier and
     (in v0.2) by specialist:

     Tier A / B with specialist="general" (v0.1 default):
       HUNTER_PROMPT from openglass.md §3, full tool set
       (read, grep, compile_file, run_with_sanitizer, write_test_case,
        fuzz_harness, record_finding).

     Tier A / B with specialist="memory_safety" (v0.2):
       MEMORY_SAFETY_HUNTER_PROMPT — focused on length vs allocation,
       signed/unsigned confusion, width truncation, memcpy bounds,
       iterator overruns, sentinel collisions. Same tool set as general.

     Tier A / B with specialist="logic_auth" (v0.2):
       LOGIC_AUTH_HUNTER_PROMPT — focused on boolean defaults, comparison
       semantics, trust propagation, bypass branches, fail-open patterns,
       cache invalidation. Same tool set, but compile/run is rarely used.

     Tier C: uses TIER_C_PROPAGATION_AUDIT_PROMPT (see pool.py), narrower
       tool set via build_propagation_auditor_tools() — no compile/run,
       focus on grep-and-reason about downstream usages.

     seeded_crash != None (v0.2): overrides the system prompt with the
       crash-explainer prompt: 'A libFuzzer run produced this crash:
       {report}. Read the code, explain root cause, assess exploitability.'
       This is dramatically easier than cold-finding bugs and produces
       higher-signal hunter runs.

     semgrep_hints (v0.2): injected into the user message as 'Static analysis
       hints (NOT ground truth — use as starting points): {hints}'.

     variant_seed (v0.3): from variant hunter loop. Includes the original
       verified finding as context: 'A similar pattern was just verified
       at {file}:{line}. Check whether this file has the same flaw.'

     Budget is enforced at the pool level (each hunter has a per-file
     cost cap that differs by tier and by specialist).
     """

 Specialist routing logic (v0.2)

 def _choose_specialist(file_target: FileTarget) -> str:
     tags = set(file_target.get("tags", []))
     if "memory_unsafe" in tags or "parser" in tags or "fuzzable" in tags:
         return "memory_safety"
     if "auth_boundary" in tags or "crypto" in tags:
         return "logic_auth"
     # No clear specialty → fall back to general
     return "general"

 In v0.1, _choose_specialist() always returns "general" because tags are populated by the v0.1 minimum-viable file tagger but specialists don't exist yet. In v0.2, the
 specialists land and the routing function activates. No code outside hunter.py changes — the parameter exists in the v0.1 signature with a default.

 The ReAct graph structure is identical across all specialists/tiers — only the system prompt and tool list change, which is why build_react_graph() (R1) is parameterized
  by both. Adding a new specialist in v1.0 (kernel-syscall hunter? web-framework hunter?) is a new prompt + tool subset, not a new graph.

 verifier.py

 Same pattern as hunter.py but:

 1. Independent context — verifier never sees hunter's reasoning messages; only the finding dict + file content + PoC (if any).
 2. Different tier, same provider — reads ProviderManager.get_llm("verifier"). Default route: hunter=anthropic/opus, verifier=anthropic/sonnet. Independence comes from
 tier difference, not provider difference — zero extra setup for users with only ANTHROPIC_API_KEY. YAML config can upgrade to cross-provider independence later.
 3. Tool set: read_source_file, grep_source, compile_file, run_with_sanitizer (needs to reproduce the crash), record_verification — narrower than hunter, no fuzzing.
 4. Adversarial output schema — even in v0.1, the verifier's structured output has fields for pro_argument, counter_argument, tie_breaker_evidence. v0.1 uses a
 non-adversarial prompt that leaves counter_argument empty. v0.2 turns on adversarial mode by changing the prompt — no schema change.
 5. v0.3 adds patch-oracle truth test — after asserting the bug is real, the verifier writes a minimal defensive fix (widen a bound, add a guard, initialize a default),
 recompiles in the sandbox, re-runs the PoC. Crash gone → evidence_level = root_cause_explained AND patch_oracle_passed = True. Crash survives → flag the root-cause
 theory as suspect, bounce the finding back to a hunter for re-analysis. This is a truth test, not a deliverable patch.

 v0.1 verifier prompt (non-adversarial baseline)

 The Glasswing §5 prompt — confirm the bug, reproduce the crash, rate severity.

 v0.2 adversarial verifier prompt (drop-in upgrade)

 I have received the following bug report from a hunter agent:

 {finding_report}

 Your job is NOT to confirm it. Your job is to STEEL-MAN BOTH SIDES and
 determine which is correct. Specifically:

 1. PRO-VULNERABILITY ARGUMENT
    Construct the strongest possible case that this IS a real, exploitable
    vulnerability. Reproduce the crash if there's a PoC. Identify the root
    cause precisely. Rate severity assuming the worst plausible exploit.

 2. COUNTER-ARGUMENT (steel-manned)
    Construct the strongest possible case that this is NOT a real
    vulnerability or that severity is overstated. Specifically check:
      a. Is the crash caused by harness misuse (e.g. caller never passes
         these inputs in production)?
      b. Is the code path actually reachable from any real entry point?
         Walk the call chain back to a network handler, file parser, or
         user input.
      c. Do invariants enforced elsewhere in the codebase neutralize this?
         (Bounds-checked at the caller, validated at the API boundary, etc.)
      d. Is the severity overstated? Is the impact actually low because
         of mitigating context?
      e. Is this a duplicate of a known CVE that's already mitigated?

 3. TIE-BREAKER
    What single piece of evidence (a specific call site, a unit test, an
    invariant in a file you haven't read yet) would resolve the disagreement?
    GO LOOK FOR IT. Use the tools.

 4. VERDICT
    After looking at the tie-breaker evidence, return:
    - is_real: bool
    - severity: critical/high/medium/low
    - pro_argument: str (max 200 words)
    - counter_argument: str (max 200 words)
    - tie_breaker: str (what evidence resolved it)
    - evidence_level: one of [suspicion, static_corroboration,
      crash_reproduced, root_cause_explained]

 The adversarial framing addresses two failure modes simultaneously: false positives (the verifier was too eager to confirm the hunter) AND motivated dismissal (the
 verifier rationalized the bug away to keep the report clean).

 exploiter.py

 Runs only on findings where verified=True and severity_verified in {"critical","high"}. Uses ProviderManager.get_llm("sourcehunt_exploit") (default: opus). Sandboxed
 execution — exploits run inside the same hunter sandbox image (read-only source, no network, writable scratch). Tool set: read_source_file, compile_file,
 run_with_sanitizer, record_exploit_attempt.

 Prompt from openglass.md §6. The exploiter's job is severity triage, not weaponization — successful PoC bumps severity to critical; failure doesn't downgrade
 (compensating controls may be masking it).

 pool.py — HunterPool with tiered budget

 Copy the pattern from clearwing/runners/parallel/executor.py:42 but scope-shift from "target" to "file", and replace the hard rank cutoff with tiered budget
 allocation.

 Tier assignment (lives here, runs after the ranker populates all three axes and computes priority):

 def _assign_tier(f: FileTarget) -> Literal["A", "B", "C"]:
     p = f["priority"]   # surface*0.5 + influence*0.2 + reachability*0.3
     # Calibrated so a (surface=4, influence=2, reachability=4) file → A
     # (surface=2, influence=2, reachability=3) file → C
     if p >= 3.0:
         return "A"
     if p >= 2.0:
         return "B"
     return "C"

 The thresholds will need calibration on real repos in v0.1 — they're starting values. The unit test on the FFmpeg propagation fixture will pin them down empirically.

 Budget split (default 70/25/5, configurable):

 @dataclass
 class TierBudget:
     tier_a_fraction: float = 0.70    # primary hunt
     tier_b_fraction: float = 0.25    # secondary hunt
     tier_c_fraction: float = 0.05    # propagation spot-check (Tier C prompt)

 At default $5 total budget, that's $3.50 for Tier A, $1.25 for Tier B, $0.25 for Tier C. At $500 it's $350/$125/$25 — exactly the "enough to probe 15–20 boring files"
 the user called out.

 @dataclass
 class HuntPoolConfig:
     files: list[FileTarget]                 # already ranked (surface/influence/tier)
     repo_path: str
     sandbox: HunterSandbox                  # shared across hunters
     max_parallel: int = 8
     budget_usd: float = 5.0
     tier_budget: TierBudget = TierBudget()
     cost_limit_per_file_tier_a: float = 0.25
     cost_limit_per_file_tier_b: float = 0.15
     cost_limit_per_file_tier_c: float = 0.04    # Tier C is cheap by design
     timeout_minutes_per_file: int = 15
     on_finding: Optional[Callable] = None   # callback for streaming UI

 class HunterPool:
     def run(self) -> list[SourceFinding]:
         """Runs three sequential phases, one per tier.

         Phase A: submit all Tier A files to ThreadPoolExecutor. Stop when
                  Tier A spend >= tier_a_fraction * total budget. Remaining
                  Tier A budget rolls into Tier B.
         Phase B: same, for Tier B files, using the `hunter` prompt.
         Phase C: same, for Tier C files, using the `propagation_auditor`
                  prompt and `build_propagation_auditor_tools()` (smaller
                  tool set — no compile/run; just read, grep, find_callers).

         Each phase tracks spend under a shared lock. Rollover is a feature,
         not a bug — if Tier A finishes under budget, the extra flows
         downhill so Tier B and C benefit from unused spend.
         """

 Tier C gets a different prompt (TIER_C_PROMPT)

 Tier C files are usually cheap: constants headers, type definitions, default-values modules, small utility files. They're not where exploits live — they're where root
 causes live. The prompt reflects that:

 TIER_C_PROPAGATION_AUDIT_PROMPT = """You are auditing a LOW-SURFACE file for
 PROPAGATION RISK. This file is unlikely to contain a vulnerability directly,
 but its DEFINITIONS may cause vulnerabilities in downstream callers.

 File: {file_path}
 Imports-by (how many files depend on this): {imports_by}

 Do NOT try to find a traditional vulnerability. Instead, answer these specific
 questions about every definition in the file:

 1. BUFFER SIZE ADEQUACY
    For each buffer size constant or macro, ask: is this big enough for every
    downstream use? Grep for usages — are any callers writing more bytes than
    this constant allows? Any cases where this constant is used as a memcpy
    length but the source data can be larger?

 2. SENTINEL / MAGIC VALUE COLLISIONS
    For each sentinel byte, terminator, magic number, or "invalid" marker, ask:
    can this value legitimately appear in valid data? If downstream code treats
    this value as "end of stream" or "unset", what happens when real data
    contains it?

 3. TYPE WIDTH TRUNCATION
    For each type alias or struct field width, ask: can a downstream caller pass
    a value that silently truncates when stored here? size_t → int, int → short,
    int64 → int32. Check callers that assign from wider types.

 4. UNSAFE DEFAULTS
    For each default value (function parameter default, struct initializer,
    config default), ask: is the DEFAULT a fail-open or fail-closed choice?
    If a caller forgets to set this field, does it default to something
    dangerous (e.g. auth=false, verify=false, timeout=0, buffer=NULL)?

 5. MACRO HYGIENE (for C/C++)
    For each macro, ask: does it correctly parenthesize arguments? Could macro
    expansion cause operator-precedence bugs in callers?

 Use the tools to grep for usages of each definition and reason about whether
 callers treat it safely. Record a finding ONLY when you can point to a
 specific downstream caller that is or could be unsafe because of this
 definition — not for abstract concerns. If you find nothing, say so.

 Severity guidance: propagation bugs are typically HIGH or CRITICAL when they
 exist, because a single fix in the header repairs many call sites.
 """

 Tier C tools are a narrower subset:

 def build_propagation_auditor_tools(ctx: HunterContext) -> list:
     # No compile/run — these files don't usually need to be executed.
     # The focus is reading the file, grepping for usages, and reasoning
     # about whether those usages are safe given the definition.
     return [read_source_file, list_source_tree, grep_source, find_callers,
             record_finding]

 This keeps Tier C cheap (no compile round-trips, no sandbox binary execution) and on-task (it can only produce propagation findings, not generic file-level vuln hunts).

 Refactor (optional): Generalize ParallelExecutor so runner_factory: Callable[[str], Runner] is injectable. Then HunterPool becomes ParallelExecutor with a
 SourceHuntRunner factory. Deferred to Phase 2 to avoid churning stable code.

 runner.py — SourceHuntRunner

 Public entry point, analog of clearwing/runners/cicd/runner.py:29:

 @dataclass
 class SourceHuntResult:
     exit_code: int                    # 0=clean, 1=medium, 2=critical/high
     repo_url: str
     repo_path: str
     findings: list[SourceFinding]
     verified_findings: list[SourceFinding]
     files_ranked: int
     files_hunted: int
     duration_seconds: float
     cost_usd: float
     tokens_used: int
     output_paths: dict[str, str]      # {"sarif": ..., "markdown": ..., "json": ...}

 class SourceHuntRunner:
     def __init__(self, repo_url: str, branch: str = "main",
                  local_path: str | None = None,
                  depth: str = "standard",   # quick/standard/deep
                  budget_usd: float = 5.0,
                  max_parallel: int = 8,
                  min_rank: int = 3,
                  output_dir: str = "./sourcehunt-results",
                  output_formats: list[str] = ["sarif", "markdown", "json"],
                  no_verify: bool = False,
                  no_exploit: bool = True,   # Phase 2
                  model_override: str | None = None):
         ...

     def run(self) -> SourceHuntResult:
         """Orchestrates preprocess → build sandbox image → rank → hunt → verify → exploit → report."""

 Uses ProviderManager for model routing unless model_override is set. Reuses existing CostTracker singleton (pattern from runner.py:115) and AuditLogger (session_id
 propagated to every sub-agent). Sandbox image is built once per run during preprocess and reused by all hunters, the verifier, and the exploiter — this amortizes the
 build cost and guarantees identical runtime behavior across agents.

 reporter.py

 New file-aware report generator:

 - SARIF: extends clearwing/runners/cicd/sarif.py:6 via subclass or small change (see Refactor §1).
 - Markdown: grouped by file, severity-sorted, includes code snippets and verification status.
 - JSON: SourceHuntResult serialized directly.

 ---
 New sandbox package: clearwing/sandbox/

 clearwing/sandbox/
 ├── __init__.py
 ├── container.py       # generic SandboxContainer (Docker SDK wrapper)
 ├── hunter_sandbox.py  # HunterSandbox — builds per-hunt image, manages lifecycle
 └── builders.py        # BuildSystemDetector — detects make/cmake/cargo/go/maven/npm

 container.py — SandboxContainer

 Generic no-network Docker abstraction, distinct from clearwing/agent/tools/kali_docker_tool.py (which is attack-focused and has approval gates / network access).
 Shape:

 @dataclass
 class SandboxConfig:
     image: str
     network_mode: str = "none"               # "none" | "bridge" | "host"
     mounts: list[tuple[str, str, str]] = []  # (host, container, mode) mode = "ro"|"rw"
     memory_mb: int = 2048
     cpu_shares: int = 1024
     timeout_seconds: int = 300
     env: dict[str, str] = {}
     working_dir: str = "/workspace"

 class SandboxContainer:
     def __init__(self, config: SandboxConfig): ...
     def start(self) -> str: ...                              # returns container_id
     def exec(self, command: list[str], timeout: int | None = None) -> ExecResult:
         """Run a command. Returns {exit_code, stdout, stderr, duration}."""
     def write_file(self, container_path: str, content: bytes) -> None: ...
     def read_file(self, container_path: str) -> bytes: ...
     def stop(self) -> None: ...
     def __enter__(self) / __exit__(self, ...): ...           # context manager

 Uses docker Python SDK (same library as kali_docker_tool.py). No new dependency.

 hunter_sandbox.py — HunterSandbox

 class HunterSandbox:
     """Builds and manages a sanitizer-instrumented container for a source hunt."""

     DEFAULT_IMAGE_MAP = {
         # language → base image with toolchain + ASan/UBSan
         "c":      "gcc:13",       # has libasan/libubsan
         "cpp":    "gcc:13",
         "rust":   "rust:1-slim",  # rust-san via -Z sanitizer=address
         "go":     "golang:1.22",  # race + msan via go build -race
         "python": "python:3.12-slim",
         "java":   "eclipse-temurin:21",
         "node":   "node:20-slim",
     }

     def __init__(self, repo_path: str, languages: list[str],
                  extra_packages: list[str] = None):
         self.repo_path = repo_path
         self.languages = languages
         ...

     def build_image(self) -> str:
         """Build a Dockerfile that:
         - FROM one of DEFAULT_IMAGE_MAP (picks the dominant language)
         - installs gdb, valgrind, rr, strace, ripgrep (via apt)
         - sets env CFLAGS/CXXFLAGS with -fsanitize=address,undefined -g -O1
         - COPYs the repo (only needed for build-time; runtime uses a mount)
         Returns image tag (e.g. 'clearwing-sourcehunt-<hash>:latest')."""

     def spawn(self, session_id: str) -> SandboxContainer:
         """Start a container from the built image, with:
         - /workspace mounted read-only from repo_path
         - /scratch mounted read-write (tmpfs)
         - network_mode="none"
         - memory and CPU caps
         Returns a SandboxContainer ready for exec()."""

     def cleanup(self) -> None:
         """Stop and remove all spawned containers; optionally remove image."""

 Lifecycle: SourceHuntRunner.run() calls HunterSandbox.build_image() once after preprocessing. Each hunter/verifier/exploiter call to HunterPool acquires a fresh spawn()
 for the duration of that agent. Containers are torn down immediately on agent completion.

 builders.py — BuildSystemDetector

 Inspects a cloned repo and detects build system (Makefile, CMakeLists.txt, Cargo.toml, go.mod, pom.xml, package.json, setup.py, pyproject.toml). Returns a
 BuildRecipe(build_cmd: str, test_cmd: str, sanitizer_flags: dict) used by the HunterSandbox Dockerfile generator. Per-language strategies live here so new languages slot
  in without touching the sandbox core.

 ---
 New hunter tools: clearwing/agent/tools/hunter_tools.py

 All tools are scoped to a hunter session via a closure-injected HunterContext(repo_path, sandbox, state_writer). This prevents path traversal and routes every command
 through the active sandbox:

 @dataclass
 class HunterContext:
     repo_path: str
     sandbox: SandboxContainer
     findings: list[SourceFinding]  # mutable — tools append via record_finding

 def build_hunter_tools(ctx: HunterContext) -> list:
     @tool
     def read_source_file(path: str, start_line: int = 1, end_line: int = -1) -> str:
         """Read a source file (path is repo-relative). Returns up to 500 lines."""

     @tool
     def list_source_tree(dir_path: str = ".", max_depth: int = 2) -> list[str]:
         """List files and directories relative to repo root."""

     @tool
     def grep_source(pattern: str, path: str = ".", file_glob: str = "*") -> list[dict]:
         """ripgrep search (delegates to sandbox exec of `rg`). Returns
         [{file, line_number, matched_text}, ...]."""

     @tool
     def find_callers(symbol: str) -> list[dict]:
         """Find files/lines that reference a symbol. Wraps grep_source."""

     @tool
     def compile_file(file_path: str, sanitizers: list[str] = ["asan", "ubsan"],
                      extra_flags: str = "") -> dict:
         """Compile file (or build whole project if file is a single TU) with
         the requested sanitizers. Returns {success, binary_path, stderr}.
         Runs inside ctx.sandbox via sandbox.exec()."""

     @tool
     def run_with_sanitizer(binary: str, args: list[str] = [],
                            stdin: str = "", timeout: int = 30) -> dict:
         """Run a binary inside the sandbox with ASan/UBSan env set.
         Returns {exit_code, stdout, stderr, crash_evidence, crashed}.
         `crash_evidence` is the parsed ASan/UBSan report (stack trace,
         error kind) if the run crashed — this is the ground truth oracle."""

     @tool
     def write_test_case(path: str, content: str) -> str:
         """Write a test input / PoC into /scratch. Never writes to the
         read-only /workspace mount."""

     @tool
     def fuzz_harness(target_function: str, signature: str,
                      corpus_path: str | None = None, duration_seconds: int = 30) -> dict:
         """Generate a libFuzzer harness for target_function, compile it, and
         run for duration_seconds. Returns {crashes_found, coverage_pct,
         crash_reports}. [Kept for Phase 1 per scoping decision — if this
         proves too heavy in implementation, punt to Phase 2 and keep the
         stub.]"""

     @tool
     def record_finding(file: str, line_number: int, finding_type: str,
                        severity: str, cwe: str, description: str,
                        code_snippet: str, crash_evidence: str = "",
                        poc: str = "", confidence: str = "medium") -> str:
         """Record a finding. Appended to SourceHuntState.findings via the
         guarded_tools_node state-update hook."""

     return [read_source_file, list_source_tree, grep_source, find_callers,
             compile_file, run_with_sanitizer, write_test_case,
             fuzz_harness, record_finding]

 Verifier and exploiter get subsets of this tool list, not all of it (verifier has no record_finding; it gets record_verification. Exploiter gets record_exploit_attempt).

 Note on fuzz_harness: Keeping it in Phase 1 per scoping, but calling it out as the single riskiest tool. If it proves brittle, the fallback is to ship it as a no-op stub
  that returns "fuzzing deferred" and re-land properly in Phase 2. This avoids holding the rest of Phase 1 hostage.

 ---
 Interactive-agent @tool wrapper

 New file: clearwing/agent/tools/sourcehunt_tools.py

 Exposes the source-hunt pipeline as a tool callable from the existing interactive network-pentest agent. Matches the wargame/remediation tool pattern
 (clearwing/agent/tools/wargame_tools.py).

 @tool
 def hunt_source_code(repo_url_or_path: str, branch: str = "main",
                      depth: str = "quick", budget_usd: float = 2.0,
                      min_rank: int = 4) -> str:
     """Run the Overwing source-code vulnerability hunting pipeline against
     a git repository or local path. Returns a summary of findings.

     Use this when the interactive agent has access to a target's source
     code (e.g. via github URL, local clone, or MCP filesystem) and wants
     to perform white-box analysis alongside network scans.

     Args:
         repo_url_or_path: Git URL or local filesystem path.
         branch: Git branch (ignored for local paths).
         depth: quick (static + ranker only), standard (rank-4+ LLM hunt + verify),
                deep (rank-3+ LLM hunt + verify + exploit triage).
         budget_usd: Max dollars to spend. The interactive agent's own cost
                     tracker wraps this.
         min_rank: Minimum rank to hunt.

     Returns:
         Human-readable summary with critical/high counts and top 5 findings.
         Full SARIF/JSON/markdown are written to ./sourcehunt-results/<session>/.
     """
     from clearwing.sourcehunt.runner import SourceHuntRunner
     runner = SourceHuntRunner(
         repo_url=repo_url_or_path, branch=branch, depth=depth,
         budget_usd=budget_usd, min_rank=min_rank,
         # Inherit parent agent session_id so audit/cost roll up
         parent_session_id=_current_session_id(),
     )
     result = runner.run()
     return _summarize_for_agent(result)

 @tool
 def list_sourcehunt_findings(session_id: str = "") -> list[dict]:
     """Return previously-collected source-hunt findings for inspection by
     the interactive agent (e.g. to plan follow-up exploits)."""

 def get_sourcehunt_tools() -> list:
     return [hunt_source_code, list_sourcehunt_findings]

 Integration: One-line edit to clearwing/agent/tools/__init__.py:
 - import get_sourcehunt_tools from .sourcehunt_tools
 - append tools.extend(get_sourcehunt_tools()) near the other optional-tools block (line ~88).

 Prompt hint: Add one bullet to clearwing/agent/prompts.py::SYSTEM_PROMPT_TEMPLATE near the existing "Hybrid Whitebox/Graybox Testing" bullet (line 28), mentioning
 hunt_source_code as the white-box companion tool.

 Re-entrancy concern: When called from inside the interactive agent, hunt_source_code spawns a new LangGraph instance with its own MemorySaver. This is safe because each
 SourceHuntRunner gets a fresh session_id and doesn't touch the parent's state. Cost is tracked under CostTracker singleton — the parent agent already sees the aggregate.

 ---
 Refactor: narrow and payoff-positive

 Two refactors are required for Phase 1 (R1, R2). R3 is deferred.

 R1 — Extract build_react_graph() from create_agent()

 File: clearwing/agent/graph.py

 Reason: the hunter/verifier agents need the same assistant + guarded_tools_node structure with different tools and state schema. Copy-paste would duplicate ~180 lines
 (lines 227–401 of graph.py) and create a drift risk in cost/audit/memory wiring.

 Shape of the refactor:
 1. Extract the assistant() closure and guarded_tools_node() closure into build_react_graph(llm_with_tools, tools, system_prompt_fn, state_schema, feature_flags...).
 2. create_agent() (existing public API) becomes a ~30-line wrapper that calls build_react_graph() with the pentest defaults. Public signature unchanged.
 3. clearwing/sourcehunt/hunter.py and verifier.py call build_react_graph() directly with their own tools + prompt.

 Risk: Low — existing callers of create_agent() see no signature change. Covered by tests/test_agent.py.

 R2 — Make SARIFGenerator file-aware

 File: clearwing/runners/cicd/sarif.py:61

 Today, every finding's physicalLocation hardcodes target as the artifactLocation URI. The change: if a finding has file key, use that instead of target; if it has
 line_number, emit a region with startLine.

 physical = {"artifactLocation": {"uri": finding.get("file", target)}}
 if "line_number" in finding:
     physical["region"] = {"startLine": finding["line_number"]}
     if finding.get("end_line"):
         physical["region"]["endLine"] = finding["end_line"]
 result["locations"] = [{"physicalLocation": physical}]

 Risk: Zero — existing network-findings don't have file/line_number keys, so they fall through to the current behavior.

 (Deferred) R3 — Generalize ParallelExecutor with injectable runner

 File: clearwing/runners/parallel/executor.py:101

 Not required for Phase 1. Phase 2 will lift the hardcoded CICDRunner instantiation into a runner_factory: Callable[[str], Runner] parameter so HunterPool becomes a
 config of ParallelExecutor. Deferring keeps Phase 1 tight — HunterPool ships as a sibling class, not a refactor of the shared one.

 (Deferred) R4 — Unified Finding type

 New file: clearwing/findings/types.py

 Currently there are three incompatible finding shapes:
 - clearwing.analysis.source_analyzer.Finding (file-level)
 - CICDRunner._collect_findings() dict (network-level)
 - clearwing.data.knowledge entities (graph nodes)

 Phase 2 refactor: consolidate behind a single Finding dataclass with optional network AND source fields. Until then, sourcehunt.state.SourceFinding is a deliberate
 superset that can be trivially downcast to the CICDRunner dict shape when consumed by SARIFGenerator.

 Dependencies

 v0.1: No new pip packages. All needed libraries are already in the project:
 - docker (already used by kali_docker_tool.py)
 - langgraph, langchain-core, langchain-anthropic (existing)
 - networkx (existing, used by knowledge graph)
 - No ripgrep dependency on the host — we exec rg inside the sandbox image, installed via apt during HunterSandbox.build_image().

 v0.2 will add: tree-sitter + tree-sitter-languages (cheap, pure-Python, ~20 MB of grammars). Called out here so v0.1 interfaces (CallGraph dataclass, build_callgraph
 flag) are designed to accept these without refactoring.

 v0.3 will add: chromadb (or equivalent — check if the project already has a vector store in clearwing/data/ by then) for cross-run memory.

 The only v0.1 external runtime requirement is Docker daemon on the host running sourcehunt. This is the same requirement as kali_docker_tool, so users of the interactive
  agent with Kali integration already have it. The CLI detects Docker availability at startup and fails cleanly with an actionable error. A documented fallback: --depth
 quick runs the preprocessor + ranker + static SourceAnalyzer without spawning any sandbox, so users without Docker can still get value.

 ---
 CLI: new subcommand

 New file: clearwing/ui/commands/sourcehunt.py

 def add_parser(subparsers):
     p = subparsers.add_parser("sourcehunt",
         help="Source-code vulnerability hunting (Overwing pipeline)")
     p.add_argument("repo", help="Git URL or local path")
     p.add_argument("--branch", default="main")
     p.add_argument("--depth", choices=["quick", "standard", "deep"], default="standard")
     p.add_argument("--budget", type=float, default=5.0, help="Max $ spend")
     p.add_argument("--max-parallel", type=int, default=8)
     p.add_argument("--tier-split", default="70/25/5",
         help="Budget split A/B/C as percentages, e.g. 70/25/5 (default) "
              "or 60/30/10 to spend more on propagation audits")
     p.add_argument("--skip-tier-c", action="store_true",
         help="Disable Tier C propagation audits (faster, cheaper, misses "
              "root-cause-in-boring-files bugs)")
     p.add_argument("--model", default=None,
         help="Override all role models with one model (simple mode)")
     p.add_argument("--no-verify", action="store_true")
     p.add_argument("--no-exploit", action="store_true")
     p.add_argument("--output-dir", default="./sourcehunt-results")
     p.add_argument("--format", nargs="+", choices=["sarif", "markdown", "json", "all"],
                    default=["all"])
     return p

 def handle(cli, args):
     from clearwing.sourcehunt.runner import SourceHuntRunner
     from clearwing.sourcehunt.pool import TierBudget
     a, b, c = [int(x) / 100.0 for x in args.tier_split.split("/")]
     if args.skip_tier_c:
         # Redistribute Tier C allocation into A (keeps total at 1.0)
         a += c
         c = 0.0
     runner = SourceHuntRunner(
         repo_url=args.repo, branch=args.branch, depth=args.depth,
         budget_usd=args.budget, max_parallel=args.max_parallel,
         tier_budget=TierBudget(tier_a_fraction=a, tier_b_fraction=b,
                                tier_c_fraction=c),
         output_dir=args.output_dir, output_formats=_expand_formats(args.format),
         no_verify=args.no_verify, no_exploit=args.no_exploit,
         model_override=args.model,
     )
     result = runner.run()
     print(_format_summary(result))
     return result.exit_code

 One-line edit: clearwing/ui/commands/__init__.py:3 adds sourcehunt to the imports and ALL_COMMANDS list.

 Note: --min-rank is deliberately absent. The tier-split IS the budget cut; there is no hard cutoff that could drop the FFmpeg-style "influence=5, surface=1" file.

 ---
 Provider routing: model-per-role

 Edit: clearwing/providers/manager.py:53 (DEFAULT_ROUTES)

 Add routes:

 ModelRoute(task="ranker",   provider="anthropic", model="claude-haiku-4-5-20251001",
            reason="File ranking is simple classification"),
 ModelRoute(task="hunter",   provider="anthropic", model="claude-opus-4-6",
            reason="Core vuln-finding reasoning"),
 ModelRoute(task="verifier", provider="anthropic", model="claude-sonnet-4-6",
            reason="Independent verification — different tier from hunter"),
 ModelRoute(task="sourcehunt_exploit", provider="anthropic", model="claude-opus-4-6",
            reason="Exploit generation is hardest reasoning"),

 YAML override: extend clearwing/core/config.py to parse a models: section and call provider_manager.set_route(task, ...) for each entry. overwing.yaml from the spec
 works as-is.

 Ideal verifier should run on a different provider (per openglass.md §5). Default leaves this at sonnet-within-anthropic, with YAML available for openai/gpt-5 etc.

 ---
 Reuse inventory (no new code needed)

 ┌─────────────────────────────┬─────────────────────────────────────┬─────────────────────────────────────────────────────────────────┐
 │            Need             │          Reused component           │                            Location                             │
 ├─────────────────────────────┼─────────────────────────────────────┼─────────────────────────────────────────────────────────────────┤
 │ Clone repo                  │ SourceAnalyzer.clone()              │ clearwing/analysis/source_analyzer.py:230                     │
 ├─────────────────────────────┼─────────────────────────────────────┼─────────────────────────────────────────────────────────────────┤
 │ Enumerate files             │ SourceAnalyzer._iter_source_files() │ clearwing/analysis/source_analyzer.py:309                     │
 ├─────────────────────────────┼─────────────────────────────────────┼─────────────────────────────────────────────────────────────────┤
 │ Language detection          │ SourceAnalyzer.LANGUAGE_MAP         │ clearwing/analysis/source_analyzer.py:70                      │
 ├─────────────────────────────┼─────────────────────────────────────┼─────────────────────────────────────────────────────────────────┤
 │ Regex/AST pre-scan          │ SourceAnalyzer.analyze()            │ clearwing/analysis/source_analyzer.py:256                     │
 ├─────────────────────────────┼─────────────────────────────────────┼─────────────────────────────────────────────────────────────────┤
 │ Cost tracking               │ CostTracker singleton               │ clearwing/telemetry/                                          │
 ├─────────────────────────────┼─────────────────────────────────────┼─────────────────────────────────────────────────────────────────┤
 │ Audit log                   │ AuditLogger                         │ clearwing/safety/audit/                                       │
 ├─────────────────────────────┼─────────────────────────────────────┼─────────────────────────────────────────────────────────────────┤
 │ Session-scoped checkpointer │ MemorySaver                         │ via graph.compile(checkpointer=...)                             │
 ├─────────────────────────────┼─────────────────────────────────────┼─────────────────────────────────────────────────────────────────┤
 │ Flag detection              │ detect_flags()                      │ clearwing/agent/graph.py:70                                   │
 ├─────────────────────────────┼─────────────────────────────────────┼─────────────────────────────────────────────────────────────────┤
 │ SARIF schema                │ SARIFGenerator                      │ clearwing/runners/cicd/sarif.py:6 (needs R2)                  │
 ├─────────────────────────────┼─────────────────────────────────────┼─────────────────────────────────────────────────────────────────┤
 │ Model routing               │ ProviderManager.get_llm()           │ clearwing/providers/manager.py:78                             │
 ├─────────────────────────────┼─────────────────────────────────────┼─────────────────────────────────────────────────────────────────┤
 │ Parallel fan-out pattern    │ ParallelExecutor                    │ clearwing/runners/parallel/executor.py:42 (copy, don't reuse) │
 ├─────────────────────────────┼─────────────────────────────────────┼─────────────────────────────────────────────────────────────────┤
 │ Subcommand registration     │ ALL_COMMANDS auto-discovery         │ clearwing/ui/commands/__init__.py:5                           │
 ├─────────────────────────────┼─────────────────────────────────────┼─────────────────────────────────────────────────────────────────┤
 │ ReAct graph skeleton        │ create_agent() (after R1)           │ clearwing/agent/graph.py:176                                  │
 └─────────────────────────────┴─────────────────────────────────────┴─────────────────────────────────────────────────────────────────┘

 ---
 v0.2 Running — sketch (next milestone after v0.1 ships)

 1. Crash-first pipeline ordering — Move Harness Generator BEFORE the HunterPool fan-out. New phase order:
 preprocess → tag → rank → fuzz → hunt → verify → exploit → report.
 Fuzzers launch in the background while preprocessing/ranking finishes; by the time the HunterPool starts, files with crashes have seeded_crash populated and their
 hunters get the easier "explain this crash" prompt instead of "find a vulnerability." Files without crashes proceed normally with the cold-start hunter prompt.
 2. Harness Generator node — new clearwing/sourcehunt/harness_generator.py. For each file tagged parser or fuzzable with surface >= 4:
   - Uses the LLM to generate a libFuzzer harness (int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)) that calls the file's main entry point with the buffer.
   - Compiles the harness in the sandbox (ASan + libFuzzer + the project's headers).
   - Launches it in the background with a per-target time budget (default 2 hours total, distributed by rank).
   - On crash, captures the ASan report, minimized input, and stack trace into a seeded_crashes entry.
   - Files that are easily fuzzable get a rank boost (priority += 0.5) since they'll produce higher-signal hunter runs.
 3. Tree-sitter callgraph in preprocessor — new clearwing/sourcehunt/callgraph.py using tree_sitter + tree_sitter_languages. Language-aware AST parsing without
 compiling. Builds a CallGraph mapping {file_path → {"functions": [...], "calls_out": [...], "called_by": [...]}}. The ranker's influence axis becomes
 clamp(log2(len(transitive_callers(f)) + 1), 1, 5) — real data, not LLM guessing. Also feeds reachability propagation.
 4. Reachability propagation — Identifies entry points by file tags (parser, syscall_entry, network-handler heuristics) and propagates "attacker-reachable" through the
 callgraph one hop at a time. Each FileTarget gains a real reachability score (1-5). Files unreachable from any tagged entry point get reachability=1 and drop in
 priority.
 5. Two specialist hunters — MEMORY_SAFETY_HUNTER_PROMPT and LOGIC_AUTH_HUNTER_PROMPT in clearwing/sourcehunt/hunter.py. Routed by _choose_specialist(file_target) based
  on tags. Same graph node as v0.1's general hunter — only the system prompt and tool emphasis change. Start with exactly two. Add more specializations only when data
 shows these are missing specific bug classes.
 6. Adversarial verifier — Activate the v0.2 prompt with the steel-manned counter-argument requirement. Verifier output schema is unchanged (slots already exist in v0.1's
  SourceFinding). Just a prompt swap.
 7. Semgrep sidecar — new clearwing/sourcehunt/semgrep_sidecar.py. One static-analysis tool, one output format, one maintenance burden. Run during preprocessing with
 the p/security-audit ruleset (or whichever is current). Per-file count fed into semgrep_hint for a surface boost; full findings injected as hints into hunter prompts.
 Never used as a source of truth — only as a starting hypothesis.
 8. Lightweight reachability tagging — Heuristic-based entry-point identification (network handlers via socket/bind/accept, file parsers via signature matching, CLI arg
 processors via argparse/getopt/clap, RPC handlers via framework conventions). NO full taint/dataflow analysis — that's v1.0+.
 9. Evidence levels — full enforcement — Pipeline gates activate. Exploiter only runs on findings with evidence_level >= crash_reproduced. Verifier only spends
 adversarial budget on findings with evidence_level >= static_corroboration. Findings stay at suspicion if neither static analysis nor a fuzz crash corroborates them, and
  they're reported as low-confidence noise (still listed but visually segregated).
 10. UBSan + MSan alongside ASan — Extend HunterSandbox.build_image() with sanitizers: list[str] config. MSan as a separate build variant (MSan can't coexist with ASan in
  the same binary). Hunter tools gain a sanitizer_variant parameter; run_with_sanitizer picks the right binary.
 11. Blast radius analysis — clearwing/sourcehunt/blast_radius.py. Given a set of changed files (from git diff or commit hash), uses the callgraph to compute all
 transitive callers. Feeds that expanded set into the HunterPool. Enabler for v0.3 Commit Monitor.
 12. R3 refactor — Generalize ParallelExecutor with runner_factory; replace HunterPool with a thin config-layer on top.

 v0.3 Flying — sketch (milestone after v0.2)

 1. Variant Hunter Loop — new clearwing/sourcehunt/variant_loop.py. Slotted between Verifier and Exploiter. For each verified finding:
   - Auto-generate three pattern artifacts: a lexical grep query, an AST pattern (tree-sitter), a semantic description.
   - Search the full codebase for structural matches.
   - Each match becomes a pre-seeded hypothesis injected back into the HunterPool as a new task: variant_seed={original_finding, pattern, match_location}.
   - Hunters working on variants get a modified prompt: "A similar pattern was just verified at {file}:{line}. Check whether this match is the same flaw."
   - This produces compounding finding-density inside one scan — one verified bug becomes a search vector for siblings.
   - Loop terminates when a pass produces no new variants OR when the variant_loop_budget (default 15% of total) is exhausted.
 2. Patch-oracle in verifier — Activate the truth test in the verifier. After verification, attempt a minimal defensive fix (widen a bound, add a guard, initialize a
 default), recompile, re-run the PoC. Crash gone → causally validated, bump to evidence_level=root_cause_explained. Crash survives → flag the root cause theory as
 suspect, bounce back to a hunter for re-analysis. Lightweight, not a deliverable.
 3. Mechanism-level cross-run memory — new clearwing/sourcehunt/mechanism_memory.py. Stores mechanisms, not findings: "length field trusted before allocation; 16-bit
 user-controlled value widened to size_t; mitigated by validating upper bound." Extracted via a short LLM pass after verification. Used as hunter prompt context on future
  runs: "patterns known to produce vulnerabilities in similar codebases."
   - Defer the vector store — start with an append-only JSON file (~/.clearwing/sourcehunt/mechanisms.jsonl). Move to Chroma only after mechanism extraction is solid.
 The hunter prompt picks the top-N most relevant mechanisms by simple keyword overlap on tags + language.
   - Storage seam is in v0.1's Reporter so future runs can read it; v0.1 just doesn't write to it.
 4. Commit Monitor (sourcehunt watch <repo> subcommand)
   - Watches for new commits via git fetch polling or GitHub webhooks.
   - On change, runs blast-radius analysis (v0.2) to expand changed files → all transitive callers.
   - Runs the full pipeline on the expanded set with --tier-split 80/15/5 (more emphasis on Tier A because changes are pre-selected).
   - Streams findings to an append-only log; integrates with GitHub Checks API to comment on PRs.
 5. CVE Retro-Hunt (sourcehunt retro-hunt <CVE_ID> subcommand)
   - Input: CVE ID + patch commit hash.
   - Fetches the patch diff (via NVD API — already used by clearwing/scanners/vulnerability_scanner.py).
   - LLM generates a Semgrep rule capturing the pattern that was fixed (Semgrep, not CodeQL — one tool).
   - Runs the rule across the target repo(s).
   - Hits go into the hunter pipeline as variant seeds with related_cve: {CVE_ID}.
 6. Auto-Patch mode — new clearwing/sourcehunt/patcher.py. Runs after the Exploiter on verified critical/high findings (evidence_level >= exploit_demonstrated):
   - Spawns a patcher agent. Writes a minimal fix.
   - Recompiles in sandbox, re-runs the exploit PoC.
   - Crash reproduces → patch rejected, log the attempt, don't include in report.
   - Crash disappears → candidate patch included in report as suggestion, evidence_level=patch_validated. Optionally opens a draft PR via gh CLI if --auto-pr.
   - Never ship an unverified patch suggestion.
 7. R4 — unified Finding type refactor — Now worth doing because v0.3 has many producers (hunter, harness generator, variant loop, retro-hunt, semgrep, auto-patcher) and
 many consumers (verifier, patch oracle, exploiter, reporter, mechanism memory). Consolidate behind a single dataclass.
 8. Knowledge-graph source entities — KnowledgeGraph.add_source_file(), add_source_finding(), auto-population from hunter results.
 9. CVE submission helper — pre-filled MITRE/HackerOne submission templates from evidence_level=patch_validated findings.

 v1.0+ — deferred (not scoped)

 These are real but premature. Listed here so the architecture keeps them possible without pre-building them:

 - Full taint/dataflow analysis — Replaces the lightweight reachability heuristic with real source/sink propagation. Slow, expensive, and only worth it once the agentic
 pipeline starts producing measurable false positives that taint analysis would catch.
 - Additional specialist hunters based on data — Kernel-syscall hunter, web-framework hunter, smart-contract hunter. Add them only when v0.2's two specialists empirically
  miss a bug class.
 - DPO fine-tuning on verified findings — Once there's a corpus of (hunt_transcript, verified_label) pairs from real runs, train a hunter via DPO. Premature without that
 corpus.
 - Distributed Ray execution — HunterPool scaled across multiple machines. ThreadPoolExecutor is fine until single-machine LLM throughput becomes the bottleneck.
 - Community finding database — Opt-in sharing of verified findings across users.

 Explicitly removed from scope: A planner-executor rewrite. ReAct-on-LangGraph is the right substrate; the rigidity of a pre-planned DAG does not justify the complexity
 in this domain.

 ---
 Testing & verification

 Unit tests (Phase 1)

 New files:
 - tests/test_sourcehunt_preprocessor.py — clone a small fixture repo, verify FileTarget list, language detection, static-hint counts, imports_by counts. Verify v0.1 file
  tagger correctly tags .c files as memory_unsafe, parse_*.c as parser, crypto/* as crypto, files with LLVMFuzzerTestOneInput as fuzzable. Verify v0.2 seams (callgraph,
 semgrep_findings, fuzz_corpora) are present and default to None/empty in v0.1.
 - tests/test_sourcehunt_ranker.py — mock ProviderManager.get_llm("ranker"), assert chunking for >150 files, verify both surface AND influence are in 1-5 range,
 static-hint-promotes-surface logic, the imports-by-floor for influence, and reachability defaults to 3 in v0.1. Verify priority is computed correctly via the three-axis
 formula.
 - tests/test_sourcehunt_tiering.py — pure-unit test of _assign_tier(): a file with surface=1 influence=5 reachability=3 must land in Tier A (priority = 0.5 + 1.0 + 0.9 =
  2.4 → wait, that's Tier B; recalibrate thresholds in implementation). A file with surface=5 influence=1 reachability=3 must land in Tier A (2.5 + 0.2 + 0.9 = 3.6). A
 file with all-2 must land in Tier C. The FFmpeg-style propagation file MUST land in Tier A or Tier B — never Tier C.
 - tests/test_sourcehunt_pool_budget.py — mock hunter execution, verify the pool spends close to tier_a_fraction * total on Tier A and rolls unused Tier A budget into
 Tier B (not discarded). Verify --skip-tier-c redistributes correctly. Verify spent_per_tier in state is populated.
 - tests/test_sourcehunt_hunter.py — mock LLM + mock SandboxContainer, assert hunter tools are invocable and record_finding appends to state. Verify v0.1 always selects
 specialist="general". Verify the seeded_crash and semgrep_hints parameters are accepted (defaulted to None) so v0.2 can fill them without changing the signature. Verify
 Tier C hunters get TIER_C_PROPAGATION_AUDIT_PROMPT and a smaller tool list (no compile_file / run_with_sanitizer).
 - tests/test_sourcehunt_verifier.py — independent-context assertion (verifier messages never contain hunter reasoning). Verify the v0.1 verifier output schema includes
 pro_argument, counter_argument, tie_breaker_evidence fields (counter is empty in v0.1, populated in v0.2). Verify evidence_level is set to crash_reproduced or
 root_cause_explained after verification.
 - tests/test_sourcehunt_exploiter.py — exploit-triage only runs on verified findings with evidence_level >= crash_reproduced. Findings at suspicion or
 static_corroboration are skipped (budget gate). Severity bumps to exploit_demonstrated on successful PoC.
 - tests/test_sourcehunt_evidence_levels.py — pure-unit test of the evidence ladder: each level is a strict ordering, comparison helpers work
 (evidence_at_or_above("crash_reproduced")), and the budget gate function correctly filters findings.
 - tests/test_sourcehunt_runner.py — end-to-end with mocked LLM + tiny in-repo C/Python fixture (under tests/fixtures/vuln_samples/). Asserts SARIF output has correct
 file+line, verified_findings count, non-zero exit code. Includes the FFmpeg-style propagation fixture and asserts the propagation bug is found. Asserts evidence_level is
  set on every finding.
 - tests/test_sourcehunt_tools.py — interactive @tool wrapper — assert hunt_source_code is discoverable via get_all_tools() and returns a summary string.
 - tests/test_sandbox_container.py — unit tests for SandboxContainer with docker mocked: start/exec/stop lifecycle, mount modes, resource limits, no-network verification.
 - tests/test_hunter_sandbox.py — unit tests for HunterSandbox.build_image() with docker mocked: Dockerfile contents, language detection, sanitizer flags. Verify
 sanitizers: list[str] parameter is accepted (v0.1 hardcodes ["asan", "ubsan"]; v0.2 unlocks msan).
 - tests/test_sarif_file_aware.py — regression: existing network-shape findings still produce the current SARIF; new file-shape findings produce physicalLocation.region.
 - tests/test_graph_refactor.py — R1 regression: create_agent() behavior unchanged after factoring out build_react_graph().

 Future-compat tests (assert the v0.1 interfaces accept v0.2/v0.3 inputs without erroring, even though the v0.1 code paths ignore them):
 - tests/test_sourcehunt_v02_seams.py — Pass callgraph, semgrep_findings, seeded_crashes, fuzz_corpora, tags into the runner and verify the pipeline runs to completion.
 v0.1 ignores them, but the schemas must accept them so v0.2 lands as a feature add, not a refactor.

 FFmpeg-style propagation fixture — tests/fixtures/vuln_samples/c_propagation/:

 c_propagation/
 ├── Makefile
 ├── include/
 │   └── codec_limits.h       # #define MAX_FRAME_BYTES 256  ← the "boring" file
 ├── src/
 │   ├── codec_a.c            # memcpy(frame, input, MAX_FRAME_BYTES)   ← 3 callers
 │   ├── codec_b.c            # memcpy(frame, input, MAX_FRAME_BYTES)
 │   └── codec_c.c            # memcpy(frame, input, MAX_FRAME_BYTES)
 └── test_oversized.c         # sends a 512-byte input → ASan detects heap overflow

 The ranker should score codec_limits.h at surface=1 influence=5 → Tier A. Even if we force the ranker to whiff (test fixture sets surface=1 influence=1), the Tier C
 audit run must still surface a finding because the TIER_C prompt specifically asks about buffer size adequacy. This is the regression test for the entire
 two-axis-plus-Tier-C design.

 Existing tests to re-run: tests/test_agent.py, tests/test_dynamic_tools.py, tests/test_kali_docker.py — guard against R1 regressions and ensure docker tool coexistence
 with the new sandbox.

 Integration tests (Docker required, opt-in)

 - tests/integration/test_sandbox_real_docker.py (pytest -m docker) — spawn a real gcc:13 container, compile a tiny C program with -fsanitize=address, run it with a known
  heap-overflow input, assert ASan report is parsed from stderr. This validates the full sandbox path without LLM cost.
 - tests/integration/test_hunter_sandbox_c_crash.py — build a HunterSandbox from tests/fixtures/vuln_samples/c_heap_overflow/, use compile_file + run_with_sanitizer tools
  to reproduce a crash, assert crash_evidence contains heap-buffer-overflow.
 - tests/integration/test_sourcehunt_real_llm.py (pytest -m "llm and docker", opt-in via env var) — point at a small real repo, run with --budget 0.50 --depth standard,
 assert at least one known CVE-style finding is recovered and survives verification.

 Manual end-to-end

 # From a clean checkout (docker must be running)
 pip install -e .
 docker info > /dev/null || echo "ERROR: Docker daemon not reachable"
 export ANTHROPIC_API_KEY=...

 # 1. Smoke test without Docker (pure static path)
 python clearwing.py sourcehunt https://github.com/snoopysecurity/dvws-node \
     --branch master --depth quick --budget 0.25 \
     --output-dir /tmp/overwing-quick

 # 2. Standard test — sandboxed Python/JS hunter + verifier
 python clearwing.py sourcehunt https://github.com/OWASP/NodeGoat \
     --depth standard --budget 1.00 --max-parallel 4 \
     --output-dir /tmp/overwing-std

 # 3. Deep test — C memory-safety hunt with ASan + exploit triage
 python clearwing.py sourcehunt tests/fixtures/vuln_samples/c_heap_overflow \
     --depth deep --budget 2.00 --max-parallel 2 \
     --output-dir /tmp/overwing-deep

 # 4. Interactive agent integration
 python clearwing.py interactive
 > hunt the source code at https://github.com/snoopysecurity/dvws-node
 # Expect the agent to call `hunt_source_code` tool and stream summary.

 # Inspect outputs
 ls /tmp/overwing-deep/
 cat /tmp/overwing-deep/findings.sarif | jq '.runs[0].results | length'
 cat /tmp/overwing-deep/report.md
 docker ps -a | grep clearwing-sourcehunt  # expect zero — cleanup verified

 Success criteria:
 - Preprocessor clones and enumerates files without errors.
 - Ranker returns both surface and influence 1–5 for every file; rationales are non-empty.
 - Tier assignment is deterministic: _assign_tier on a surface=1 influence=5 file returns "A".
 - HunterSandbox.build_image() succeeds and the image includes rg, gdb, libasan.
 - At least one finding with file+line_number is emitted; for the C fixture, at least one has non-empty crash_evidence.
 - Propagation smoke test: running against tests/fixtures/vuln_samples/c_propagation/ with a forced-whiff ranker (tier_c_fraction bumped to 30%) must produce at least one
  Tier C finding pointing at codec_limits.h with finding_type="buffer_size_inadequate" or similar.
 - Budget distribution check: after a run, the sourcehunt-results/<session>/manifest.json shows tier_a_spend + tier_b_spend + tier_c_spend ≈ total_spend, each within ±20%
  of its allocation (rollover is allowed, over-spend is not).
 - Verifier marks at least one finding as verified with severity_verified set.
 - SARIF validates against the v2.1.0 schema (npm install -g @microsoft/sarif-multitool && sarif-multitool validate /tmp/overwing-deep/findings.sarif).
 - CostTracker total is within budget.
 - Audit log at ~/.clearwing/audit/<session>/audit.jsonl contains log_tool_call entries for hunter tools (including compile_file and run_with_sanitizer for Tier A/B,
 and grep_source/find_callers for Tier C).
 - All containers are torn down (docker ps -a shows zero lingering sourcehunt containers).
 - Interactive agent successfully calls hunt_source_code and surfaces the summary back to the user.

 ---
 Critical files to be created / modified (Phase 1)

 New files:
 - clearwing/sourcehunt/__init__.py
 - clearwing/sourcehunt/state.py
 - clearwing/sourcehunt/preprocessor.py
 - clearwing/sourcehunt/ranker.py
 - clearwing/sourcehunt/hunter.py
 - clearwing/sourcehunt/verifier.py
 - clearwing/sourcehunt/exploiter.py
 - clearwing/sourcehunt/pool.py
 - clearwing/sourcehunt/runner.py
 - clearwing/sourcehunt/reporter.py
 - clearwing/sandbox/__init__.py
 - clearwing/sandbox/container.py
 - clearwing/sandbox/hunter_sandbox.py
 - clearwing/sandbox/builders.py
 - clearwing/agent/tools/hunter_tools.py
 - clearwing/agent/tools/sourcehunt_tools.py (interactive @tool wrapper)
 - clearwing/ui/commands/sourcehunt.py
 - tests/test_sourcehunt_*.py (11 files — see §Testing: preprocessor, ranker, tiering, pool_budget, hunter, verifier, exploiter, evidence_levels, runner, tools,
 v02_seams)
 - tests/test_sandbox_container.py
 - tests/test_hunter_sandbox.py
 - tests/test_sarif_file_aware.py
 - tests/test_graph_refactor.py
 - tests/integration/test_sandbox_real_docker.py
 - tests/integration/test_hunter_sandbox_c_crash.py
 - tests/integration/test_sourcehunt_real_llm.py
 - tests/fixtures/vuln_samples/ (Python/JS/C vulnerable snippets — at minimum: py_sqli/, js_xss/, c_heap_overflow/, c_propagation/ — the FFmpeg-style influence=5
 regression fixture)

 Modified files:
 - clearwing/agent/graph.py — R1: extract build_react_graph(), keep create_agent() as wrapper.
 - clearwing/runners/cicd/sarif.py — R2: file-aware physicalLocation (backwards compatible).
 - clearwing/providers/manager.py — add ranker/hunter/verifier/sourcehunt_exploit routes to DEFAULT_ROUTES.
 - clearwing/core/config.py — optional YAML models: section loader calling set_route().
 - clearwing/ui/commands/__init__.py — register sourcehunt command.
 - clearwing/agent/tools/__init__.py — one-line tools.extend(get_sourcehunt_tools()) near the other optional-tools block (~line 88).
 - clearwing/agent/prompts.py — one bullet added to SYSTEM_PROMPT_TEMPLATE describing hunt_source_code as the white-box companion tool.
 - README.md — Overwing section in features list (no new docs files per repo convention).

 No existing files are deleted. No breaking changes to public APIs.

 ---
 Implementation order (rough, v0.1 only)

 1. R2 (SARIF file-awareness) — trivial, lands first so hunter tests can use it.
 2. R1 (extract build_react_graph) — covered by existing agent tests; enables hunter/verifier/exploiter to share core.
 3. State schemas — SourceHuntState, FileTarget (with tags, reachability, priority), SourceFinding (with evidence_level, discovered_by, adversarial-verifier slots, future
  v0.2/v0.3 fields). Get the schema right BEFORE writing any pipeline code — these are the seams everything plugs into.
 4. Evidence ladder helpers — evidence_at_or_above(), evidence_compare(), the budget-gate filter function. Trivial, but needed everywhere.
 5. Sandbox primitives — SandboxContainer, HunterSandbox, BuildSystemDetector. Unit-test with mocked docker, integration-test against real docker.
 6. Provider routes — add entries to DEFAULT_ROUTES.
 7. Preprocessor — clone + enumerate + static pre-scan + cheap heuristic file tagger. v0.2 seams (callgraph=None, semgrep_findings=[], etc.) are present but unused.
 8. Ranker — three-axis with reachability defaulted to 3. Priority formula and tier assignment.
 9. Hunter tools + hunter.py — wire tools to a real sandbox; unit tests mock the sandbox. specialist="general" is the only path. seeded_crash and semgrep_hints parameters
  exist with default None.
 10. verifier.py — non-adversarial v0.1 prompt, but output schema has the adversarial slots populated as empty strings.
 11. exploiter.py — gated on evidence_level >= crash_reproduced. Use the existing exploit specialist pattern.
 12. pool.py — tiered 70/25/5 budget with rollover, three sequential phases (A, B, C), Tier C uses propagation auditor.
 13. runner.py — orchestrates preprocess → rank → tiered hunt → verify → exploit → report.
 14. reporter.py — SARIF via R2, markdown/JSON. Findings sorted by evidence_level descending.
 15. CLI subcommand — registers the runner.
 16. Interactive @tool wrapper — sourcehunt_tools.py + registry + prompt hint.
 17. Integration tests against real Docker + (opt-in) real LLM.
 18. Manual verification per the Testing §.
 19. README update.

 Critical schema discipline: Every v0.1 type must accept v0.2/v0.3 fields with sensible defaults so future phases land as feature additions, not refactors. The
 tests/test_sourcehunt_v02_seams.py test enforces this.