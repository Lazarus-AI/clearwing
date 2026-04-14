"""SourceHuntRunner — the public orchestrator for the sourcehunt pipeline.

Analog of clearwing/runners/cicd/runner.py::CICDRunner, but for source-code
hunting instead of network targets.

Pipeline:
    preprocess → sandbox build → rank → tiered hunt → verify → exploit → report
"""
from __future__ import annotations

import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

from .disclosure import (
    DisclosureGenerator,
    write_bundle as write_disclosure_bundle,
)
from .exploiter import Exploiter, apply_exploiter_result
from .patcher import AutoPatcher, PatchAttempt, apply_patch_attempt
from .poc_runner import PocRunner, build_rerun_poc_callback
from .harness_generator import HarnessGenerator, HarnessGeneratorConfig, SeededCrash
from .mechanism_memory import (
    MechanismExtractor,
    MechanismStore,
    format_mechanisms_for_prompt,
)
from .pool import HunterPool, HuntPoolConfig, TierBudget
from .preprocessor import Preprocessor, PreprocessResult
from .ranker import Ranker, RankerConfig
from .state import Finding, evidence_at_or_above, filter_by_evidence
from .variant_loop import (
    VariantLoop,
    VariantLoopConfig,
    VariantPatternGenerator,
    VariantSearcher,
)
from .verifier import Verifier, apply_verifier_result

logger = logging.getLogger(__name__)


@dataclass
class SourceHuntResult:
    """Result of a complete sourcehunt run."""
    exit_code: int                          # 0=clean, 1=medium, 2=critical/high
    repo_url: str
    repo_path: str
    findings: list[Finding]
    verified_findings: list[Finding]
    exploited_findings: list[Finding]
    files_ranked: int
    files_hunted: int
    duration_seconds: float
    cost_usd: float
    spent_per_tier: dict[str, float]
    tokens_used: int
    output_paths: dict[str, str] = field(default_factory=dict)
    session_id: str = ""

    @property
    def critical_count(self) -> int:
        return sum(
            1 for f in self.verified_findings
            if (f.get("severity_verified") or f.get("severity")) == "critical"
        )

    @property
    def high_count(self) -> int:
        return sum(
            1 for f in self.verified_findings
            if (f.get("severity_verified") or f.get("severity")) == "high"
        )


class SourceHuntRunner:
    """Public entry point for the sourcehunt pipeline."""

    def __init__(
        self,
        repo_url: str,
        branch: str = "main",
        local_path: Optional[str] = None,
        depth: str = "standard",                # quick | standard | deep
        budget_usd: float = 5.0,
        max_parallel: int = 8,
        tier_budget: Optional[TierBudget] = None,
        output_dir: str = "./sourcehunt-results",
        output_formats: Optional[list[str]] = None,
        no_verify: bool = False,
        no_exploit: bool = False,
        adversarial_verifier: bool = True,      # v0.2: on by default
        adversarial_threshold: Optional[str] = "static_corroboration",  # v0.4: budget gate
        enable_mechanism_memory: bool = True,   # v0.3: cross-run mechanism store
        mechanism_store_path=None,              # override default store location
        enable_patch_oracle: bool = True,       # v0.3: patch oracle truth test
        enable_variant_loop: bool = True,       # v0.3: compound finding density
        enable_auto_patch: bool = False,        # v0.3: opt-in auto-patch mode
        auto_pr: bool = False,                  # v0.3: open a draft PR via gh
        enable_knowledge_graph: bool = True,    # v0.3: populate source-hunt KG
        knowledge_graph=None,                   # inject a KG instance for tests
        export_disclosures: bool = False,       # v0.4: write MITRE/HackerOne templates
        disclosure_reporter_name: str = "(your name)",
        disclosure_reporter_affiliation: str = "(your affiliation)",
        disclosure_reporter_email: str = "(your email)",
        model_override: Optional[str] = None,
        provider_manager=None,                  # optional ProviderManager
        ranker_llm=None,                        # injectable for tests
        hunter_llm=None,
        verifier_llm=None,
        exploiter_llm=None,
        sandbox_factory=None,                   # callable[[], SandboxContainer]
        parent_session_id: Optional[str] = None,
    ):
        self.repo_url = repo_url
        self.branch = branch
        self.local_path = local_path
        self.depth = depth
        self.budget_usd = budget_usd
        self.max_parallel = max_parallel
        self.tier_budget = tier_budget or TierBudget()
        self.output_dir = output_dir
        self.output_formats = output_formats or ["sarif", "markdown", "json"]
        self.no_verify = no_verify
        self.no_exploit = no_exploit
        self.adversarial_verifier = adversarial_verifier
        self.adversarial_threshold = adversarial_threshold
        self.enable_mechanism_memory = enable_mechanism_memory
        self._mechanism_store = MechanismStore(path=mechanism_store_path) if enable_mechanism_memory else None
        self.enable_patch_oracle = enable_patch_oracle
        self.enable_variant_loop = enable_variant_loop
        self.enable_auto_patch = enable_auto_patch
        self.auto_pr = auto_pr
        self.enable_knowledge_graph = enable_knowledge_graph
        self._knowledge_graph = knowledge_graph
        self.export_disclosures = export_disclosures
        self.disclosure_reporter_name = disclosure_reporter_name
        self.disclosure_reporter_affiliation = disclosure_reporter_affiliation
        self.disclosure_reporter_email = disclosure_reporter_email
        self.model_override = model_override
        self.provider_manager = provider_manager
        self.ranker_llm = ranker_llm
        self.hunter_llm = hunter_llm
        self.verifier_llm = verifier_llm
        self.exploiter_llm = exploiter_llm
        self.sandbox_factory = sandbox_factory
        self._session_id = parent_session_id or f"sh-{uuid.uuid4().hex[:8]}"

    # --- Public API ---------------------------------------------------------

    def run(self) -> SourceHuntResult:
        start_time = time.monotonic()
        logger.info("Sourcehunt session %s starting on %s", self._session_id, self.repo_url)

        # 1. Preprocess
        preprocess_result = self._preprocess()
        repo_path = preprocess_result.repo_path
        files = preprocess_result.file_targets
        files_ranked = len(files)
        logger.info("Preprocessor enumerated %d files", files_ranked)

        # 2. Rank — unless depth=quick AND no LLM available
        ranker_llm = self._get_llm("ranker", self.ranker_llm)
        if ranker_llm is not None and files:
            try:
                Ranker(ranker_llm, RankerConfig()).rank(files)
            except Exception:
                logger.warning("Ranker failed", exc_info=True)
        else:
            # Fallback: assign reasonable defaults so tier assignment still works
            for ft in files:
                ft["surface"] = ft.get("surface") or 3
                ft["influence"] = ft.get("influence") or 2
                ft["reachability"] = ft.get("reachability") or 3
                ft["priority"] = (
                    ft["surface"] * 0.5 + ft["influence"] * 0.2 + ft["reachability"] * 0.3
                )

        # depth=quick exits here with the static_findings as-is
        if self.depth == "quick":
            return self._build_quick_result(
                start_time=start_time,
                repo_path=repo_path,
                preprocess_result=preprocess_result,
                files_ranked=files_ranked,
            )

        # 2.5. Harness Generator (crash-first ordering) — only at depth=deep
        #      and only if we have a sandbox and an LLM.
        seeded_crashes: list[SeededCrash] = []
        if self.depth == "deep":
            harness_llm = self._get_llm("hunter", self.hunter_llm)
            if harness_llm is not None and self.sandbox_factory is not None:
                try:
                    hg = HarnessGenerator(
                        llm=harness_llm,
                        sandbox_factory=self.sandbox_factory,
                        config=HarnessGeneratorConfig(),
                    )
                    hg_result = hg.run(files, repo_path)
                    seeded_crashes = hg_result.seeded_crashes
                    logger.info(
                        "Harness generator produced %d crashes from %d harnesses",
                        len(seeded_crashes), hg_result.harnesses_generated,
                    )
                except Exception:
                    logger.warning("Harness generator failed", exc_info=True)

        # Build a lookup so hunters for fuzzed files can pull their seeded
        # crash context via file path
        seeded_by_file: dict[str, dict] = {}
        for c in seeded_crashes:
            seeded_by_file[c.file] = {
                "report": c.report,
                "target_function": c.target_function,
                "harness_source": c.harness_source,
            }

        # Build a per-file Semgrep hint lookup so hunters get their file's hits
        semgrep_hints_by_file: dict[str, list[dict]] = {}
        for sf in preprocess_result.semgrep_findings:
            semgrep_hints_by_file.setdefault(sf.get("file", ""), []).append(sf)

        # v0.3: Recall cross-run mechanisms and inject them into every hunter's
        # hint list as a synthetic entry. The hunter's prompt wraps these in
        # "static analysis hints — NOT ground truth" framing.
        if self._mechanism_store is not None:
            mechanism_hints = self._recalled_mechanism_hints(files)
            if mechanism_hints:
                for ft in files:
                    key = ft.get("path", "")
                    semgrep_hints_by_file.setdefault(key, []).extend(mechanism_hints)

        # 3. Tiered hunt
        hunter_llm = self._get_llm("hunter", self.hunter_llm)
        all_findings: list[Finding] = []
        files_hunted = 0
        if hunter_llm is not None and files:
            pool = HunterPool(HuntPoolConfig(
                files=files,
                repo_path=repo_path,
                sandbox_factory=self.sandbox_factory,
                hunter_factory=None,
                llm=hunter_llm,
                max_parallel=self.max_parallel,
                budget_usd=self.budget_usd,
                tier_budget=self.tier_budget,
                session_id_prefix=self._session_id,
                seeded_crashes_by_file=seeded_by_file,
                semgrep_hints_by_file=semgrep_hints_by_file,
            ))
            try:
                all_findings = pool.run()
            except Exception:
                logger.warning("HunterPool run failed", exc_info=True)
            spent_per_tier = pool.spent_per_tier
            files_hunted = sum([
                p.get("tier") in ("A", "B", "C")
                for p in files
                if p.get("tier") != "C" or self.tier_budget.tier_c_fraction > 0
            ])
        else:
            spent_per_tier = {"A": 0.0, "B": 0.0, "C": 0.0}

        # Promote static findings into the all_findings list so depth=quick
        # output is still useful when no hunter llm is available
        all_findings = self._merge_static_findings(all_findings, preprocess_result)

        # 4. Verify (unless --no-verify)
        verified: list[Finding] = []
        if not self.no_verify:
            verifier_llm = self._get_llm("verifier", self.verifier_llm)
            if verifier_llm is not None:
                v = Verifier(
                    verifier_llm,
                    adversarial=self.adversarial_verifier,
                    adversarial_threshold=self.adversarial_threshold,
                )
                for finding in all_findings:
                    try:
                        result = v.verify(finding)
                        # v0.3: patch-oracle truth test on verified findings.
                        # Use a real sandbox validator when sandbox_factory is
                        # wired; otherwise fall back to LLM-only mode.
                        if self.enable_patch_oracle and result.is_real:
                            try:
                                oracle_sandbox = None
                                oracle_rerun_poc = None
                                if self.sandbox_factory is not None:
                                    try:
                                        oracle_sandbox = self.sandbox_factory()
                                        oracle_rerun_poc = build_rerun_poc_callback(
                                            oracle_sandbox,
                                        )
                                    except Exception:
                                        logger.debug(
                                            "Patch-oracle sandbox spawn failed",
                                            exc_info=True,
                                        )
                                        oracle_sandbox = None
                                        oracle_rerun_poc = None
                                try:
                                    passed, diff, notes = v.run_patch_oracle(
                                        finding,
                                        file_content=self._load_file_content(repo_path, finding),
                                        sandbox=oracle_sandbox,
                                        rerun_poc=oracle_rerun_poc,
                                    )
                                finally:
                                    if oracle_sandbox is not None:
                                        try:
                                            oracle_sandbox.stop()
                                        except Exception:
                                            pass
                                result.patch_oracle_attempted = True
                                result.patch_oracle_passed = passed
                                result.patch_oracle_diff = diff
                                result.patch_oracle_notes = notes
                            except Exception:
                                logger.debug("Patch-oracle pass failed", exc_info=True)
                        apply_verifier_result(finding, result, session_id=self._session_id + "-v")
                        if finding.get("verified"):
                            verified.append(finding)
                    except Exception:
                        logger.warning("Verifier failed for %s", finding.get("id"), exc_info=True)
            else:
                # Without a verifier LLM, treat every finding as verified
                # (low-trust mode — mark them as static-only confidence)
                for f in all_findings:
                    f["verified"] = True
                verified = all_findings
        else:
            verified = all_findings

        # 4.5. v0.3: Extract mechanisms from verified findings and persist them
        #      to the cross-run store. Cheap LLM pass; failures are non-fatal.
        if self._mechanism_store is not None and verified:
            verifier_llm_for_extract = self._get_llm("verifier", self.verifier_llm)
            if verifier_llm_for_extract is not None:
                try:
                    extractor = MechanismExtractor(verifier_llm_for_extract)
                    for finding in verified:
                        mech = extractor.extract(finding, source_repo=self.repo_url)
                        if mech is not None:
                            self._mechanism_store.append(mech)
                except Exception:
                    logger.warning("Mechanism extraction failed", exc_info=True)

        # 4.75. v0.3: Variant Hunter Loop — compound finding density within
        #       this run. For each verified finding, generate a grep pattern,
        #       search the codebase for structural matches, and surface each
        #       match as a new suspicion-level finding linked back to the
        #       original. v0.3 scope: we surface the matches in the report;
        #       we don't re-spawn hunters on each match (that's a v1.0 pass).
        if self.enable_variant_loop and verified:
            variant_llm = self._get_llm("verifier", self.verifier_llm)
            if variant_llm is not None:
                try:
                    loop = VariantLoop(
                        pattern_gen=VariantPatternGenerator(variant_llm),
                    )
                    # Track locations we've already reported to avoid dupes
                    already_seen = {
                        (f.get("file", ""), f.get("line_number", 0))
                        for f in all_findings
                    }
                    # v0.4: drive the multi-iteration fixpoint loop rather
                    # than the single-pass run_once. Each iteration feeds
                    # its new seeds back in as starting points for the
                    # next pattern generation pass.
                    variant_result = loop.run(
                        verified_findings=verified,
                        repo_path=repo_path,
                        already_seen_locations=already_seen,
                        reverify_callback=None,   # reuse the original seeds across passes
                    )
                    # Turn VariantSeed entries into Finding records.
                    # Each variant inherits its parent's CWE and severity
                    # but starts at evidence_level=suspicion (the hunter
                    # hasn't re-verified the match yet).
                    for seed in variant_result.seeds:
                        parent = seed.original_finding
                        variant_finding = Finding(
                            id=f"variant-{uuid.uuid4().hex[:8]}",
                            file=seed.match.file,
                            line_number=seed.match.line_number,
                            finding_type=parent.finding_type or "variant",
                            cwe=parent.cwe,
                            severity=parent.effective_severity or "medium",
                            confidence="low",
                            description=(
                                f"Variant of {parent.id}: "
                                f"{seed.match.pattern.semantic_description}"
                            ),
                            code_snippet=seed.match.matched_text,
                            evidence_level="suspicion",
                            discovered_by="variant_loop",
                            related_finding_id=parent.id or None,
                            related_cve=parent.related_cve,
                            hunter_session_id=self._session_id,
                        )
                        all_findings.append(variant_finding)
                    logger.info(
                        "Variant loop: %d patterns, %d matches surfaced",
                        variant_result.patterns_generated,
                        variant_result.matches_found,
                    )
                except Exception:
                    logger.warning("Variant loop failed", exc_info=True)

        # 5. Exploit-triage (unless --no-exploit) — gated on evidence_level
        exploited: list[Finding] = []
        # 5.5 v0.3: Auto-patch (opt-in) — runs after exploiter on verified
        #          critical/high findings with root_cause_explained evidence.
        patched: list[Finding] = []
        if not self.no_exploit:
            exploiter_llm = self._get_llm("sourcehunt_exploit", self.exploiter_llm)
            if exploiter_llm is not None:
                e = Exploiter(exploiter_llm)
                eligible = filter_by_evidence(verified, "crash_reproduced")
                for finding in eligible:
                    try:
                        exploit_result = e.attempt(finding)
                        apply_exploiter_result(finding, exploit_result)
                        if exploit_result.success:
                            exploited.append(finding)
                    except Exception:
                        logger.warning("Exploiter failed", exc_info=True)

        # 5.5. v0.3: Auto-patch mode (opt-in).
        # The verify-by-recompile gate is MANDATORY — a patch is only marked
        # `validated` if we actually applied it, rebuilt, and re-ran the PoC.
        if self.enable_auto_patch and verified:
            patcher_llm = self._get_llm("sourcehunt_exploit", self.exploiter_llm)
            if patcher_llm is not None:
                try:
                    patcher = AutoPatcher(patcher_llm)
                    for finding in verified:
                        if not patcher.is_eligible(finding):
                            continue
                        # Spawn a fresh sandbox per attempt so patches don't
                        # cross-contaminate.
                        patch_sandbox = None
                        rerun_cb = None
                        if self.sandbox_factory is not None:
                            try:
                                patch_sandbox = self.sandbox_factory()
                                rerun_cb = build_rerun_poc_callback(patch_sandbox)
                            except Exception:
                                logger.debug(
                                    "Auto-patch sandbox spawn failed",
                                    exc_info=True,
                                )
                                patch_sandbox = None
                                rerun_cb = None
                        try:
                            attempt = patcher.attempt(
                                finding,
                                file_content=self._load_file_content(repo_path, finding),
                                sandbox=patch_sandbox,
                                rerun_poc=rerun_cb,
                            )
                        finally:
                            if patch_sandbox is not None:
                                try:
                                    patch_sandbox.stop()
                                except Exception:
                                    pass
                        apply_patch_attempt(finding, attempt)
                        if attempt.validated:
                            patched.append(finding)
                            if self.auto_pr:
                                self._open_draft_pr(finding, attempt)
                except Exception:
                    logger.warning("Auto-patcher failed", exc_info=True)

        # 5.75. v0.3: Populate the cross-run knowledge graph with source
        #       findings. Best-effort — never blocks the run.
        if self.enable_knowledge_graph and all_findings:
            try:
                self._populate_knowledge_graph_source(repo_path, all_findings)
            except Exception:
                logger.warning("Knowledge graph population failed", exc_info=True)

        # 5.85. v0.4: Coordinated-disclosure templates (opt-in).
        disclosure_paths: dict[str, list[str]] = {}
        if self.export_disclosures and verified:
            try:
                disclosure_paths = self._export_disclosure_bundle(verified)
            except Exception:
                logger.warning("Disclosure export failed", exc_info=True)

        # 6. Report
        output_paths = self._write_report(
            findings=all_findings,
            verified=verified,
            spent_per_tier=spent_per_tier,
        )

        duration = time.monotonic() - start_time
        return SourceHuntResult(
            exit_code=self._exit_code(verified),
            repo_url=self.repo_url,
            repo_path=repo_path,
            findings=all_findings,
            verified_findings=verified,
            exploited_findings=exploited,
            files_ranked=files_ranked,
            files_hunted=files_hunted,
            duration_seconds=round(duration, 2),
            cost_usd=sum(spent_per_tier.values()),
            spent_per_tier=spent_per_tier,
            tokens_used=0,    # filled by cost tracker if attached
            output_paths=output_paths,
            session_id=self._session_id,
        )

    @property
    def session_id(self) -> str:
        return self._session_id

    # --- Pipeline helpers ---------------------------------------------------

    def _export_disclosure_bundle(
        self,
        verified_findings: list[Finding],
    ) -> dict[str, list[str]]:
        """Generate MITRE + HackerOne templates for verified findings.

        Returns a dict {format: [file_paths]} for the reporter to surface.
        """
        generator = DisclosureGenerator(
            repo_url=self.repo_url,
            reporter_name=self.disclosure_reporter_name,
            reporter_affiliation=self.disclosure_reporter_affiliation,
            reporter_email=self.disclosure_reporter_email,
        )
        bundle = generator.generate_bundle(verified_findings)
        if not bundle.templates:
            logger.info(
                "Disclosure export: no findings passed the eligibility gate "
                "(skipped=%d, reasons=%s)",
                bundle.skipped, bundle.skipped_reasons,
            )
            return {}
        return write_disclosure_bundle(bundle, self.output_dir, self._session_id)

    def _populate_knowledge_graph_source(
        self,
        repo_path: str,
        findings: list[Finding],
    ) -> None:
        """Auto-populate the KG with source-hunt entities. Best-effort."""
        kg = self._knowledge_graph
        if kg is None:
            try:
                from clearwing.data.knowledge import KnowledgeGraph
                kg = KnowledgeGraph(persist_path="~/.clearwing/knowledge_graph.json")
            except Exception:
                logger.debug("Could not import KnowledgeGraph", exc_info=True)
                return

        try:
            kg.add_repo(self.repo_url, local_path=repo_path)
        except Exception:
            pass

        # First pass: add all findings so VARIANT_OF edges can resolve parents
        for f in findings:
            try:
                kg.add_source_finding(
                    repo_url=self.repo_url,
                    file_path=f.get("file", ""),
                    finding=f,
                )
            except Exception:
                logger.debug("KG source finding add failed", exc_info=True)

        try:
            kg.save()
        except Exception:
            logger.debug("KG save failed", exc_info=True)

    def _open_draft_pr(self, finding: Finding, attempt) -> None:
        """Open a draft PR for a validated auto-patch via the `gh` CLI.

        v0.3: best-effort only — failures are logged and the run continues.
        The PR is always opened as draft so a human reviews before merge.
        """
        import shutil
        import subprocess

        if shutil.which("gh") is None:
            logger.info("auto_pr=True but `gh` CLI not found; skipping")
            return

        title = (
            attempt.commit_message
            or f"fix: {finding.get('finding_type', 'vulnerability')} "
               f"in {finding.get('file', 'unknown')}"
        )
        body = (
            f"## Auto-generated patch from clearwing sourcehunt\n\n"
            f"**Finding:** {finding.get('id', '')}\n"
            f"**File:** {finding.get('file', '')}:{finding.get('line_number', '')}\n"
            f"**CWE:** {finding.get('cwe', '')}\n"
            f"**Evidence level:** {finding.get('evidence_level', '')}\n\n"
            f"### Description\n{finding.get('description', '')}\n\n"
            f"### Fix explanation\n{attempt.explanation}\n\n"
            f"### Diff\n```\n{attempt.diff[:3000]}\n```\n\n"
            f"**Human review required before merge.**\n"
        )
        try:
            subprocess.run(
                ["gh", "pr", "create", "--draft", "--title", title, "--body", body],
                check=False,
                capture_output=True,
                timeout=30,
            )
        except Exception:
            logger.debug("gh pr create failed", exc_info=True)

    def _load_file_content(self, repo_path: str, finding: Finding) -> str:
        """Read the file referenced by a finding. Used by the patch oracle."""
        import os
        rel = finding.get("file", "")
        if not rel:
            return ""
        abs_path = os.path.join(repo_path, rel)
        try:
            with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except OSError:
            return ""

    def _recalled_mechanism_hints(self, files: list) -> list[dict]:
        """Build a synthetic hint entry from cross-run mechanisms.

        Queries the MechanismStore once with the aggregate language + tag set
        across all files, and formats the top-N mechanisms as a single hint
        dict. Returns an empty list if no mechanisms are relevant.
        """
        if self._mechanism_store is None:
            return []

        # Aggregate languages and tags from the file set
        languages: dict[str, int] = {}
        tag_set: set[str] = set()
        for ft in files:
            lang = ft.get("language", "")
            if lang:
                languages[lang] = languages.get(lang, 0) + 1
            tag_set.update(ft.get("tags", []))

        if not languages:
            return []

        # Use the most common language
        primary_language = max(languages.items(), key=lambda kv: kv[1])[0]
        recalled = self._mechanism_store.recall(
            language=primary_language,
            tags=list(tag_set),
            top_n=3,
        )
        if not recalled:
            return []

        # Format as a single synthetic "hint" that flows through the
        # existing semgrep_hints channel into hunter prompts.
        formatted = format_mechanisms_for_prompt(recalled)
        return [{
            "line": 0,
            "description": formatted,
            "source": "mechanism_memory",
        }]

    def _preprocess(self) -> PreprocessResult:
        # v0.2: enable callgraph + reachability + Semgrep by default at
        # standard/deep depths. Quick depth stays cheap — just enumerate
        # and tag files.
        pp = Preprocessor(
            repo_url=self.repo_url,
            branch=self.branch,
            local_path=self.local_path,
            tag_files=True,
            build_callgraph=(self.depth != "quick"),
            propagate_reachability=(self.depth != "quick"),
            run_semgrep=(self.depth != "quick"),
            run_taint=(self.depth != "quick"),   # v0.4: taint analysis
        )
        return pp.run()

    def _build_quick_result(
        self,
        start_time: float,
        repo_path: str,
        preprocess_result: PreprocessResult,
        files_ranked: int,
    ) -> SourceHuntResult:
        """depth=quick exit — only static findings, no LLM hunters."""
        all_findings = self._merge_static_findings([], preprocess_result)
        # Populate KG even for the quick path
        if self.enable_knowledge_graph and all_findings:
            try:
                self._populate_knowledge_graph_source(repo_path, all_findings)
            except Exception:
                logger.warning("Knowledge graph population failed", exc_info=True)
        output_paths = self._write_report(
            findings=all_findings,
            verified=[],
            spent_per_tier={"A": 0.0, "B": 0.0, "C": 0.0},
        )
        duration = time.monotonic() - start_time
        return SourceHuntResult(
            exit_code=self._exit_code(all_findings),
            repo_url=self.repo_url,
            repo_path=repo_path,
            findings=all_findings,
            verified_findings=[],
            exploited_findings=[],
            files_ranked=files_ranked,
            files_hunted=0,
            duration_seconds=round(duration, 2),
            cost_usd=0.0,
            spent_per_tier={"A": 0.0, "B": 0.0, "C": 0.0},
            tokens_used=0,
            output_paths=output_paths,
            session_id=self._session_id,
        )

    def _merge_static_findings(
        self,
        existing: list[Finding],
        preprocess_result: PreprocessResult,
    ) -> list[Finding]:
        """Promote SourceAnalyzer static findings into the Finding shape.

        These get evidence_level="static_corroboration" because they're
        regex/AST hits, not just suspicion.
        """
        out = list(existing)
        for sf in preprocess_result.static_findings:
            out.append(Finding(
                id=f"static-{uuid.uuid4().hex[:8]}",
                file=os.path.relpath(sf.file_path, preprocess_result.repo_path),
                line_number=sf.line_number,
                finding_type=sf.finding_type,
                cwe=sf.cwe,
                severity=sf.severity,  # type: ignore[arg-type]
                confidence=sf.confidence,  # type: ignore[arg-type]
                description=sf.description,
                code_snippet=sf.code_snippet,
                evidence_level="static_corroboration",
                discovered_by="source_analyzer",
            ))
        return out

    def _exit_code(self, findings: list[Finding]) -> int:
        severities = {
            (f.get("severity_verified") or f.get("severity") or "info").lower()
            for f in findings
        }
        if severities & {"critical", "high"}:
            return 2
        if "medium" in severities:
            return 1
        return 0

    # --- LLM resolution -----------------------------------------------------

    def _get_llm(self, task: str, override):
        """Return an LLM for the given task, or None if not available.

        Resolution order:
          1. Explicit kwarg override (ranker_llm=, hunter_llm=, etc.)
          2. self.model_override (single model for all tasks)
          3. self.provider_manager.get_llm(task)
          4. None — caller falls back to a no-LLM path
        """
        import os

        if override is not None:
            return override
        # If no API key is set anywhere, skip LLM entirely (don't even try
        # to construct one — that throws a noisy stack trace at first .invoke)
        if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("OPENAI_API_KEY")):
            logger.debug("No API key in environment; skipping LLM for task=%s", task)
            return None
        if self.model_override:
            return self._build_llm_from_model_string(self.model_override)
        if self.provider_manager is not None:
            try:
                return self.provider_manager.get_llm(task)
            except Exception:
                logger.debug("ProviderManager failed for task=%s", task, exc_info=True)
        # Try the default ProviderManager
        try:
            from clearwing.providers.manager import ProviderManager
            pm = ProviderManager()
            return pm.get_llm(task)
        except Exception:
            return None

    def _build_llm_from_model_string(self, model: str):
        """Build a single LLM from a model string. Used by --model override."""
        try:
            from langchain_anthropic import ChatAnthropic
            return ChatAnthropic(model=model)
        except Exception:
            logger.warning("Failed to build LLM from model string", exc_info=True)
            return None

    # --- Reporting ----------------------------------------------------------

    def _write_report(
        self,
        findings: list[Finding],
        verified: list[Finding],
        spent_per_tier: dict,
    ) -> dict[str, str]:
        """Write SARIF / markdown / JSON outputs to the output directory.

        v0.1 implementation lives in reporter.py — but that module isn't built
        yet at the time this runner is being constructed. Keep the call here
        and let reporter.py register itself lazily.
        """
        try:
            from .reporter import write_sourcehunt_report
        except ImportError:
            logger.warning("reporter.py not yet available; skipping report")
            return {}
        try:
            return write_sourcehunt_report(
                output_dir=self.output_dir,
                session_id=self._session_id,
                repo_url=self.repo_url,
                findings=findings,
                verified_findings=verified,
                spent_per_tier=spent_per_tier,
                formats=self.output_formats,
            )
        except Exception:
            logger.warning("Reporter failed", exc_info=True)
            return {}
