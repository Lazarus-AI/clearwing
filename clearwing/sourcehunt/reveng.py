"""Reverse engineering pipeline — binary → decompile → reconstruct → hunt (spec 016).

Takes a closed-source stripped binary, decompiles via Ghidra headless,
reconstructs plausible source via LLM, then runs a hybrid hunt where
findings from the source are validated against the original binary.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

from .exploiter import EXPLOIT_BUDGET_BANDS, AgenticExploiter, ExploiterResult
from .reveng_decompiler import (
    DecompilationResult,
    RevengSandbox,
    StaticAnalysisResult,
    format_static_summary,
    run_ghidra_decompilation,
    run_static_analysis,
    validate_binary,
)
from .reveng_reconstructor import (
    ReconstructionResult,
    RevengReconstructor,
    validate_reconstruction,
)

logger = logging.getLogger(__name__)

REVENG_HUNT_PROMPT = """\
You are a security researcher hunting for vulnerabilities in a closed-source
binary. You have:

- /workspace/binary/ — the original stripped binary
- /workspace/source/ — best-effort LLM-reconstructed source code
- /workspace/analysis/ — static analysis output (strings, checksec, sections, imports)

The reconstructed source is approximately correct but MAY have errors in
function boundaries, data types, struct layouts, and inlined function expansion.
ALWAYS validate hypotheses from the source against the original binary using
GDB, test inputs, and runtime tracing.

Project: {project_name}
Binary: {binary_name}
Architecture: {arch}

{static_summary}

Approach:
1. Read the static analysis summary in /workspace/analysis/
2. Review reconstructed source in /workspace/source/ for suspicious patterns
3. For each candidate vulnerability:
   a. Verify the code path exists in the binary (GDB breakpoints, objdump)
   b. Craft test inputs that exercise the path
   c. Run the binary under GDB to confirm behavior
   d. If crash/unexpected behavior occurs, document with crash evidence
4. Focus on: buffer overflows, format strings, integer overflows,
   use-after-free, command injection, path traversal, hardcoded credentials
5. Call record_finding for each confirmed or strongly suspected vulnerability

When you find a vulnerability, call record_finding with severity, CWE,
evidence level, and description. Partial results are valuable — if you find
a primitive but cannot build a full exploit, record it anyway.
If you find nothing after thorough analysis, say so explicitly."""


@dataclass
class RevengResult:
    binary_path: str = ""
    arch: str = "x86_64"
    static_analysis: StaticAnalysisResult | None = None
    decompilation: DecompilationResult | None = None
    reconstruction: ReconstructionResult | None = None
    findings: list[dict] = field(default_factory=list)
    exploit_results: list[ExploiterResult] = field(default_factory=list)
    status: str = "pending"
    total_cost_usd: float = 0.0
    duration_seconds: float = 0.0


class RevengPipeline:
    """Reverse engineering pipeline: binary → decompile → reconstruct → hunt."""

    def __init__(
        self,
        llm: Any,
        binary_path: str = "",
        arch: str = "x86_64",
        budget_band: str = "deep",
        output_dir: str | None = None,
        project_name: str = "",
        sandbox_factory: Any = None,
        reconstruction_batch_size: int | None = None,
    ):
        self._llm = llm
        self._binary_path = binary_path
        self._arch = arch
        self._budget_band = budget_band
        if output_dir is None:
            from clearwing.core.config import default_results_dir

            output_dir = default_results_dir("sourcehunt")
        self._output_dir = output_dir
        self._project_name = project_name or os.path.basename(binary_path)
        self._sandbox_factory = sandbox_factory
        from .config import HuntTuning

        self._reconstruction_batch_size = (
            reconstruction_batch_size
            if reconstruction_batch_size is not None
            else HuntTuning().reveng_batch_size
        )

    async def arun(self) -> RevengResult:
        start_time = time.monotonic()
        result = RevengResult(
            binary_path=self._binary_path,
            arch=self._arch,
        )

        # 1. Validate binary
        valid, error = validate_binary(self._binary_path)
        if not valid:
            result.status = "failed"
            logger.warning("Binary validation failed: %s", error)
            result.duration_seconds = time.monotonic() - start_time
            return result

        # 2. Build sandbox
        reveng_sandbox = RevengSandbox(sandbox_factory=self._sandbox_factory)
        try:
            reveng_sandbox.build_image()
        except Exception:
            logger.warning("Reveng image build failed", exc_info=True)
            result.status = "failed"
            result.duration_seconds = time.monotonic() - start_time
            return result

        container = reveng_sandbox.spawn(self._binary_path)
        if container is None:
            result.status = "failed"
            result.duration_seconds = time.monotonic() - start_time
            return result

        try:
            binary_name = os.path.basename(self._binary_path)

            # 3. Static analysis
            result.static_analysis = run_static_analysis(container, binary_name)
            result.status = "analyzed"

            # Write static summary to container
            static_summary = format_static_summary(result.static_analysis)
            try:
                container.write_file(
                    "/workspace/analysis/static.txt",
                    static_summary.encode("utf-8"),
                )
            except Exception:
                pass

            # 4. Ghidra decompilation
            result.decompilation = run_ghidra_decompilation(
                container, binary_name, timeout=600,
            )
            if result.decompilation.total_functions == 0:
                logger.warning("No functions decompiled for %s", binary_name)
                result.status = "failed"
                result.duration_seconds = time.monotonic() - start_time
                return result
            result.status = "decompiled"

            # 5. LLM source reconstruction
            reconstructor = RevengReconstructor(
                self._llm, batch_size=self._reconstruction_batch_size,
            )
            result.reconstruction = await reconstructor.areconstruct(
                result.decompilation, result.static_analysis,
            )

            # Write reconstructed source into container
            if result.reconstruction.combined_source:
                try:
                    container.write_file(
                        "/workspace/source/reconstructed.c",
                        result.reconstruction.combined_source.encode("utf-8"),
                    )
                except Exception:
                    pass

            # Validate reconstruction
            result.reconstruction.validation = await validate_reconstruction(
                container,
                result.reconstruction.combined_source,
                result.reconstruction.total_functions,
                result.reconstruction.reconstructed_count,
            )
            result.status = "reconstructed"

            # 6. Hybrid hunt
            findings = await self._hybrid_hunt(
                container, binary_name, static_summary,
            )
            result.findings = findings
            result.status = "hunted"

            # 7. Exploit development for confirmed findings
            for finding in findings:
                evidence = finding.get("evidence_level", "suspicion")
                if evidence in ("crash_reproduced", "root_cause_explained",
                                "exploit_demonstrated", "patch_validated"):
                    try:
                        exploit_result = await self._attempt_exploit(
                            finding, container,
                        )
                        result.exploit_results.append(exploit_result)
                        result.total_cost_usd += exploit_result.cost_usd
                    except Exception:
                        logger.warning(
                            "Exploit attempt failed for %s",
                            finding.get("id", "?"),
                            exc_info=True,
                        )

            if any(r.success for r in result.exploit_results):
                result.status = "exploited"

        except Exception:
            logger.warning("Reveng pipeline failed", exc_info=True)
            result.status = "failed"
        finally:
            reveng_sandbox.cleanup()

        result.duration_seconds = time.monotonic() - start_time
        return result

    async def _hybrid_hunt(
        self,
        container: Any,
        binary_name: str,
        static_summary: str,
    ) -> list[dict]:
        """Run a NativeHunter with the reveng prompt against the binary."""
        from clearwing.agent.tools.hunt.deep_agent import build_deep_agent_tools
        from clearwing.agent.tools.hunt.sandbox import HunterContext
        from clearwing.sourcehunt.hunter import NativeHunter

        ctx = HunterContext(
            repo_path="/workspace",
            sandbox=container,
            file_path=f"/workspace/binary/{binary_name}",
            session_id=f"reveng-{binary_name}",
            specialist="reveng",
        )

        tools = build_deep_agent_tools(ctx)
        prompt = REVENG_HUNT_PROMPT.format(
            project_name=self._project_name,
            binary_name=binary_name,
            arch=self._arch,
            static_summary=static_summary,
        )

        band = EXPLOIT_BUDGET_BANDS.get(self._budget_band, EXPLOIT_BUDGET_BANDS["deep"])

        hunter = NativeHunter(
            llm=self._llm,
            prompt=prompt,
            tools=tools,
            ctx=ctx,
            max_steps=band["max_steps"],
            agent_mode="deep",
            budget_usd=band["budget_usd"],
            initial_user_message=(
                f"Hunt for vulnerabilities in the closed-source binary {binary_name}. "
                "Reconstructed source is at /workspace/source/reconstructed.c. "
                "Static analysis is at /workspace/analysis/static.txt. "
                "Validate all hypotheses against the binary with GDB."
            ),
        )

        try:
            await asyncio.wait_for(
                hunter.arun(),
                timeout=band["timeout_seconds"],
            )
        except asyncio.TimeoutError:
            logger.info("Reveng hunt timed out for %s", binary_name)

        return [self._to_dict(f) for f in ctx.findings]

    async def _attempt_exploit(
        self,
        finding: dict,
        container: Any,
    ) -> ExploiterResult:
        """Feed a confirmed finding to AgenticExploiter."""
        exploiter = AgenticExploiter(
            llm=self._llm,
            sandbox_factory=lambda: container,
            budget_band=self._budget_band,
            output_dir=self._output_dir,
            project_name=self._project_name,
        )
        return await exploiter.aattempt(finding)

    def _to_dict(self, finding: Any) -> dict:
        """Convert a Finding to a plain dict if needed."""
        if isinstance(finding, dict):
            return finding
        try:
            return dict(finding)
        except (TypeError, ValueError):
            return {"id": str(finding), "description": str(finding)}
