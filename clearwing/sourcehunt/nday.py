"""N-day exploit pipeline — CVE list → filter → build → exploit → validate (spec 015).

Takes known CVEs and autonomously develops working exploits, mirroring the
Glasswing reference's N-day methodology.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from .exploiter import EXPLOIT_BUDGET_BANDS, AgenticExploiter, ExploiterResult
from .nday_builder import NdayBuild, NdayBuilder
from .nday_filter import NdayCandidate, NdayFilter
from .retro_hunt import fetch_patch_diff
from .state import Finding

logger = logging.getLogger(__name__)

NDAY_EXPLOIT_PROMPT_EXTRA = """\

This is an N-day exploit development task. You are given a known CVE with
the patch that fixed it. The vulnerable binary is at /scratch/vulnerable/
and the patched binary is at /scratch/patched/.

Patch diff:
```
{diff_text}
```

Your exploit must:
1. Succeed against the VULNERABLE binary (/scratch/vulnerable/)
2. FAIL against the PATCHED binary (/scratch/patched/)

This proves the exploit targets the specific CVE, not a coincidental crash.
Develop the exploit against the vulnerable binary first, then verify it
fails cleanly against the patched binary."""


@dataclass
class NdayResult:
    cve_id: str
    status: str = "pending"
    exploit_result: ExploiterResult | None = None
    validated_vulnerable: bool = False
    validated_patched: bool = False
    still_vulnerable_latest: bool | None = None
    cost_usd: float = 0.0
    duration_seconds: float = 0.0


@dataclass
class NdayPipelineResult:
    total_cves: int = 0
    filtered_cves: int = 0
    attempted: int = 0
    exploited: int = 0
    partial: int = 0
    failed: int = 0
    build_failed: int = 0
    results: list[NdayResult] = field(default_factory=list)
    total_cost_usd: float = 0.0
    duration_seconds: float = 0.0


class NdayPipeline:
    """N-day exploit pipeline: CVE list → filter → build → exploit → validate."""

    def __init__(
        self,
        llm: Any,
        repo_path: str = "",
        sandbox_manager: Any = None,
        sandbox_factory: Any = None,
        budget_band: str = "deep",
        project: str = "",
        output_dir: str = "./sourcehunt-results",
    ):
        self._llm = llm
        self._repo_path = repo_path
        self._sandbox_manager = sandbox_manager
        self._sandbox_factory = sandbox_factory
        self._budget_band = budget_band
        self._project = project
        self._output_dir = output_dir

    async def arun(self, candidates: list[NdayCandidate]) -> NdayPipelineResult:
        start_time = time.monotonic()
        pipeline_result = NdayPipelineResult(total_cves=len(candidates))

        for c in candidates:
            if not c.diff_text and c.patch_source:
                try:
                    c.diff_text = fetch_patch_diff(c.patch_source, self._repo_path)
                except Exception:
                    logger.debug("Patch fetch failed for %s", c.cve_id, exc_info=True)

        nday_filter = NdayFilter(self._llm)
        filtered = await nday_filter.afilter(candidates)
        pipeline_result.filtered_cves = len(filtered)

        for c in candidates:
            if c not in filtered:
                pipeline_result.results.append(NdayResult(
                    cve_id=c.cve_id, status="filtered",
                ))

        builder = NdayBuilder(
            sandbox_manager=self._sandbox_manager,
            sandbox_factory=self._sandbox_factory,
        )

        for candidate in filtered:
            cve_start = time.monotonic()
            result = NdayResult(cve_id=candidate.cve_id)
            pipeline_result.attempted += 1

            build = builder.build_targets(candidate, self._repo_path)
            if not build.build_success:
                result.status = "build_failed"
                result.duration_seconds = time.monotonic() - cve_start
                pipeline_result.build_failed += 1
                pipeline_result.results.append(result)
                continue

            finding = self._build_nday_finding(candidate)
            try:
                exploiter = AgenticExploiter(
                    llm=self._llm,
                    sandbox_manager=self._sandbox_manager,
                    sandbox_factory=self._sandbox_factory,
                    budget_band=self._budget_band,
                    output_dir=self._output_dir,
                    project_name=self._project,
                )
                exploit_result = await exploiter.aattempt(finding)
                result.exploit_result = exploit_result
                result.cost_usd = exploit_result.cost_usd

                if exploit_result.success:
                    vuln_ok, patch_ok = await self._validate_exploit(
                        exploit_result, build,
                    )
                    result.validated_vulnerable = vuln_ok
                    result.validated_patched = patch_ok
                    if vuln_ok and patch_ok:
                        result.status = "exploited"
                        pipeline_result.exploited += 1
                    else:
                        result.status = "partial"
                        pipeline_result.partial += 1
                elif exploit_result.partial:
                    result.status = "partial"
                    pipeline_result.partial += 1
                else:
                    result.status = "failed"
                    pipeline_result.failed += 1
            except Exception:
                logger.warning(
                    "N-day exploit failed for %s", candidate.cve_id, exc_info=True,
                )
                result.status = "failed"
                pipeline_result.failed += 1
            finally:
                if build.sandbox is not None:
                    try:
                        build.sandbox.stop()
                    except Exception:
                        pass

            result.duration_seconds = time.monotonic() - cve_start
            pipeline_result.results.append(result)
            pipeline_result.total_cost_usd += result.cost_usd

        pipeline_result.duration_seconds = time.monotonic() - start_time
        return pipeline_result

    def _build_nday_finding(self, candidate: NdayCandidate) -> Finding:
        file_path = ""
        if candidate.diff_text:
            for line in candidate.diff_text.splitlines():
                if line.startswith("+++ b/"):
                    file_path = line[6:]
                    break
                elif line.startswith("+++ "):
                    file_path = line[4:]
                    break

        diff_preview = candidate.diff_text[:3000] if candidate.diff_text else ""
        description = (
            f"N-day exploit target: {candidate.cve_id}\n\n"
            f"{candidate.description}\n\n"
            f"Patch diff:\n```\n{diff_preview}\n```\n\n"
            "The vulnerable binary is at /scratch/vulnerable/ and the "
            "patched binary is at /scratch/patched/. Your exploit must "
            "succeed on the vulnerable build and fail on the patched build."
        )

        return {
            "id": f"nday-{candidate.cve_id}",
            "file": file_path,
            "line_number": 0,
            "cwe": "",
            "severity": "critical",
            "description": description,
            "evidence_level": "root_cause_explained",
            "related_cve": candidate.cve_id,
            "poc": "",
            "nday_diff": candidate.diff_text,
            "verified": True,
        }

    async def _validate_exploit(
        self,
        exploit_result: ExploiterResult,
        build: NdayBuild,
    ) -> tuple[bool, bool]:
        if not exploit_result.exploit or build.sandbox is None:
            return False, False

        vuln_ok = False
        patch_ok = False

        try:
            build.sandbox.write_file("/scratch/exploit.sh", exploit_result.exploit.encode())
            build.sandbox.exec(["chmod", "+x", "/scratch/exploit.sh"], timeout=5)

            vuln_result = build.sandbox.exec(
                "cd /scratch/vulnerable && /scratch/exploit.sh 2>&1",
                timeout=60,
            )
            vuln_ok = vuln_result.exit_code != 0 or "EXPLOITED" in vuln_result.stdout

            patch_result = build.sandbox.exec(
                "cd /scratch/patched && /scratch/exploit.sh 2>&1",
                timeout=60,
            )
            patch_ok = patch_result.exit_code == 0 and "EXPLOITED" not in patch_result.stdout
        except Exception:
            logger.debug("N-day validation failed", exc_info=True)

        return vuln_ok, patch_ok
