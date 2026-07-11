"""PoC stability verification — Stage 2.5 (spec 010).

Runs validated PoCs through multiple fresh containers to verify
reliability before sending to maintainers. Unreliable PoCs burn
reputation.

Procedure: spin up N fresh containers, run the PoC M times per
container, classify as stable/flaky/unreliable. Unreliable PoCs
get one hardening attempt via LLM before archival.
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from dataclasses import dataclass, replace
from typing import Any

from clearwing.llm import AsyncLLMClient

from .poc_runner import PocRunner
from .state import Finding, StabilityResult

logger = logging.getLogger(__name__)

# --- Constants ----------------------------------------------------------------

RACE_CWES = {"CWE-362", "CWE-367", "CWE-421", "CWE-366"}

_ADDR_RE = re.compile(r"0x[0-9a-fA-F]{8,16}")


# --- Config -------------------------------------------------------------------


@dataclass
class StabilityConfig:
    """Tuning knobs for PoC stability verification."""

    num_containers: int = 3
    runs_per_container: int = 20
    race_runs_per_container: int = 100
    stable_threshold: float = 0.90
    race_stable_threshold: float = 0.70
    flaky_threshold: float = 0.50
    enable_hardening: bool = True
    disable_aslr_container: int = 0  # container index to disable ASLR (-1 = none)


# --- Prompts ------------------------------------------------------------------

HARDEN_SYSTEM_PROMPT = """\
You are a PoC hardening specialist. Given an unreliable proof-of-concept \
that triggers a real vulnerability but fails to reproduce consistently, \
your job is to modify it so it reproduces reliably across fresh containers \
with varying ASLR layouts."""

HARDEN_PROMPT = """\
Your PoC for {finding_id} only reproduces {success_rate:.0%} of the time \
in fresh containers. The crash is real but the reproduction is unreliable.

Reproduction data:
{per_container_detail}

Common failure mode: {failure_analysis}

Please produce a hardened version of the PoC that reproduces reliably. \
Return ONLY the raw PoC input (no explanation, no markdown fences).

Consider:
- Is the crash timing-dependent? Add retry logic or synchronization.
- Is the crash heap-layout-dependent? Add heap grooming.
- Is the crash ASLR-dependent? Make the PoC ASLR-agnostic.
- Is the crash dependent on discovery-session state? Remove the dependency.

Original PoC:
{original_poc}"""


# --- StabilityVerifier --------------------------------------------------------


class StabilityVerifier:
    """Runs PoCs through multiple fresh containers to verify reliability."""

    def __init__(
        self,
        sandbox_manager: Any,  # HunterSandbox
        config: StabilityConfig | None = None,
        hardening_llm: AsyncLLMClient | None = None,
    ):
        self._sandbox_manager = sandbox_manager
        self.config = config or StabilityConfig()
        self._hardening_llm = hardening_llm

    async def averify(self, finding: Finding) -> StabilityResult:
        runs_per = self._runs_for_finding(finding)
        threshold = self._threshold_for_finding(finding)
        container_results: list[tuple[int, int]] = []
        all_failures: list[str] = []

        for i in range(self.config.num_containers):
            successes, total, failures = self._run_in_container(
                finding, i, runs_per,
            )
            container_results.append((successes, total))
            all_failures.extend(failures)

        total_successes = sum(s for s, _ in container_results)
        total_runs = sum(t for _, t in container_results)
        rate = total_successes / total_runs if total_runs > 0 else 0.0
        per_container = [
            s / t if t > 0 else 0.0 for s, t in container_results
        ]
        classification = self._classify(rate, threshold)
        failure_analysis = self._analyze_failures(all_failures)

        result = StabilityResult(
            finding_id=finding.get("id", "unknown"),
            total_runs=total_runs,
            successes=total_successes,
            success_rate=rate,
            per_container_rates=per_container,
            classification=classification,
            failure_analysis=failure_analysis,
            original_poc=finding.get("poc", "") or "",
        )

        if (
            classification == "unreliable"
            and self.config.enable_hardening
            and self._hardening_llm is not None
        ):
            result = await self._attempt_hardening(finding, result)

        return result

    def _run_in_container(
        self,
        finding: Finding,
        container_idx: int,
        runs: int,
    ) -> tuple[int, int, list[str]]:
        """Spawn a fresh container, run PoC `runs` times.

        Returns (successes, total, failure_stderrs).
        Success = crash reproduces (still_crashes == True).
        """
        container = None
        try:
            container = self._sandbox_manager.spawn(
                session_id=f"stability-{finding.get('id', 'x')}-c{container_idx}",
            )
        except Exception:
            logger.debug(
                "Stability container spawn failed for container %d",
                container_idx, exc_info=True,
            )
            return 0, 0, []

        try:
            if container_idx == self.config.disable_aslr_container:
                try:
                    container.exec(
                        ["sh", "-c", "echo 0 > /proc/sys/kernel/randomize_va_space"],
                        timeout=5,
                    )
                except Exception:
                    logger.debug("ASLR disable failed (expected without CAP_SYS_ADMIN)")

            runner = PocRunner(container)
            successes = 0
            failures: list[str] = []
            for _ in range(runs):
                try:
                    report = runner.replay(finding, candidate_diff="")
                    if report.get("still_crashes", False):
                        successes += 1
                    else:
                        failures.append(report.get("stderr", ""))
                except Exception:
                    failures.append("replay exception")
            return successes, runs, failures
        finally:
            try:
                container.stop()
            except Exception:
                pass

    def _is_race_condition(self, finding: Finding) -> bool:
        cwe = finding.get("cwe", "") or ""
        return cwe in RACE_CWES

    def _runs_for_finding(self, finding: Finding) -> int:
        if self._is_race_condition(finding):
            return self.config.race_runs_per_container
        return self.config.runs_per_container

    def _threshold_for_finding(self, finding: Finding) -> float:
        if self._is_race_condition(finding):
            return self.config.race_stable_threshold
        return self.config.stable_threshold

    def _classify(self, rate: float, threshold: float) -> str:
        if rate >= threshold:
            return "stable"
        if rate >= self.config.flaky_threshold:
            return "flaky"
        return "unreliable"

    def _analyze_failures(self, stderrs: list[str]) -> str:
        if not stderrs:
            return ""

        timeout_count = sum(1 for s in stderrs if "timeout" in s.lower())
        clean_count = sum(1 for s in stderrs if not s.strip())
        addresses = []
        for s in stderrs:
            addresses.extend(_ADDR_RE.findall(s))
        unique_addrs = len(set(addresses))

        parts: list[str] = []
        if timeout_count > len(stderrs) * 0.3:
            parts.append(
                f"timing-dependent ({timeout_count}/{len(stderrs)} failures are timeouts)"
            )
        if unique_addrs > 3 and addresses:
            parts.append(
                f"ASLR-sensitive ({unique_addrs} unique addresses across failures)"
            )
        if clean_count > len(stderrs) * 0.3:
            parts.append(
                f"environment-dependent ({clean_count}/{len(stderrs)} failures produce no output)"
            )
        if not parts:
            parts.append("no dominant failure pattern identified")

        return "; ".join(parts)

    async def _attempt_hardening(
        self,
        finding: Finding,
        result: StabilityResult,
    ) -> StabilityResult:
        per_detail_lines = []
        for i, rate in enumerate(result.per_container_rates):
            per_detail_lines.append(f"- Container {i + 1}: {rate:.0%}")

        prompt = HARDEN_PROMPT.format(
            finding_id=result.finding_id,
            success_rate=result.success_rate,
            per_container_detail="\n".join(per_detail_lines),
            failure_analysis=result.failure_analysis or "unknown",
            original_poc=result.original_poc,
        )

        try:
            response = await self._hardening_llm.aask_text(
                system=HARDEN_SYSTEM_PROMPT, user=prompt,
            )
            hardened_poc = (response.first_text or "").strip()
        except Exception:
            logger.warning("Hardening LLM call failed", exc_info=True)
            return replace(result, hardened=True, hardening_improved=False)

        if not hardened_poc:
            return replace(result, hardened=True, hardening_improved=False)

        hardened_finding = dict(finding)
        hardened_finding["poc"] = hardened_poc

        no_harden_config = replace(self.config, enable_hardening=False)
        retest = StabilityVerifier(
            self._sandbox_manager, config=no_harden_config,
        )
        try:
            retest_result = await retest.averify(hardened_finding)
        except Exception:
            logger.warning("Hardening retest failed", exc_info=True)
            return replace(result, hardened=True, hardening_improved=False)

        improved = retest_result.success_rate > result.success_rate
        return StabilityResult(
            finding_id=result.finding_id,
            total_runs=retest_result.total_runs,
            successes=retest_result.successes,
            success_rate=retest_result.success_rate,
            per_container_rates=retest_result.per_container_rates,
            classification=retest_result.classification,
            hardened=True,
            hardening_improved=improved,
            failure_analysis=retest_result.failure_analysis,
            original_poc=result.original_poc,
            hardened_poc=hardened_poc if improved else None,
        )


# --- Apply helper -------------------------------------------------------------


def apply_stability_result(finding: Finding, result: StabilityResult) -> None:
    """Merge stability data into the finding."""
    finding["stability_classification"] = result.classification
    finding["stability_success_rate"] = result.success_rate
    finding["stability_per_container_rates"] = result.per_container_rates
    finding["stability_total_runs"] = result.total_runs
    finding["stability_hardened"] = result.hardened
    finding["stability_hardening_improved"] = result.hardening_improved
    if result.failure_analysis:
        finding["stability_failure_analysis"] = result.failure_analysis
    if result.hardened_poc:
        finding["poc"] = result.hardened_poc
