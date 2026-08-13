"""Offline vulnerable/fixed validator replay over LAIR golden chains.

This module deliberately feeds the same source-backed alleged finding to both
revisions.  Only source text changes, so the model receives no positive/fixed
label and cannot pass by recognizing an evaluation arm.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import subprocess
from collections import defaultdict
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from clearwing.findings.types import Finding
from clearwing.sourcehunt.state import ValidatorVerdict
from clearwing.sourcehunt.validator import Validator

from .sourcehunt_lair import LairGoldenChain, LairRevision

REPLAY_SCHEMA_VERSION = "cw.sourcehunt.lair-validator-replay.v2"
REPLAY_CONTEXT_PROFILE = "balanced-anchor-v1"
_REPLAY_ARMS = ("vulnerable", "fixed")
_SOURCE_LINE_SLOT_CHARS = 96


class _ReplayModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ReplayVerdict(_ReplayModel):
    advance: bool
    severity_validated: str | None
    evidence_level: str
    axes: dict[str, dict[str, Any]]
    pro_argument: str
    counter_argument: str
    tie_breaker: str
    model_error: bool


class LairValidatorCaseResult(_ReplayModel):
    cve: str
    repository: str
    finding_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_window_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    vulnerable: ReplayVerdict
    fixed: ReplayVerdict
    vulnerable_correct: bool
    fixed_correct: bool
    pair_correct: bool


class LairValidatorReplaySummary(_ReplayModel):
    schema_version: str = REPLAY_SCHEMA_VERSION
    model: str
    prompt_profile: str
    context_profile: str = REPLAY_CONTEXT_PROFILE
    max_output_tokens: int | None = Field(default=None, ge=1)
    temperature: float | None = Field(default=None, ge=0.0, le=2.0)
    case_count: int = Field(ge=0)
    vulnerable_recall: float = Field(ge=0.0, le=1.0)
    fixed_rejection_rate: float = Field(ge=0.0, le=1.0)
    pair_accuracy: float = Field(ge=0.0, le=1.0)
    vulnerable_false_negatives: int = Field(ge=0)
    fixed_false_positives: int = Field(ge=0)
    model_errors: int = Field(ge=0)
    axis_pass_counts: dict[str, dict[str, int]]
    cases: list[LairValidatorCaseResult]


@dataclass(frozen=True)
class SourceWindow:
    path: str
    start: int
    end: int
    anchors: tuple[int, ...] = ()


ValidatorCall = Callable[[Finding, str], Awaitable[ValidatorVerdict]]


def build_lair_validator_finding(golden: LairGoldenChain) -> Finding:
    """Convert a golden into one immutable alleged finding for both snapshots."""

    trace = golden.chain.investigation.causal_trace
    operation = next(step for step in trace if step.kind.value == "vulnerable_operation")
    operation_citation = operation.evidence[0]
    trace_steps = [
        {
            "file": citation.path,
            "line": citation.line_start,
            "function": "",
            "code_snippet": citation.excerpt,
            "note": f"{step.kind.value}: {step.claim}",
        }
        for step in trace
        for citation in step.evidence
    ]
    cwe = re.search(r"\bCWE-[0-9]+\b", golden.vulnerability_class, re.IGNORECASE)
    return Finding(
        id=f"lair-replay-{hashlib.sha256(golden.cve.encode()).hexdigest()[:16]}",
        file=operation_citation.path,
        line_number=operation_citation.line_start,
        end_line=operation_citation.line_end,
        finding_type="source_security",
        cwe=cwe.group(0).upper() if cwe else "",
        severity="medium",
        confidence="high",
        description=golden.summary,
        code_snippet=operation_citation.excerpt,
        discovered_by="sourcehunt_offline_replay",
        evidence_level="static_corroboration",
        vulnerability_trace={
            "summary": golden.summary,
            "steps": trace_steps,
        },
    )


def source_windows_for_golden(
    golden: LairGoldenChain,
    *,
    radius: int = 18,
) -> list[SourceWindow]:
    """Select revision-independent windows using vulnerable trace coordinates only."""

    if radius < 0:
        raise ValueError("source context radius cannot be negative")
    grouped: dict[str, list[tuple[int, int, tuple[int, ...]]]] = defaultdict(list)
    for step in golden.chain.investigation.causal_trace:
        for citation in step.evidence:
            if citation.revision != LairRevision.VULNERABLE:
                raise ValueError("investigation trace contains non-vulnerable evidence")
            grouped[citation.path].append(
                (
                    max(1, citation.line_start - radius),
                    citation.line_end + radius,
                    ((citation.line_start + citation.line_end) // 2,),
                )
            )

    windows: list[SourceWindow] = []
    for path, ranges in sorted(grouped.items()):
        for start, end, anchors in _merge_anchored_windows(ranges):
            windows.append(
                SourceWindow(path=path, start=start, end=end, anchors=anchors)
            )
    return windows


def render_revision_context(
    repo: str | Path,
    revision: str,
    windows: Sequence[SourceWindow],
    *,
    max_chars: int = 20_000,
) -> str:
    """Render identical path/line selections from one Git revision."""

    if max_chars < 1:
        raise ValueError("source context max_chars must be positive")
    repository = Path(repo)
    source_cache: dict[str, list[str] | None] = {}
    grouped: dict[str, list[SourceWindow]] = defaultdict(list)
    for window in windows:
        grouped[window.path].append(window)
    path_count = len(grouped)
    if not path_count:
        return ""

    chunks: list[str] = []
    separator_chars = max(0, len(windows) - 1) * 2
    content_budget = max(1, max_chars - separator_chars)
    path_budget, path_remainder = divmod(content_budget, path_count)
    for path_index, (path, path_windows) in enumerate(sorted(grouped.items())):
        budget = path_budget + (1 if path_index < path_remainder else 0)
        window_budget, window_remainder = divmod(budget, len(path_windows))
        source_cache[path] = _git_source(repository, revision, path)
        for window_index, window in enumerate(path_windows):
            quota = window_budget + (1 if window_index < window_remainder else 0)
            chunks.append(
                _render_source_window(
                    window,
                    source_cache[path],
                    max_chars=quota,
                )
            )
    return "\n\n".join(chunks)[:max_chars]


async def replay_lair_validator_case(
    golden: LairGoldenChain,
    repo: str | Path,
    validator_call: ValidatorCall,
    *,
    context_radius: int = 18,
    max_context_chars: int = 20_000,
) -> LairValidatorCaseResult:
    """Run one alleged finding against vulnerable and fixed source snapshots."""

    finding = build_lair_validator_finding(golden)
    windows = source_windows_for_golden(golden, radius=context_radius)
    vulnerable_context = render_revision_context(
        repo,
        golden.vulnerable_commit,
        windows,
        max_chars=max_context_chars,
    )
    fixed_context = render_revision_context(
        repo,
        golden.fix_commit,
        windows,
        max_chars=max_context_chars,
    )
    finding_digest = _digest(asdict(finding))
    window_digest = _digest([asdict(window) for window in windows])

    vulnerable = await validator_call(finding, vulnerable_context)
    fixed = await validator_call(finding, fixed_context)
    vulnerable_payload = _verdict_payload(vulnerable)
    fixed_payload = _verdict_payload(fixed)
    vulnerable_correct = vulnerable.advance and not vulnerable_payload.model_error
    fixed_correct = not fixed.advance and not fixed_payload.model_error
    return LairValidatorCaseResult(
        cve=golden.cve,
        repository=golden.repo,
        finding_digest=finding_digest,
        source_window_digest=window_digest,
        vulnerable=vulnerable_payload,
        fixed=fixed_payload,
        vulnerable_correct=vulnerable_correct,
        fixed_correct=fixed_correct,
        pair_correct=vulnerable_correct and fixed_correct,
    )


async def run_lair_validator_replay(
    goldens: Sequence[LairGoldenChain],
    campaign_root: str | Path,
    validator: Validator,
    *,
    model: str,
    prompt_profile: str = "legacy-v1",
    max_output_tokens: int | None = None,
    temperature: float | None = None,
    max_parallel: int = 2,
    context_radius: int = 18,
    max_context_chars: int = 20_000,
) -> LairValidatorReplaySummary:
    """Replay all goldens with bounded concurrency and aggregate pair metrics."""

    if max_parallel < 1:
        raise ValueError("validator replay max_parallel must be positive")
    root = Path(campaign_root)
    semaphore = asyncio.Semaphore(max_parallel)

    async def validator_call(finding: Finding, source_context: str) -> ValidatorVerdict:
        return await validator.avalidate(finding, source_context=source_context)

    async def run_one(golden: LairGoldenChain) -> LairValidatorCaseResult:
        async with semaphore:
            repo = root / "workspaces" / golden.cve / "repo"
            if not repo.is_dir():
                raise ValueError(f"LAIR replay repository is missing: {repo}")
            return await replay_lair_validator_case(
                golden,
                repo,
                validator_call,
                context_radius=context_radius,
                max_context_chars=max_context_chars,
            )

    cases = await asyncio.gather(*(run_one(golden) for golden in goldens))
    return summarize_lair_validator_replay(
        cases,
        model=model,
        prompt_profile=prompt_profile,
        max_output_tokens=max_output_tokens,
        temperature=temperature,
    )


def summarize_lair_validator_replay(
    cases: Sequence[LairValidatorCaseResult],
    *,
    model: str,
    prompt_profile: str = "legacy-v1",
    max_output_tokens: int | None = None,
    temperature: float | None = None,
) -> LairValidatorReplaySummary:
    count = len(cases)
    axis_counts: dict[str, dict[str, int]] = {}
    for arm in _REPLAY_ARMS:
        counts: dict[str, int] = defaultdict(int)
        for case in cases:
            verdict = getattr(case, arm)
            for name, result in verdict.axes.items():
                if result.get("passed") is True:
                    counts[name] += 1
        axis_counts[arm] = dict(counts)
    errors = sum(case.vulnerable.model_error + case.fixed.model_error for case in cases)
    return LairValidatorReplaySummary(
        model=model,
        prompt_profile=prompt_profile,
        max_output_tokens=max_output_tokens,
        temperature=temperature,
        case_count=count,
        vulnerable_recall=_fraction(sum(case.vulnerable_correct for case in cases), count),
        fixed_rejection_rate=_fraction(sum(case.fixed_correct for case in cases), count),
        pair_accuracy=_fraction(sum(case.pair_correct for case in cases), count),
        vulnerable_false_negatives=sum(not case.vulnerable_correct for case in cases),
        fixed_false_positives=sum(not case.fixed_correct for case in cases),
        model_errors=errors,
        axis_pass_counts=axis_counts,
        cases=list(cases),
    )


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def _merge_anchored_windows(
    windows: Sequence[tuple[int, int, tuple[int, ...]]],
) -> list[tuple[int, int, tuple[int, ...]]]:
    merged: list[tuple[int, int, tuple[int, ...]]] = []
    for start, end, anchors in sorted(windows):
        if not merged or start > merged[-1][1] + 4:
            merged.append((start, end, tuple(sorted(set(anchors)))))
        else:
            prior_start, prior_end, prior_anchors = merged[-1]
            merged[-1] = (
                prior_start,
                max(prior_end, end),
                tuple(sorted(set(prior_anchors + anchors))),
            )
    return merged


def _render_source_window(
    window: SourceWindow,
    lines: list[str] | None,
    *,
    max_chars: int,
) -> str:
    if max_chars < 1:
        return ""
    if lines is None:
        return f"--- {window.path}: unavailable in current snapshot ---"[:max_chars]

    start = min(window.start, max(1, len(lines)))
    end = min(window.end, len(lines))
    anchors = tuple(line for line in window.anchors if start <= line <= end)
    if not anchors:
        anchors = ((start + end) // 2,)
    header = f"--- {window.path}:{start}-{end} ---\n"
    candidates = sorted(
        range(start, end + 1),
        key=lambda line: (min(abs(line - anchor) for anchor in anchors), line),
    )
    line_budget = max(1, (max_chars - len(header)) // _SOURCE_LINE_SLOT_CHARS)
    selected = sorted(candidates[:line_budget])
    source_chars = _SOURCE_LINE_SLOT_CHARS - 9
    body = "\n".join(
        f"{line:6d}: {lines[line - 1][:source_chars]}" for line in selected
    )
    return f"{header}{body}"[:max_chars]


def _git_source(repo: Path, revision: str, path: str) -> list[str] | None:
    result = subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "show", f"{revision}:{path}"],
        cwd=repo,
        text=True,
        capture_output=True,
        timeout=120,
        check=False,
    )
    return result.stdout.splitlines() if result.returncode == 0 else None


def _verdict_payload(verdict: ValidatorVerdict) -> ReplayVerdict:
    return ReplayVerdict(
        advance=verdict.advance,
        severity_validated=verdict.severity_validated,
        evidence_level=verdict.evidence_level,
        axes={name: result.model_dump(mode="json") for name, result in verdict.axes.items()},
        pro_argument=verdict.pro_argument,
        counter_argument=verdict.counter_argument,
        tie_breaker=verdict.tie_breaker,
        model_error=not any(True for _ in verdict.axes.items()),
    )


def _fraction(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


__all__ = [
    "REPLAY_CONTEXT_PROFILE",
    "REPLAY_SCHEMA_VERSION",
    "LairValidatorCaseResult",
    "LairValidatorReplaySummary",
    "ReplayVerdict",
    "SourceWindow",
    "build_lair_validator_finding",
    "render_revision_context",
    "replay_lair_validator_case",
    "run_lair_validator_replay",
    "source_windows_for_golden",
    "summarize_lair_validator_replay",
]
