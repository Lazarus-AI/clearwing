"""Blind, matched-snapshot CVE benchmark for native Sourcehunt and CyberPi."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path, PurePosixPath
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from clearwing.agent.tools.hunt.sandbox import HunterContext
from clearwing.core.config import clearwing_home
from clearwing.findings.types import Finding
from clearwing.llm import AsyncLLMClient, NativeToolSpec
from clearwing.sourcehunt.cyberpi import CyberPiHuntEngine
from clearwing.sourcehunt.hunt_engine import HuntAssignment
from clearwing.sourcehunt.hunter import NativeHunter
from clearwing.sourcehunt.native_hunt_engine import NativeHuntEngine

_SYSTEM_PROMPT = """You are performing a blind security audit of a focused source snapshot.
Start with the assigned file and use read_file for exact source evidence. Trace attacker-controlled
input through relevant transformations and guards to a concrete security-sensitive sink. Check
whether the apparent issue is actually prevented before recording it. Safe code is a valid result.

For a real vulnerability, record source, transformation, guard, and sink steps as you inspect them,
then call record_finding with the precise file and best source line. The description must state the
trigger, causal mechanism, missing or ineffective guard, and concrete impact. Do not infer a finding
from a project name, historical vulnerability, unavailable patch, or missing code. Do not fabricate
runtime evidence. Finish without a finding when the available source does not support one."""

_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_IDENTIFIER_RE = re.compile(r"^[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?$")
_AUTH_RE = re.compile(r"(?i)(authorization\s*:\s*(?:bearer|basic)\s+)[^\s\"']+")
_URL_SECRET_RE = re.compile(r"(?i)(https?://[^\s/:@]+:)[^\s/@]+(@)")
_SNAPSHOT_VARIANTS: tuple[Literal["vulnerable", "fixed"], ...] = ("vulnerable", "fixed")


class CyberPiSuiteError(ValueError):
    """Raised when a CVE suite or snapshot violates the benchmark contract."""


@dataclass(frozen=True, slots=True)
class SourceLocation:
    file: str
    line: int
    function: str
    tolerance: int = 3


@dataclass(frozen=True, slots=True)
class CaseOracle:
    accepted_cwes: tuple[str, ...]
    locations: tuple[SourceLocation, ...]
    evidence_groups: tuple[tuple[str, ...], ...]


@dataclass(frozen=True, slots=True)
class CyberPiCVECase:
    id: str
    cve: str
    repository: str
    vulnerable_commit: str
    fixed_commit: str
    target_file: str
    context_roots: tuple[str, ...]
    language: str
    oracle: CaseOracle
    references: tuple[str, ...] = ()

    def commit_for(self, variant: Literal["vulnerable", "fixed"]) -> str:
        return self.vulnerable_commit if variant == "vulnerable" else self.fixed_commit


@dataclass(frozen=True, slots=True)
class CyberPiCVESuite:
    name: str
    role: Literal["tuning", "held_out"]
    minimum_runs: int
    cases: tuple[CyberPiCVECase, ...]
    digest: str

    @classmethod
    def load(cls, name_or_path: str | Path) -> CyberPiCVESuite:
        candidate = Path(name_or_path).expanduser()
        if candidate.is_file():
            raw = candidate.read_text(encoding="utf-8")
        else:
            name = str(name_or_path)
            if name not in cls.builtin_names():
                raise CyberPiSuiteError(
                    f"Unknown CyberPi suite {name!r}; available: " + ", ".join(cls.builtin_names())
                )
            raw = files("clearwing.bench.cyberpi_suites").joinpath(f"{name}.json").read_text()
        try:
            payload = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise CyberPiSuiteError(f"Invalid CyberPi suite JSON: {exc}") from exc
        return cls._from_payload(payload, raw)

    @staticmethod
    def builtin_names() -> tuple[str, ...]:
        return ("tuning-cves", "held-out-cves")

    @classmethod
    def _from_payload(cls, payload: Any, raw: str) -> CyberPiCVESuite:
        if not isinstance(payload, dict) or payload.get("schema_version") != 1:
            raise CyberPiSuiteError("CyberPi suites require schema_version 1")
        name = _safe_identifier(_required_string(payload, "name"), field="suite name")
        role = payload.get("role")
        if role not in {"tuning", "held_out"}:
            raise CyberPiSuiteError("CyberPi suite role must be 'tuning' or 'held_out'")
        minimum_runs = payload.get("minimum_runs")
        if not isinstance(minimum_runs, int) or isinstance(minimum_runs, bool) or minimum_runs < 2:
            raise CyberPiSuiteError("CyberPi suite minimum_runs must be at least 2")
        raw_cases = payload.get("cases")
        if not isinstance(raw_cases, list) or not raw_cases:
            raise CyberPiSuiteError("CyberPi suites require at least one case")
        cases = tuple(_case_from_payload(item) for item in raw_cases)
        identifiers = [case.id for case in cases]
        if len(identifiers) != len(set(identifiers)):
            raise CyberPiSuiteError("CyberPi suite case IDs must be unique")
        return cls(
            name=name,
            role=role,
            minimum_runs=minimum_runs,
            cases=cases,
            digest=hashlib.sha256(raw.encode()).hexdigest(),
        )


@dataclass(frozen=True, slots=True)
class PreparedSnapshot:
    path: Path
    commit: str
    digest: str


class CyberPiSnapshotMaterializer:
    """Fetch pinned commits into a private cache and export source-only subtrees."""

    def __init__(self, cache_dir: str | Path | None = None) -> None:
        self.cache_dir = (
            Path(cache_dir).expanduser()
            if cache_dir is not None
            else clearwing_home() / "cyberpi" / "benchmark-cache-v1"
        )

    def materialize(
        self,
        case: CyberPiCVECase,
        variant: Literal["vulnerable", "fixed"],
    ) -> PreparedSnapshot:
        commit = case.commit_for(variant)
        repository_key = hashlib.sha256(case.repository.encode()).hexdigest()[:16]
        bare_repository = self.cache_dir / "repositories" / f"{repository_key}.git"
        snapshots = self.cache_dir / "snapshots"
        snapshot_key = f"{case.id}-{variant}-{commit[:12]}"
        destination = snapshots / snapshot_key
        marker = snapshots / f".{snapshot_key}.json"
        if destination.is_dir() and marker.is_file():
            metadata = json.loads(marker.read_text(encoding="utf-8"))
            digest = _snapshot_digest(destination)
            if (
                metadata.get("repository") == case.repository
                and metadata.get("commit") == commit
                and metadata.get("target_file") == case.target_file
                and metadata.get("context_roots") == list(case.context_roots)
                and metadata.get("digest") == digest
                and (destination / case.target_file).is_file()
            ):
                return PreparedSnapshot(destination, commit, digest)
            raise CyberPiSuiteError(
                f"Cached CyberPi snapshot failed integrity check: {destination}"
            )

        bare_repository.parent.mkdir(parents=True, exist_ok=True)
        snapshots.mkdir(parents=True, exist_ok=True)
        if not bare_repository.is_dir():
            self._run(["git", "init", "--bare", str(bare_repository)])
        self._run(
            [
                "git",
                "--git-dir",
                str(bare_repository),
                "fetch",
                "--force",
                "--no-tags",
                "--depth=1",
                case.repository,
                commit,
            ]
        )
        resolved = self._run(
            ["git", "--git-dir", str(bare_repository), "rev-parse", "FETCH_HEAD^{commit}"]
        ).strip()
        if resolved != commit:
            raise CyberPiSuiteError(
                f"Repository returned {resolved or 'no commit'} for pinned snapshot {commit}"
            )

        staging_parent = Path(tempfile.mkdtemp(prefix=".cyberpi-snapshot-", dir=snapshots))
        archive = staging_parent / "snapshot.tar"
        exported = staging_parent / "source"
        exported.mkdir()
        try:
            self._run(
                [
                    "git",
                    "--git-dir",
                    str(bare_repository),
                    "archive",
                    "--format=tar",
                    f"--output={archive}",
                    commit,
                    "--",
                    *case.context_roots,
                ]
            )
            _extract_regular_files(archive, exported)
            if not (exported / case.target_file).is_file():
                raise CyberPiSuiteError(
                    f"Snapshot {case.id}/{variant} does not contain {case.target_file}"
                )
            digest = _snapshot_digest(exported)
            if destination.exists():
                raise CyberPiSuiteError(f"Refusing to replace unrecognized snapshot: {destination}")
            os.replace(exported, destination)
            marker.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "repository": case.repository,
                        "commit": commit,
                        "target_file": case.target_file,
                        "context_roots": list(case.context_roots),
                        "digest": digest,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            return PreparedSnapshot(destination, commit, digest)
        finally:
            shutil.rmtree(staging_parent, ignore_errors=True)

    @staticmethod
    def _run(command: list[str]) -> str:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise CyberPiSuiteError(f"Snapshot command failed: {exc}") from exc
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "unknown git error").strip()[-2000:]
            raise CyberPiSuiteError(f"Snapshot command failed: {detail}")
        return result.stdout


@dataclass(frozen=True, slots=True)
class CVECaseScore:
    detected: bool
    false_positive: bool
    cwe_accuracy: float
    source_location_accuracy: float
    evidence_quality: float


@dataclass(frozen=True, slots=True)
class CVEBenchmarkObservation:
    engine: Literal["native", "cyberpi"]
    case_id: str
    cve: str
    variant: Literal["vulnerable", "fixed"]
    commit: str
    snapshot_digest: str
    replicate: int
    arm_position: int
    findings: tuple[dict[str, Any], ...]
    trace_steps: tuple[dict[str, Any], ...]
    score: CVECaseScore
    tokens_used: int
    cost_usd: float
    cost_basis: str
    duration_seconds: float
    stop_reason: str
    trajectory: str
    trajectory_sha256: str
    trajectory_redactions: int
    error: str = ""


@dataclass(frozen=True, slots=True)
class CyberPiCVEBenchmarkReport:
    benchmark_id: str
    created_at: str
    suite: str
    suite_role: str
    suite_digest: str
    model: str
    base_url: str
    max_turns: int
    max_output_tokens: int
    observations: tuple[CVEBenchmarkObservation, ...]

    @property
    def successful(self) -> bool:
        return all(not observation.error for observation in self.observations)

    def metrics(self) -> dict[str, dict[str, Any]]:
        return {
            engine: self._engine_metrics(
                [item for item in self.observations if item.engine == engine]
            )
            for engine in ("native", "cyberpi")
            if any(item.engine == engine for item in self.observations)
        }

    @staticmethod
    def _engine_metrics(observations: list[CVEBenchmarkObservation]) -> dict[str, Any]:
        vulnerable = [item for item in observations if item.variant == "vulnerable"]
        fixed = [item for item in observations if item.variant == "fixed"]
        denominator = max(len(vulnerable), 1)
        fixed_denominator = max(len(fixed), 1)
        return {
            "vulnerable_recall": sum(item.score.detected for item in vulnerable) / denominator,
            "fixed_false_positive_rate": (
                sum(item.score.false_positive for item in fixed) / fixed_denominator
            ),
            "cwe_accuracy": sum(item.score.cwe_accuracy for item in vulnerable) / denominator,
            "source_location_accuracy": (
                sum(item.score.source_location_accuracy for item in vulnerable) / denominator
            ),
            "evidence_quality": (
                sum(item.score.evidence_quality for item in vulnerable) / denominator
            ),
            "tokens_total": sum(item.tokens_used for item in observations),
            "tokens_mean": sum(item.tokens_used for item in observations) / len(observations),
            "cost_usd": sum(item.cost_usd for item in observations),
            "duration_seconds_total": sum(item.duration_seconds for item in observations),
            "latency_seconds_mean": (
                sum(item.duration_seconds for item in observations) / len(observations)
            ),
            "decision_stability": _decision_stability(observations),
            "finding_stability": _finding_stability(observations),
            "errors": sum(bool(item.error) for item in observations),
            "observations": len(observations),
        }

    def to_dict(self) -> dict[str, Any]:
        metrics = self.metrics()
        comparison: dict[str, float] = {}
        if {"native", "cyberpi"}.issubset(metrics):
            for key in (
                "vulnerable_recall",
                "fixed_false_positive_rate",
                "cwe_accuracy",
                "source_location_accuracy",
                "evidence_quality",
                "tokens_mean",
                "latency_seconds_mean",
                "decision_stability",
                "finding_stability",
            ):
                comparison[key] = float(metrics["cyberpi"][key]) - float(metrics["native"][key])
        return {
            "schema_version": 2,
            "benchmark_id": self.benchmark_id,
            "created_at": self.created_at,
            "suite": self.suite,
            "suite_role": self.suite_role,
            "suite_digest": self.suite_digest,
            "model": self.model,
            "base_url": self.base_url,
            "max_turns": self.max_turns,
            "max_output_tokens": self.max_output_tokens,
            "metrics": metrics,
            "cyberpi_minus_native": comparison,
            "observations": [
                {**asdict(item), "score": asdict(item.score)} for item in self.observations
            ],
        }

    def markdown(self) -> str:
        lines = [
            "# CyberPi blind CVE benchmark",
            "",
            f"- Benchmark: `{self.benchmark_id}`",
            f"- Suite: `{self.suite}` (`{self.suite_role}`)",
            f"- Suite digest: `{self.suite_digest}`",
            f"- Model: `{self.model}`",
            f"- Endpoint: `{self.base_url}`",
            "",
            "| Engine | Recall | Fixed FPR | CWE | Location | Evidence | Mean tokens | Mean latency | Decision stability | Finding stability | Errors |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
        for engine, values in self.metrics().items():
            lines.append(
                f"| {engine} | {values['vulnerable_recall']:.0%} | "
                f"{values['fixed_false_positive_rate']:.0%} | {values['cwe_accuracy']:.0%} | "
                f"{values['source_location_accuracy']:.0%} | {values['evidence_quality']:.0%} | "
                f"{values['tokens_mean']:.0f} | {values['latency_seconds_mean']:.1f}s | "
                f"{values['decision_stability']:.0%} | {values['finding_stability']:.0%} | "
                f"{values['errors']} |"
            )
        lines.extend(
            [
                "",
                "## Observations",
                "",
                "| Engine | Case | Snapshot | Run | Detected | FP | CWE | Location | Evidence | Tokens | Stop |",
                "| --- | --- | --- | ---: | --- | --- | ---: | ---: | ---: | ---: | --- |",
            ]
        )
        for item in self.observations:
            lines.append(
                f"| {item.engine} | {item.case_id} | {item.variant} | {item.replicate} | "
                f"{'yes' if item.score.detected else 'no'} | "
                f"{'yes' if item.score.false_positive else 'no'} | "
                f"{item.score.cwe_accuracy:.0%} | {item.score.source_location_accuracy:.0%} | "
                f"{item.score.evidence_quality:.0%} | {item.tokens_used} | "
                f"{('error: ' + item.error) if item.error else item.stop_reason} |"
            )
        return "\n".join(lines).rstrip() + "\n"

    def write(self, output_dir: str | Path) -> tuple[Path, Path]:
        destination = Path(output_dir).expanduser()
        destination.mkdir(parents=True, exist_ok=True)
        json_path = destination / f"{self.benchmark_id}.json"
        markdown_path = destination / f"{self.benchmark_id}.md"
        json_path.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n")
        markdown_path.write_text(self.markdown(), encoding="utf-8")
        return json_path, markdown_path


class CyberPiCVEBenchmark:
    """Run paired source-only snapshots through the two hunt-engine adapters."""

    def __init__(
        self,
        llm: AsyncLLMClient,
        suite: CyberPiCVESuite,
        *,
        output_dir: str | Path,
        repository_cache: str | Path | None = None,
        max_turns: int = 8,
        max_output_tokens: int = 4096,
        materializer: CyberPiSnapshotMaterializer | None = None,
    ) -> None:
        self.llm = llm
        self.suite = suite
        self.output_dir = Path(output_dir).expanduser()
        self.max_turns = max_turns
        self.max_output_tokens = max_output_tokens
        self.materializer = materializer or CyberPiSnapshotMaterializer(repository_cache)

    async def arun(
        self,
        *,
        replicates: int,
        engines: tuple[Literal["native", "cyberpi"], ...] = ("native", "cyberpi"),
    ) -> CyberPiCVEBenchmarkReport:
        if replicates < self.suite.minimum_runs:
            raise CyberPiSuiteError(
                f"Suite {self.suite.name!r} requires at least {self.suite.minimum_runs} runs"
            )
        benchmark_id = (
            f"cyberpi-{self.suite.name}-"
            + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            + f"-{uuid4().hex[:6]}"
        )
        prepared = {
            (case.id, variant): self.materializer.materialize(case, variant)
            for case in self.suite.cases
            for variant in _SNAPSHOT_VARIANTS
        }
        observations: list[CVEBenchmarkObservation] = []
        for replicate in range(1, replicates + 1):
            cases = self.suite.cases if replicate % 2 else tuple(reversed(self.suite.cases))
            for case_index, case in enumerate(cases):
                variants = (
                    _SNAPSHOT_VARIANTS
                    if replicate % 2
                    else tuple(reversed(_SNAPSHOT_VARIANTS))
                )
                for variant_index, variant in enumerate(variants):
                    order = (
                        engines
                        if (replicate + case_index + variant_index) % 2
                        else tuple(reversed(engines))
                    )
                    for arm_position, engine in enumerate(order, start=1):
                        observations.append(
                            await self._run_one(
                                benchmark_id,
                                engine,
                                case,
                                variant,
                                prepared[(case.id, variant)],
                                replicate,
                                arm_position,
                            )
                        )
        return CyberPiCVEBenchmarkReport(
            benchmark_id=benchmark_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            suite=self.suite.name,
            suite_role=self.suite.role,
            suite_digest=self.suite.digest,
            model=self.llm.model_name,
            base_url=_safe_base_url(self.llm.base_url or "https://api.anthropic.com"),
            max_turns=self.max_turns,
            max_output_tokens=self.max_output_tokens,
            observations=tuple(observations),
        )

    async def _run_one(
        self,
        benchmark_id: str,
        engine_name: Literal["native", "cyberpi"],
        case: CyberPiCVECase,
        variant: Literal["vulnerable", "fixed"],
        snapshot: PreparedSnapshot,
        replicate: int,
        arm_position: int,
    ) -> CVEBenchmarkObservation:
        work_item_id = f"{engine_name}-{case.id}-{variant}-{replicate}"
        trajectory_dir = self.output_dir / benchmark_id / "trajectories" / work_item_id
        trajectory_path = trajectory_dir / "transcript.jsonl"
        assignment = HuntAssignment(
            file_target={"path": f"/workspace/{case.target_file}"},
            session_id=benchmark_id,
            work_item_id=work_item_id,
        )
        contexts: list[HunterContext] = []

        def build_hunter(_assignment: HuntAssignment, _sandbox: object):
            hunter, context = self._build_hunter(
                case,
                snapshot.path,
                trajectory_dir,
                session_id=benchmark_id,
                work_item_id=work_item_id,
            )
            contexts.append(context)
            return hunter, context

        engine = (
            NativeHuntEngine(build_hunter)
            if engine_name == "native"
            else CyberPiHuntEngine(build_hunter)
        )
        started = time.monotonic()
        findings: tuple[dict[str, Any], ...] = ()
        trace_steps: tuple[dict[str, Any], ...] = ()
        tokens = 0
        cost = 0.0
        stop_reason = "error"
        error = ""
        try:
            outcome = await engine.hunt(assignment, object())
            findings = tuple(_finding_dict(finding) for finding in outcome.findings)
            trace_steps = tuple(dict(step) for step in contexts[0].trace_steps)
            tokens = outcome.tokens_used
            cost = outcome.cost_usd
            stop_reason = outcome.stop_reason
        except Exception as exc:  # preserve the rest of the paired experiment
            error = self._safe_error(exc)
        trajectory_sha256, redactions = sanitize_trajectory(
            trajectory_path, secrets=(self.llm.api_key,)
        )
        return CVEBenchmarkObservation(
            engine=engine_name,
            case_id=case.id,
            cve=case.cve,
            variant=variant,
            commit=snapshot.commit,
            snapshot_digest=snapshot.digest,
            replicate=replicate,
            arm_position=arm_position,
            findings=findings,
            trace_steps=trace_steps,
            score=score_case(case, variant, findings, trace_steps),
            tokens_used=tokens,
            cost_usd=cost,
            cost_basis=("clearwing_estimate" if engine_name == "native" else "provider_reported"),
            duration_seconds=time.monotonic() - started,
            stop_reason=stop_reason,
            trajectory=str(trajectory_path),
            trajectory_sha256=trajectory_sha256,
            trajectory_redactions=redactions,
            error=error,
        )

    def _build_hunter(
        self,
        case: CyberPiCVECase,
        snapshot: Path,
        trajectory_dir: Path,
        *,
        session_id: str,
        work_item_id: str,
    ) -> tuple[NativeHunter, HunterContext]:
        target = f"/workspace/{case.target_file}"
        context = HunterContext(
            repo_path=str(snapshot),
            file_path=target,
            session_id=session_id,
            agent_mode="deep",
            trajectory_dir=trajectory_dir,
            work_item_id=work_item_id,
        )

        async def read_file(path: str, offset: int = 0, limit: int = 500) -> str:
            try:
                relative = _workspace_relative(path)
                resolved = (snapshot / relative).resolve()
                resolved.relative_to(snapshot.resolve())
            except (TypeError, ValueError):
                return json.dumps({"error": "path must remain inside /workspace"})
            if not resolved.is_file():
                return json.dumps({"error": f"source file not found: /workspace/{relative}"})
            if resolved.stat().st_size > 2_000_000:
                return json.dumps({"error": "source file exceeds the 2 MB benchmark limit"})
            context.files_read.add(str(relative))
            selected_offset = max(int(offset), 0)
            selected_limit = min(max(int(limit), 1), 500)
            lines = resolved.read_text(encoding="utf-8", errors="replace").splitlines()
            selected = lines[selected_offset : selected_offset + selected_limit]
            return "\n".join(
                f"{number}: {line}"
                for number, line in enumerate(selected, start=selected_offset + 1)
            )

        async def execute(command: str) -> dict[str, str]:
            return {
                "error": (
                    "execution is disabled in this source-only benchmark; use read_file on "
                    "the assigned file or a related path named by that source"
                )
            }

        async def write_file(path: str, contents: str) -> str:
            if path != "/scratch/notes.txt":
                return json.dumps({"error": "only /scratch/notes.txt is allowed"})
            return f"stored {len(contents)} bytes"

        async def record_trace_step(
            file: str,
            line: int,
            function: str = "",
            code_snippet: str = "",
            note: str = "",
        ) -> str:
            context.trace_steps.append(
                {
                    "file": file,
                    "line": line,
                    "function": function,
                    "code_snippet": code_snippet,
                    "note": note,
                }
            )
            return "trace step recorded"

        async def record_finding(
            file: str,
            line_number: int,
            finding_type: str,
            severity: str,
            cwe: str,
            description: str,
        ) -> str:
            context.findings.append(
                Finding(
                    file=file,
                    line_number=line_number,
                    finding_type=finding_type,
                    severity=severity,  # type: ignore[arg-type]
                    cwe=_normalize_cwe(cwe),
                    description=description,
                    evidence_level="static_corroboration",
                    vulnerability_trace={"steps": list(context.trace_steps)},
                    discovered_by="cyberpi-blind-cve-benchmark",
                )
            )
            return "finding recorded"

        tools = [
            NativeToolSpec(
                "read_file",
                "Read a UTF-8 source file under /workspace with 0-based offset and line limit.",
                _schema(
                    {
                        "path": {"type": "string"},
                        "offset": {"type": "integer"},
                        "limit": {"type": "integer"},
                    },
                    ["path"],
                ),
                read_file,
            ),
            NativeToolSpec(
                "execute",
                "Execution is unavailable in this source-only benchmark.",
                _schema({"command": {"type": "string"}}, ["command"]),
                execute,
            ),
            NativeToolSpec(
                "write_file",
                "Optionally store temporary notes only at /scratch/notes.txt.",
                _schema(
                    {"path": {"type": "string"}, "contents": {"type": "string"}},
                    ["path", "contents"],
                ),
                write_file,
            ),
            NativeToolSpec(
                "record_trace_step",
                "Record one exact source step in the candidate vulnerability trace.",
                _schema(
                    {
                        "file": {"type": "string"},
                        "line": {"type": "integer"},
                        "function": {"type": "string"},
                        "code_snippet": {"type": "string"},
                        "note": {"type": "string"},
                    },
                    ["file", "line"],
                ),
                record_trace_step,
            ),
            NativeToolSpec(
                "record_finding",
                "Record one concrete vulnerability supported by the inspected source trace.",
                _schema(
                    {
                        "file": {"type": "string"},
                        "line_number": {"type": "integer"},
                        "finding_type": {"type": "string"},
                        "severity": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low", "info"],
                        },
                        "cwe": {"type": "string"},
                        "description": {"type": "string"},
                    },
                    ["file", "line_number", "finding_type", "severity", "cwe", "description"],
                ),
                record_finding,
            ),
        ]
        roots = ", ".join(f"/workspace/{root}" for root in case.context_roots)
        initial_message = (
            f"Audit {target}. The focused source snapshot contains these roots: {roots}. "
            "Read the target first, follow only concrete related paths, and report only findings "
            "supported by the available source."
        )
        return (
            NativeHunter(
                llm=self.llm,
                prompt=_SYSTEM_PROMPT,
                tools=tools,
                ctx=context,
                max_steps=self.max_turns,
                agent_mode="deep",
                initial_user_message=initial_message,
                max_output_tokens=self.max_output_tokens,
            ),
            context,
        )

    def _safe_error(self, exc: Exception) -> str:
        message, _ = _sanitize_text(f"{type(exc).__name__}: {exc}", (self.llm.api_key,))
        return message[:2000]


def score_case(
    case: CyberPiCVECase,
    variant: Literal["vulnerable", "fixed"],
    findings: tuple[dict[str, Any], ...],
    trace_steps: tuple[dict[str, Any], ...] = (),
) -> CVECaseScore:
    if variant == "fixed":
        return CVECaseScore(False, bool(findings), 0.0, 0.0, 0.0)
    accepted_cwes = {_normalize_cwe(value) for value in case.oracle.accepted_cwes}
    trace_text = " ".join(
        str(step.get(key) or "")
        for step in trace_steps
        for key in ("file", "function", "code_snippet", "note")
    )
    candidates: list[tuple[float, float, bool]] = []
    for finding in findings:
        evidence_text = " ".join(
            [
                str(finding.get("finding_type") or ""),
                str(finding.get("description") or ""),
                str(finding.get("code_snippet") or ""),
                trace_text,
            ]
        ).casefold()
        evidence = sum(
            any(anchor.casefold() in evidence_text for anchor in group)
            for group in case.oracle.evidence_groups
        ) / len(case.oracle.evidence_groups)
        location = _location_score(case, finding, trace_steps)
        cwe_ok = _normalize_cwe(str(finding.get("cwe") or "")) in accepted_cwes
        candidates.append((evidence, location, cwe_ok))
    supported = [candidate for candidate in candidates if candidate[0] >= 0.5]
    detected = any(location >= 0.5 for _, location, _ in supported)
    return CVECaseScore(
        detected=detected,
        false_positive=False,
        cwe_accuracy=float(any(cwe_ok for _, _, cwe_ok in supported)),
        source_location_accuracy=max((item[1] for item in supported), default=0.0),
        evidence_quality=max((item[0] for item in candidates), default=0.0),
    )


def sanitize_trajectory(path: Path, *, secrets: tuple[str, ...]) -> tuple[str, int]:
    """Sanitize a complete JSONL trajectory in place and return digest/redaction count."""

    if not path.is_file():
        return "", 0
    redactions = 0
    sanitized_lines: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            value = json.loads(line)
        except ValueError as exc:
            raise CyberPiSuiteError(f"Trajectory contains invalid JSON: {path}") from exc
        value, count = _sanitize_value(value, secrets)
        redactions += count
        sanitized_lines.append(json.dumps(value, sort_keys=True, default=str))
    payload = ("\n".join(sanitized_lines) + "\n").encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    for secret in secrets:
        if secret and secret.encode() in payload:
            raise CyberPiSuiteError("Inference credential remained in sanitized trajectory")
    return hashlib.sha256(payload).hexdigest(), redactions


def _case_from_payload(payload: Any) -> CyberPiCVECase:
    if not isinstance(payload, dict):
        raise CyberPiSuiteError("CyberPi suite cases must be objects")
    cve = _required_string(payload, "cve").upper()
    if not _CVE_RE.fullmatch(cve):
        raise CyberPiSuiteError(f"Invalid CVE identifier: {cve!r}")
    vulnerable = _required_string(payload, "vulnerable_commit")
    fixed = _required_string(payload, "fixed_commit")
    if not _SHA1_RE.fullmatch(vulnerable) or not _SHA1_RE.fullmatch(fixed):
        raise CyberPiSuiteError(f"Case {payload.get('id')!r} requires full lowercase commit SHAs")
    if vulnerable == fixed:
        raise CyberPiSuiteError(f"Case {payload.get('id')!r} snapshots must differ")
    repository = _required_string(payload, "repository")
    parsed_repository = urlsplit(repository)
    if (
        parsed_repository.scheme != "https"
        or not parsed_repository.hostname
        or parsed_repository.username
        or parsed_repository.password
        or parsed_repository.query
        or parsed_repository.fragment
    ):
        raise CyberPiSuiteError("CyberPi suite repositories must be credential-free HTTPS URLs")
    context_roots = _string_tuple(payload, "context_roots")
    target_file = _safe_relative(_required_string(payload, "target_file"))
    safe_roots = tuple(_safe_relative(root) for root in context_roots)
    if not any(
        target_file == root or target_file.startswith(root.rstrip("/") + "/") for root in safe_roots
    ):
        raise CyberPiSuiteError(f"Target {target_file!r} is outside its exported context roots")
    raw_oracle = payload.get("oracle")
    if not isinstance(raw_oracle, dict):
        raise CyberPiSuiteError("CyberPi cases require a private grading oracle")
    raw_locations = raw_oracle.get("locations")
    if not isinstance(raw_locations, list) or not raw_locations:
        raise CyberPiSuiteError("CyberPi case oracles require source locations")
    locations = tuple(
        SourceLocation(
            file=_safe_relative(_required_string(item, "file")),
            line=_positive_integer(item, "line"),
            function=_required_string(item, "function"),
            tolerance=_positive_integer(item, "tolerance", allow_zero=True),
        )
        for item in raw_locations
        if isinstance(item, dict)
    )
    if len(locations) != len(raw_locations):
        raise CyberPiSuiteError("CyberPi source locations must be objects")
    raw_groups = raw_oracle.get("evidence_groups")
    if not isinstance(raw_groups, list) or not raw_groups:
        raise CyberPiSuiteError("CyberPi case oracles require evidence groups")
    evidence_groups = tuple(
        tuple(str(anchor).strip() for anchor in group if str(anchor).strip())
        for group in raw_groups
        if isinstance(group, list) and group
    )
    if len(evidence_groups) != len(raw_groups) or any(not group for group in evidence_groups):
        raise CyberPiSuiteError("CyberPi evidence groups must be non-empty string arrays")
    return CyberPiCVECase(
        id=_safe_identifier(_required_string(payload, "id"), field="case ID"),
        cve=cve,
        repository=repository,
        vulnerable_commit=vulnerable,
        fixed_commit=fixed,
        target_file=target_file,
        context_roots=safe_roots,
        language=_required_string(payload, "language"),
        oracle=CaseOracle(
            accepted_cwes=tuple(
                _normalize_cwe(value) for value in _string_tuple(raw_oracle, "accepted_cwes")
            ),
            locations=locations,
            evidence_groups=evidence_groups,
        ),
        references=tuple(str(value) for value in payload.get("references", [])),
    )


def _required_string(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise CyberPiSuiteError(f"CyberPi suite field {key!r} must be a non-empty string")
    return value.strip()


def _safe_identifier(value: str, *, field: str) -> str:
    if not _IDENTIFIER_RE.fullmatch(value):
        raise CyberPiSuiteError(
            f"CyberPi {field} must be a lowercase filesystem-safe identifier"
        )
    return value


def _string_tuple(payload: dict[str, Any], key: str) -> tuple[str, ...]:
    value = payload.get(key)
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) and item.strip() for item in value)
    ):
        raise CyberPiSuiteError(f"CyberPi suite field {key!r} must be a non-empty string array")
    return tuple(item.strip() for item in value)


def _positive_integer(payload: dict[str, Any], key: str, *, allow_zero: bool = False) -> int:
    value = payload.get(key)
    minimum = 0 if allow_zero else 1
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise CyberPiSuiteError(f"CyberPi suite field {key!r} must be >= {minimum}")
    return value


def _safe_relative(value: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise CyberPiSuiteError(f"Unsafe benchmark source path: {value!r}")
    return str(path)


def _workspace_relative(path: str) -> Path:
    normalized = path.removeprefix("/workspace/").removeprefix("workspace/")
    return Path(_safe_relative(normalized))


def _extract_regular_files(archive: Path, destination: Path) -> None:
    with tarfile.open(archive, "r:") as bundle:
        for member in bundle.getmembers():
            relative = PurePosixPath(member.name)
            if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
                raise CyberPiSuiteError(f"Unsafe path in repository archive: {member.name!r}")
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = bundle.extractfile(member)
            if source is None:
                raise CyberPiSuiteError(f"Could not extract repository file: {member.name}")
            with source, target.open("wb") as stream:
                shutil.copyfileobj(source, stream)


def _snapshot_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _finding_dict(finding: Finding) -> dict[str, Any]:
    return {
        "file": finding.file,
        "line_number": finding.line_number,
        "finding_type": finding.finding_type,
        "severity": finding.severity,
        "cwe": finding.cwe,
        "description": finding.description,
        "evidence_level": finding.evidence_level,
        "vulnerability_trace": finding.vulnerability_trace,
    }


def _location_score(
    case: CyberPiCVECase,
    finding: dict[str, Any],
    trace_steps: tuple[dict[str, Any], ...],
) -> float:
    reported_file = str(finding.get("file") or "").removeprefix("/workspace/")
    reported_line = finding.get("line_number")
    trace_functions = {str(step.get("function") or "").casefold() for step in trace_steps}
    evidence_text = (
        str(finding.get("finding_type") or "") + " " + str(finding.get("description") or "")
    ).casefold()
    scores: list[float] = []
    for location in case.oracle.locations:
        if reported_file != location.file:
            scores.append(0.0)
            continue
        if (
            isinstance(reported_line, int)
            and abs(reported_line - location.line) <= location.tolerance
        ):
            scores.append(1.0)
        elif (
            location.function.casefold() in trace_functions
            or location.function.casefold() in evidence_text
        ):
            scores.append(0.75)
        else:
            scores.append(0.5)
    return max(scores, default=0.0)


def _decision_stability(observations: list[CVEBenchmarkObservation]) -> float:
    grouped: dict[tuple[str, str], list[bool]] = defaultdict(list)
    for item in observations:
        decision = (
            item.score.detected if item.variant == "vulnerable" else item.score.false_positive
        )
        grouped[(item.case_id, item.variant)].append(decision)
    return sum(
        max(sum(values), len(values) - sum(values)) / len(values) for values in grouped.values()
    ) / max(len(grouped), 1)


def _finding_stability(observations: list[CVEBenchmarkObservation]) -> float:
    grouped: dict[tuple[str, str], list[set[str]]] = defaultdict(list)
    for item in observations:
        signatures = {
            f"{_normalize_cwe(str(finding.get('cwe') or ''))}:"
            f"{str(finding.get('file') or '').removeprefix('/workspace/')}:"
            f"{finding.get('line_number')}"
            for finding in item.findings
        }
        grouped[(item.case_id, item.variant)].append(signatures)
    scores: list[float] = []
    for run_signatures in grouped.values():
        if len(run_signatures) < 2:
            scores.append(1.0)
            continue
        pairs = [
            (left, right)
            for index, left in enumerate(run_signatures)
            for right in run_signatures[index + 1 :]
        ]
        scores.append(
            sum(
                len(left & right) / len(left | right) if left | right else 1.0
                for left, right in pairs
            )
            / len(pairs)
        )
    return sum(scores) / max(len(scores), 1)


def _sanitize_value(value: Any, secrets: tuple[str, ...]) -> tuple[Any, int]:
    if isinstance(value, str):
        return _sanitize_text(value, secrets)
    if isinstance(value, list):
        cleaned = []
        count = 0
        for item in value:
            sanitized, item_count = _sanitize_value(item, secrets)
            cleaned.append(sanitized)
            count += item_count
        return cleaned, count
    if isinstance(value, dict):
        cleaned_dict: dict[str, Any] = {}
        count = 0
        for key, item in value.items():
            sanitized, item_count = _sanitize_value(item, secrets)
            cleaned_dict[str(key)] = sanitized
            count += item_count
        return cleaned_dict, count
    return value, 0


def _sanitize_text(value: str, secrets: tuple[str, ...]) -> tuple[str, int]:
    redactions = 0
    cleaned = value
    for secret in secrets:
        if secret and secret in cleaned:
            redactions += cleaned.count(secret)
            cleaned = cleaned.replace(secret, "[REDACTED]")
    cleaned, count = _AUTH_RE.subn(r"\1[REDACTED]", cleaned)
    redactions += count
    cleaned, count = _URL_SECRET_RE.subn(r"\1[REDACTED]\2", cleaned)
    redactions += count
    return cleaned, redactions


def _normalize_cwe(value: str) -> str:
    normalized = value.upper().strip().replace("_", "-")
    number = normalized.removeprefix("CWE-").removeprefix("CWE")
    return f"CWE-{number.lstrip('0') or '0'}" if number.isdigit() else normalized


def _safe_base_url(value: str) -> str:
    parsed = urlsplit(value)
    if not parsed.hostname:
        return value.split("?", 1)[0].split("#", 1)[0]
    hostname = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    netloc = f"{hostname}:{parsed.port}" if parsed.port is not None else hostname
    return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))


def _schema(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }


__all__ = [
    "CVEBenchmarkObservation",
    "CVECaseScore",
    "CaseOracle",
    "CyberPiCVEBenchmark",
    "CyberPiCVEBenchmarkReport",
    "CyberPiCVECase",
    "CyberPiCVESuite",
    "CyberPiSnapshotMaterializer",
    "CyberPiSuiteError",
    "PreparedSnapshot",
    "SourceLocation",
    "sanitize_trajectory",
    "score_case",
]
