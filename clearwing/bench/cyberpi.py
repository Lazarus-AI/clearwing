"""Small paired harness benchmark for native Sourcehunt and CyberPi."""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from clearwing.agent.tools.hunt.sandbox import HunterContext
from clearwing.findings.types import Finding
from clearwing.llm import AsyncLLMClient, NativeToolSpec
from clearwing.sourcehunt.cyberpi import CyberPiHuntEngine
from clearwing.sourcehunt.hunt_engine import HuntAssignment
from clearwing.sourcehunt.hunter import NativeHunter
from clearwing.sourcehunt.native_hunt_engine import NativeHuntEngine

_SYSTEM_PROMPT = """You are auditing one C source file for memory-safety vulnerabilities.
Read /workspace/fixture.c before deciding. Trace attacker-controlled sizes to memory operations.
Call record_finding only for a concrete vulnerability in the supplied source. Use CWE-122 for a
heap-buffer overflow. Safe code is a valid outcome: if bounds checks make the operation safe,
finish without calling record_finding. Do not invent missing code, runtime evidence, or findings."""


@dataclass(frozen=True, slots=True)
class CyberPiFixture:
    """A source snippet with a deliberately narrow expected outcome."""

    name: str
    source: str
    vulnerable: bool
    expected_cwe: str | None = None
    expected_line: int | None = None


BUILTIN_FIXTURES = (
    CyberPiFixture(
        name="heap-overflow",
        source="""#include <stdlib.h>
#include <string.h>

void copy_packet(const unsigned char *packet, size_t packet_length) {
    char *destination = malloc(16);
    if (destination == NULL) return;
    memcpy(destination, packet, packet_length);
    free(destination);
}
""",
        vulnerable=True,
        expected_cwe="CWE-122",
        expected_line=7,
    ),
    CyberPiFixture(
        name="bounded-copy",
        source="""#include <stdlib.h>
#include <string.h>

void copy_packet(const unsigned char *packet, size_t packet_length) {
    if (packet_length > 16) return;
    char *destination = malloc(16);
    if (destination == NULL) return;
    memcpy(destination, packet, packet_length);
    free(destination);
}
""",
        vulnerable=False,
    ),
)


@dataclass(frozen=True, slots=True)
class BenchmarkObservation:
    engine: Literal["native", "cyberpi"]
    fixture: str
    replicate: int
    passed: bool
    findings: tuple[dict[str, Any], ...]
    tokens_used: int
    cost_usd: float
    cost_basis: str
    duration_seconds: float
    stop_reason: str
    trajectory: str
    error: str = ""


@dataclass(frozen=True, slots=True)
class CyberPiBenchmarkReport:
    benchmark_id: str
    created_at: str
    model: str
    base_url: str
    max_turns: int
    max_output_tokens: int
    observations: tuple[BenchmarkObservation, ...]

    @property
    def successful(self) -> bool:
        return all(not observation.error for observation in self.observations)

    def metrics(self) -> dict[str, dict[str, Any]]:
        metrics: dict[str, dict[str, Any]] = {}
        for engine in ("native", "cyberpi"):
            observations = [item for item in self.observations if item.engine == engine]
            if not observations:
                continue
            metrics[engine] = {
                "passed": sum(item.passed for item in observations),
                "cases": len(observations),
                "pass_rate": sum(item.passed for item in observations) / len(observations),
                "tokens": sum(item.tokens_used for item in observations),
                "cost_usd": sum(item.cost_usd for item in observations),
                "cost_basis": ", ".join(sorted({item.cost_basis for item in observations})),
                "duration_seconds": sum(item.duration_seconds for item in observations),
                "errors": sum(bool(item.error) for item in observations),
            }
        return metrics

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "benchmark_id": self.benchmark_id,
            "created_at": self.created_at,
            "model": self.model,
            "base_url": self.base_url,
            "max_turns": self.max_turns,
            "max_output_tokens": self.max_output_tokens,
            "metrics": self.metrics(),
            "observations": [asdict(observation) for observation in self.observations],
        }

    def markdown(self) -> str:
        lines = [
            "# CyberPi harness benchmark",
            "",
            f"- Benchmark: `{self.benchmark_id}`",
            f"- Model: `{self.model}`",
            f"- Endpoint: `{self.base_url}`",
            f"- Maximum turns per case: {self.max_turns}",
            f"- Maximum output tokens per turn: {self.max_output_tokens}",
            "",
            "| Engine | Passed | Cases | Pass rate | Tokens | Reported cost* | Duration | Errors |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
        for engine, values in self.metrics().items():
            lines.append(
                f"| {engine} | {values['passed']} | {values['cases']} | "
                f"{float(values['pass_rate']):.0%} | {values['tokens']} | "
                f"${float(values['cost_usd']):.4f} | "
                f"{float(values['duration_seconds']):.1f}s | {values['errors']} |"
            )
        lines.extend(
            [
                "",
                "## Cases",
                "",
                "| Engine | Fixture | Run | Result | Findings | Stop | Trajectory |",
                "| --- | --- | ---: | --- | ---: | --- | --- |",
            ]
        )
        for item in self.observations:
            result = f"error: {item.error}" if item.error else ("pass" if item.passed else "miss")
            lines.append(
                f"| {item.engine} | {item.fixture} | {item.replicate} | {result} | "
                f"{len(item.findings)} | {item.stop_reason} | `{item.trajectory}` |"
            )
        lines.extend(
            [
                "",
                "\\* Native cost is Clearwing's pricing-table estimate; CyberPi cost is Pi's "
                "provider/model report. Compare tokens unless both arms use configured endpoint pricing.",
                "",
                "This is a deterministic-fixture harness comparison, not a CVE recall claim. "
                "Use multiple runs and inspect the JSONL trajectories before changing prompts.",
                "",
            ]
        )
        return "\n".join(lines)

    def write(self, output_dir: str | Path) -> tuple[Path, Path]:
        destination = Path(output_dir).expanduser()
        destination.mkdir(parents=True, exist_ok=True)
        json_path = destination / f"{self.benchmark_id}.json"
        markdown_path = destination / f"{self.benchmark_id}.md"
        json_path.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n")
        markdown_path.write_text(self.markdown(), encoding="utf-8")
        return json_path, markdown_path


class CyberPiBenchmark:
    """Run both harnesses with the same model, prompt, tools, cases, and turn cap."""

    def __init__(
        self,
        llm: AsyncLLMClient,
        *,
        output_dir: str | Path,
        max_turns: int = 4,
        max_output_tokens: int = 4096,
    ) -> None:
        self.llm = llm
        self.output_dir = Path(output_dir).expanduser()
        self.max_turns = max_turns
        self.max_output_tokens = max_output_tokens

    async def arun(
        self,
        *,
        replicates: int = 1,
        engines: tuple[Literal["native", "cyberpi"], ...] = ("native", "cyberpi"),
        fixtures: tuple[CyberPiFixture, ...] = BUILTIN_FIXTURES,
    ) -> CyberPiBenchmarkReport:
        benchmark_id = (
            "cyberpi-"
            + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            + f"-{uuid4().hex[:6]}"
        )
        observations: list[BenchmarkObservation] = []
        for replicate in range(1, replicates + 1):
            engine_order = engines if replicate % 2 else tuple(reversed(engines))
            for fixture in fixtures:
                for engine_name in engine_order:
                    observations.append(
                        await self._run_one(benchmark_id, engine_name, fixture, replicate)
                    )
        return CyberPiBenchmarkReport(
            benchmark_id=benchmark_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            model=self.llm.model_name,
            base_url=self._safe_base_url(self.llm.base_url or "https://api.anthropic.com"),
            max_turns=self.max_turns,
            max_output_tokens=self.max_output_tokens,
            observations=tuple(observations),
        )

    async def _run_one(
        self,
        benchmark_id: str,
        engine_name: Literal["native", "cyberpi"],
        fixture: CyberPiFixture,
        replicate: int,
    ) -> BenchmarkObservation:
        work_item_id = f"{engine_name}-{fixture.name}-{replicate}"
        trajectory_dir = self.output_dir / benchmark_id / "trajectories" / work_item_id
        assignment = HuntAssignment(
            file_target={"path": "/workspace/fixture.c"},
            session_id=benchmark_id,
            work_item_id=work_item_id,
        )

        def build_hunter(_assignment: HuntAssignment, _sandbox: object):
            return self._build_hunter(fixture, trajectory_dir, benchmark_id, work_item_id)

        engine = (
            NativeHuntEngine(build_hunter)
            if engine_name == "native"
            else CyberPiHuntEngine(build_hunter)
        )
        started = time.monotonic()
        try:
            outcome = await engine.hunt(assignment, object())
            findings = tuple(self._finding_dict(finding) for finding in outcome.findings)
            return BenchmarkObservation(
                engine=engine_name,
                fixture=fixture.name,
                replicate=replicate,
                passed=self._passed(fixture, findings),
                findings=findings,
                tokens_used=outcome.tokens_used,
                cost_usd=outcome.cost_usd,
                cost_basis=(
                    "clearwing_estimate" if engine_name == "native" else "provider_reported"
                ),
                duration_seconds=time.monotonic() - started,
                stop_reason=outcome.stop_reason,
                trajectory=str(trajectory_dir / "transcript.jsonl"),
            )
        except Exception as exc:  # keep the paired experiment and its artifacts intact
            return BenchmarkObservation(
                engine=engine_name,
                fixture=fixture.name,
                replicate=replicate,
                passed=False,
                findings=(),
                tokens_used=0,
                cost_usd=0.0,
                cost_basis=(
                    "clearwing_estimate" if engine_name == "native" else "provider_reported"
                ),
                duration_seconds=time.monotonic() - started,
                stop_reason="error",
                trajectory=str(trajectory_dir / "transcript.jsonl"),
                error=self._safe_error(exc),
            )

    def _build_hunter(
        self,
        fixture: CyberPiFixture,
        trajectory_dir: Path,
        session_id: str,
        work_item_id: str,
    ) -> tuple[NativeHunter, HunterContext]:
        context = HunterContext(
            repo_path="/workspace",
            file_path="/workspace/fixture.c",
            session_id=session_id,
            agent_mode="deep",
            trajectory_dir=trajectory_dir,
            work_item_id=work_item_id,
        )

        async def read_file(path: str, offset: int = 0, limit: int = 500) -> str:
            if not path.endswith("fixture.c"):
                return json.dumps({"error": "the benchmark exposes only /workspace/fixture.c"})
            lines = fixture.source.splitlines()
            selected = lines[max(offset, 0) : max(offset, 0) + max(limit, 1)]
            return "\n".join(
                f"{number}: {line}" for number, line in enumerate(selected, start=max(offset, 0) + 1)
            )

        async def execute(command: str) -> dict[str, str]:
            return {"error": f"execution is disabled in this source-only fixture: {command[:80]}"}

        async def write_file(path: str, contents: str) -> str:
            if path != "/scratch/notes.txt":
                return json.dumps({"error": "the fixture permits only /scratch/notes.txt"})
            return f"stored {len(contents)} bytes"

        async def record_trace_step(
            file: str, line: int, function: str = "", note: str = ""
        ) -> str:
            context.trace_steps.append(
                {"file": file, "line": line, "function": function, "note": note}
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
                    cwe=cwe.upper(),
                    description=description,
                    discovered_by="cyberpi-benchmark",
                )
            )
            return "finding recorded"

        tools = [
            NativeToolSpec(
                "read_file",
                "Read the benchmark source with 0-based offset and line limit.",
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
                "Optionally write notes to /scratch/notes.txt.",
                _schema(
                    {"path": {"type": "string"}, "contents": {"type": "string"}},
                    ["path", "contents"],
                ),
                write_file,
            ),
            NativeToolSpec(
                "record_trace_step",
                "Record one source step supporting a finding.",
                _schema(
                    {
                        "file": {"type": "string"},
                        "line": {"type": "integer"},
                        "function": {"type": "string"},
                        "note": {"type": "string"},
                    },
                    ["file", "line"],
                ),
                record_trace_step,
            ),
            NativeToolSpec(
                "record_finding",
                "Record a concrete vulnerability found in the supplied source.",
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
        return (
            NativeHunter(
                llm=self.llm,
                prompt=_SYSTEM_PROMPT,
                tools=tools,
                ctx=context,
                max_steps=self.max_turns,
                agent_mode="deep",
                initial_user_message=(
                    "Audit /workspace/fixture.c. Read it, reason about the copy bound, and record "
                    "only a concrete vulnerability."
                ),
                max_output_tokens=self.max_output_tokens,
            ),
            context,
        )

    @staticmethod
    def _passed(fixture: CyberPiFixture, findings: tuple[dict[str, Any], ...]) -> bool:
        if not fixture.vulnerable:
            return not findings
        expected_cwe = CyberPiBenchmark._normalize_cwe(fixture.expected_cwe or "")
        expected_line = fixture.expected_line
        return any(
            (
                not expected_cwe
                or CyberPiBenchmark._normalize_cwe(str(finding.get("cwe") or ""))
                == expected_cwe
            )
            and (
                expected_line is None
                or abs(int(finding.get("line_number") or -1000) - expected_line) <= 1
            )
            for finding in findings
        )

    @staticmethod
    def _finding_dict(finding: Finding) -> dict[str, Any]:
        return {
            "file": finding.file,
            "line_number": finding.line_number,
            "finding_type": finding.finding_type,
            "severity": finding.severity,
            "cwe": finding.cwe,
            "description": finding.description,
        }

    def _safe_error(self, exc: Exception) -> str:
        message = f"{type(exc).__name__}: {exc}"
        if self.llm.api_key:
            message = message.replace(self.llm.api_key, "[REDACTED]")
        return message[:2000]

    @staticmethod
    def _normalize_cwe(value: str) -> str:
        normalized = value.upper().strip().replace("_", "-")
        number = normalized.removeprefix("CWE-").removeprefix("CWE")
        return f"CWE-{number.lstrip('0') or '0'}" if number.isdigit() else normalized

    @staticmethod
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
    "BUILTIN_FIXTURES",
    "BenchmarkObservation",
    "CyberPiBenchmark",
    "CyberPiBenchmarkReport",
    "CyberPiFixture",
]
