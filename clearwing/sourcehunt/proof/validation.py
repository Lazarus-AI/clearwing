"""Typed, manifest-driven dynamic-validation backends for proof actions."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, cast

from pydantic import Field, model_validator

from .extractors import CommandRunner, ProofPreflightError
from .models import Candidate, Evidence, Obligation, Provenance, StrictModel
from .store import ProofStore

DynamicAction = Literal[
    "harness",
    "fuzz",
    "sanitizer_run",
    "integration_test",
    "differential_test",
    "symbolic_execution",
    "model_check",
    "protocol_replay",
    "race_detector",
    "schedule_perturbation",
    "load_test",
]

SuccessCondition = Literal[
    "sanitizer",
    "exit_zero",
    "exit_nonzero",
    "output_regex",
]

_DECISIVE_EVIDENCE_KINDS = {
    "authorization_differential",
    "bounded_resource_exhaustion",
    "cryptographic_differential",
    "debugger_memory_violation",
    "injection_differential",
    "protocol_transition_violation",
    "race_detector_violation",
    "sanitizer_crash",
    "sanitizer_uaf",
    "symbolic_memory_violation",
}


class ValidationCommandSpec(StrictModel):
    """One bounded experiment tied to one proof predicate."""

    name: str = Field(min_length=1)
    action_template: DynamicAction
    obligation_predicate: str = Field(min_length=1)
    candidate_mechanism: str | None = None
    command: list[str] = Field(min_length=1)
    cwd: str = "."
    repeats: int = Field(default=1, ge=1, le=20)
    timeout_seconds: int = Field(default=300, ge=1, le=3600)
    success_condition: SuccessCondition
    output_regex: str | None = None
    evidence_kind: str | None = None
    minimum_reproductions: int | None = Field(default=None, ge=1, le=20)
    metadata: dict[str, object] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_contract(self) -> ValidationCommandSpec:
        path = Path(self.cwd)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("Validation cwd must remain inside the repository")
        if self.success_condition == "output_regex" and not self.output_regex:
            raise ValueError("output_regex success requires an output_regex")
        if self.output_regex:
            try:
                re.compile(self.output_regex)
            except re.error as exc:
                raise ValueError(f"Invalid validation output_regex: {exc}") from exc
        if (
            self.minimum_reproductions is not None
            and self.minimum_reproductions > self.repeats
        ):
            raise ValueError("minimum_reproductions cannot exceed repeats")
        if self.action_template in {"sanitizer_run", "race_detector"}:
            if self.success_condition != "sanitizer":
                raise ValueError(
                    "sanitizer and race-detector actions require sanitizer output"
                )
        elif self.evidence_kind not in _DECISIVE_EVIDENCE_KINDS:
            raise ValueError(
                "Non-sanitizer validation requires a recognized decisive evidence_kind"
            )
        return self

    @property
    def required_reproductions(self) -> int:
        return self.minimum_reproductions or self.repeats


class ValidationManifest(StrictModel):
    schema_version: Literal[1] = 1
    commands: list[ValidationCommandSpec] = Field(default_factory=list)

    @classmethod
    def load(cls, path: str | Path) -> ValidationManifest:
        source = Path(path).expanduser().resolve()
        if not source.is_file():
            raise ProofPreflightError(
                f"Validation manifest does not exist: {source}",
                missing=("validation_manifest",),
            )
        try:
            return cast(
                ValidationManifest,
                cls.model_validate_json(source.read_text(encoding="utf-8")),
            )
        except Exception as exc:
            raise ProofPreflightError(
                f"Invalid validation manifest {source}: {exc}",
                missing=("valid_validation_manifest",),
            ) from exc

    def match(
        self,
        candidate: Candidate,
        obligation: Obligation,
        action_template: str,
    ) -> ValidationCommandSpec | None:
        matches = [
            spec
            for spec in self.commands
            if spec.action_template == action_template
            and spec.obligation_predicate == obligation.predicate
            and spec.candidate_mechanism in {
                None,
                candidate.suspected_mechanism,
            }
        ]
        if not matches:
            return None
        return sorted(
            matches,
            key=lambda spec: (
                spec.candidate_mechanism is None,
                spec.name,
            ),
        )[0]


@dataclass(frozen=True)
class ValidationRequest:
    snapshot_id: str
    candidate_id: str
    command: tuple[str, ...]
    cwd: Path
    repeats: int = 1
    timeout_seconds: int = 300
    environment_digest: str = ""
    metadata: dict[str, object] = field(default_factory=dict)
    success_condition: SuccessCondition = "sanitizer"
    output_regex: str | None = None
    evidence_kind: str | None = None
    required_reproductions: int = 1


@dataclass(frozen=True)
class ValidationResult:
    evidence: Evidence
    runs: int
    reproductions: int


class SanitizerValidationBackend:
    """Run an existing harness/integration command in an isolated backend."""

    def __init__(self, runner: CommandRunner, store: ProofStore):
        if not runner.sandboxed:
            raise ProofPreflightError(
                "Dynamic proof validation requires a sandboxed command runner",
                missing=("sandboxed_validation_runner",),
            )
        self.runner = runner
        self.store = store

    def validate(self, request: ValidationRequest) -> ValidationResult:
        if not request.command:
            raise ValueError("Validation command cannot be empty")
        observations: list[dict[str, object]] = []
        reproductions = 0
        combined = ""
        signatures: set[str] = set()
        for attempt in range(1, max(1, request.repeats) + 1):
            result = self.runner.run(
                request.command,
                cwd=request.cwd,
                timeout=request.timeout_seconds,
            )
            output = f"{result.stdout}\n{result.stderr}"
            combined += f"\n--- attempt {attempt} ---\n{output}"
            signature = _sanitizer_signature(output)
            if signature:
                reproductions += 1
                signatures.add(signature)
            observations.append(
                {
                    "attempt": attempt,
                    "exit_code": result.exit_code,
                    "timed_out": result.timed_out,
                    "sanitizer_signature": signature,
                }
            )
        uri, digest = self.store.store_artifact(
            combined,
            media_type="text/plain",
            name="dynamic-validation.txt",
            metadata={
                "candidate_id": request.candidate_id,
                "command": list(request.command),
            },
        )
        evidence_kind = _evidence_kind(signatures)
        evidence = Evidence(
            snapshot_id=request.snapshot_id,
            kind=evidence_kind,
            artifact_uri=uri,
            artifact_digest=digest,
            observations=observations,
            provenance=Provenance(
                producer="sanitizer-validation-backend",
                producer_version="1",
                command=list(request.command),
                environment_digest=(
                    request.environment_digest or self.runner.identity
                ),
            ),
            reliability={
                "runs": max(1, request.repeats),
                "reproductions": reproductions,
                "stable": reproductions == max(1, request.repeats),
                "scope": "runtime behavior only; does not establish attacker reachability",
                **request.metadata,
            },
        )
        self.store.append(evidence)
        return ValidationResult(
            evidence=evidence,
            runs=max(1, request.repeats),
            reproductions=reproductions,
        )


class CommandValidationBackend:
    """Execute a typed differential, integration, or bounded-load check."""

    def __init__(self, runner: CommandRunner, store: ProofStore):
        if not runner.sandboxed:
            raise ProofPreflightError(
                "Dynamic proof validation requires a sandboxed command runner",
                missing=("sandboxed_validation_runner",),
            )
        self.runner = runner
        self.store = store

    def validate(self, request: ValidationRequest) -> ValidationResult:
        if not request.command:
            raise ValueError("Validation command cannot be empty")
        if request.success_condition == "output_regex" and not request.output_regex:
            raise ValueError("output_regex success requires a pattern")
        observations: list[dict[str, object]] = []
        reproductions = 0
        combined = ""
        for attempt in range(1, max(1, request.repeats) + 1):
            result = self.runner.run(
                request.command,
                cwd=request.cwd,
                timeout=request.timeout_seconds,
            )
            output = f"{result.stdout}\n{result.stderr}"
            combined += f"\n--- attempt {attempt} ---\n{output}"
            matched = _condition_matched(
                request.success_condition,
                result.exit_code,
                output,
                request.output_regex,
            )
            reproductions += int(matched)
            observations.append(
                {
                    "attempt": attempt,
                    "exit_code": result.exit_code,
                    "timed_out": result.timed_out,
                    "success_condition_matched": matched,
                }
            )
        succeeded = reproductions >= request.required_reproductions
        uri, digest = self.store.store_artifact(
            combined,
            media_type="text/plain",
            name="dynamic-validation.txt",
            metadata={
                "candidate_id": request.candidate_id,
                "command": list(request.command),
            },
        )
        evidence = Evidence(
            snapshot_id=request.snapshot_id,
            kind=(
                request.evidence_kind or "runtime_execution"
                if succeeded
                else "runtime_execution"
            ),
            artifact_uri=uri,
            artifact_digest=digest,
            observations=observations,
            provenance=Provenance(
                producer="command-validation-backend",
                producer_version="1",
                command=list(request.command),
                environment_digest=(
                    request.environment_digest or self.runner.identity
                ),
            ),
            reliability={
                "runs": max(1, request.repeats),
                "reproductions": reproductions,
                "required_reproductions": request.required_reproductions,
                "stable": reproductions == max(1, request.repeats),
                "scope": (
                    "bounded runtime behavior only; reachability and threat-model "
                    "claims require separate evidence"
                ),
                **request.metadata,
            },
        )
        self.store.append(evidence)
        return ValidationResult(
            evidence=evidence,
            runs=max(1, request.repeats),
            reproductions=reproductions,
        )


def _sanitizer_signature(output: str) -> str:
    patterns = (
        ("heap-buffer-overflow", r"AddressSanitizer: heap-buffer-overflow"),
        ("stack-buffer-overflow", r"AddressSanitizer: stack-buffer-overflow"),
        ("global-buffer-overflow", r"AddressSanitizer: global-buffer-overflow"),
        ("use-after-free", r"AddressSanitizer: heap-use-after-free"),
        ("double-free", r"AddressSanitizer: attempting double-free"),
        ("undefined-behavior", r"(?:UndefinedBehaviorSanitizer|runtime error:)"),
        ("memory-sanitizer", r"MemorySanitizer:"),
        ("thread-sanitizer", r"ThreadSanitizer:"),
    )
    for name, pattern in patterns:
        if re.search(pattern, output, re.IGNORECASE):
            return name
    return ""


def _evidence_kind(signatures: set[str]) -> str:
    if "use-after-free" in signatures or "double-free" in signatures:
        return "sanitizer_uaf"
    if "thread-sanitizer" in signatures:
        return "race_detector_violation"
    if signatures:
        return "sanitizer_crash"
    return "runtime_execution"


def _condition_matched(
    condition: SuccessCondition,
    exit_code: int,
    output: str,
    output_regex: str | None,
) -> bool:
    if condition == "sanitizer":
        return bool(_sanitizer_signature(output))
    if condition == "exit_zero":
        return exit_code == 0
    if condition == "exit_nonzero":
        return exit_code != 0
    if condition == "output_regex" and output_regex:
        return re.search(output_regex, output, re.MULTILINE) is not None
    return False
