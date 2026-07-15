"""Typed, manifest-driven dynamic-validation backends for proof actions."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, cast

from pydantic import Field, model_validator

from clearwing.agent.tools.hunt.analysis import _default_libfuzzer_template

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
    "fault_injection",
    "configuration_matrix",
    "patch_differential",
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
    "fault_injection_violation",
    "configuration_differential",
    "patch_differential",
}


class HarnessTemplateSpec(StrictModel):
    """Deterministic libFuzzer harness materialization instructions."""

    target_function: str = Field(pattern=r"^[A-Za-z_]\w*$")
    signature: str = ""
    source_files: list[str] = Field(default_factory=list)
    include_dirs: list[str] = Field(default_factory=list)
    extra_compile_args: list[str] = Field(default_factory=list)
    duration_seconds: int = Field(default=30, ge=1, le=3600)

    @model_validator(mode="after")
    def _validate_paths_and_flags(self) -> HarnessTemplateSpec:
        for value in [*self.source_files, *self.include_dirs]:
            path = Path(value)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("Harness template paths must remain inside the repository")
        forbidden = ("@", "-fplugin", "-Xclang", "-load", "-wrapper")
        if any(argument.startswith(forbidden) for argument in self.extra_compile_args):
            raise ValueError("Harness template contains a forbidden compiler option")
        return self


class ValidationCommandSpec(StrictModel):
    """One bounded experiment tied to one proof predicate."""

    name: str = Field(min_length=1)
    action_template: DynamicAction
    obligation_predicate: str = Field(min_length=1)
    candidate_mechanism: str | None = None
    command: list[str] = Field(default_factory=list)
    harness_template: HarnessTemplateSpec | None = None
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
        if not self.command and self.harness_template is None:
            raise ValueError("Validation requires a command or harness_template")
        if self.command and self.harness_template is not None:
            raise ValueError("Validation command and harness_template are mutually exclusive")
        if self.harness_template is not None and self.action_template not in {
            "harness",
            "fuzz",
            "sanitizer_run",
        }:
            raise ValueError("Harness templates require a harness, fuzz, or sanitizer action")
        if self.harness_template is not None and self.success_condition != "sanitizer":
            raise ValueError("Harness templates require sanitizer success evidence")
        if self.output_regex:
            try:
                re.compile(self.output_regex)
            except re.error as exc:
                raise ValueError(f"Invalid validation output_regex: {exc}") from exc
        if self.minimum_reproductions is not None and self.minimum_reproductions > self.repeats:
            raise ValueError("minimum_reproductions cannot exceed repeats")
        if self.action_template in {"sanitizer_run", "race_detector"}:
            if self.success_condition != "sanitizer":
                raise ValueError("sanitizer and race-detector actions require sanitizer output")
        elif (
            self.success_condition != "sanitizer"
            and self.evidence_kind not in _DECISIVE_EVIDENCE_KINDS
        ):
            raise ValueError(
                "Non-sanitizer validation requires a recognized decisive evidence_kind"
            )
        if self.evidence_kind is not None and self.evidence_kind not in _DECISIVE_EVIDENCE_KINDS:
            raise ValueError("Validation evidence_kind is not recognized as decisive")
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
            and spec.candidate_mechanism
            in {
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


@dataclass(frozen=True)
class HarnessPreparationResult:
    command: tuple[str, ...]
    evidence: Evidence
    succeeded: bool
    error: str | None = None


class TemplateHarnessBackend:
    """Materialize, compile, and provenance-track a bounded harness template."""

    def __init__(self, runner: CommandRunner, store: ProofStore):
        if not runner.sandboxed:
            raise ProofPreflightError(
                "Template harnesses require a sandboxed command runner",
                missing=("sandboxed_validation_runner",),
            )
        if not callable(getattr(runner, "write_file", None)):
            raise ProofPreflightError(
                "The validation sandbox cannot materialize harness files",
                missing=("sandbox_scratch_write",),
            )
        self.runner = runner
        self.store = store

    def prepare(
        self,
        *,
        snapshot_id: str,
        candidate_id: str,
        spec: HarnessTemplateSpec,
        repo_root: Path,
        timeout_seconds: int,
    ) -> HarnessPreparationResult:
        source = _default_libfuzzer_template(spec.target_function, spec.signature)
        digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
        harness_path = f"/scratch/clearwing-harness-{digest[:12]}.c"
        binary_path = f"/scratch/clearwing-harness-{digest[:12]}"
        self.runner.write_file(harness_path, source.encode("utf-8"))
        source_uri, source_digest = self.store.store_artifact(
            source,
            media_type="text/x-c",
            name="generated-harness.c",
            metadata={
                "candidate_id": candidate_id,
                "target_function": spec.target_function,
                "signature": spec.signature,
            },
        )
        command = [
            "clang",
            "-fsanitize=fuzzer,address,undefined",
            "-fno-omit-frame-pointer",
            "-g",
            "-O1",
            harness_path,
        ]
        for directory in spec.include_dirs:
            command.extend(["-I", self.runner.map_path((repo_root / directory).resolve())])
        command.extend(
            self.runner.map_path((repo_root / path).resolve()) for path in spec.source_files
        )
        command.extend(spec.extra_compile_args)
        command.extend(["-o", binary_path])
        result = self.runner.run(
            command,
            cwd=repo_root,
            timeout=timeout_seconds,
        )
        compile_output = f"{result.stdout}\n{result.stderr}"
        output_uri, output_digest = self.store.store_artifact(
            compile_output,
            media_type="text/plain",
            name="harness-build.txt",
            metadata={"candidate_id": candidate_id, "command": command},
        )
        succeeded = result.exit_code == 0 and not result.timed_out
        evidence = Evidence(
            snapshot_id=snapshot_id,
            kind="harness_build" if succeeded else "harness_build_failure",
            artifact_uri=output_uri,
            artifact_digest=output_digest,
            observations=[
                {
                    "exit_code": result.exit_code,
                    "timed_out": result.timed_out,
                    "harness_source_uri": source_uri,
                    "harness_source_digest": source_digest,
                    "target_function": spec.target_function,
                }
            ],
            provenance=Provenance(
                producer="template-harness-backend",
                producer_version="1",
                command=command,
                environment_digest=self.runner.identity,
            ),
            reliability={
                "template": "default-libfuzzer",
                "generated": True,
                "compile_succeeded": succeeded,
                "scope": "harness construction only; no vulnerability claim",
            },
        )
        self.store.append(evidence)
        run_command = (
            binary_path,
            f"-max_total_time={spec.duration_seconds}",
            f"-timeout={max(10, spec.duration_seconds // 2)}",
            "-error_exitcode=77",
            "-print_final_stats=1",
        )
        return HarnessPreparationResult(
            command=run_command,
            evidence=evidence,
            succeeded=succeeded,
            error=(None if succeeded else "generated harness did not compile"),
        )


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
                environment_digest=(request.environment_digest or self.runner.identity),
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
                request.evidence_kind or "runtime_execution" if succeeded else "runtime_execution"
            ),
            artifact_uri=uri,
            artifact_digest=digest,
            observations=observations,
            provenance=Provenance(
                producer="command-validation-backend",
                producer_version="1",
                command=list(request.command),
                environment_digest=(request.environment_digest or self.runner.identity),
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
