"""Small, bounded workspace tool palette for independent verification."""

from __future__ import annotations

import hashlib
import shlex
from pathlib import PurePosixPath

from pydantic import Field

from clearwing.llm import NativeToolSpec, ToolInputModel
from clearwing.reporting.safety import redact_text

from .sandbox import HunterContext

_MAX_OUTPUT_CHARS = 100_000
_MAX_WRITE_CHARS = 256 * 1024
_ALLOWED_ROOTS = (PurePosixPath("/workspace"), PurePosixPath("/scratch"))


class VerificationExecuteInput(ToolInputModel):
    command: str = Field(
        min_length=1,
        max_length=8192,
        description="Shell command to execute inside the isolated verification sandbox.",
    )
    timeout: int = Field(
        default=300,
        ge=1,
        le=600,
        description="Command timeout in seconds (1-600).",
    )


class VerificationReadInput(ToolInputModel):
    path: str = Field(min_length=1, max_length=4096)
    start_line: int = Field(default=1, ge=1)
    end_line: int | None = Field(default=None, ge=1)


class VerificationWriteInput(ToolInputModel):
    path: str = Field(min_length=1, max_length=4096)
    contents: str = Field(max_length=_MAX_WRITE_CHARS)


def _bounded_output(value: str, label: str) -> str:
    safe = redact_text(value)
    if len(safe) <= _MAX_OUTPUT_CHARS:
        return safe
    return safe[:_MAX_OUTPUT_CHARS] + (
        f"\n\n[{label} truncated at {_MAX_OUTPUT_CHARS} characters]"
    )


def _sandbox_path(raw_path: str) -> str:
    candidate = PurePosixPath(raw_path)
    if not candidate.is_absolute():
        candidate = PurePosixPath("/workspace") / candidate
    if ".." in candidate.parts or "\x00" in raw_path:
        raise ValueError("verification paths must stay under /workspace or /scratch")
    if not any(candidate == root or root in candidate.parents for root in _ALLOWED_ROOTS):
        raise ValueError("verification paths must stay under /workspace or /scratch")
    return candidate.as_posix()


def _workspace_integrity(ctx: HunterContext) -> dict:
    baseline = getattr(ctx.sandbox, "workspace_baseline_commit", None)
    if not isinstance(baseline, str) or len(baseline) != 40:
        return {"available": False, "valid": False}
    command = (
        "cd /workspace && "
        f"git rev-parse HEAD && git diff --name-only {shlex.quote(baseline)} -- && "
        "git status --porcelain --untracked-files=all"
    )
    result = ctx.sandbox.exec(command, timeout=30)
    lines = result.stdout.splitlines()
    head = lines[0].strip() if lines else ""
    changed = [line.strip() for line in lines[1:] if line.strip()]
    return {
        "available": True,
        "valid": result.exit_code == 0 and head == baseline,
        "baseline_commit": baseline,
        "head_commit": head,
        "workspace_changes": changed[:1000],
        "error": _bounded_output(result.stderr, "workspace integrity")
        if result.stderr
        else "",
    }


def build_verification_workspace_tools(ctx: HunterContext) -> list[NativeToolSpec]:
    """Return only execute/read/write, with verifier-specific bounds and audit data."""

    def execute(command: str, timeout: int = 300) -> dict:
        if ctx.sandbox is None:
            return {"error": "no verification sandbox available"}
        result = ctx.sandbox.exec(command, timeout=timeout)
        return {
            "exit_code": result.exit_code,
            "stdout": _bounded_output(result.stdout, "stdout"),
            "stderr": _bounded_output(result.stderr, "stderr"),
            "timed_out": result.timed_out,
            "duration_seconds": round(result.duration_seconds, 2),
            "workspace_integrity": _workspace_integrity(ctx),
        }

    def read_file(path: str, start_line: int = 1, end_line: int | None = None) -> dict:
        if ctx.sandbox is None:
            return {"error": "no verification sandbox available"}
        normalized = _sandbox_path(path)
        if end_line is None:
            end_line = start_line + 1999
        if end_line < start_line or end_line - start_line + 1 > 4000:
            return {"error": "read range must contain between 1 and 4000 lines"}
        quoted = shlex.quote(normalized)
        result = ctx.sandbox.exec(
            f"sed -n '{start_line},{end_line}p' {quoted}",
            timeout=30,
        )
        if result.exit_code != 0:
            return {"error": _bounded_output(result.stderr, "read error")}
        return {
            "path": normalized,
            "start_line": start_line,
            "end_line": end_line,
            "contents": _bounded_output(result.stdout, "file"),
        }

    def write_file(path: str, contents: str) -> dict:
        if ctx.sandbox is None:
            return {"error": "no verification sandbox available"}
        normalized = _sandbox_path(path)
        parent = PurePosixPath(normalized).parent.as_posix()
        created = ctx.sandbox.exec(f"mkdir -p {shlex.quote(parent)}", timeout=30)
        if created.exit_code != 0:
            return {"error": _bounded_output(created.stderr, "write error")}
        encoded = contents.encode("utf-8")
        ctx.sandbox.write_file(normalized, encoded)
        return {
            "path": normalized,
            "size_bytes": len(encoded),
            "sha256": hashlib.sha256(encoded).hexdigest(),
            "workspace_integrity": _workspace_integrity(ctx),
        }

    return [
        NativeToolSpec(
            name="execute",
            description=(
                "Run one bounded shell command in the fresh no-network verification "
                "sandbox. Use this for builds, tests, debuggers, sanitizers, and PoCs."
            ),
            schema=VerificationExecuteInput.model_json_schema(),
            handler=execute,
        ),
        NativeToolSpec(
            name="read_file",
            description=(
                "Read a bounded line range under /workspace or /scratch. Paths may "
                "be absolute or repository-relative."
            ),
            schema=VerificationReadInput.model_json_schema(),
            handler=read_file,
        ),
        NativeToolSpec(
            name="write_file",
            description=(
                "Write a bounded harness or test artifact under /workspace or /scratch."
            ),
            schema=VerificationWriteInput.model_json_schema(),
            handler=write_file,
        ),
    ]
