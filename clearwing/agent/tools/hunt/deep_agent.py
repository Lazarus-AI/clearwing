"""Deep agent mode tools: execute, read_file, write_file, think.

Replaces the constrained 9-tool hunter set with 4 primitives that give
the model full-shell access inside the sandbox container.  The model
uses the same tools a human researcher would — gcc, gdb, strace, make,
etc. — all via ``execute()``.

See docs/spec/001_deep_agent_mode.md for the design rationale.
"""

from __future__ import annotations

import logging
import shlex

from clearwing.llm import NativeToolSpec

from .reporting import build_reporting_tools
from .sandbox import HunterContext

logger = logging.getLogger(__name__)

_OUTPUT_CAP = 100_000  # 100 KB cap on stdout/stderr per execute call


def _cap_output(text: str, label: str = "output") -> str:
    if len(text) <= _OUTPUT_CAP:
        return text
    return text[:_OUTPUT_CAP] + f"\n\n[{label} truncated at {_OUTPUT_CAP} bytes]"


def build_deep_agent_tools(ctx: HunterContext) -> list[NativeToolSpec]:
    """Build the 4+1 deep agent tool set.

    Returns tools: execute, read_file, write_file, think, record_finding.
    """

    def execute(command: str, timeout: int = 300) -> dict:
        if ctx.sandbox is None:
            return {"error": "no sandbox available"}
        result = ctx.sandbox.exec(command, timeout=timeout)
        return {
            "exit_code": result.exit_code,
            "stdout": _cap_output(result.stdout, "stdout"),
            "stderr": _cap_output(result.stderr, "stderr"),
            "timed_out": result.timed_out,
            "duration_seconds": round(result.duration_seconds, 2),
        }

    def read_file(path: str, offset: int = 0, limit: int = 2000) -> str:
        if ctx.sandbox is None:
            return "error: no sandbox available"
        start = offset + 1
        end = offset + limit
        cmd = f"sed -n '{start},{end}p' {shlex.quote(path)} | cat -n"
        result = ctx.sandbox.exec(cmd, timeout=30)
        if result.exit_code != 0:
            return f"error reading {path}: {result.stderr.strip()}"
        return result.stdout

    def write_file(path: str, contents: str) -> str:
        if ctx.sandbox is None:
            return "error: no sandbox available"
        ctx.sandbox.exec(
            f"mkdir -p $(dirname {shlex.quote(path)})", timeout=10
        )
        ctx.sandbox.write_file(path, contents.encode("utf-8"))
        return f"Wrote {len(contents)} bytes to {path}"

    def think(notes: str) -> str:
        return "Noted."

    reporting_tools = build_reporting_tools(ctx)

    return [
        NativeToolSpec(
            name="execute",
            description=(
                "Run a shell command inside the sandbox container. "
                "Use for compilation, debugging, running tests, etc."
            ),
            schema={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Shell command to execute.",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds (default 300).",
                        "default": 300,
                    },
                },
                "required": ["command"],
            },
            handler=execute,
        ),
        NativeToolSpec(
            name="read_file",
            description="Read lines from a file in the container.",
            schema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute path in the container.",
                    },
                    "offset": {
                        "type": "integer",
                        "description": "Line offset (0-based, default 0).",
                        "default": 0,
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max lines to return (default 2000).",
                        "default": 2000,
                    },
                },
                "required": ["path"],
            },
            handler=read_file,
        ),
        NativeToolSpec(
            name="write_file",
            description="Write contents to a file in the container. Creates parent directories.",
            schema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute path in the container.",
                    },
                    "contents": {
                        "type": "string",
                        "description": "File contents to write.",
                    },
                },
                "required": ["path", "contents"],
            },
            handler=write_file,
        ),
        NativeToolSpec(
            name="think",
            description=(
                "Record your reasoning. Use this to think through hypotheses, "
                "plan next steps, or note observations. Appears in the audit trail."
            ),
            schema={
                "type": "object",
                "properties": {
                    "notes": {
                        "type": "string",
                        "description": "Your reasoning or observations.",
                    },
                },
                "required": ["notes"],
            },
            handler=think,
        ),
        *reporting_tools,
    ]
