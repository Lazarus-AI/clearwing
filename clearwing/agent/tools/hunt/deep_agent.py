"""Deep agent mode tools: execute, read_file, write_file.

Replaces the constrained 9-tool hunter set with 3 primitives that give
the model full-shell access inside the sandbox container. The model
uses the same tools a human researcher would — gcc, gdb, strace, make,
etc. — all via ``execute()``.

Model-side reasoning is captured natively via rust-genai's
`capture_reasoning_content=True` on every chat request; the hunter
transcript logs `ChatResponse.reasoning_content` alongside the
visible text, so there's no need for an explicit `think()`
scratchpad tool (and one doesn't exist here — it was removed after
verifying native reasoning is strictly richer than a model-callable
no-op).

See docs/spec/001_deep_agent_mode.md for the design rationale.
"""

from __future__ import annotations

import logging
import shlex

from clearwing.llm import NativeToolSpec

from .pool_query import build_pool_query_tools
from .reporting import build_reporting_tools
from .sandbox import HunterContext

logger = logging.getLogger(__name__)

_OUTPUT_CAP = 100_000  # 100 KB cap on stdout/stderr per execute call


def _cap_output(text: str, label: str = "output") -> str:
    if len(text) <= _OUTPUT_CAP:
        return text
    return text[:_OUTPUT_CAP] + f"\n\n[{label} truncated at {_OUTPUT_CAP} bytes]"


def build_deep_agent_tools(ctx: HunterContext) -> list[NativeToolSpec]:
    """Build the deep agent tool set: execute, read_file, write_file,
    plus the shared reporting + findings-pool tools.
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
        # Previously this was `sed ... | cat -n`, which numbers output
        # starting from 1 regardless of offset — a hunter asking for
        # lines 101-150 got back "line 1..line 50" and then reasoned
        # about the wrong line numbers when reporting findings. Use awk
        # with NR directly so the emitted line numbers match the file.
        cmd = (
            f"awk -v s={start} -v e={end} "
            f"'NR>=s && NR<=e {{ printf \"%6d\\t%s\\n\", NR, $0 }}' "
            f"{shlex.quote(path)}"
        )
        result = ctx.sandbox.exec(cmd, timeout=30)
        if result.exit_code != 0:
            return f"error reading {path}: {result.stderr.strip()}"
        return result.stdout

    def write_file(path: str, contents: str) -> str:
        if ctx.sandbox is None:
            return "error: no sandbox available"
        ctx.sandbox.exec(f"mkdir -p $(dirname {shlex.quote(path)})", timeout=10)
        ctx.sandbox.write_file(path, contents.encode("utf-8"))
        return f"Wrote {len(contents)} bytes to {path}"

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
        *reporting_tools,
        *(build_pool_query_tools(ctx) if ctx.findings_pool is not None else []),
    ]
