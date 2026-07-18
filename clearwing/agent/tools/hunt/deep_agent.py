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

import difflib
import logging
import re
import shlex

from pydantic import Field

from clearwing.llm import NativeToolSpec, ToolInputModel

from .discovery import build_semgrep_tool
from .pool_query import build_pool_query_tools
from .potentials import build_potential_tools
from .reporting import build_reporting_tools
from .sandbox import HunterContext

logger = logging.getLogger(__name__)

_OUTPUT_CAP = 100_000  # 100 KB cap on stdout/stderr per execute call


class ExecuteInput(ToolInputModel):
    command: str = Field(description="Shell command to execute.")
    timeout: int = Field(default=300, description="Timeout in seconds (default 300).")


class ReadFileInput(ToolInputModel):
    path: str = Field(description="Absolute path in the container.")
    offset: int = Field(default=0, description="Line offset (0-based, default 0). Or use start_line (1-based).")
    limit: int = Field(default=2000, description="Max lines to return (default 2000). Or use end_line with start_line.")
    start_line: int | None = Field(default=None, description="Alias — 1-based line number to start at. Overrides offset if set.")
    end_line: int | None = Field(default=None, description="Alias — 1-based inclusive end line. Requires start_line.")


class WriteFileInput(ToolInputModel):
    path: str = Field(description="Absolute path in the container.")
    contents: str = Field(description="File contents to write.")


class LookupCallersInput(ToolInputModel):
    func_name: str = Field(description="Function name to find callers of.")


class LookupCalleesInput(ToolInputModel):
    func_name: str = Field(description="Function name to find callees of.")


class ListFunctionsInput(ToolInputModel):
    path: str = Field(description="Relative file path (e.g. src/foo.c).")
    filter: str | None = Field(
        default=None,
        description=(
            "Optional filter. Split into tokens on non-alphanumeric AND camelCase "
            "boundaries; each token must appear (case-insensitive) as a substring "
            "of the function name. filter='DigestFinal' matches DigestVerifyFinal, "
            "DigestFinal_ex, wolfSSL_EVP_DigestFinal, etc."
        ),
    )


class ReadFunctionInput(ToolInputModel):
    name: str = Field(
        description="Exact function name to read (e.g. 'wolfSSL_EVP_DigestVerifyFinal')."
    )


def _cap_output(text: str, label: str = "output") -> str:
    if len(text) <= _OUTPUT_CAP:
        return text
    return text[:_OUTPUT_CAP] + f"\n\n[{label} truncated at {_OUTPUT_CAP} bytes]"


# Split on non-alphanumeric AND camelCase boundaries so filter="DigestFinal"
# yields ["digest","final"] and matches DigestVerifyFinal.
_TOKEN_SPLIT = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def _tokenize(s: str) -> list[str]:
    return [t.lower() for t in _TOKEN_SPLIT.split(s) if t]


def _matches(name: str, tokens: list[str]) -> bool:
    low = name.lower()
    return all(t in low for t in tokens)


# Self-check — asserts run at import; catches regressions in the token match.
assert _tokenize("DigestFinal") == ["digest", "final"]
assert _tokenize("digest_final") == ["digest", "final"]
assert _matches("wolfSSL_EVP_DigestVerifyFinal", _tokenize("DigestFinal"))
assert _matches("wolfSSL_EVP_DigestFinal_ex", _tokenize("DigestFinal"))
assert _matches("wolfSSL_EVP_VerifyFinal", _tokenize("verify"))
assert not _matches("wolfSSL_EVP_CipherFinal", _tokenize("DigestFinal"))


def build_deep_agent_tools(ctx: HunterContext) -> list[NativeToolSpec]:
    """Build the deep agent tool set: execute, read_file, write_file,
    plus the shared reporting + findings-pool tools.
    """
    # Deep hunters read source via read_file/execute (cat/sed/grep), not the
    # constrained read_source_file that populates ctx.files_read. Mark the
    # context so the reporting guard doesn't reject every trace step for a
    # file it never saw a read_source_file call for.
    ctx.agent_mode = "deep"

    def execute(command: str, timeout: int = 300, **_: object) -> dict:
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

    def read_file(
        path: str,
        offset: int = 0,
        limit: int = 2000,
        start_line: int | None = None,
        end_line: int | None = None,
        **_: object,
    ) -> str:
        if ctx.sandbox is None:
            return "error: no sandbox available"
        # Accept both idioms. Model naturally reaches for start_line/end_line
        # (the prompt used to advertise them); swallowing them via **_ made the
        # tool silently return lines 1-2000 and looked like a tool bug.
        if start_line is not None:
            offset = start_line - 1
            if end_line is not None:
                limit = max(1, end_line - start_line + 1)
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

    def write_file(path: str, contents: str, **_: object) -> str:
        if ctx.sandbox is None:
            return "error: no sandbox available"
        ctx.sandbox.exec(f"mkdir -p $(dirname {shlex.quote(path)})", timeout=10)
        ctx.sandbox.write_file(path, contents.encode("utf-8"))
        return f"Wrote {len(contents)} bytes to {path}"

    def lookup_callers(func_name: str, **_: object) -> dict:
        """Return every function that calls func_name, grouped by file."""
        cg = ctx.callgraph
        if cg is None:
            return {"error": "callgraph not available"}
        result = cg.callers_of(func_name)
        if not result:
            return {"callers": {}, "note": f"no callers of '{func_name}' found in callgraph"}
        line_index = {
            f: {fi.name: (fi.start_line, fi.end_line) for fi in cg.function_info.get(f, [])}
            for f in result
        }
        return {
            "callers": {
                f: [
                    {"func": fn, "start_line": line_index[f].get(fn, (None, None))[0],
                     "end_line": line_index[f].get(fn, (None, None))[1]}
                    for fn in sorted(callers)
                ]
                for f, callers in sorted(result.items())
            }
        }

    def lookup_callees(func_name: str, **_: object) -> dict:
        """Return every function called by func_name, grouped by defining file."""
        cg = ctx.callgraph
        if cg is None:
            return {"error": "callgraph not available"}
        result = cg.callees_of(func_name)
        if not result:
            return {"callees": {}, "note": f"'{func_name}' not found in callgraph or calls nothing"}
        return {"callees": {f: sorted(callees) for f, callees in sorted(result.items())}}

    def list_functions(path: str, filter: str | None = None, **_: object) -> dict:
        """List all functions defined in a file with their line ranges."""
        cg = ctx.callgraph
        if cg is None:
            return {"error": "callgraph not available"}
        infos = cg.function_info.get(path) or cg.function_info.get(path.lstrip("/workspace/"))
        if not infos:
            return {"functions": [], "note": f"no functions found for '{path}' in callgraph"}
        results = sorted(infos, key=lambda fi: fi.start_line)
        if filter:
            tokens = _tokenize(filter)
            if tokens:
                results = [fi for fi in results if _matches(fi.name, tokens)]
        return {
            "functions": [
                {"name": fi.name, "start_line": fi.start_line, "end_line": fi.end_line}
                for fi in results
            ],
            "total": len(results),
        }

    def read_function(name: str, **_: object) -> dict:
        """Read a function body by exact name. One atomic op — replaces the
        list_functions(filter=...) → pick line range → read_file dance.
        On miss, returns did_you_mean suggestions.
        """
        cg = ctx.callgraph
        if cg is None:
            return {"error": "callgraph not available"}
        hits = [
            (f, fi)
            for f, infos in cg.function_info.items()
            for fi in infos
            if fi.name == name
        ]
        if not hits:
            all_names = {fi.name for infos in cg.function_info.values() for fi in infos}
            near = difflib.get_close_matches(name, all_names, n=5, cutoff=0.6)
            return {"error": f"no function named '{name}'", "did_you_mean": near}
        # De-dup identical (file, start, end) — callgraph sometimes double-lists.
        uniq = list({(f, fi.start_line, fi.end_line): (f, fi) for f, fi in hits}.values())
        if len(uniq) > 1:
            return {
                "error": "ambiguous name; multiple definitions",
                "candidates": [
                    {"file": f, "start_line": fi.start_line, "end_line": fi.end_line}
                    for f, fi in uniq
                ],
            }
        f, fi = uniq[0]
        body = read_file(f"/workspace/{f}", offset=fi.start_line - 1, limit=fi.end_line - fi.start_line + 1)
        return {"file": f, "start_line": fi.start_line, "end_line": fi.end_line, "body": body}

    reporting_tools = build_reporting_tools(ctx)

    semgrep_tool = build_semgrep_tool(ctx)

    callgraph_tools = (
        [
            NativeToolSpec(
                name="lookup_callers",
                description=(
                    "REACH FOR THIS FIRST when you identify a dangerous function "
                    "(memcpy, image copy, free, decrypt, verify, write). "
                    "Returns every function in the codebase that calls func_name, "
                    "with file path and line range so you can read each caller directly. "
                    "This is faster and more complete than grep. "
                    "Use it immediately after spotting a sink — do not read the sink's "
                    "definition, read its callers to find which one skips a guard."
                ),
                schema=LookupCallersInput.model_json_schema(),
                handler=lookup_callers,
            ),
            NativeToolSpec(
                name="lookup_callees",
                description=(
                    "Returns every function called by func_name, with file and line range. "
                    "Use when you need to understand what a function does without reading "
                    "it line by line, or to compare what setup calls two sibling functions "
                    "make before reaching the same sink (e.g. streaming vs one-shot path)."
                ),
                schema=LookupCalleesInput.model_json_schema(),
                handler=lookup_callees,
            ),
            NativeToolSpec(
                name="list_functions",
                description=(
                    "CALL THIS FIRST on your target file before reading any code. "
                    "Returns functions defined in the file with start/end line numbers. "
                    "Use filter= to search by keyword. Filter tokens are split on "
                    "non-alphanumerics AND camelCase — filter='DigestFinal' matches "
                    "'DigestVerifyFinal', 'wolfSSL_EVP_DigestFinal_ex', etc. "
                    "High-value targets: verify, final, check, validate, decode, parse, free, copy. "
                    "If you already know the exact name, prefer read_function(name)."
                ),
                schema=ListFunctionsInput.model_json_schema(),
                handler=list_functions,
            ),
            NativeToolSpec(
                name="read_function",
                description=(
                    "Read a function body by exact name — one atomic op. Use whenever "
                    "you've said 'let me look at wolfSSL_EVP_DigestVerifyFinal' or any "
                    "specific function you can name. Skips the list_functions→pick-line-"
                    "range→read_file chain (where wrong picks silently open the wrong "
                    "function). Returns {file, start_line, end_line, body}. On miss: "
                    "did_you_mean suggestions. On ambiguity: candidate list."
                ),
                schema=ReadFunctionInput.model_json_schema(),
                handler=read_function,
            ),
        ]
        if ctx.callgraph is not None
        else []
    )

    return [
        NativeToolSpec(
            name="execute",
            description=(
                "Run a shell command inside the sandbox container. "
                "Use for compilation, debugging, running tests, etc."
            ),
            schema=ExecuteInput.model_json_schema(),
            handler=execute,
        ),
        NativeToolSpec(
            name="read_file",
            description=(
                "Read lines from a file in the container. "
                "Parameters: path (required), offset (line offset, default 0), "
                "limit (max lines, default 2000). No other parameters exist."
            ),
            schema=ReadFileInput.model_json_schema(),
            handler=read_file,
        ),
        NativeToolSpec(
            name="write_file",
            description="Write contents to a file in the container. Creates parent directories.",
            schema=WriteFileInput.model_json_schema(),
            handler=write_file,
        ),
        semgrep_tool,
        *reporting_tools,
        *build_potential_tools(ctx),
        *(build_pool_query_tools(ctx) if ctx.findings_pool is not None else []),
        *callgraph_tools,
    ]
