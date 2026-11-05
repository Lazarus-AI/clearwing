"""Deep agent mode tools: bounded source discovery and sandbox operations.

Pairs repository-scoped search with sandbox tools for source reading,
compilation, debugging, and test execution.

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
import fnmatch
import logging
import os
import re
import shlex
from pathlib import Path

from pydantic import Field

from clearwing.llm import NativeToolSpec, ToolInputModel
from clearwing.reporting.safety import redact_text
from clearwing.sourcehunt.paths import resolve_repo_directory, resolve_repo_file

from .discovery import build_discovery_tools
from .pool_query import build_pool_query_tools
from .potentials import build_potential_tools
from .reporting import build_reporting_tools
from .sandbox import HunterContext

logger = logging.getLogger(__name__)

_OUTPUT_CAP = 100_000  # 100 KB cap on stdout/stderr per execute call
READ_FILE_DEFAULT_LINES = 100


class ExecuteInput(ToolInputModel):
    command: str = Field(description="Shell command to execute.")
    timeout: int = Field(default=300, description="Timeout in seconds (default 300).")


class ReadFileInput(ToolInputModel):
    path: str = Field(
        description="Repository-relative path from a search hit, or /workspace/... path."
    )
    offset: int = Field(
        default=0, description="Line offset (0-based, default 0). Or use start_line (1-based)."
    )
    limit: int = Field(
        default=READ_FILE_DEFAULT_LINES,
        description="Max lines to return (default 100). Or use end_line with start_line.",
    )
    start_line: int | None = Field(
        default=None,
        description="Alias — 1-based line number to start at. Overrides offset if set.",
    )
    end_line: int | None = Field(
        default=None, description="Alias — 1-based inclusive end line. Requires start_line."
    )
    refresh: bool = Field(
        default=False,
        description="Set true to deliberately reread lines already shown during this hunt.",
    )


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
            "of the function name. e.g. filter='FooBar' matches "
            "do_foo_bar, FooBarBaz, my_FooBar_impl, etc."
        ),
    )


class ReadFunctionInput(ToolInputModel):
    name: str = Field(description="Exact function name to read (e.g. 'foo_bar_baz').")
    refresh: bool = Field(
        default=False,
        description="Set true to deliberately reread a function already shown during this hunt.",
    )


def function_locations(callgraph: object, name: str) -> list[tuple[str, int, int]]:
    """Return distinct exact-name definitions in the callgraph."""
    return list(
        dict.fromkeys(
            (path, info.start_line, info.end_line)
            for path, infos in callgraph.function_info.items()
            for info in infos
            if info.name == name
        )
    )


class FindSourceInput(ToolInputModel):
    query: str = Field(description="Filename or directory name substring, or glob pattern.")
    path: str = Field(default=".", description="Repository-relative directory to search.")
    kind: str = Field(default="both", description="Match files, directories, or both.")


_SEARCH_LIMIT = 40
_SHELL_SEARCH = re.compile(r"(?:^|[;&|]\s*)\s*(?:find|grep|rg)\b")


def _cap_output(text: str, label: str = "output") -> str:
    safe = redact_text(text)
    if len(safe) <= _OUTPUT_CAP:
        return safe
    return safe[:_OUTPUT_CAP] + f"\n\n[{label} truncated at {_OUTPUT_CAP} characters]"


# Split on non-alphanumeric AND camelCase boundaries so filter="FooBar"
# yields ["foo","bar"] and matches FooBarBaz, do_foo_bar, etc.
_TOKEN_SPLIT = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def _tokenize(s: str) -> list[str]:
    return [t.lower() for t in _TOKEN_SPLIT.split(s) if t]


def _matches(name: str, tokens: list[str]) -> bool:
    low = name.lower()
    return all(t in low for t in tokens)


def build_deep_agent_tools(ctx: HunterContext) -> list[NativeToolSpec]:  # noqa: C901
    """Build the deep agent tool set: bounded search, execute, read_file, write_file,
    plus the shared reporting + findings-pool tools.
    """
    # Deep hunters read source via read_file/execute (cat/sed/grep), not the
    # constrained read_source_file that populates ctx.files_read. Mark the
    # context so the reporting guard doesn't reject every trace step for a
    # file it never saw a read_source_file call for.
    ctx.agent_mode = "deep"
    discovery_grep = next(tool for tool in build_discovery_tools(ctx) if tool.name == "grep_source")

    def grep_source(pattern: str, path: str = ".", file_glob: str = "", **_: object) -> dict:
        matches = discovery_grep.handler(
            pattern=pattern, path=path, file_glob=file_glob, max_results=_SEARCH_LIMIT + 1
        )
        if matches and "error" in matches[0]:
            return {
                "status": "error",
                "error": matches[0]["error"],
                "matches": [],
                "truncated": False,
            }
        truncated = len(matches) > _SEARCH_LIMIT
        visible = [
            {**match, "matched_text": str(match.get("matched_text", ""))[:240]}
            for match in matches[:_SEARCH_LIMIT]
        ]
        return {
            "status": "truncated" if truncated else "matches" if matches else "no_matches",
            "pattern": pattern,
            "scope": path,
            "matches": visible,
            "count": min(len(matches), _SEARCH_LIMIT),
            "truncated": truncated,
            "next_action": "Read a relevant hit with read_file; refine the query if truncated or empty.",
        }

    def find_source(query: str, path: str = ".", kind: str = "both", **_: object) -> dict:  # noqa: C901
        if kind not in {"file", "directory", "both"}:
            return {
                "status": "error",
                "error": "kind must be file, directory, or both",
                "matches": [],
                "truncated": False,
            }
        if not query.strip():
            return {
                "status": "error",
                "error": "query must not be empty",
                "matches": [],
                "truncated": False,
            }
        base = resolve_repo_directory(ctx.repo_path, path)
        if base is None:
            return {
                "status": "error",
                "error": "path is outside the repository or is not a directory",
                "matches": [],
                "truncated": False,
            }
        root = Path(ctx.repo_path).resolve()
        has_glob = any(char in query for char in "*?[]")
        needle = query.lower()
        matches: list[dict[str, str]] = []

        if ctx.sandbox is not None:
            relative_base = base.relative_to(root).as_posix()
            container_base = "/workspace" if relative_base == "." else f"/workspace/{relative_base}"
            name_pattern = query if has_glob else f"*{query}*"
            type_filter = {
                "file": "-type f",
                "directory": "-type d",
                "both": r"\( -type f -o -type d \)",
            }[kind]
            command = (
                f"find {shlex.quote(container_base)} -path '*/.git' -prune -o "
                f"\\( -iname {shlex.quote(name_pattern)} -a {type_filter} \\) -print "
                "| while IFS= read -r match; do "
                'if [ -d "$match" ]; then printf "directory\\t%s\\n" "$match"; '
                'else printf "file\\t%s\\n" "$match"; fi; done '
                f"| head -n {_SEARCH_LIMIT + 1}"
            )
            result = ctx.sandbox.exec(command, timeout=30)
            if result.timed_out:
                return {
                    "status": "error",
                    "error": "repository path search timed out",
                    "matches": [],
                    "truncated": False,
                }
            if result.stderr and not result.stdout:
                return {
                    "status": "error",
                    "error": _cap_output(result.stderr.strip(), "find error"),
                    "matches": [],
                    "truncated": False,
                }
            for row in result.stdout.splitlines():
                entry_type, separator, absolute = row.partition("\t")
                if not separator or entry_type not in {"file", "directory"}:
                    continue
                if not absolute.startswith("/workspace/"):
                    continue
                matches.append(
                    {"path": redact_text(absolute.removeprefix("/workspace/")), "type": entry_type}
                )
        else:

            def wanted(name: str) -> bool:
                return fnmatch.fnmatch(name.lower(), needle) if has_glob else needle in name.lower()

            for directory, dirnames, filenames in os.walk(base, followlinks=False):
                dirnames[:] = sorted(
                    name
                    for name in dirnames
                    if name != ".git"
                    and resolve_repo_directory(
                        ctx.repo_path, (Path(directory) / name).relative_to(root).as_posix()
                    )
                    is not None
                )
                if kind in {"directory", "both"}:
                    for name in dirnames:
                        if wanted(name):
                            relative = (Path(directory) / name).relative_to(root).as_posix()
                            matches.append({"path": redact_text(relative), "type": "directory"})
                            if len(matches) > _SEARCH_LIMIT:
                                break
                if len(matches) > _SEARCH_LIMIT:
                    break
                if kind in {"file", "both"}:
                    for name in sorted(filenames):
                        candidate = Path(directory) / name
                        relative = candidate.relative_to(root).as_posix()
                        if wanted(name) and resolve_repo_file(ctx.repo_path, relative) is not None:
                            matches.append({"path": redact_text(relative), "type": "file"})
                            if len(matches) > _SEARCH_LIMIT:
                                break
                if len(matches) > _SEARCH_LIMIT:
                    break
        truncated = len(matches) > _SEARCH_LIMIT
        return {
            "status": "truncated" if truncated else "matches" if matches else "no_matches",
            "query": query,
            "scope": path,
            "matches": matches[:_SEARCH_LIMIT],
            "count": min(len(matches), _SEARCH_LIMIT),
            "truncated": truncated,
            "next_action": "Read a relevant file with read_file; refine the query if truncated or empty.",
        }

    def execute(command: str, timeout: int = 300, **_: object) -> dict:
        if _SHELL_SEARCH.search(command):
            return {
                "error": (
                    "Shell search blocked. Use grep_source for repository "
                    "content or find_source for repository paths, then read_file a hit."
                )
            }
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
        limit: int = READ_FILE_DEFAULT_LINES,
        start_line: int | None = None,
        end_line: int | None = None,
        **_: object,
    ) -> str:
        if ctx.sandbox is None:
            return "error: no sandbox available"
        # Accept both idioms. Model naturally reaches for start_line/end_line
        # (the prompt used to advertise them); swallowing them via **_ made the
        # tool silently return the default first window and looked like a tool bug.
        if start_line is not None:
            start_line = max(1, start_line)
            offset = start_line - 1
            if end_line is not None:
                limit = max(1, end_line - start_line + 1)
        offset = max(0, offset)
        limit = max(1, limit)
        start = offset + 1
        end = offset + limit
        # Previously this was `sed ... | cat -n`, which numbers output
        # starting from 1 regardless of offset — a hunter asking for
        # lines 101-150 got back "line 1..line 50" and then reasoned
        # about the wrong line numbers when reporting findings. Use awk
        # with NR directly so the emitted line numbers match the file.
        cmd = (
            f"awk -v s={start} -v e={end} "
            '\'NR>=s && NR<=e { printf "%6d\\t%s\\n", NR, $0 } '
            'END { printf "__CLEARWING_TOTAL_LINES__=%d\\n", NR > "/dev/stderr" }\' '
            f"{shlex.quote(path)}"
        )
        result = ctx.sandbox.exec(cmd, timeout=30)
        if result.exit_code != 0:
            return _cap_output(f"error reading {path}: {result.stderr.strip()}", "file error")
        ctx.deep_files_read.add(str(path))
        content = _cap_output(result.stdout, "file")
        total_match = re.search(r"__CLEARWING_TOTAL_LINES__=(\d+)", result.stderr)
        if total_match:
            content += f"\n[CLEARWING_READ_METADATA total_lines={total_match.group(1)}]"
        return content

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
                    {
                        "func": fn,
                        "start_line": line_index[f].get(fn, (None, None))[0],
                        "end_line": line_index[f].get(fn, (None, None))[1],
                    }
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
        infos = cg.function_info.get(path) or cg.function_info.get(path.removeprefix("/workspace/"))
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
        locations = function_locations(cg, name)
        if not locations:
            all_names = {fi.name for infos in cg.function_info.values() for fi in infos}
            near = difflib.get_close_matches(name, all_names, n=5, cutoff=0.6)
            return {"error": f"no function named '{name}'", "did_you_mean": near}
        if len(locations) > 1:
            return {
                "error": "ambiguous name; multiple definitions",
                "candidates": [
                    {"file": f, "start_line": start, "end_line": end} for f, start, end in locations
                ],
            }
        f, start, end = locations[0]
        body = read_file(f"/workspace/{f}", offset=start - 1, limit=end - start + 1)
        return {"file": f, "start_line": start, "end_line": end, "body": body}

    reporting_tools = build_reporting_tools(ctx)

    callgraph_tools = (
        [
            NativeToolSpec(
                name="lookup_callers",
                description=(
                    "Returns every function in the codebase that calls func_name, "
                    "grouped by file with start/end line ranges."
                ),
                schema=LookupCallersInput.model_json_schema(),
                handler=lookup_callers,
            ),
            NativeToolSpec(
                name="lookup_callees",
                description=(
                    "Returns every function called by func_name, grouped by defining file "
                    "with line ranges."
                ),
                schema=LookupCalleesInput.model_json_schema(),
                handler=lookup_callees,
            ),
            NativeToolSpec(
                name="list_functions",
                description=(
                    "Returns all functions defined in a file with start/end line numbers. "
                    "Use filter= to search by keyword (tokens split on non-alphanumerics "
                    "and camelCase boundaries)."
                ),
                schema=ListFunctionsInput.model_json_schema(),
                handler=list_functions,
            ),
            NativeToolSpec(
                name="read_function",
                description=(
                    "Read a function body by exact name. Returns {file, start_line, "
                    "end_line, body}. On miss: did_you_mean suggestions. On ambiguity: "
                    "candidate list. Uses the same source coverage and 12,000-character "
                    "visible limit as read_file; use refresh=true for a deliberate reread."
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
            name="grep_source",
            description=(
                "Search source content inside the repository. Returns at most 40 file:line "
                "matches and an explicit no_matches or truncated state. Read a relevant hit "
                "with read_file; repeated results call for a different approach or a finish."
            ),
            schema=discovery_grep.schema,
            handler=grep_source,
        ),
        NativeToolSpec(
            name="find_source",
            description=(
                "Find repository files or directories by name substring or glob. Returns at "
                "most 40 labeled paths and an explicit no_matches or truncated state. "
                "Read a relevant file with read_file."
            ),
            schema=FindSourceInput.model_json_schema(),
            handler=find_source,
        ),
        NativeToolSpec(
            name="execute",
            description=(
                "Run a shell command inside the sandbox container for compilation, "
                "debugging, and tests. Use grep_source for source content and "
                "find_source for paths instead of shell grep/find searches."
            ),
            schema=ExecuteInput.model_json_schema(),
            handler=execute,
        ),
        NativeToolSpec(
            name="read_file",
            description=(
                "Read lines from a relevant grep_source or find_source hit. "
                "Repository-relative paths resolve inside /workspace. "
                "Parameters: path (required), offset (line offset, default 0), "
                "limit (max lines, default 100), or start_line and end_line. "
                "Set refresh=true to deliberately revisit covered lines. "
                "The response reports returned lines and the next line to read."
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
        *reporting_tools,
        *build_potential_tools(ctx),
        *(build_pool_query_tools(ctx) if ctx.findings_pool is not None else []),
        *callgraph_tools,
    ]
