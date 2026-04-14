"""Read-only filesystem discovery tools for the source-hunt hunter.

Four tools: `read_source_file`, `list_source_tree`, `grep_source`,
`find_callers`. None of them compile or execute anything — they only
probe the cloned repo on the host and (for grep) delegate to ripgrep
inside the sandbox when one is attached.

Every path crossing the hunter/host boundary is funneled through
`_normalize_path` so a tool argument like `../../../etc/passwd` is
clamped inside the repo root before we touch the filesystem.
"""

from __future__ import annotations

import logging
import os
import re

from langchain_core.tools import tool

from .sandbox import HunterContext

logger = logging.getLogger(__name__)


# --- Path + ripgrep helpers -------------------------------------------------


def _normalize_path(repo_path: str, path: str) -> str:
    """Turn a (possibly user-supplied) path into a safe repo-relative path.

    Prevents path traversal: any '..' that escapes the repo is clamped.
    Returns a repo-relative path (no leading slash). Caller can prepend
    repo_path or '/workspace' depending on context.
    """
    # Strip leading slash
    if path.startswith("/"):
        path = path.lstrip("/")
    # Resolve and check it's still under repo_path
    abs_path = os.path.abspath(os.path.join(repo_path, path))
    common = os.path.commonpath([abs_path, repo_path])
    if common != os.path.abspath(repo_path):
        raise ValueError(f"path escapes repo: {path}")
    return os.path.relpath(abs_path, repo_path)


def _container_path(rel_path: str) -> str:
    """Turn a repo-relative path into the path inside the /workspace mount."""
    return f"/workspace/{rel_path}".replace("//", "/")


def _parse_rg_output(stdout: str) -> list[dict]:
    """Turn ripgrep's `--no-heading --line-number` output into match dicts."""
    matches: list[dict] = []
    for line in stdout.splitlines():
        # Format: <path>:<line>:<text>
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        path, line_num, text = parts
        try:
            ln = int(line_num)
        except ValueError:
            continue
        matches.append(
            {
                "file": path.replace("/workspace/", "", 1),
                "line_number": ln,
                "matched_text": text.rstrip(),
            }
        )
        if len(matches) >= 100:
            break
    return matches


def _grep_python_fallback(
    repo_path: str,
    rel_dir: str,
    pattern: str,
    file_glob: str,
) -> list[dict]:
    """Pure-Python fallback when no sandbox is attached (test mode)."""
    try:
        regex = re.compile(pattern)
    except re.error as e:
        return [{"error": f"invalid regex: {e}"}]
    base = os.path.join(repo_path, rel_dir)
    matches: list[dict] = []
    for dirpath, dirnames, filenames in os.walk(base):
        # Skip common cruft
        dirnames[:] = [d for d in dirnames if not d.startswith(".") and d != "node_modules"]
        for fname in filenames:
            if file_glob:
                # Very simple glob: only handles trailing-extension globs like '*.c'
                if file_glob.startswith("*.") and not fname.endswith(file_glob[1:]):
                    continue
            full = os.path.join(dirpath, fname)
            try:
                with open(full, encoding="utf-8", errors="ignore") as f:
                    for i, line in enumerate(f, 1):
                        if regex.search(line):
                            matches.append(
                                {
                                    "file": os.path.relpath(full, repo_path),
                                    "line_number": i,
                                    "matched_text": line.rstrip(),
                                }
                            )
                            if len(matches) >= 100:
                                return matches
            except OSError:
                continue
    return matches


# --- Tool builder -----------------------------------------------------------


def build_discovery_tools(ctx: HunterContext) -> list:
    """Build the four read-only discovery tools for a hunter session.

    Returns them in the order `build_hunter_tools()` used to emit them
    so the aggregate registry is byte-identical.
    """

    @tool
    def read_source_file(path: str, start_line: int = 1, end_line: int = -1) -> str:
        """Read a source file (path is repo-relative) and return up to 500 lines.

        Args:
            path: Repo-relative path to the file.
            start_line: 1-indexed first line to include.
            end_line: Last line to include, or -1 for end-of-file.
        """
        try:
            rel = _normalize_path(ctx.repo_path, path)
        except ValueError as e:
            return f"Error: {e}"
        host_path = os.path.join(ctx.repo_path, rel)
        try:
            with open(host_path, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError as e:
            return f"Error reading {rel}: {e}"
        total = len(lines)
        s = max(0, start_line - 1)
        e = total if end_line < 0 else min(total, end_line)
        sliced = lines[s:e]
        # Cap at 500 lines
        if len(sliced) > 500:
            sliced = sliced[:500]
            footer = f"\n... (truncated; file has {total} lines, showing {s + 1}..{s + 500})"
        else:
            footer = ""
        return "".join(sliced) + footer

    @tool
    def list_source_tree(dir_path: str = ".", max_depth: int = 2) -> list[str]:
        """List files and directories relative to the repo root.

        Args:
            dir_path: Repo-relative directory path. Default '.' = repo root.
            max_depth: Max recursion depth (1 = immediate children only).
        """
        try:
            rel = _normalize_path(ctx.repo_path, dir_path)
        except ValueError as e:
            return [f"Error: {e}"]
        base = os.path.join(ctx.repo_path, rel)
        if not os.path.isdir(base):
            return [f"Error: not a directory: {rel}"]
        out: list[str] = []
        base_depth = base.rstrip(os.sep).count(os.sep)
        for dirpath, dirnames, filenames in os.walk(base):
            depth = dirpath.rstrip(os.sep).count(os.sep) - base_depth
            if depth >= max_depth:
                dirnames[:] = []
            for d in dirnames:
                out.append(os.path.relpath(os.path.join(dirpath, d), ctx.repo_path) + "/")
            for f in filenames:
                out.append(os.path.relpath(os.path.join(dirpath, f), ctx.repo_path))
            if len(out) > 500:
                out.append("... (truncated)")
                return out
        return out

    @tool
    def grep_source(pattern: str, path: str = ".", file_glob: str = "") -> list[dict]:
        """ripgrep-style search for a pattern. Returns up to 100 matches.

        Args:
            pattern: Regex pattern.
            path: Repo-relative directory to search (default = repo root).
            file_glob: Optional glob like '*.c' or '*.py' (passed to rg via -g).
        """
        try:
            rel = _normalize_path(ctx.repo_path, path)
        except ValueError as e:
            return [{"error": str(e)}]

        if ctx.sandbox is not None:
            # Run rg inside the sandbox so we don't depend on the host having it
            target = _container_path(rel)
            argv = ["rg", "--no-heading", "--line-number", "--max-count", "100"]
            if file_glob:
                argv += ["-g", file_glob]
            argv += [pattern, target]
            result = ctx.sandbox.exec(argv, timeout=30)
            return _parse_rg_output(result.stdout)
        else:
            # Fallback: use Python re on the host file tree (slower but works in tests)
            return _grep_python_fallback(ctx.repo_path, rel, pattern, file_glob)

    @tool
    def find_callers(symbol: str) -> list[dict]:
        """Find files/lines that reference a symbol. Wraps grep_source.

        Args:
            symbol: Function or constant name to search for.
        """
        # Word-boundary-ish search on the symbol
        pattern = rf"\b{re.escape(symbol)}\b"
        return grep_source.invoke({"pattern": pattern, "path": "."})

    return [read_source_file, list_source_tree, grep_source, find_callers]
