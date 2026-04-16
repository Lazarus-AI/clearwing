"""Lightweight taint / dataflow analysis for the sourcehunt preprocessor.

v0.4: builds on the existing tree-sitter callgraph to identify source→sink
paths in C and Python code. Scope is DELIBERATELY limited:

    - Intra-procedural only (within one function)
    - Pattern-based source / sink identification
    - Simple def-use tracking via identifier names
    - No SSA, no phi nodes, no field sensitivity, no pointer aliasing

Full IR-level dataflow analysis is deferred to v1.0+. The v0.4 design
catches the common cases — `read(fd, buf, n); memcpy(dst, buf, n);` —
without the machinery cost of a full abstract interpreter.

Sources and sinks live in pattern tables so new languages / new APIs are
additive. Each pattern specifies:
    - language (c | python)
    - function name (literal or regex)
    - role (source | sink)
    - For sources: which call argument or the return value becomes tainted
    - For sinks: which call argument is the sensitive one

The analyzer feeds `taint_paths` onto each FileTarget. The ranker uses
this signal to promote files with confirmed source→sink paths — real
attacker-reachability evidence as opposed to the lightweight heuristic.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# --- Pattern types ----------------------------------------------------------


@dataclass
class TaintPattern:
    """One source or sink pattern for a specific language."""

    language: str  # "c" | "python"
    role: str  # "source" | "sink"
    name: str  # function name (literal match)
    cwe: str = ""  # CWE category the sink maps to
    description: str = ""  # human-readable sink description
    taints_return: bool = False  # source: the return value is tainted
    taints_args: list[int] = field(default_factory=list)
    # source: which arg positions are out-parameters
    sensitive_args: list[int] = field(default_factory=list)
    # sink: which arg positions are the dangerous ones
    severity: str = "medium"  # default severity for findings from this sink


# --- Pattern database -------------------------------------------------------


# C/C++ source functions. These either return attacker-controlled data
# or write it into an out-parameter buffer.
C_SOURCES: tuple[TaintPattern, ...] = (
    # Stream input — return value is bytes read, out-arg is the buffer
    TaintPattern("c", "source", "read", taints_args=[1]),
    TaintPattern("c", "source", "recv", taints_args=[1]),
    TaintPattern("c", "source", "recvfrom", taints_args=[1]),
    TaintPattern("c", "source", "fgets", taints_args=[0], taints_return=True),
    TaintPattern("c", "source", "fread", taints_args=[0]),
    TaintPattern("c", "source", "getline", taints_args=[0]),
    TaintPattern("c", "source", "scanf", taints_args=[1, 2, 3, 4, 5]),
    TaintPattern("c", "source", "sscanf", taints_args=[2, 3, 4, 5]),
    TaintPattern("c", "source", "fscanf", taints_args=[2, 3, 4, 5]),
    # Environment / argv — return value is tainted
    TaintPattern("c", "source", "getenv", taints_return=True),
    TaintPattern("c", "source", "getpass", taints_return=True),
    # Wide-char variants
    TaintPattern("c", "source", "fgetws", taints_args=[0], taints_return=True),
)

# C/C++ sink functions. Each has one or more "sensitive" arg indices — an
# expression derived from tainted data at one of those positions is an
# intra-procedural taint path.
C_SINKS: tuple[TaintPattern, ...] = (
    # Unchecked memory copies
    TaintPattern(
        "c",
        "sink",
        "memcpy",
        cwe="CWE-787",
        description="memcpy length derived from untrusted input",
        sensitive_args=[1, 2],
        severity="high",
    ),
    TaintPattern(
        "c",
        "sink",
        "memmove",
        cwe="CWE-787",
        description="memmove length from untrusted input",
        sensitive_args=[1, 2],
        severity="high",
    ),
    TaintPattern(
        "c",
        "sink",
        "strcpy",
        cwe="CWE-120",
        description="strcpy source from untrusted input",
        sensitive_args=[1],
        severity="high",
    ),
    TaintPattern(
        "c",
        "sink",
        "strncpy",
        cwe="CWE-120",
        description="strncpy source from untrusted input",
        sensitive_args=[1, 2],
        severity="medium",
    ),
    TaintPattern(
        "c",
        "sink",
        "strcat",
        cwe="CWE-120",
        description="strcat source from untrusted input",
        sensitive_args=[1],
        severity="high",
    ),
    TaintPattern(
        "c",
        "sink",
        "sprintf",
        cwe="CWE-134",
        description="sprintf format/arg from untrusted input",
        sensitive_args=[1, 2],
        severity="high",
    ),
    TaintPattern(
        "c",
        "sink",
        "snprintf",
        cwe="CWE-134",
        description="snprintf format/arg from untrusted input",
        sensitive_args=[2, 3],
        severity="medium",
    ),
    # Command execution
    TaintPattern(
        "c",
        "sink",
        "system",
        cwe="CWE-78",
        description="system() command from untrusted input",
        sensitive_args=[0],
        severity="critical",
    ),
    TaintPattern(
        "c",
        "sink",
        "popen",
        cwe="CWE-78",
        description="popen command from untrusted input",
        sensitive_args=[0],
        severity="critical",
    ),
    TaintPattern(
        "c",
        "sink",
        "execl",
        cwe="CWE-78",
        description="execl path/arg from untrusted input",
        sensitive_args=[0, 1],
        severity="critical",
    ),
    TaintPattern(
        "c",
        "sink",
        "execlp",
        cwe="CWE-78",
        description="execlp path/arg from untrusted input",
        sensitive_args=[0, 1],
        severity="critical",
    ),
    TaintPattern(
        "c",
        "sink",
        "execve",
        cwe="CWE-78",
        description="execve path from untrusted input",
        sensitive_args=[0],
        severity="critical",
    ),
    # Allocation size
    TaintPattern(
        "c",
        "sink",
        "malloc",
        cwe="CWE-190",
        description="malloc size from untrusted input (integer overflow)",
        sensitive_args=[0],
        severity="medium",
    ),
    TaintPattern(
        "c",
        "sink",
        "calloc",
        cwe="CWE-190",
        description="calloc count/size from untrusted input",
        sensitive_args=[0, 1],
        severity="medium",
    ),
    # File ops
    TaintPattern(
        "c",
        "sink",
        "fopen",
        cwe="CWE-22",
        description="fopen path from untrusted input (path traversal)",
        sensitive_args=[0],
        severity="high",
    ),
    TaintPattern(
        "c",
        "sink",
        "open",
        cwe="CWE-22",
        description="open path from untrusted input (path traversal)",
        sensitive_args=[0],
        severity="high",
    ),
)

# Python sources
PYTHON_SOURCES: tuple[TaintPattern, ...] = (
    # Stdin
    TaintPattern("python", "source", "input", taints_return=True),
    # argv
    TaintPattern("python", "source", "sys.argv", taints_return=True),
    # os.environ subscript — approximated via get/getitem
    TaintPattern("python", "source", "os.environ.get", taints_return=True),
    TaintPattern("python", "source", "getenv", taints_return=True),
    # Socket / file reads
    TaintPattern("python", "source", "recv", taints_return=True),
    TaintPattern("python", "source", "read", taints_return=True),
    TaintPattern("python", "source", "readline", taints_return=True),
    TaintPattern("python", "source", "readlines", taints_return=True),
    # Flask / Django request attribute accesses — approximated by name
    TaintPattern("python", "source", "request.args", taints_return=True),
    TaintPattern("python", "source", "request.form", taints_return=True),
    TaintPattern("python", "source", "request.get_json", taints_return=True),
    TaintPattern("python", "source", "request.json", taints_return=True),
    TaintPattern("python", "source", "request.data", taints_return=True),
    TaintPattern("python", "source", "request.GET", taints_return=True),
    TaintPattern("python", "source", "request.POST", taints_return=True),
)

# Python sinks
PYTHON_SINKS: tuple[TaintPattern, ...] = (
    # Command execution
    TaintPattern(
        "python",
        "sink",
        "system",
        cwe="CWE-78",
        description="os.system with user input",
        sensitive_args=[0],
        severity="critical",
    ),
    TaintPattern(
        "python",
        "sink",
        "popen",
        cwe="CWE-78",
        description="os.popen with user input",
        sensitive_args=[0],
        severity="critical",
    ),
    TaintPattern(
        "python",
        "sink",
        "run",
        cwe="CWE-78",
        description="subprocess.run with user input (check shell=True)",
        sensitive_args=[0],
        severity="high",
    ),
    TaintPattern(
        "python",
        "sink",
        "Popen",
        cwe="CWE-78",
        description="subprocess.Popen with user input",
        sensitive_args=[0],
        severity="high",
    ),
    # Code exec
    TaintPattern(
        "python",
        "sink",
        "eval",
        cwe="CWE-95",
        description="eval with user input",
        sensitive_args=[0],
        severity="critical",
    ),
    TaintPattern(
        "python",
        "sink",
        "exec",
        cwe="CWE-95",
        description="exec with user input",
        sensitive_args=[0],
        severity="critical",
    ),
    # Database
    TaintPattern(
        "python",
        "sink",
        "execute",
        cwe="CWE-89",
        description="cursor.execute with user input — check parameterization",
        sensitive_args=[0],
        severity="high",
    ),
    TaintPattern(
        "python",
        "sink",
        "executemany",
        cwe="CWE-89",
        description="cursor.executemany with user input",
        sensitive_args=[0],
        severity="high",
    ),
    # Deserialization
    TaintPattern(
        "python",
        "sink",
        "loads",
        cwe="CWE-502",
        description="deserialization (pickle/yaml/marshal) of user input",
        sensitive_args=[0],
        severity="critical",
    ),
    TaintPattern(
        "python",
        "sink",
        "load",
        cwe="CWE-502",
        description="yaml.load / marshal.load of user input",
        sensitive_args=[0],
        severity="critical",
    ),
    # Templates
    TaintPattern(
        "python",
        "sink",
        "render_template_string",
        cwe="CWE-1336",
        description="SSTI via render_template_string with user input",
        sensitive_args=[0],
        severity="critical",
    ),
    # File ops
    TaintPattern(
        "python",
        "sink",
        "open",
        cwe="CWE-22",
        description="open() with user-controlled path",
        sensitive_args=[0],
        severity="high",
    ),
)


ALL_PATTERNS: dict[str, list[TaintPattern]] = {
    "c": list(C_SOURCES) + list(C_SINKS),
    "cpp": list(C_SOURCES) + list(C_SINKS),
    "python": list(PYTHON_SOURCES) + list(PYTHON_SINKS),
}


# --- Results ----------------------------------------------------------------


@dataclass
class TaintPath:
    """One source→sink path found in a file."""

    file: str  # repo-relative
    source_function: str  # e.g. "read", "request.args"
    source_line: int
    sink_function: str  # e.g. "memcpy", "os.system"
    sink_line: int
    sink_cwe: str
    sink_description: str
    severity: str  # from the sink pattern
    variable: str  # the identifier that carries taint
    # The containing function in source code (best-effort, for context)
    containing_function: str = ""
    language: str = ""


@dataclass
class TaintAnalysisResult:
    """Output of running taint analysis across a repo."""

    paths: list[TaintPath] = field(default_factory=list)
    files_analyzed: int = 0
    files_with_paths: int = 0
    duration_seconds: float = 0.0

    def paths_by_file(self) -> dict[str, list[TaintPath]]:
        out: dict[str, list[TaintPath]] = {}
        for p in self.paths:
            out.setdefault(p.file, []).append(p)
        return out


# --- Analyzer ---------------------------------------------------------------


class TaintAnalyzer:
    """Lightweight intra-procedural taint analyzer using tree-sitter ASTs.

    Usage:
        analyzer = TaintAnalyzer()
        if analyzer.available:
            result = analyzer.analyze_repo(repo_path)
            for path in result.paths:
                ...
    """

    # Maximum file size — above this we skip to keep the analyzer cheap
    MAX_FILE_SIZE = 500_000

    SKIP_DIRS = {
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "vendor",
        "dist",
        "build",
        ".tox",
        ".mypy_cache",
        "target",
        "third_party",
    }

    def __init__(self) -> None:
        self._languages = _load_tree_sitter_languages()
        self._parsers: dict[str, Any] = {}

    @property
    def available(self) -> bool:
        """True if at least one tree-sitter grammar loaded."""
        return bool(self._languages)

    # --- Repo-level entry point --------------------------------------------

    def analyze_repo(
        self,
        repo_path: str,
        files: list[str] | None = None,
    ) -> TaintAnalysisResult:
        """Walk the repo, analyze each source file, aggregate paths.

        Args:
            repo_path: clone root (absolute).
            files: optional pre-filtered list of absolute file paths.
                If None, walk the tree.
        """
        start = time.monotonic()
        result = TaintAnalysisResult()

        if not self.available:
            return result

        file_iter = files if files is not None else list(self._walk(repo_path))
        for abs_path in file_iter:
            lang = self._language_for(abs_path)
            if lang is None:
                continue
            try:
                size = os.path.getsize(abs_path)
            except OSError:
                continue
            if size == 0 or size > self.MAX_FILE_SIZE:
                continue

            result.files_analyzed += 1
            file_paths = self._analyze_file(abs_path, lang, repo_path)
            if file_paths:
                result.files_with_paths += 1
                result.paths.extend(file_paths)

        result.duration_seconds = round(time.monotonic() - start, 2)
        return result

    # --- Per-file analysis -------------------------------------------------

    def _analyze_file(
        self,
        abs_path: str,
        lang: str,
        repo_path: str,
    ) -> list[TaintPath]:
        try:
            with open(abs_path, "rb") as f:
                source_bytes = f.read()
        except OSError:
            return []

        parser = self._get_parser(lang)
        try:
            tree = parser.parse(source_bytes)
        except Exception:
            logger.debug("tree-sitter parse failed for %s", abs_path, exc_info=True)
            return []

        rel_path = os.path.relpath(abs_path, repo_path)
        # Pass raw bytes through so byte offsets from tree-sitter work
        # correctly even when the source contains multi-byte UTF-8 chars.
        return self._walk_ast_for_taint(
            root=tree.root_node,
            source_text=source_bytes,
            lang=lang,
            rel_path=rel_path,
        )

    def _walk_ast_for_taint(
        self,
        root: Any,
        source_text: bytes | str,
        lang: str,
        rel_path: str,
    ) -> list[TaintPath]:
        """Find source → sink intra-procedural paths in one file.

        Strategy:
            1. Walk the AST function-by-function
            2. For each function, collect all taint-source assignments
               (e.g. `x = read(...)` → `x` is tainted)
            3. For each sink call in the same function, check if any
               sensitive argument resolves to a tainted identifier
            4. Emit a TaintPath on match
        """
        paths: list[TaintPath] = []
        sources = {p.name: p for p in ALL_PATTERNS.get(lang, []) if p.role == "source"}
        sinks = {p.name: p for p in ALL_PATTERNS.get(lang, []) if p.role == "sink"}
        if not sources or not sinks:
            return paths

        # Walk function-scope nodes
        for func_node in self._iter_function_nodes(root, lang):
            func_name = self._function_name(func_node, lang, source_text)
            # Collect tainted identifiers in this function's scope
            tainted: dict[str, tuple[str, int]] = {}  # ident → (source_fn, line)

            for call, call_name, call_line in self._iter_call_expressions(
                func_node, lang, source_text
            ):
                src_pat = self._match_source(call_name, sources)
                if src_pat is None:
                    continue
                # Mark the assignment target as tainted, if present
                target_ident = self._assignment_target_for_call(call, lang, source_text)
                if target_ident:
                    tainted[target_ident] = (src_pat.name, call_line)
                # Mark out-param identifiers from call args as tainted
                for arg_idx in src_pat.taints_args:
                    arg_ident = self._argument_identifier(
                        call,
                        arg_idx,
                        lang,
                        source_text,
                    )
                    if arg_ident:
                        tainted[arg_ident] = (src_pat.name, call_line)

            if not tainted:
                continue

            # Second pass: find sinks whose sensitive args are tainted
            for call, call_name, call_line in self._iter_call_expressions(
                func_node, lang, source_text
            ):
                sink_pat = self._match_sink(call_name, sinks)
                if sink_pat is None:
                    continue
                for arg_idx in sink_pat.sensitive_args:
                    arg_ident = self._argument_identifier(
                        call,
                        arg_idx,
                        lang,
                        source_text,
                    )
                    if arg_ident and arg_ident in tainted:
                        src_fn, src_line = tainted[arg_ident]
                        paths.append(
                            TaintPath(
                                file=rel_path,
                                source_function=src_fn,
                                source_line=src_line,
                                sink_function=sink_pat.name,
                                sink_line=call_line,
                                sink_cwe=sink_pat.cwe,
                                sink_description=sink_pat.description,
                                severity=sink_pat.severity,
                                variable=arg_ident,
                                containing_function=func_name or "",
                                language=lang,
                            )
                        )
                        break  # one path per sink call is enough
        return paths

    # --- AST walkers --------------------------------------------------------

    def _iter_function_nodes(self, root: Any, lang: str) -> Iterator[Any]:
        """Yield the bodies of every function defined at or under `root`.

        For C, function bodies are `function_definition` nodes. For Python,
        they're `function_definition` (sync) and `async_function_definition`.
        """
        func_types = _FUNCTION_DEF_TYPES.get(lang, set())
        if not func_types:
            return
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type in func_types:
                yield node
                # Don't recurse into nested functions inside the body —
                # the tainted dict is function-scoped per the plan
                continue
            stack.extend(list(node.children))

    def _iter_call_expressions(
        self, func_node: Any, lang: str, source_text: bytes | str
    ) -> Iterator[tuple[Any, str, int]]:
        """Yield (call_node, callee_name, line_number) for every call in func_node."""
        call_types = _CALL_EXPR_TYPES.get(lang, set())
        if not call_types:
            return
        stack = [func_node]
        while stack:
            node = stack.pop()
            if node.type in call_types:
                name = self._callee_name(node, lang, source_text)
                line = node.start_point[0] + 1  # tree-sitter rows are 0-indexed
                if name:
                    yield node, name, line
            stack.extend(list(node.children))

    def _callee_name(self, call_node: Any, lang: str, source_text: bytes | str) -> str | None:
        """Extract the callee name from a call_expression / call node.

        Returns the FULL dotted callee path as it appears in source, so the
        pattern matcher can check both the literal full name and each
        suffix segment:
            `foo()`              → "foo"
            `obj.bar()`          → "obj.bar"
            `module.foo.bar()`   → "module.foo.bar"
            `request.args.get()` → "request.args.get"

        Production choice: full paths beat rightmost-identifier for Python
        where module.function calls are the norm. For C, field / arrow
        dereferences are rarer in the source/sink tables so the full-path
        shape still works.
        """
        func_field = None
        try:
            func_field = call_node.child_by_field_name("function")
        except Exception:
            pass
        target = (
            func_field
            if func_field is not None
            else (call_node.children[0] if call_node.children else None)
        )
        if target is None:
            return None
        # Extract the whole callee expression's source text (preserves the
        # dotted path verbatim). Trim whitespace.
        text = _node_text(target, source_text).strip()
        if text:
            return text
        return self._rightmost_identifier_text(target, source_text)

    def _match_source(
        self,
        call_name: str,
        sources: dict[str, TaintPattern],
    ) -> TaintPattern | None:
        """Find a source pattern that matches a (possibly dotted) callee.

        Match order:
            1. Literal equality — `read` == "read"
            2. Pattern name is a suffix of the dotted call — `request.args`
               matches `request.args.get`
            3. Last segment of the call matches a literal pattern — `get`
               in `os.environ.get` matches the `os.environ.get` pattern
        """
        # 1. Literal
        if call_name in sources:
            return sources[call_name]
        # 2. Pattern as prefix/suffix — `request.args` matches `request.args.get`
        for pattern_name, pat in sources.items():
            if "." in pattern_name and (
                call_name.startswith(pattern_name + ".")
                or call_name.endswith("." + pattern_name)
                or pattern_name in call_name
            ):
                return pat
        # 3. Rightmost segment of the call matches a single-word pattern
        last = call_name.split(".")[-1]
        if last in sources and "." not in last:
            return sources[last]
        # 4. Rightmost segment matches the LAST SEGMENT of a dotted pattern
        for pattern_name, pat in sources.items():
            if "." in pattern_name and pattern_name.split(".")[-1] == last:
                return pat
        return None

    def _match_sink(
        self,
        call_name: str,
        sinks: dict[str, TaintPattern],
    ) -> TaintPattern | None:
        """Same matching rules as _match_source — literal, then last segment."""
        if call_name in sinks:
            return sinks[call_name]
        for pattern_name, pat in sinks.items():
            if "." in pattern_name and (
                call_name.startswith(pattern_name + ".")
                or call_name.endswith("." + pattern_name)
                or pattern_name in call_name
            ):
                return pat
        last = call_name.split(".")[-1]
        if last in sinks:
            return sinks[last]
        return None

    def _assignment_target_for_call(
        self,
        call_node: Any,
        lang: str,
        source_text: bytes | str,
    ) -> str | None:
        """For `x = foo()`, return `"x"`. None if the call isn't an rvalue.

        Walks up several parent levels because tree-sitter nests call
        expressions inside `expression_statement` / `expression` wrappers
        before reaching the assignment node.
        """
        target_types = {
            "c": {"init_declarator", "assignment_expression"},
            "cpp": {"init_declarator", "assignment_expression"},
            "python": {"assignment"},
        }.get(lang, set())
        if not target_types:
            return None

        # Walk up up to 4 parents looking for an assignment-shaped node.
        # Any more than that and we're outside the immediate assignment
        # context (e.g. the call is a sub-expression).
        node = call_node
        for _ in range(4):
            parent = getattr(node, "parent", None)
            if parent is None:
                return None
            if parent.type in target_types:
                if lang in ("c", "cpp") and parent.type == "init_declarator":
                    decl = None
                    try:
                        decl = parent.child_by_field_name("declarator")
                    except Exception:
                        pass
                    if decl is None and parent.children:
                        decl = parent.children[0]
                    return self._rightmost_identifier_text(decl, source_text)
                # assignment_expression / Python assignment: left side
                left = None
                try:
                    left = parent.child_by_field_name("left")
                except Exception:
                    pass
                if left is None and parent.children:
                    left = parent.children[0]
                if left is not None:
                    return self._rightmost_identifier_text(left, source_text)
                return None
            node = parent
        return None

    def _argument_identifier(
        self,
        call_node: Any,
        arg_index: int,
        lang: str,
        source_text: bytes | str,
    ) -> str | None:
        """Return the identifier name of the arg at `arg_index`, if it's a
        plain identifier (not a complex expression).

        This is the deliberately-simple def-use approximation: we only catch
        the case where a source's output is passed DIRECTLY to a sink as an
        identifier. `memcpy(dst, buf, n)` works; `memcpy(dst, buf + 2, n)`
        does not match because `buf + 2` is a binary_expression.
        """
        args_node = None
        try:
            args_node = call_node.child_by_field_name("arguments")
        except Exception:
            pass
        if args_node is None:
            # Fall back: the arguments are typically the last child that's
            # a parenthesized list. Scan children.
            for child in call_node.children:
                if child.type in ("argument_list", "arguments"):
                    args_node = child
                    break
        if args_node is None:
            return None

        # Collect non-punctuation children as the argument expressions
        arg_nodes: list[Any] = []
        for child in args_node.children:
            if child.type in ("(", ")", ","):
                continue
            arg_nodes.append(child)
        if arg_index >= len(arg_nodes):
            return None
        target_arg = arg_nodes[arg_index]
        # Only match plain identifiers (or attribute chains ending in one)
        if target_arg.type in ("identifier", "name"):
            return _node_text(target_arg, source_text)
        # For attribute chains like `self.buf`, take the rightmost identifier
        return self._rightmost_identifier_text(target_arg, source_text)

    def _rightmost_identifier_text(self, node: Any, source_text: bytes | str) -> str | None:
        """Walk a node subtree and return the rightmost identifier token."""
        if node is None:
            return None
        result: str | None = None
        stack = [node]
        while stack:
            n = stack.pop(0)
            if n.type in ("identifier", "name", "field_identifier", "attribute"):
                # For attribute nodes, recurse into children to find the
                # deepest identifier
                if n.type == "attribute":
                    stack[0:0] = list(n.children)
                    continue
                result = _node_text(n, source_text)
            stack[0:0] = list(n.children)
        return result

    def _function_name(self, func_node: Any, lang: str, source_text: bytes | str) -> str | None:
        """Extract the name of the function being defined."""
        try:
            name_field = func_node.child_by_field_name("name")
            if name_field is not None:
                return _node_text(name_field, source_text)
        except Exception:
            pass
        try:
            decl = func_node.child_by_field_name("declarator")
            if decl is not None:
                return self._rightmost_identifier_text(decl, source_text)
        except Exception:
            pass
        return None

    # --- Helpers -----------------------------------------------------------

    def _language_for(self, abs_path: str) -> str | None:
        ext = Path(abs_path).suffix.lower()
        if ext in (".c", ".h"):
            return "c" if "c" in self._languages else None
        if ext in (".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"):
            return "cpp" if "cpp" in self._languages else None
        if ext == ".py":
            return "python" if "python" in self._languages else None
        return None

    def _get_parser(self, lang: str) -> Any:
        if lang not in self._parsers:
            from tree_sitter import Parser

            self._parsers[lang] = Parser(self._languages[lang])
        return self._parsers[lang]

    def _walk(self, repo_path: str) -> Iterator[str]:
        for dirpath, dirnames, filenames in os.walk(repo_path):
            dirnames[:] = [d for d in dirnames if d not in self.SKIP_DIRS]
            for fname in filenames:
                yield os.path.join(dirpath, fname)


# --- Tree-sitter node-type tables ------------------------------------------


_FUNCTION_DEF_TYPES: dict[str, set[str]] = {
    "c": {"function_definition"},
    "cpp": {"function_definition"},
    "python": {"function_definition", "async_function_definition"},
}

_CALL_EXPR_TYPES: dict[str, set[str]] = {
    "c": {"call_expression"},
    "cpp": {"call_expression"},
    "python": {"call"},
}


def _node_text(node: Any, source: Any) -> str:
    """Return the source text spanned by a tree-sitter node.

    Tree-sitter returns BYTE offsets. If `source` is bytes, we slice and
    decode — this is the safe path for any file containing multi-byte
    characters (em-dashes in comments, non-ASCII string literals, etc.).
    If `source` is str, we assume the caller has already guaranteed
    byte == character offsets (ASCII-only); maintained for callers that
    still pass decoded text.
    """
    try:
        if isinstance(source, bytes | bytearray):
            return bytes(source[node.start_byte : node.end_byte]).decode(
                "utf-8",
                errors="replace",
            )
        return str(source[node.start_byte : node.end_byte])
    except Exception:
        return ""


def _load_tree_sitter_languages() -> dict[str, Any]:
    """Lazy-load available tree-sitter grammars. Missing grammars are skipped."""
    langs: dict[str, Any] = {}
    try:
        from tree_sitter import Language
    except ImportError:
        return langs

    grammars = [
        ("c", "tree_sitter_c"),
        ("cpp", "tree_sitter_cpp"),
        ("python", "tree_sitter_python"),
    ]
    for name, module_name in grammars:
        try:
            mod = __import__(module_name)
            langs[name] = Language(mod.language())
        except Exception:
            logger.debug("tree_sitter grammar %s not available", module_name)
    return langs
