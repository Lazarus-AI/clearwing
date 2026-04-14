"""Tree-sitter callgraph builder.

Builds a {file_path → {functions, calls_out, called_by}} mapping from a
cloned repo using language-aware AST parsing. Cheap enough to always-on
in v0.2 preprocessing.

The callgraph powers two signals:
    1. `transitive_callers` — how many files transitively call any function
       defined in this file. Replaces `imports_by` as the primary influence
       signal.
    2. `reachability` — how many hops from an attacker-tagged entry point.
       Propagated one hop at a time from entry files.

Supported languages: c, cpp, python, javascript, go, rust.
"""
from __future__ import annotations

import logging
import os
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# --- Language grammar loading ------------------------------------------------


def _load_languages() -> dict:
    """Load every grammar that's installed. Silently skip missing ones."""
    langs: dict[str, object] = {}
    try:
        from tree_sitter import Language
    except ImportError:
        logger.debug("tree_sitter not installed; callgraph disabled")
        return langs

    grammars = [
        ("c", "tree_sitter_c"),
        ("cpp", "tree_sitter_cpp"),
        ("python", "tree_sitter_python"),
        ("javascript", "tree_sitter_javascript"),
        ("go", "tree_sitter_go"),
        ("rust", "tree_sitter_rust"),
    ]
    for name, module_name in grammars:
        try:
            mod = __import__(module_name)
            langs[name] = Language(mod.language())
        except Exception:
            logger.debug("tree_sitter grammar %s not available", module_name)
    return langs


_LANG_EXT_MAP = {
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".hxx": "cpp",
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".go": "go",
    ".rs": "rust",
}


# --- Per-language query nodes ------------------------------------------------

# We don't use tree_sitter queries here because grammar compatibility varies
# across versions. Instead we walk the AST and pattern-match on node types.
# These sets are empirically chosen from grammar inspection.

_FUNCTION_DEF_NODE_TYPES = {
    "c":          {"function_definition"},
    "cpp":        {"function_definition"},
    "python":     {"function_definition", "async_function_definition"},
    "javascript": {"function_declaration", "method_definition", "arrow_function"},
    "go":         {"function_declaration", "method_declaration"},
    "rust":       {"function_item"},
}

_FUNCTION_CALL_NODE_TYPES = {
    "c":          {"call_expression"},
    "cpp":        {"call_expression"},
    "python":     {"call"},
    "javascript": {"call_expression"},
    "go":         {"call_expression"},
    "rust":       {"call_expression", "macro_invocation"},
}

# Within a function_definition node, the name is reached via different paths
# per language. Walk down the first-child chain looking for an identifier.


# --- Data classes ------------------------------------------------------------


@dataclass
class CallGraph:
    """Callgraph output.

    - `functions[file]` = set of function names defined in that file
    - `calls_out[file]` = set of function names called from that file
    - `defined_in[name]` = set of files that define a function of that name
      (multiple files can shadow the same name, especially in C/C++)
    """
    functions: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    calls_out: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    defined_in: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))

    def callers_of_file(self, target_file: str) -> set[str]:
        """Return the set of files that call any function defined in target_file."""
        target_functions = self.functions.get(target_file, set())
        if not target_functions:
            return set()
        out: set[str] = set()
        for caller_file, called in self.calls_out.items():
            if caller_file == target_file:
                continue
            if called & target_functions:
                out.add(caller_file)
        return out

    def transitive_callers_of_file(self, target_file: str) -> set[str]:
        """Return every file that can reach target_file through the callgraph.

        BFS over the reverse edges. Excludes target_file itself.
        """
        seen: set[str] = set()
        frontier = self.callers_of_file(target_file)
        while frontier:
            new_frontier: set[str] = set()
            for f in frontier:
                if f in seen:
                    continue
                seen.add(f)
                new_frontier |= self.callers_of_file(f)
            frontier = new_frontier - seen
        seen.discard(target_file)
        return seen

    def reachable_from(self, entry_files: set[str], max_depth: int = 8) -> dict[str, int]:
        """BFS forward from entry files. Returns {file: hop_distance}.

        Files not reachable from any entry have no entry in the result.
        `max_depth` caps the BFS depth (default 8).
        """
        distance: dict[str, int] = {f: 0 for f in entry_files}
        frontier = set(entry_files)
        for hop in range(1, max_depth + 1):
            next_frontier: set[str] = set()
            for f in frontier:
                # Files this one calls into
                for called_name in self.calls_out.get(f, set()):
                    for defining_file in self.defined_in.get(called_name, set()):
                        if defining_file in distance:
                            continue
                        distance[defining_file] = hop
                        next_frontier.add(defining_file)
            if not next_frontier:
                break
            frontier = next_frontier
        return distance

    @property
    def empty(self) -> bool:
        return not self.functions


# --- Builder -----------------------------------------------------------------


class CallGraphBuilder:
    """Build a CallGraph by parsing every source file in a repo with tree-sitter."""

    def __init__(self):
        self._languages = _load_languages()
        self._parsers: dict[str, object] = {}

    @property
    def available(self) -> bool:
        """True if tree-sitter and at least one grammar are loaded."""
        return bool(self._languages)

    def build(self, repo_path: str, files: Optional[list[str]] = None) -> CallGraph:
        """Parse all source files in the repo and return a CallGraph.

        Args:
            repo_path: absolute path to the cloned repo.
            files: Optional list of absolute paths to include. If None, walk
                the repo and include every file with a recognised extension.

        Returns a (possibly empty) CallGraph. Errors on individual files are
        logged and skipped.
        """
        graph = CallGraph()
        if not self.available:
            logger.debug("CallGraphBuilder.build: no grammars available")
            return graph

        if files is None:
            files = list(self._walk_repo(repo_path))

        for abs_path in files:
            ext = Path(abs_path).suffix.lower()
            lang_name = _LANG_EXT_MAP.get(ext)
            if lang_name is None or lang_name not in self._languages:
                continue
            try:
                self._ingest_file(abs_path, lang_name, graph, repo_path)
            except Exception:
                logger.debug("Failed to parse %s", abs_path, exc_info=True)

        return graph

    # --- internals ----------------------------------------------------------

    def _get_parser(self, lang_name: str):
        if lang_name not in self._parsers:
            from tree_sitter import Parser
            self._parsers[lang_name] = Parser(self._languages[lang_name])
        return self._parsers[lang_name]

    def _walk_repo(self, repo_path: str):
        skip_dirs = {
            ".git", "node_modules", "__pycache__", ".venv", "venv", "vendor",
            "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", "target",
        }
        for dirpath, dirnames, filenames in os.walk(repo_path):
            dirnames[:] = [d for d in dirnames if d not in skip_dirs]
            for fname in filenames:
                if os.path.splitext(fname)[1].lower() in _LANG_EXT_MAP:
                    yield os.path.join(dirpath, fname)

    def _ingest_file(
        self,
        abs_path: str,
        lang_name: str,
        graph: CallGraph,
        repo_path: str,
    ) -> None:
        try:
            with open(abs_path, "rb") as f:
                source = f.read()
        except OSError:
            return
        if len(source) > 2_000_000:   # skip huge files
            return

        parser = self._get_parser(lang_name)
        tree = parser.parse(source)
        rel_path = os.path.relpath(abs_path, repo_path)

        def_types = _FUNCTION_DEF_NODE_TYPES.get(lang_name, set())
        call_types = _FUNCTION_CALL_NODE_TYPES.get(lang_name, set())

        # Walk the AST iteratively
        stack = [tree.root_node]
        while stack:
            node = stack.pop()

            if node.type in def_types:
                name = self._extract_definition_name(node, lang_name, source)
                if name:
                    graph.functions[rel_path].add(name)
                    graph.defined_in[name].add(rel_path)

            elif node.type in call_types:
                name = self._extract_call_name(node, lang_name, source)
                if name:
                    graph.calls_out[rel_path].add(name)

            # DFS
            stack.extend(node.children)

    def _extract_definition_name(self, node, lang_name: str, source: bytes) -> Optional[str]:
        """Find the name identifier for a function-definition node.

        Walks `child_by_field_name('name')` when available, else searches for
        the first identifier-ish child.
        """
        # tree-sitter supports named fields on most grammars
        for field_name in ("name", "declarator"):
            try:
                sub = node.child_by_field_name(field_name)
            except Exception:
                sub = None
            if sub is None:
                continue
            # The 'declarator' in C wraps the identifier — recurse to find it
            ident = self._first_identifier(sub, source)
            if ident:
                return ident

        # Fallback: the first identifier anywhere in the signature
        return self._first_identifier(node, source)

    def _extract_call_name(self, node, lang_name: str, source: bytes) -> Optional[str]:
        """Find the callee name for a call-expression node.

        For `foo(x)` the name is `foo`.
        For `obj.method(x)` the name is `method` (we record the method name;
        cross-file resolution with types is out of scope for v0.2).
        """
        try:
            sub = node.child_by_field_name("function")
        except Exception:
            sub = None
        if sub is None and node.children:
            sub = node.children[0]
        if sub is None:
            return None

        # Method call: pick the rightmost identifier (the method name)
        ident = self._rightmost_identifier(sub, source)
        return ident

    def _first_identifier(self, node, source: bytes) -> Optional[str]:
        """Return the first identifier token found in node's subtree."""
        if node is None:
            return None
        stack = [node]
        while stack:
            n = stack.pop(0)
            if n.type in ("identifier", "field_identifier", "type_identifier"):
                try:
                    return source[n.start_byte:n.end_byte].decode("utf-8", errors="replace")
                except Exception:
                    return None
            stack[0:0] = list(n.children)
        return None

    def _rightmost_identifier(self, node, source: bytes) -> Optional[str]:
        """Return the rightmost identifier token in node's subtree.

        Used for call sites: `a.b.c()` → `c`.
        """
        if node is None:
            return None
        result: Optional[str] = None
        stack = [node]
        while stack:
            n = stack.pop(0)
            if n.type in ("identifier", "field_identifier", "type_identifier"):
                try:
                    result = source[n.start_byte:n.end_byte].decode("utf-8", errors="replace")
                except Exception:
                    pass
            stack[0:0] = list(n.children)
        return result
