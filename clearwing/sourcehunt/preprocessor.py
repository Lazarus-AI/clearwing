"""Preprocessor: clone, enumerate, statically pre-scan, and tag source files.

Pure code, no LLM. Wraps `clearwing.analysis.SourceAnalyzer` for v0.1 and
exposes seams for v0.2 (tree-sitter callgraph, Semgrep, fuzz corpus auto-detect)
that default to no-ops.

The output is a `PreprocessResult` containing a list of FileTarget entries
ready for the Ranker.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from clearwing.analysis import SourceAnalyzer
from clearwing.analysis.source_analyzer import AnalyzerFinding as StaticFinding

from .callgraph import CallGraph, CallGraphBuilder
from .semgrep_sidecar import SemgrepSidecar
from .semgrep_sidecar import finding_to_dict as _semgrep_finding_to_dict
from .state import FileTag, FileTarget
from .taint import TaintAnalyzer, TaintPath

logger = logging.getLogger(__name__)


@dataclass
class PreprocessResult:
    """Output of the preprocessor — fed into the Ranker."""

    repo_path: str
    file_targets: list[FileTarget]
    static_findings: list[StaticFinding]
    semgrep_findings: list[dict] = field(default_factory=list)  # v0.2
    callgraph: CallGraph | None = None  # v0.2
    fuzz_corpora: list[dict] = field(default_factory=list)  # v0.2
    taint_paths: list[TaintPath] = field(default_factory=list)  # v0.4

    @property
    def file_count(self) -> int:
        return len(self.file_targets)

    @property
    def language_summary(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for ft in self.file_targets:
            lang = ft.get("language", "unknown")
            out[lang] = out.get(lang, 0) + 1
        return out


# --- File tagger heuristics --------------------------------------------------

# Filename → tag heuristics. Order matters: more specific patterns first.
_PARSER_NAME_PATTERNS = re.compile(
    r"(parse|decode|deserialize|unmarshal|read_msg|recv_packet|tokeniz|lex|scan_input)",
    re.IGNORECASE,
)
_CRYPTO_NAME_PATTERNS = re.compile(
    r"(crypto|cipher|hmac|sha\d|md5|aes|rsa|dsa|ecdsa|hash|sign|encrypt|decrypt)",
    re.IGNORECASE,
)
_AUTH_NAME_PATTERNS = re.compile(
    r"(auth|login|session|token|jwt|permission|access_control|acl|rbac|password)",
    re.IGNORECASE,
)
_SYSCALL_NAME_PATTERNS = re.compile(
    r"(ioctl|syscall|netlink|sysfs|kernel)",
    re.IGNORECASE,
)

# Directory-based hints — match path components, not the whole path
_CRYPTO_DIRS = {"crypto", "cryptography", "openssl", "boringssl", "tls", "ssl"}
_AUTH_DIRS = {"auth", "authentication", "authorization", "session", "security"}
_PARSER_DIRS = {"parser", "parsers", "decoder", "decoders", "codec", "codecs", "format"}
_SYSCALL_DIRS = {"kernel", "drivers", "syscalls"}

# C/C++ file extensions → memory_unsafe candidate
_MEMORY_UNSAFE_EXTS = {".c", ".h", ".cpp", ".cc", ".hpp", ".cxx"}

# Source extensions we care about. Extends SourceAnalyzer.LANGUAGE_MAP with
# C/C++/Rust which are first-class targets for the source-hunt pipeline but
# weren't covered by the original network-pentest static analyzer.
_SOURCE_EXTS_TO_LANG: dict[str, str] = {
    **SourceAnalyzer.LANGUAGE_MAP,
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".hxx": "cpp",
    ".rs": "rust",
}


def _tag_file(file_path: str, content_sample: str) -> list[FileTag]:
    """Heuristic file tagger — pure code, no LLM. v0.1.

    Returns a list of FileTag values. v0.2 adds an LLM polish pass on top.
    """
    tags: list[FileTag] = []
    name = os.path.basename(file_path).lower()
    parts = {p.lower() for p in Path(file_path).parts}
    ext = Path(file_path).suffix.lower()

    # memory_unsafe — C/C++ files (we're broad here; the ranker sees the
    # surface signal independently)
    if ext in _MEMORY_UNSAFE_EXTS:
        tags.append("memory_unsafe")

    # parser — name patterns or directory hints
    if _PARSER_NAME_PATTERNS.search(name) or (parts & _PARSER_DIRS):
        tags.append("parser")

    # crypto — name patterns or directory hints
    if _CRYPTO_NAME_PATTERNS.search(name) or (parts & _CRYPTO_DIRS):
        tags.append("crypto")

    # auth_boundary — name patterns or directory hints
    if _AUTH_NAME_PATTERNS.search(name) or (parts & _AUTH_DIRS):
        tags.append("auth_boundary")

    # syscall_entry — name patterns or directory hints
    if _SYSCALL_NAME_PATTERNS.search(name) or (parts & _SYSCALL_DIRS):
        tags.append("syscall_entry")

    # fuzzable — content contains a libFuzzer entry point signature
    if "LLVMFuzzerTestOneInput" in content_sample:
        tags.append("fuzzable")

    return tags


def _file_defines_constants(content_sample: str, language: str) -> bool:
    """True if the file contains top-level constants/macros/typedefs.

    Used as an influence floor — files that define things tend to be load-bearing.
    """
    if language in ("c", "cpp"):
        return bool(re.search(r"^\s*#define\s+\w+", content_sample, re.MULTILINE))
    if language in ("python",):
        return bool(re.search(r"^[A-Z_][A-Z0-9_]*\s*=", content_sample, re.MULTILINE))
    if language in ("javascript", "typescript"):
        return bool(re.search(r"^\s*const\s+[A-Z_]", content_sample, re.MULTILINE))
    if language == "rust":
        return bool(re.search(r"^\s*(const|static)\s+[A-Z_]", content_sample, re.MULTILINE))
    if language == "go":
        return bool(re.search(r"^\s*const\s+[A-Z_]", content_sample, re.MULTILINE))
    return False


def _count_imports_by(repo_path: str, file_path: str, language: str) -> int:
    """Cheap heuristic for `imports_by`: grep the repo for references to this
    file's basename. Used as the v0.1 influence signal until v0.2's tree-sitter
    callgraph lands.
    """
    basename = os.path.basename(file_path)
    stem = os.path.splitext(basename)[0]
    # Build a regex per language for include/import/require patterns
    if language in ("c", "cpp"):
        pattern = re.compile(rf'#\s*include\s*[<"][^>"]*{re.escape(basename)}[>"]')
    elif language == "python":
        pattern = re.compile(rf"\b(?:from|import)\s+\S*\b{re.escape(stem)}\b")
    elif language in ("javascript", "typescript"):
        pattern = re.compile(rf"""(?:import|require)\s*\(?[^"']*['"][^"']*{re.escape(stem)}['"]""")
    elif language == "go":
        pattern = re.compile(rf'"\S*/{re.escape(stem)}"')
    elif language == "rust":
        pattern = re.compile(rf"\b(?:use|mod)\s+{re.escape(stem)}\b")
    elif language == "java":
        pattern = re.compile(rf"\bimport\s+\S*\.{re.escape(stem)}\b")
    else:
        return 0

    count = 0
    for dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = [d for d in dirnames if d not in SourceAnalyzer.SKIP_DIRS]
        for fname in filenames:
            other = os.path.join(dirpath, fname)
            if other == file_path:
                continue
            try:
                if os.path.getsize(other) > SourceAnalyzer.MAX_FILE_SIZE:
                    continue
                with open(other, encoding="utf-8", errors="ignore") as f:
                    head = f.read(64 * 1024)  # only scan the first 64 KB
                if pattern.search(head):
                    count += 1
            except OSError:
                continue
    return count


# --- Preprocessor ------------------------------------------------------------


class Preprocessor:
    """Clone (if needed), enumerate, statically pre-scan, and tag source files.

    v0.1 does: clone + enumerate + SourceAnalyzer pre-scan + cheap file tagger
              + cheap imports_by counts.
    v0.2 will add: tree-sitter callgraph, Semgrep sidecar, fuzz corpus
                   auto-detect, reachability propagation.
    """

    # Static-analysis hits sample this many lines from each file for tagging
    _CONTENT_SAMPLE_BYTES = 16 * 1024

    def __init__(
        self,
        repo_url: str,
        branch: str = "main",
        local_path: str | None = None,
        build_callgraph: bool = False,  # v0.2 seam
        run_semgrep: bool = False,  # v0.2 seam
        tag_files: bool = True,
        propagate_reachability: bool = False,  # v0.2 seam
        ingest_fuzz_corpora: bool = False,  # v0.2 seam
        run_taint: bool = False,  # v0.4: tree-sitter taint analysis
        max_imports_by_files: int = 1000,  # cap the imports_by walk
    ):
        self.repo_url = repo_url
        self.branch = branch
        self.local_path = local_path
        self.build_callgraph = build_callgraph
        self.run_semgrep = run_semgrep
        self.tag_files = tag_files
        self.propagate_reachability = propagate_reachability
        self.ingest_fuzz_corpora = ingest_fuzz_corpora
        self.run_taint = run_taint
        self.max_imports_by_files = max_imports_by_files
        self._analyzer: SourceAnalyzer | None = None

    def run(self) -> PreprocessResult:
        """Execute the full preprocess pipeline. See class docstring."""
        repo_path = self._clone_or_use_local()

        # Pre-scan for static findings — also gives us the file iterator
        self._analyzer = SourceAnalyzer(repo_path=repo_path)
        analysis_result = self._analyzer.analyze()
        static_findings = analysis_result.findings

        # Build per-file static_hint counts
        per_file_hints: dict[str, int] = {}
        for sf in static_findings:
            per_file_hints[sf.file_path] = per_file_hints.get(sf.file_path, 0) + 1

        # Enumerate source files and build FileTarget entries
        file_targets: list[FileTarget] = []
        for abs_path in self._analyzer._iter_source_files(repo_path):
            ext = Path(abs_path).suffix.lower()
            language = _SOURCE_EXTS_TO_LANG.get(ext)
            if not language:
                continue

            try:
                with open(abs_path, encoding="utf-8", errors="ignore") as f:
                    content_sample = f.read(self._CONTENT_SAMPLE_BYTES)
                loc = sum(1 for _ in content_sample.splitlines())
            except OSError:
                continue

            rel_path = os.path.relpath(abs_path, repo_path)

            tags: list[FileTag] = []
            if self.tag_files:
                tags = _tag_file(rel_path, content_sample)

            defines_constants = _file_defines_constants(content_sample, language)

            # v0.1 imports_by — capped to keep large repos snappy
            imports_by = 0
            if len(file_targets) < self.max_imports_by_files:
                imports_by = _count_imports_by(repo_path, abs_path, language)

            target: FileTarget = {
                "path": rel_path,
                "absolute_path": abs_path,
                "surface": 0,  # ranker fills in
                "influence": 0,  # ranker fills in
                "reachability": 3,  # v0.1 default; v0.2 propagates
                "priority": 0.0,  # ranker fills in
                "tier": "C",  # ranker fills in via _assign_tier
                "tags": tags,
                "language": language,
                "loc": loc,
                "surface_rationale": "",
                "influence_rationale": "",
                "reachability_rationale": "",
                "static_hint": per_file_hints.get(abs_path, 0),
                "semgrep_hint": 0,  # v0.2 fills in
                "taint_hits": 0,  # v0.4: taint analyzer fills in
                "imports_by": imports_by,
                "transitive_callers": 0,  # v0.2 fills in
                "defines_constants": defines_constants,
                "has_fuzz_entry_point": "fuzzable" in tags,
                "fuzz_harness_path": None,  # v0.2 fills in
            }
            file_targets.append(target)

        # v0.2 seams
        callgraph: CallGraph | None = None
        semgrep_findings: list[dict] = []
        fuzz_corpora: list[dict] = []

        if self.build_callgraph:
            try:
                builder = CallGraphBuilder()
                if builder.available:
                    callgraph = builder.build(repo_path)
                    self._populate_callgraph_signals(file_targets, callgraph)
                else:
                    logger.info("tree-sitter grammars not available; callgraph skipped")
            except Exception:
                logger.warning("Callgraph build failed", exc_info=True)

        if self.propagate_reachability:
            if callgraph is not None and not callgraph.empty:
                self._propagate_reachability(file_targets, callgraph)
            else:
                logger.info("propagate_reachability=True but no callgraph; skipping")

        if self.run_semgrep:
            try:
                sidecar = SemgrepSidecar()
                if sidecar.available:
                    semgrep_findings_objs = sidecar.run_scan(repo_path)
                    semgrep_findings = [_semgrep_finding_to_dict(f) for f in semgrep_findings_objs]
                    self._apply_semgrep_hints(file_targets, semgrep_findings)
                else:
                    logger.info("Semgrep binary not found; sidecar skipped")
            except Exception:
                logger.warning("Semgrep sidecar failed", exc_info=True)

        if self.ingest_fuzz_corpora:
            logger.info("ingest_fuzz_corpora=True but corpus detection is not wired in yet")

        # v0.4: tree-sitter taint analysis
        taint_paths: list[TaintPath] = []
        if self.run_taint:
            try:
                analyzer = TaintAnalyzer()
                if analyzer.available:
                    taint_result = analyzer.analyze_repo(repo_path)
                    taint_paths = taint_result.paths
                    self._apply_taint_signals(file_targets, taint_paths)
                else:
                    logger.info("tree-sitter grammars not available; taint skipped")
            except Exception:
                logger.warning("Taint analysis failed", exc_info=True)

        return PreprocessResult(
            repo_path=repo_path,
            file_targets=file_targets,
            static_findings=static_findings,
            semgrep_findings=semgrep_findings,
            callgraph=callgraph,
            fuzz_corpora=fuzz_corpora,
            taint_paths=taint_paths,
        )

    # --- v0.4 taint-path signal apply --------------------------------------

    @staticmethod
    def _apply_taint_signals(
        file_targets: list[FileTarget],
        taint_paths: list[TaintPath],
    ) -> None:
        """Count taint paths per file and stamp them onto FileTargets.

        Taint paths are a strong signal that a file has real attacker→sink
        flow. The ranker uses `taint_hits` to promote files with confirmed
        source→sink edges to a higher surface floor (similar to the
        static_hint floor from v0.1).
        """
        counts: dict[str, int] = {}
        for path in taint_paths:
            counts[path.file] = counts.get(path.file, 0) + 1
        for ft in file_targets:
            p = ft.get("path", "")
            if p in counts:
                ft["taint_hits"] = counts[p]

    # --- v0.2 Semgrep hint apply -------------------------------------------

    @staticmethod
    def _apply_semgrep_hints(
        file_targets: list[FileTarget],
        semgrep_findings: list[dict],
    ) -> None:
        """Set `semgrep_hint` count per file from Semgrep findings.

        This becomes a surface-boost signal for the ranker (similar to
        static_hint), and the full findings are later injected into the
        hunter prompt as hints.
        """
        counts: dict[str, int] = {}
        for f in semgrep_findings:
            counts[f["file"]] = counts.get(f["file"], 0) + 1
        for ft in file_targets:
            path = ft.get("path", "")
            if path in counts:
                ft["semgrep_hint"] = counts[path]

    # --- v0.2 callgraph + reachability helpers -----------------------------

    @staticmethod
    def _populate_callgraph_signals(
        file_targets: list[FileTarget],
        callgraph: CallGraph,
    ) -> None:
        """Fill in transitive_callers counts from the callgraph.

        Logs how much the callgraph disagrees with the cheap `imports_by`
        count so future analysis can compare the two signals.
        """
        for ft in file_targets:
            rel = ft.get("path", "")
            if not rel:
                continue
            transitive = callgraph.transitive_callers_of_file(rel)
            ft["transitive_callers"] = len(transitive)

    @staticmethod
    def _propagate_reachability(
        file_targets: list[FileTarget],
        callgraph: CallGraph,
    ) -> None:
        """Walk the callgraph from entry-tagged files and set `reachability`.

        Reachability score (1-5):
            1 — not reachable from any tagged entry point
            2 — reachable at distance >= 4
            3 — reachable at distance 2-3 (v0.1 default for everything)
            4 — reachable at distance 1
            5 — IS an entry point
        """
        # Collect entry points: files tagged parser, fuzzable, or syscall_entry
        ft_by_path = {ft.get("path", ""): ft for ft in file_targets}
        entry_files: set[str] = set()
        for ft in file_targets:
            tags = set(ft.get("tags", []))
            if tags & {"parser", "fuzzable", "syscall_entry"}:
                entry_files.add(ft.get("path", ""))

        if not entry_files:
            # No entry-tagged files — leave reachability at default (3)
            return

        distances = callgraph.reachable_from(entry_files, max_depth=8)

        for path, ft in ft_by_path.items():
            if path in entry_files:
                ft["reachability"] = 5
                ft["reachability_rationale"] = "entry point (parser/fuzzable/syscall)"
                continue
            dist = distances.get(path)
            if dist is None:
                ft["reachability"] = 1
                ft["reachability_rationale"] = "not reachable from any entry point"
                # Also tag it (attacker_reachable is the opposite signal)
            elif dist == 1:
                ft["reachability"] = 4
                ft["reachability_rationale"] = "directly called by an entry point"
                tag_list = list(ft.get("tags", []))
                if "attacker_reachable" not in tag_list:
                    tag_list.append("attacker_reachable")
                    ft["tags"] = tag_list
            elif dist <= 3:
                ft["reachability"] = 3
                ft["reachability_rationale"] = f"reachable at distance {dist}"
                tag_list = list(ft.get("tags", []))
                if "attacker_reachable" not in tag_list:
                    tag_list.append("attacker_reachable")
                    ft["tags"] = tag_list
            else:
                ft["reachability"] = 2
                ft["reachability_rationale"] = f"reachable at distance {dist}"

    def cleanup(self) -> None:
        """Clean up the cloned repo (if we cloned one)."""
        if self._analyzer is not None:
            try:
                self._analyzer.cleanup()
            except Exception:
                logger.debug("Preprocessor cleanup failed", exc_info=True)

    def _clone_or_use_local(self) -> str:
        """Return the repo path. Clones if repo_url is a git URL."""
        if self.local_path:
            if not os.path.isdir(self.local_path):
                raise ValueError(f"local_path does not exist: {self.local_path}")
            return os.path.abspath(self.local_path)

        # Heuristic: looks like a git URL?
        if self._is_git_url(self.repo_url):
            self._analyzer = SourceAnalyzer()
            return self._analyzer.clone(self.repo_url, branch=self.branch)

        # Otherwise treat repo_url as a local path
        if os.path.isdir(self.repo_url):
            return os.path.abspath(self.repo_url)

        raise ValueError(
            f"repo_url is neither a git URL nor an existing local path: {self.repo_url}"
        )

    @staticmethod
    def _is_git_url(s: str) -> bool:
        return (
            s.startswith("http://")
            or s.startswith("https://")
            or s.startswith("git@")
            or s.startswith("ssh://")
            or s.endswith(".git")
        )
