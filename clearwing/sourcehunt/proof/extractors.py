"""Mechanical, completeness-aware source fact extraction."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from .models import (
    CompletenessItem,
    CompletenessManifest,
    CompletenessStatus,
    Fact,
    Provenance,
    SourceLocation,
)
from .normalization import FactNormalizer
from .store import ProofStore

SUPPORTED_LANGUAGES = frozenset(
    {
        "c",
        "cpp",
        "python",
        "javascript",
        "typescript",
        "php",
        "java",
        "ruby",
        "go",
        "rust",
        "csharp",
    }
)

LANGUAGE_BY_EXTENSION = {
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
    ".ts": "typescript",
    ".tsx": "typescript",
    ".php": "php",
    ".java": "java",
    ".rb": "ruby",
    ".go": "go",
    ".rs": "rust",
    ".cs": "csharp",
}

_C_FAMILY = {"c", "cpp"}
_C_TRANSLATION_UNITS = {".c", ".cpp", ".cc", ".cxx"}
_SKIP_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    "target",
    "dist",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
}


class ProofPreflightError(RuntimeError):
    """A required mechanical analysis backend is absent or unusable."""

    def __init__(self, message: str, *, missing: Sequence[str] = ()):
        super().__init__(message)
        self.missing = tuple(missing)


@dataclass(frozen=True)
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False


class CommandRunner(Protocol):
    """Execution boundary for untrusted compilation commands."""

    sandboxed: bool
    identity: str

    def run(
        self,
        arguments: Sequence[str],
        *,
        cwd: Path,
        timeout: int,
    ) -> CommandResult: ...

    def map_path(self, path: Path) -> str: ...

    def write_file(self, path: str, content: bytes) -> None:
        """Write a generated validation artifact inside the sandbox."""

        ...


class LocalCommandRunner:
    """Explicit opt-in local runner, intended for trusted fixtures only."""

    sandboxed = False
    identity = "trusted-local-subprocess"

    def run(
        self,
        arguments: Sequence[str],
        *,
        cwd: Path,
        timeout: int,
    ) -> CommandResult:
        try:
            result = subprocess.run(
                list(arguments),
                cwd=cwd,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            return CommandResult(
                exit_code=124,
                stdout=_command_text(exc.stdout),
                stderr=_command_text(exc.stderr),
                timed_out=True,
            )
        return CommandResult(
            exit_code=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )

    def map_path(self, path: Path) -> str:
        return os.fspath(path)


class SandboxCommandRunner:
    """Adapter for a no-network §SandboxContainer§."""

    sandboxed = True
    identity = "clearwing-sandbox"

    def __init__(
        self,
        container: Any,
        *,
        host_root: str | Path,
        sandbox_root: str = "/workspace",
    ):
        self.container = container
        self.host_root = Path(host_root).resolve()
        self.sandbox_root = Path(sandbox_root)

    def map_path(self, path: Path) -> str:
        resolved = path.resolve()
        try:
            relative = resolved.relative_to(self.host_root)
        except ValueError as exc:
            raise ProofPreflightError(
                f"Compilation path is outside the sandboxed repository: {path}"
            ) from exc
        return (self.sandbox_root / relative).as_posix()

    def run(
        self,
        arguments: Sequence[str],
        *,
        cwd: Path,
        timeout: int,
    ) -> CommandResult:
        result = self.container.exec(
            list(arguments),
            timeout=timeout,
            workdir=self.map_path(cwd),
        )
        return CommandResult(
            exit_code=int(result.exit_code),
            stdout=str(result.stdout),
            stderr=str(result.stderr),
            timed_out=bool(result.timed_out),
        )

    def write_file(self, path: str, content: bytes) -> None:
        if not path.startswith("/scratch/") or ".." in Path(path).parts:
            raise ProofPreflightError("Generated files must remain under /scratch")
        self.container.write_file(path, content)


@dataclass(frozen=True)
class CompilationCommand:
    file: Path
    directory: Path
    arguments: tuple[str, ...]


class CompilationDatabase:
    """Validated view of §compile_commands.json§."""

    def __init__(self, path: str | Path, repo_root: str | Path):
        self.path = Path(path).expanduser().resolve()
        self.repo_root = Path(repo_root).resolve()
        if not self.path.is_file():
            raise ProofPreflightError(
                f"C/C++ proof flow requires a compilation database: {self.path}",
                missing=("compile_commands.json",),
            )
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProofPreflightError(
                f"Invalid compilation database {self.path}: {exc}",
                missing=("valid_compile_commands.json",),
            ) from exc
        if not isinstance(raw, list):
            raise ProofPreflightError("Compilation database root must be a JSON array")
        commands: list[CompilationCommand] = []
        for index, entry in enumerate(raw):
            if not isinstance(entry, dict):
                raise ProofPreflightError(f"Compilation database entry {index} is not an object")
            directory = Path(str(entry.get("directory") or self.repo_root))
            if not directory.is_absolute():
                directory = self.repo_root / directory
            file_path = Path(str(entry.get("file") or ""))
            if not file_path.is_absolute():
                file_path = directory / file_path
            arguments = entry.get("arguments")
            if arguments is None and isinstance(entry.get("command"), str):
                arguments = shlex.split(entry["command"])
            if not isinstance(arguments, list) or not all(
                isinstance(argument, str) for argument in arguments
            ):
                raise ProofPreflightError(
                    f"Compilation database entry {index} has no valid command"
                )
            commands.append(
                CompilationCommand(
                    file=file_path.resolve(),
                    directory=directory.resolve(),
                    arguments=tuple(arguments),
                )
            )
        if not commands:
            raise ProofPreflightError("Compilation database contains no commands")
        self.commands = commands

    def for_translation_units(self, paths: set[Path]) -> list[CompilationCommand]:
        resolved = {path.resolve() for path in paths}
        return [command for command in self.commands if command.file in resolved]


@dataclass(frozen=True)
class ExtractionConfig:
    compile_commands: str | Path | None = None
    clang_binary: str = "clang"
    require_sandboxed_clang: bool = True
    clang_timeout_seconds: int = 120
    max_source_bytes: int = 8 * 1024 * 1024
    build_configuration: str = "default"


@dataclass
class ExtractionResult:
    facts: list[Fact]
    completeness: CompletenessManifest
    languages: dict[str, int]
    files_seen: int
    files_analyzed: int
    errors: list[dict[str, Any]] = field(default_factory=list)


class FactExtractor:
    """Emit normalized facts without making vulnerability conclusions."""

    def __init__(
        self,
        repo_path: str | Path,
        snapshot_id: str,
        *,
        store: ProofStore | None = None,
        config: ExtractionConfig | None = None,
        command_runner: CommandRunner | None = None,
    ):
        self.root = Path(repo_path).expanduser().resolve()
        self.snapshot_id = snapshot_id
        self.store = store
        self.config = config or ExtractionConfig()
        self.command_runner = command_runner

    def extract(self) -> ExtractionResult:
        files = list(self._source_files())
        languages: dict[str, int] = {}
        for _path, language in files:
            languages[language] = languages.get(language, 0) + 1

        c_files = [(path, language) for path, language in files if language in _C_FAMILY]
        compilation_db: CompilationDatabase | None = None
        clang_version = ""
        clang_facts: list[Fact] = []
        clang_errors: list[dict[str, Any]] = []
        clang_analyzed: set[Path] = set()
        if c_files:
            compilation_db, clang_version = self._clang_preflight()
            clang_facts, clang_errors, clang_analyzed = self._extract_clang(
                compilation_db,
                clang_version,
                {path for path, _ in c_files if path.suffix.lower() in _C_TRANSLATION_UNITS},
            )

        facts: list[Fact] = []
        errors: list[dict[str, Any]] = list(clang_errors)
        files_analyzed = 0
        for path, language in files:
            try:
                size = path.stat().st_size
                if size > self.config.max_source_bytes:
                    errors.append(
                        {
                            "file": self._relative(path),
                            "stage": "source_read",
                            "reason": "file_too_large",
                            "bytes": size,
                        }
                    )
                    continue
                source = path.read_text(encoding="utf-8", errors="replace")
                digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
                facts.extend(self._lexical_facts(path, language, source, digest))
                files_analyzed += 1
            except OSError as exc:
                errors.append(
                    {
                        "file": self._relative(path),
                        "stage": "source_read",
                        "reason": str(exc),
                    }
                )

        facts.extend(clang_facts)
        structural_facts, structural_analysis, structural_errors = self._structural_facts(files)
        facts.extend(structural_facts)
        errors.extend(structural_errors)
        facts = FactNormalizer().normalize(_deduplicate_facts(facts))
        completeness = self._completeness(
            files=files,
            files_analyzed=files_analyzed,
            c_files=c_files,
            compilation_db=compilation_db,
            clang_analyzed=clang_analyzed,
            clang_errors=clang_errors,
            errors=errors,
            structural_analysis=structural_analysis,
        )
        result = ExtractionResult(
            facts=facts,
            completeness=completeness,
            languages=languages,
            files_seen=len(files),
            files_analyzed=files_analyzed,
            errors=errors,
        )
        if self.store is not None:
            self.store.append_many(facts)
            self.store.write_json(
                "facts/extraction-coverage.json",
                {
                    "snapshot_id": self.snapshot_id,
                    "languages": languages,
                    "files_seen": len(files),
                    "files_analyzed": files_analyzed,
                    "items": completeness.model_dump(mode="json")["items"],
                    "errors": errors,
                },
            )
        return result

    def _structural_facts(
        self,
        files: list[tuple[Path, str]],
    ) -> tuple[list[Fact], dict[str, Any], list[dict[str, Any]]]:
        """Reuse language-aware analyzers as facts, never conclusions."""

        facts: list[Fact] = []
        errors: list[dict[str, Any]] = []
        analysis: dict[str, Any] = {
            "callgraph_available": False,
            "callgraph_files": 0,
            "taint_available": False,
            "taint_files": 0,
            "taint_paths": 0,
        }
        paths = [str(path) for path, _language in files]
        try:
            from ..callgraph import CallGraphBuilder

            builder = CallGraphBuilder()
            analysis["callgraph_available"] = builder.available
            if builder.available:
                graph = builder.build(str(self.root), files=paths)
                analysis["callgraph_files"] = len(graph.function_info)
                provenance = Provenance(
                    producer="tree-sitter-callgraph",
                    producer_version="1",
                )
                for relative, functions in graph.function_info.items():
                    for function in functions:
                        facts.append(
                            Fact(
                                snapshot_id=self.snapshot_id,
                                kind="function_range",
                                subject=function.name,
                                properties={
                                    "start_line": function.start_line,
                                    "end_line": function.end_line,
                                },
                                location=SourceLocation(
                                    file=relative,
                                    line=function.start_line,
                                    end_line=function.end_line,
                                    function=function.name,
                                ),
                                provenance=provenance,
                            )
                        )
                for caller_file, callees in graph.calls_out.items():
                    for callee in sorted(callees):
                        facts.append(
                            Fact(
                                snapshot_id=self.snapshot_id,
                                kind="call_edge",
                                subject=caller_file,
                                predicate="calls",
                                object=callee,
                                properties={
                                    "callee": callee,
                                    "possible_target_files": sorted(
                                        graph.defined_in.get(callee, set())
                                    ),
                                    "resolution": (
                                        "name-based-direct-call"
                                        if graph.defined_in.get(callee)
                                        else "external-or-unresolved"
                                    ),
                                },
                                location=SourceLocation(file=caller_file),
                                provenance=provenance,
                            )
                        )
        except Exception as exc:
            errors.append(
                {
                    "stage": "tree_sitter_callgraph",
                    "reason": str(exc),
                }
            )

        try:
            from ..taint import TaintAnalyzer

            analyzer = TaintAnalyzer()
            analysis["taint_available"] = analyzer.available
            if analyzer.available:
                result = analyzer.analyze_repo(str(self.root), files=paths)
                analysis["taint_files"] = result.files_analyzed
                analysis["taint_paths"] = len(result.paths)
                provenance = Provenance(
                    producer="tree-sitter-taint",
                    producer_version="1",
                )
                for path in result.paths:
                    facts.append(
                        Fact(
                            snapshot_id=self.snapshot_id,
                            kind="taint_path",
                            subject=path.variable,
                            predicate="source_reaches_sink",
                            object=path.sink_function,
                            properties={
                                "language": path.language,
                                "source_function": path.source_function,
                                "source_line": path.source_line,
                                "sink_function": path.sink_function,
                                "sink_line": path.sink_line,
                                "variable": path.variable,
                                "cwe": path.sink_cwe,
                                "description": path.sink_description,
                                "severity": path.severity,
                                "expression": (
                                    f"{path.source_function} -> "
                                    f"{path.sink_function} via {path.variable}"
                                ),
                            },
                            location=SourceLocation(
                                file=path.file,
                                line=path.source_line,
                                end_line=max(path.source_line, path.sink_line),
                                function=path.containing_function,
                            ),
                            provenance=provenance,
                        )
                    )
        except Exception as exc:
            errors.append(
                {
                    "stage": "tree_sitter_taint",
                    "reason": str(exc),
                }
            )
        return facts, analysis, errors

    def _clang_preflight(self) -> tuple[CompilationDatabase, str]:
        runner = self.command_runner
        if runner is None:
            raise ProofPreflightError(
                "C/C++ proof flow requires a Clang command runner",
                missing=("sandboxed_clang_runner",),
            )
        if self.config.require_sandboxed_clang and not runner.sandboxed:
            raise ProofPreflightError(
                "C/C++ proof flow refuses to execute compilation commands outside "
                "an isolated sandbox",
                missing=("sandboxed_clang_runner",),
            )
        compile_commands = (
            Path(self.config.compile_commands)
            if self.config.compile_commands is not None
            else self.root / "compile_commands.json"
        )
        database = CompilationDatabase(compile_commands, self.root)
        version_result = runner.run(
            [self.config.clang_binary, "--version"],
            cwd=self.root,
            timeout=20,
        )
        if version_result.exit_code != 0:
            raise ProofPreflightError(
                "C/C++ proof flow requires runnable Clang in the analysis sandbox",
                missing=("clang",),
            )
        version = version_result.stdout.splitlines()[0] if version_result.stdout else "clang"
        return database, version

    def _extract_clang(
        self,
        database: CompilationDatabase,
        clang_version: str,
        translation_units: set[Path],
    ) -> tuple[list[Fact], list[dict[str, Any]], set[Path]]:
        runner = self.command_runner
        assert runner is not None
        commands = database.for_translation_units(translation_units)
        missing = translation_units - {command.file for command in commands}
        errors = [
            {
                "file": self._relative(path),
                "stage": "clang_ast",
                "reason": "missing_compilation_command",
            }
            for path in sorted(missing)
        ]
        facts: list[Fact] = []
        analyzed: set[Path] = set()
        for command in commands:
            try:
                arguments = self._clang_ast_arguments(command)
            except ProofPreflightError as exc:
                errors.append(
                    {
                        "file": self._relative(command.file),
                        "stage": "clang_ast",
                        "reason": str(exc),
                    }
                )
                continue
            result = runner.run(
                arguments,
                cwd=command.directory,
                timeout=self.config.clang_timeout_seconds,
            )
            if result.exit_code != 0:
                errors.append(
                    {
                        "file": self._relative(command.file),
                        "stage": "clang_ast",
                        "reason": "timed_out" if result.timed_out else "clang_failed",
                        "stderr": result.stderr[-4000:],
                    }
                )
                continue
            try:
                ast = json.loads(result.stdout)
            except json.JSONDecodeError as exc:
                errors.append(
                    {
                        "file": self._relative(command.file),
                        "stage": "clang_ast",
                        "reason": f"invalid_ast_json: {exc}",
                    }
                )
                continue
            analyzed.add(command.file)
            facts.extend(
                self._facts_from_clang_ast(
                    ast,
                    command.file,
                    clang_version,
                    arguments,
                )
            )
        if commands and not analyzed:
            raise ProofPreflightError(
                "Clang could not analyze any C/C++ translation unit; inspect "
                "facts/extraction-coverage.json for command failures",
                missing=("usable_clang_ast",),
            )
        return facts, errors, analyzed

    def _clang_ast_arguments(self, command: CompilationCommand) -> list[str]:
        original = list(command.arguments)
        if not original:
            raise ProofPreflightError("Empty compilation command")
        if Path(original[0]).name in {"ccache", "sccache"}:
            original.pop(0)
        if not original:
            raise ProofPreflightError("Compilation command contains no compiler")
        dangerous = {
            "-fplugin",
            "-fplugin-arg",
            "-load",
            "--config",
            "-wrapper",
        }
        filtered: list[str] = []
        skip_next = False
        for index, argument in enumerate(original[1:]):
            if skip_next:
                skip_next = False
                continue
            if argument.startswith("@"):
                raise ProofPreflightError("Response files are not permitted in proof extraction")
            if any(argument == flag or argument.startswith(f"{flag}=") for flag in dangerous):
                raise ProofPreflightError(
                    f"Compilation option is not permitted in proof extraction: {argument}"
                )
            if argument in {"-o", "-MF", "-MT", "-MQ"}:
                skip_next = True
                continue
            if argument in {"-c", "-MMD", "-MD", "-MP"}:
                continue
            if argument == "-Xclang" and index + 2 <= len(original):
                raise ProofPreflightError(
                    "Pre-existing -Xclang options are not permitted in proof extraction"
                )
            filtered.append(self._map_argument_path(argument, command.directory))

        extension = command.file.suffix.lower()
        compiler = "clang++" if extension in {".cpp", ".cc", ".cxx"} else self.config.clang_binary
        mapped_file = (
            self.command_runner.map_path(command.file) if self.command_runner else str(command.file)
        )
        if not any(_same_source_argument(argument, mapped_file) for argument in filtered):
            filtered.append(mapped_file)
        return [
            compiler,
            *filtered,
            "-fsyntax-only",
            "-Xclang",
            "-ast-dump=json",
        ]

    def _map_argument_path(self, argument: str, directory: Path) -> str:
        runner = self.command_runner
        assert runner is not None
        prefixes = ("-I", "-isystem", "-iquote")
        for prefix in prefixes:
            if argument.startswith(prefix) and len(argument) > len(prefix):
                value = Path(argument[len(prefix) :])
                if not value.is_absolute():
                    value = directory / value
                try:
                    return prefix + runner.map_path(value)
                except ProofPreflightError:
                    return argument
        candidate = Path(argument)
        if candidate.is_absolute():
            try:
                return runner.map_path(candidate)
            except ProofPreflightError:
                return argument
        return argument

    def _facts_from_clang_ast(
        self,
        ast: dict[str, Any],
        translation_unit: Path,
        clang_version: str,
        command: list[str],
    ) -> list[Fact]:
        relative_tu = self._relative(translation_unit)
        provenance = Provenance(
            producer="clang-ast",
            producer_version=clang_version,
            command=command,
            environment_digest=getattr(self.command_runner, "identity", ""),
        )
        facts: list[Fact] = []
        interesting = {
            "VarDecl": "variable",
            "FieldDecl": "field",
            "ParmVarDecl": "parameter",
            "FunctionDecl": "function",
            "IntegerLiteral": "integer_literal",
            "BinaryOperator": "operation",
            "CompoundAssignOperator": "operation",
            "UnaryOperator": "operation",
            "CallExpr": "call",
            "ArraySubscriptExpr": "memory_access",
            "CStyleCastExpr": "cast",
            "ImplicitCastExpr": "cast",
        }
        for node in _walk_ast(ast):
            kind = str(node.get("kind") or "")
            fact_kind = interesting.get(kind)
            if fact_kind is None:
                continue
            location = _clang_location(node, relative_tu, self.root)
            if location is None:
                continue
            raw_type_info = node.get("type")
            type_info: dict[str, Any] = raw_type_info if isinstance(raw_type_info, dict) else {}
            qual_type = str(type_info.get("qualType") or "")
            properties: dict[str, Any] = {
                "ast_kind": kind,
                "name": str(node.get("name") or ""),
                "type": qual_type,
            }
            for key in ("value", "opcode", "valueCategory", "isPostfix"):
                if key in node:
                    properties[key] = node[key]
            width = _integer_width(qual_type)
            if width is not None:
                properties["integer_width"] = width
            facts.append(
                Fact(
                    snapshot_id=self.snapshot_id,
                    kind=fact_kind,
                    subject=str(node.get("name") or f"{relative_tu}:{location.line}"),
                    predicate=kind,
                    properties=properties,
                    location=location,
                    provenance=provenance,
                )
            )
        return facts

    def _lexical_facts(  # noqa: C901
        self,
        path: Path,
        language: str,
        source: str,
        digest: str,
    ) -> list[Fact]:
        relative = self._relative(path)
        provenance = Provenance(
            producer=f"{language}-syntax-adapter",
            producer_version="1",
            source_digest=digest,
        )
        lines = source.splitlines()
        facts = [
            Fact(
                snapshot_id=self.snapshot_id,
                kind="source_file",
                subject=relative,
                properties={
                    "language": language,
                    "bytes": len(source.encode("utf-8")),
                    "lines": len(lines),
                    "digest": digest,
                },
                location=SourceLocation(file=relative),
                provenance=provenance,
            )
        ]
        current_function = ""
        for line_number, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("//", "#", "/*", "*")):
                continue
            function = _function_name(stripped, language)
            if function:
                current_function = function
                facts.append(
                    self._line_fact(
                        "function",
                        function,
                        path,
                        line_number,
                        current_function,
                        provenance,
                        language=language,
                        excerpt=stripped,
                    )
                )
            declaration = _typed_declaration(stripped)
            if declaration:
                declared_type, name = declaration
                properties: dict[str, Any] = {
                    "language": language,
                    "type": declared_type,
                    "excerpt": stripped,
                }
                width = _integer_width(declared_type)
                if width is not None:
                    properties["integer_width"] = width
                facts.append(
                    self._line_fact(
                        "variable",
                        name,
                        path,
                        line_number,
                        current_function,
                        provenance,
                        **properties,
                    )
                )
            if _GUARD_PATTERN.search(stripped):
                following = " ".join(item.strip() for item in lines[line_number : line_number + 3])
                facts.append(
                    self._line_fact(
                        "guard",
                        f"{relative}:{line_number}",
                        path,
                        line_number,
                        current_function,
                        provenance,
                        language=language,
                        expression=stripped,
                        operators=_comparison_operators(stripped),
                        control_effect=(_first_control_effect(f"{stripped} {following}")),
                    )
                )
            if _SENTINEL_PATTERN.search(stripped):
                facts.append(
                    self._line_fact(
                        "sentinel_use",
                        f"{relative}:{line_number}",
                        path,
                        line_number,
                        current_function,
                        provenance,
                        language=language,
                        expression=stripped,
                        values=_sentinel_values(stripped),
                    )
                )
            assignment = _assignment(stripped)
            if assignment:
                lhs, rhs = assignment
                facts.append(
                    self._line_fact(
                        "assignment",
                        lhs,
                        path,
                        line_number,
                        current_function,
                        provenance,
                        language=language,
                        lhs=lhs,
                        rhs=rhs,
                        excerpt=stripped,
                    )
                )
            if _COUNTER_UPDATE_PATTERN.search(stripped):
                facts.append(
                    self._line_fact(
                        "counter_update",
                        f"{relative}:{line_number}",
                        path,
                        line_number,
                        current_function,
                        provenance,
                        language=language,
                        expression=stripped,
                    )
                )
            if _LOOP_PATTERN.search(stripped):
                facts.append(
                    self._line_fact(
                        "loop",
                        f"{relative}:{line_number}",
                        path,
                        line_number,
                        current_function,
                        provenance,
                        language=language,
                        expression=stripped,
                    )
                )
            if _ALLOCATION_PATTERN.search(stripped):
                facts.append(
                    self._line_fact(
                        "allocation",
                        f"{relative}:{line_number}",
                        path,
                        line_number,
                        current_function,
                        provenance,
                        language=language,
                        expression=stripped,
                    )
                )
            if _MEMORY_WRITE_PATTERN.search(stripped):
                facts.append(
                    self._line_fact(
                        "memory_write",
                        f"{relative}:{line_number}",
                        path,
                        line_number,
                        current_function,
                        provenance,
                        language=language,
                        expression=stripped,
                    )
                )
            if _ARRAY_ACCESS_PATTERN.search(stripped):
                facts.append(
                    self._line_fact(
                        "memory_access",
                        f"{relative}:{line_number}",
                        path,
                        line_number,
                        current_function,
                        provenance,
                        language=language,
                        expression=stripped,
                    )
                )
            if _CAST_PATTERN.search(stripped):
                facts.append(
                    self._line_fact(
                        "cast",
                        f"{relative}:{line_number}",
                        path,
                        line_number,
                        current_function,
                        provenance,
                        language=language,
                        expression=stripped,
                    )
                )
            for called in _call_names(stripped):
                if called not in _CONTROL_WORDS:
                    facts.append(
                        self._line_fact(
                            "call",
                            current_function or relative,
                            path,
                            line_number,
                            current_function,
                            provenance,
                            language=language,
                            callee=called,
                            excerpt=stripped,
                        )
                    )
        return facts

    def _line_fact(
        self,
        kind: str,
        subject: str,
        path: Path,
        line: int,
        function: str,
        provenance: Provenance,
        **properties: Any,
    ) -> Fact:
        return Fact(
            snapshot_id=self.snapshot_id,
            kind=kind,
            subject=subject,
            properties=properties,
            location=SourceLocation(
                file=self._relative(path),
                line=line,
                function=function,
            ),
            provenance=provenance,
        )

    def _completeness(
        self,
        *,
        files: list[tuple[Path, str]],
        files_analyzed: int,
        c_files: list[tuple[Path, str]],
        compilation_db: CompilationDatabase | None,
        clang_analyzed: set[Path],
        clang_errors: list[dict[str, Any]],
        errors: list[dict[str, Any]],
        structural_analysis: dict[str, Any],
    ) -> CompletenessManifest:
        translation_units = {
            path for path, _ in c_files if path.suffix.lower() in _C_TRANSLATION_UNITS
        }
        inventory_status = (
            CompletenessStatus.COMPLETE
            if files_analyzed == len(files)
            else CompletenessStatus.PARTIAL
        )
        if not c_files:
            compilation_item = CompletenessItem(
                status=CompletenessStatus.NOT_APPLICABLE,
                basis="repository contains no C/C++ source",
            )
            type_item = CompletenessItem(
                status=CompletenessStatus.PARTIAL,
                basis="language syntax adapters",
                limitations=["dynamic and generic types are not fully resolved"],
            )
            macro_item = CompletenessItem(
                status=CompletenessStatus.NOT_APPLICABLE,
                basis="no C/C++ preprocessing",
            )
        else:
            analyzed_all = translation_units <= clang_analyzed
            compilation_item = CompletenessItem(
                status=(
                    CompletenessStatus.COMPLETE if analyzed_all else CompletenessStatus.PARTIAL
                ),
                basis=str(compilation_db.path) if compilation_db else "",
                limitations=[] if analyzed_all else ["some translation units were unresolved"],
                unresolved=[
                    str(error.get("file", "")) for error in clang_errors if error.get("file")
                ],
            )
            type_item = CompletenessItem(
                status=(
                    CompletenessStatus.COMPLETE if analyzed_all else CompletenessStatus.PARTIAL
                ),
                basis="clang-ast",
                limitations=[] if analyzed_all else ["failed translation units"],
            )
            macro_item = CompletenessItem(
                status=CompletenessStatus.PARTIAL,
                basis="clang compilation commands",
                limitations=["macro definitions are compiled but not all expansions are retained"],
            )
        return CompletenessManifest(
            snapshot_id=self.snapshot_id,
            items={
                "source_inventory": CompletenessItem(
                    status=inventory_status,
                    basis="extension inventory",
                    unresolved=[
                        str(error.get("file", ""))
                        for error in errors
                        if error.get("stage") == "source_read"
                    ],
                ),
                "syntax_trees": CompletenessItem(
                    status=inventory_status,
                    basis="language syntax adapters plus clang-ast for C/C++",
                    limitations=(
                        []
                        if inventory_status == CompletenessStatus.COMPLETE
                        else ["some files were unreadable or exceeded the configured size"]
                    ),
                ),
                "types": type_item,
                "macro_expansions": macro_item,
                "compilation_database": compilation_item,
                "direct_calls": CompletenessItem(
                    status=CompletenessStatus.PARTIAL,
                    basis=(
                        "tree-sitter name-resolved callgraph"
                        if structural_analysis["callgraph_available"]
                        else "syntax adapters"
                    ),
                    limitations=["overload and dynamic dispatch resolution is incomplete"],
                ),
                "indirect_calls": CompletenessItem(
                    status=CompletenessStatus.UNRESOLVED,
                    basis="no whole-program points-to analysis",
                    unresolved=["callbacks", "virtual dispatch", "function pointers"],
                ),
                "data_dependencies": CompletenessItem(
                    status=CompletenessStatus.PARTIAL,
                    basis=(
                        "assignments plus tree-sitter intraprocedural taint"
                        if structural_analysis["taint_available"]
                        else "assignments and syntax-level expressions"
                    ),
                    limitations=[
                        "interprocedural aliases and field-sensitive flows are unresolved"
                    ],
                ),
                "taint_paths": CompletenessItem(
                    status=(
                        CompletenessStatus.PARTIAL
                        if structural_analysis["taint_available"]
                        else CompletenessStatus.NOT_AVAILABLE
                    ),
                    basis="tree-sitter intraprocedural source/sink analysis",
                    limitations=[
                        "absence of a path is not evidence of absence",
                        "pattern coverage is language and API dependent",
                    ],
                ),
                "control_dominators": CompletenessItem(
                    status=CompletenessStatus.NOT_AVAILABLE,
                    basis="CFG backend not yet run",
                ),
                "configuration_variants": CompletenessItem(
                    status=CompletenessStatus.PARTIAL,
                    basis=self.config.build_configuration,
                    limitations=["only the selected build configuration was analyzed"],
                ),
                "memory_fact_normalization": CompletenessItem(
                    status=CompletenessStatus.COMPLETE,
                    basis="proof-fact-normalizer schema v1",
                ),
                "parser_ranges": CompletenessItem(
                    status=CompletenessStatus.PARTIAL,
                    basis="normalized guards, offsets, and extents",
                    limitations=["path-sensitive arithmetic ranges require a range backend"],
                ),
                "authorization_paths": CompletenessItem(
                    status=CompletenessStatus.PARTIAL,
                    basis="policy-like guards and callgraph facts",
                    limitations=[
                        "framework middleware and indirect policy hooks may be unresolved"
                    ],
                ),
                "lifetime_analysis": CompletenessItem(
                    status=CompletenessStatus.NOT_AVAILABLE,
                    basis="release/use syntax events only",
                    limitations=["alias-aware ownership and lifetime analysis was not run"],
                ),
                "state_models": CompletenessItem(
                    status=CompletenessStatus.NOT_AVAILABLE,
                    basis="state assignments only",
                    limitations=["no bounded transition model was supplied"],
                ),
                "cryptographic_contracts": CompletenessItem(
                    status=CompletenessStatus.PARTIAL,
                    basis="cryptographic API syntax markers",
                    limitations=["construction-specific security properties require contracts"],
                ),
                "encoding_analysis": CompletenessItem(
                    status=CompletenessStatus.PARTIAL,
                    basis="interpreter calls and intraprocedural taint",
                    limitations=["context-correct encoding and framework parameterization vary"],
                ),
                "concurrency_analysis": CompletenessItem(
                    status=CompletenessStatus.NOT_AVAILABLE,
                    basis="thread and synchronization syntax markers",
                    limitations=["happens-before and schedule exploration were not run"],
                ),
                "resource_bounds": CompletenessItem(
                    status=CompletenessStatus.PARTIAL,
                    basis="loop, guard, and allocation facts",
                    limitations=["whole-request and distributed accounting are unresolved"],
                ),
            },
        )

    def _source_files(self) -> Iterator[tuple[Path, str]]:
        for directory, directories, filenames in os.walk(self.root):
            directories[:] = sorted(item for item in directories if item not in _SKIP_DIRECTORIES)
            for filename in sorted(filenames):
                path = Path(directory) / filename
                language = LANGUAGE_BY_EXTENSION.get(path.suffix.lower())
                if language is not None:
                    yield path, language

    def _relative(self, path: Path) -> str:
        try:
            return path.resolve().relative_to(self.root).as_posix()
        except ValueError:
            return path.as_posix()


_GUARD_PATTERN = re.compile(r"\b(if|unless|assert|require|check|guard)\b|^\s*if\s*\(")
_SENTINEL_PATTERN = re.compile(
    r"\b(?:0x[fF]{2,16}|UINT(?:8|16|32|64)_MAX|INT(?:8|16|32|64)_MAX|"
    r"(?:INVALID|SENTINEL|NONE|UNOWNED)[A-Z0-9_]*)\b|"
    r"(?<![\w])-1(?![\w])"
)
_COUNTER_UPDATE_PATTERN = re.compile(
    r"(?:\+\+|--|\+=\s*\d+|-=\s*\d+)|\b(?:increment|next_id|next_index)\s*\("
)
_LOOP_PATTERN = re.compile(r"^\s*(?:for|while|loop)\b")
_ALLOCATION_PATTERN = re.compile(
    r"\b(?:malloc|calloc|realloc|alloca|new|Box::new|Vec::with_capacity|"
    r"make|Array|Buffer\.alloc|bytearray)\s*(?:<[^>]+>)?\s*[\[(]"
)
_MEMORY_WRITE_PATTERN = re.compile(
    r"\b(?:memcpy|memmove|memset|strcpy|strncpy|copy_from_slice|write|"
    r"put_unaligned|Buffer\.write)\s*\("
)
_ARRAY_ACCESS_PATTERN = re.compile(r"\b[A-Za-z_]\w*(?:->|\.)?\w*\s*\[[^\]]+\]")
_CAST_PATTERN = re.compile(
    r"\(\s*(?:u?int(?:8|16|32|64)_t|short|int|long|size_t)\s*\)|"
    r"\bas\s+(?:u8|u16|u32|u64|i8|i16|i32|i64|usize)\b|"
    r"\b(?:int|Number|parseInt)\s*\("
)
_CALL_PATTERN = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_CONTROL_WORDS = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
    "catch",
    "with",
    "match",
    "assert",
}
_ASSIGNMENT_PATTERN = re.compile(
    r"^\s*(?:[A-Za-z_][\w:<>,\s*&]*\s+)?"
    r"([A-Za-z_]\w*(?:(?:->|\.)\w+|\[[^\]]+\])*)\s*"
    r"(?<![=!<>])=(?!=)\s*(.+?);?\s*$"
)
_TYPE_DECLARATION_PATTERN = re.compile(
    r"\b("
    r"(?:const\s+)?(?:unsigned\s+|signed\s+)?(?:char|short|int|long(?:\s+long)?|"
    r"size_t|ssize_t|u?int(?:8|16|32|64)_t|u8|u16|u32|u64|i8|i16|i32|i64|"
    r"usize|isize|byte|ushort|uint|ulong)"
    r")\s+(?:[*&]\s*)?([A-Za-z_]\w*)\b"
)


def _function_name(line: str, language: str) -> str:
    patterns = {
        "python": r"^(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(",
        "javascript": r"^(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(",
        "typescript": r"^(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(",
        "ruby": r"^def\s+([A-Za-z_]\w*[!?=]?)",
        "rust": r"^(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)",
        "go": r"^func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(",
        "php": r"^(?:public|protected|private|static|\s)*function\s+([A-Za-z_]\w*)",
    }
    pattern = patterns.get(language)
    if pattern:
        match = re.search(pattern, line)
        return match.group(1) if match else ""
    match = re.search(
        r"^(?:(?:public|private|protected|static|inline|extern|virtual|constexpr|"
        r"async|unsafe)\s+)*(?:[\w:<>,~*&\[\]?]+\s+)+([A-Za-z_~]\w*)\s*\([^;]*\)"
        r"\s*(?:const\s*)?(?:\{|=>)?$",
        line,
    )
    return match.group(1) if match else ""


def _typed_declaration(line: str) -> tuple[str, str] | None:
    match = _TYPE_DECLARATION_PATTERN.search(line)
    if not match:
        return None
    return match.group(1), match.group(2)


def _integer_width(type_name: str) -> int | None:
    normalized = " ".join(type_name.lower().split())
    explicit = re.search(r"(?:u?int|[ui])(?:_least|_fast)?(8|16|32|64)", normalized)
    if explicit:
        return int(explicit.group(1))
    if normalized in {"char", "signed char", "unsigned char", "byte"}:
        return 8
    if normalized in {"short", "short int", "unsigned short", "ushort"}:
        return 16
    if normalized in {"int", "unsigned", "unsigned int", "uint"}:
        return 32
    if "long long" in normalized or normalized in {"ulong", "long"}:
        return 64
    return None


def _comparison_operators(expression: str) -> list[str]:
    return re.findall(r"==|!=|<=|>=|<|>", expression)


def _first_control_effect(expression: str) -> str:
    match = re.search(r"\b(return|raise|throw|goto|break)\b", expression)
    return match.group(1) if match else ""


def _sentinel_values(expression: str) -> list[str]:
    return sorted(set(match.group(0) for match in _SENTINEL_PATTERN.finditer(expression)))


def _assignment(line: str) -> tuple[str, str] | None:
    match = _ASSIGNMENT_PATTERN.match(line)
    if not match:
        return None
    return match.group(1), match.group(2).rstrip(";").strip()


def _call_names(line: str) -> list[str]:
    return [match.group(1) for match in _CALL_PATTERN.finditer(line)]


def _same_source_argument(argument: str, mapped_file: str) -> bool:
    return argument == mapped_file or Path(argument).name == Path(mapped_file).name


def _walk_ast(root: dict[str, Any]) -> Iterator[dict[str, Any]]:
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        children = node.get("inner")
        if isinstance(children, list):
            stack.extend(child for child in reversed(children) if isinstance(child, dict))


def _clang_location(
    node: dict[str, Any],
    fallback_file: str,
    repo_root: Path,
) -> SourceLocation | None:
    raw_location = node.get("loc")
    location: dict[str, Any] = raw_location if isinstance(raw_location, dict) else {}
    raw_range = node.get("range")
    range_info: dict[str, Any] = raw_range if isinstance(raw_range, dict) else {}
    raw_begin = range_info.get("begin")
    begin: dict[str, Any] = raw_begin if isinstance(raw_begin, dict) else {}
    file_name = str(location.get("file") or begin.get("file") or fallback_file)
    if file_name.startswith("<"):
        return None
    path = Path(file_name)
    if path.is_absolute():
        try:
            file_name = path.resolve().relative_to(repo_root).as_posix()
        except ValueError:
            return None
    line = location.get("line") or begin.get("line") or 1
    column = location.get("col") or begin.get("col")
    return SourceLocation(
        file=file_name,
        line=max(1, int(line)),
        column=max(1, int(column)) if column else None,
    )


def _deduplicate_facts(facts: list[Fact]) -> list[Fact]:
    by_id: dict[str, Fact] = {}
    for fact in facts:
        by_id[fact.id] = fact
    return list(by_id.values())


def _command_text(value: str | bytes | None) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""
