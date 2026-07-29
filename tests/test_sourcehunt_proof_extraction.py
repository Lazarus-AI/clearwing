"""Fact extraction and repository snapshot tests."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from clearwing.sourcehunt.proof import (
    CompletenessStatus,
    ExtractionConfig,
    FactExtractor,
    ProofPreflightError,
    ProofStore,
    capture_snapshot,
)
from clearwing.sourcehunt.proof.extractors import CommandResult


class _FakeClangRunner:
    sandboxed = True
    identity = "fake-isolated-runner"

    def __init__(self, root: Path):
        self.root = root
        self.commands: list[list[str]] = []

    def map_path(self, path: Path) -> str:
        return "/workspace/" + path.resolve().relative_to(self.root).as_posix()

    def run(
        self,
        arguments: list[str] | tuple[str, ...],
        *,
        cwd: Path,
        timeout: int,
    ) -> CommandResult:
        del cwd, timeout
        command = list(arguments)
        self.commands.append(command)
        if "--version" in command:
            return CommandResult(0, "clang version 22.1.0\n", "")
        ast = {
            "kind": "TranslationUnitDecl",
            "inner": [
                {
                    "kind": "VarDecl",
                    "name": "slice_num",
                    "loc": {"file": "codec.c", "line": 2, "col": 14},
                    "type": {"qualType": "uint16_t"},
                }
            ],
        }
        return CommandResult(0, json.dumps(ast), "")


@pytest.mark.parametrize(
    ("filename", "source", "language"),
    [
        ("app.py", "def parse(data):\n    return decode(data)\n", "python"),
        ("app.js", "function parse(data) { return decode(data); }\n", "javascript"),
        ("app.ts", "function parse(data: Uint8Array) { return decode(data); }\n", "typescript"),
        ("app.php", "function parse($data) { return decode($data); }\n", "php"),
        ("App.java", "public int parse(byte[] data) { return decode(data); }\n", "java"),
        ("app.rb", "def parse(data)\n decode(data)\nend\n", "ruby"),
        ("app.go", "func parse(data []byte) int { return decode(data) }\n", "go"),
        ("app.rs", "pub fn parse(data: &[u8]) { decode(data); }\n", "rust"),
        ("App.cs", "public int Parse(byte[] data) { return Decode(data); }\n", "csharp"),
    ],
)
def test_language_adapters_emit_first_class_facts(
    tmp_path,
    filename: str,
    source: str,
    language: str,
) -> None:
    (tmp_path / filename).write_text(source)
    result = FactExtractor(tmp_path, "snapshot-1").extract()

    assert result.languages == {language: 1}
    assert any(
        fact.kind == "source_file" and fact.properties["language"] == language
        for fact in result.facts
    )
    assert any(fact.kind == "call" for fact in result.facts)
    assert (
        result.completeness.items["indirect_calls"].status
        == CompletenessStatus.UNRESOLVED
    )


def test_c_requires_sandbox_and_compilation_database(tmp_path) -> None:
    (tmp_path / "codec.c").write_text("int decode(void) { return 0; }\n")

    with pytest.raises(ProofPreflightError, match="command runner"):
        FactExtractor(tmp_path, "snapshot-1").extract()

    with pytest.raises(ProofPreflightError, match="isolated sandbox"):
        FactExtractor(
            tmp_path,
            "snapshot-1",
            command_runner=type(
                "UnsafeRunner",
                (),
                {"sandboxed": False, "identity": "unsafe"},
            )(),
        ).extract()


def test_clang_facts_and_coverage_are_persisted(tmp_path) -> None:
    source = tmp_path / "codec.c"
    source.write_text(
        "#include <stdint.h>\nuint16_t slice_num = 0xFFFF;\n"
        "int decode(void) { return slice_num; }\n"
    )
    (tmp_path / "compile_commands.json").write_text(
        json.dumps(
            [
                {
                    "directory": str(tmp_path),
                    "file": str(source),
                    "arguments": ["cc", "-c", str(source), "-o", "codec.o"],
                }
            ]
        )
    )
    store = ProofStore(tmp_path / "proof-session")
    runner = _FakeClangRunner(tmp_path)
    result = FactExtractor(
        tmp_path,
        "snapshot-1",
        store=store,
        config=ExtractionConfig(compile_commands=tmp_path / "compile_commands.json"),
        command_runner=runner,
    ).extract()

    clang_variable = next(
        fact
        for fact in result.facts
        if fact.provenance.producer == "clang-ast" and fact.subject == "slice_num"
    )
    assert clang_variable.properties["integer_width"] == 16
    assert (
        result.completeness.items["types"].status
        == CompletenessStatus.COMPLETE
    )
    coverage = json.loads(
        (store.root / "facts" / "extraction-coverage.json").read_text()
    )
    assert coverage["files_analyzed"] == 1
    ast_command = runner.commands[-1]
    assert ast_command[0] == "clang"
    assert "-ast-dump=json" in ast_command
    assert "-o" not in ast_command


def test_tree_sitter_callgraph_and_taint_are_normalized_as_facts(
    tmp_path,
) -> None:
    (tmp_path / "handler.py").write_text(
        "import os\n"
        "def handle():\n"
        "    user_input = input()\n"
        "    os.system(user_input)\n"
    )

    result = FactExtractor(tmp_path, "snapshot-1").extract()

    taint = next(fact for fact in result.facts if fact.kind == "taint_path")
    assert taint.properties["source_function"] == "input"
    assert taint.properties["sink_function"] == "system"
    assert taint.properties["variable"] == "user_input"
    assert any(
        fact.kind == "call_edge" and fact.object == "system"
        for fact in result.facts
    )
    assert (
        result.completeness.items["taint_paths"].status
        == CompletenessStatus.PARTIAL
    )


def test_snapshot_changes_when_dirty_content_changes(tmp_path) -> None:
    subprocess.run(["git", "init", "-q", tmp_path], check=True)
    subprocess.run(
        ["git", "-C", tmp_path, "config", "user.email", "test@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", tmp_path, "config", "user.name", "Test"],
        check=True,
    )
    target = tmp_path / "example.py"
    target.write_text("safe = True\n")
    subprocess.run(["git", "-C", tmp_path, "add", "example.py"], check=True)
    subprocess.run(["git", "-C", tmp_path, "commit", "-qm", "initial"], check=True)
    clean = capture_snapshot(tmp_path)

    target.write_text("safe = False\n")
    dirty = capture_snapshot(tmp_path)

    assert clean.commit == dirty.commit
    assert clean.dirty_tree_digest is None
    assert dirty.dirty_tree_digest
    assert clean.id != dirty.id
