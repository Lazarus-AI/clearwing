"""Tests for reverse engineering pipeline (spec 016)."""

from __future__ import annotations

import struct
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from clearwing.sourcehunt.reveng import RevengPipeline, RevengResult
from clearwing.sourcehunt.reveng_decompiler import (
    DecompiledFunction,
    DecompilationResult,
    RevengSandbox,
    StaticAnalysisResult,
    format_static_summary,
    validate_binary,
)
from clearwing.sourcehunt.reveng_reconstructor import (
    ReconstructedSource,
    ReconstructionResult,
    ReconstructionValidation,
    RevengReconstructor,
)


# --- Dataclass defaults tests ------------------------------------------------


class TestDataclassDefaults:
    def test_static_analysis_defaults(self):
        r = StaticAnalysisResult()
        assert r.file_type == ""
        assert r.arch == ""
        assert r.checksec == {}
        assert r.imports == []
        assert r.binary_size == 0

    def test_decompiled_function_defaults(self):
        f = DecompiledFunction()
        assert f.name == ""
        assert f.address == 0
        assert f.decompiled_c == ""
        assert f.size == 0
        assert f.calls == []

    def test_decompilation_result_defaults(self):
        r = DecompilationResult()
        assert r.functions == []
        assert r.total_functions == 0
        assert r.decompilation_errors == []
        assert r.ghidra_log == ""

    def test_reconstructed_source_defaults(self):
        s = ReconstructedSource()
        assert s.original_name == ""
        assert s.confidence == 0.0

    def test_reconstruction_result_defaults(self):
        r = ReconstructionResult()
        assert r.sources == []
        assert r.total_functions == 0
        assert r.combined_source == ""

    def test_reveng_result_defaults(self):
        r = RevengResult()
        assert r.status == "pending"
        assert r.findings == []
        assert r.exploit_results == []
        assert r.total_cost_usd == 0.0


# --- Binary validation tests -------------------------------------------------


class TestValidateBinary:
    def test_valid_elf_x86_64(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            # ELF magic + class64 + little-endian + version + padding + e_type + e_machine
            header = b"\x7fELF"  # magic
            header += b"\x02"  # 64-bit
            header += b"\x01"  # little-endian
            header += b"\x01"  # ELF version
            header += b"\x00" * 9  # padding
            header += struct.pack("<H", 2)  # e_type = ET_EXEC
            header += struct.pack("<H", 62)  # e_machine = EM_X86_64
            f.write(header)
            f.flush()
            valid, error = validate_binary(f.name)
        assert valid is True
        assert error == ""

    def test_rejects_non_elf(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"MZ" + b"\x00" * 50)  # PE header
            f.flush()
            valid, error = validate_binary(f.name)
        assert valid is False
        assert "Not an ELF" in error

    def test_rejects_wrong_arch(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            header = b"\x7fELF"
            header += b"\x02\x01\x01"
            header += b"\x00" * 9
            header += struct.pack("<H", 2)  # e_type
            header += struct.pack("<H", 40)  # e_machine = EM_ARM
            f.write(header)
            f.flush()
            valid, error = validate_binary(f.name)
        assert valid is False
        assert "Unsupported architecture" in error

    def test_rejects_missing_file(self):
        valid, error = validate_binary("/nonexistent/path/binary")
        assert valid is False
        assert "not found" in error

    def test_rejects_too_small(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"\x7fE")
            f.flush()
            valid, error = validate_binary(f.name)
        assert valid is False
        assert "too small" in error


# --- RevengSandbox tests -----------------------------------------------------


class TestRevengSandbox:
    def test_spawn_with_factory(self):
        mock_sandbox = MagicMock()
        mock_factory = MagicMock(return_value=mock_sandbox)
        sandbox = RevengSandbox(sandbox_factory=mock_factory)
        result = sandbox.spawn("/tmp/test.bin")
        assert result is mock_sandbox
        mock_factory.assert_called_once_with(binary_path="/tmp/test.bin")

    def test_spawn_factory_failure_returns_none(self):
        mock_factory = MagicMock(side_effect=RuntimeError("no docker"))
        sandbox = RevengSandbox(sandbox_factory=mock_factory)
        result = sandbox.spawn("/tmp/test.bin")
        assert result is None

    def test_cleanup_stops_containers(self):
        mock_sandbox = MagicMock()
        mock_factory = MagicMock(return_value=mock_sandbox)
        sandbox = RevengSandbox(sandbox_factory=mock_factory)
        sandbox.spawn("/tmp/test.bin")
        sandbox.cleanup()
        mock_sandbox.stop.assert_called_once()

    def test_image_tag_deterministic(self):
        s1 = RevengSandbox()
        s2 = RevengSandbox()
        assert s1._compute_tag() == s2._compute_tag()
        assert s1._compute_tag().startswith("clearwing-reveng:")


# --- Static analysis formatting tests ----------------------------------------


class TestFormatStaticSummary:
    def test_format_with_all_fields(self):
        analysis = StaticAnalysisResult(
            file_type="ELF 64-bit LSB executable",
            arch="x86_64",
            binary_size=12345,
            checksec={"pie": True, "full_relro": False},
            imports=["printf", "malloc", "free"],
        )
        summary = format_static_summary(analysis)
        assert "ELF 64-bit" in summary
        assert "x86_64" in summary
        assert "12345" in summary
        assert "printf" in summary
        assert "pie=True" in summary

    def test_format_minimal(self):
        analysis = StaticAnalysisResult()
        summary = format_static_summary(analysis)
        assert "File type:" in summary


# --- RevengReconstructor tests ------------------------------------------------


class TestRevengReconstructor:
    @pytest.mark.asyncio
    async def test_reconstruct_single_function(self):
        mock_llm = AsyncMock()
        mock_response = MagicMock()
        mock_response.first_text = '[{"original_name": "FUN_00401234", "reconstructed_name": "parse_input", "source_code": "void parse_input(char *buf) {}", "confidence": 0.8, "notes": "parses user input"}]'
        mock_llm.aask_text = AsyncMock(return_value=mock_response)

        reconstructor = RevengReconstructor(mock_llm)
        decompilation = DecompilationResult(
            functions=[DecompiledFunction(
                name="FUN_00401234",
                address=0x401234,
                decompiled_c="void FUN_00401234(char *param1) {}",
                size=100,
                calls=["strlen"],
            )],
            total_functions=1,
        )
        static_info = StaticAnalysisResult(file_type="ELF")

        result = await reconstructor.areconstruct(decompilation, static_info)
        assert result.reconstructed_count == 1
        assert result.sources[0].reconstructed_name == "parse_input"
        assert result.sources[0].confidence == 0.8

    @pytest.mark.asyncio
    async def test_reconstruct_empty_input(self):
        mock_llm = AsyncMock()
        reconstructor = RevengReconstructor(mock_llm)
        result = await reconstructor.areconstruct(
            DecompilationResult(), StaticAnalysisResult(),
        )
        assert result.reconstructed_count == 0
        assert result.sources == []

    @pytest.mark.asyncio
    async def test_reconstruct_llm_failure_degrades(self):
        mock_llm = AsyncMock()
        mock_llm.aask_text = AsyncMock(side_effect=RuntimeError("LLM down"))

        reconstructor = RevengReconstructor(mock_llm)
        decompilation = DecompilationResult(
            functions=[DecompiledFunction(
                name="FUN_00401234",
                decompiled_c="void FUN_00401234() { return; }",
            )],
            total_functions=1,
        )

        result = await reconstructor.areconstruct(
            decompilation, StaticAnalysisResult(),
        )
        assert result.reconstructed_count == 1
        assert result.sources[0].original_name == "FUN_00401234"
        assert result.sources[0].confidence == 0.0
        assert "raw Ghidra" in result.sources[0].notes

    @pytest.mark.asyncio
    async def test_batch_size_respected(self):
        mock_llm = AsyncMock()
        mock_response = MagicMock()
        mock_response.first_text = "[]"
        mock_llm.aask_text = AsyncMock(return_value=mock_response)

        reconstructor = RevengReconstructor(mock_llm)
        functions = [
            DecompiledFunction(name=f"FUN_{i:08x}", decompiled_c=f"void f{i}() {{}}")
            for i in range(20)
        ]
        decompilation = DecompilationResult(
            functions=functions, total_functions=20,
        )

        await reconstructor.areconstruct(decompilation, StaticAnalysisResult())
        # 20 functions / batch_size 8 = 3 LLM calls
        assert mock_llm.aask_text.call_count == 3


# --- RevengPipeline tests ----------------------------------------------------


class TestRevengPipeline:
    def test_result_defaults(self):
        r = RevengResult()
        assert r.status == "pending"
        assert r.total_cost_usd == 0.0

    @pytest.mark.asyncio
    async def test_pipeline_rejects_non_elf(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"MZ" + b"\x00" * 50)
            f.flush()

            pipeline = RevengPipeline(llm=MagicMock(), binary_path=f.name)
            result = await pipeline.arun()

        assert result.status == "failed"

    @pytest.mark.asyncio
    async def test_pipeline_rejects_missing_file(self):
        pipeline = RevengPipeline(llm=MagicMock(), binary_path="/nonexistent")
        result = await pipeline.arun()
        assert result.status == "failed"

    def test_reveng_hunt_prompt_has_placeholders(self):
        from clearwing.sourcehunt.reveng import REVENG_HUNT_PROMPT
        assert "{project_name}" in REVENG_HUNT_PROMPT
        assert "{binary_name}" in REVENG_HUNT_PROMPT
        assert "{arch}" in REVENG_HUNT_PROMPT
        assert "{static_summary}" in REVENG_HUNT_PROMPT


# --- Hunter specialist tests --------------------------------------------------


class TestHunterSpecialist:
    def test_reveng_in_specialist_prompts(self):
        from clearwing.sourcehunt.hunter import _SPECIALIST_PROMPTS
        assert "reveng" in _SPECIALIST_PROMPTS

    def test_reveng_in_deep_specialist_focus(self):
        from clearwing.sourcehunt.hunter import _DEEP_SPECIALIST_FOCUS
        assert "reveng" in _DEEP_SPECIALIST_FOCUS
        assert "binary" in _DEEP_SPECIALIST_FOCUS["reveng"].lower()


# --- CLI tests ----------------------------------------------------------------


class TestRevengCLI:
    def test_reveng_flag(self):
        import argparse
        from clearwing.ui.commands import sourcehunt

        parser = argparse.ArgumentParser()
        subs = parser.add_subparsers()
        sourcehunt.add_parser(subs)
        args = parser.parse_args(["sourcehunt", "repo", "--reveng"])
        assert args.reveng is True

    def test_arch_flag(self):
        import argparse
        from clearwing.ui.commands import sourcehunt

        parser = argparse.ArgumentParser()
        subs = parser.add_subparsers()
        sourcehunt.add_parser(subs)
        args = parser.parse_args(["sourcehunt", "repo", "--reveng", "--arch", "x86_64"])
        assert args.arch == "x86_64"

    def test_arch_default(self):
        import argparse
        from clearwing.ui.commands import sourcehunt

        parser = argparse.ArgumentParser()
        subs = parser.add_subparsers()
        sourcehunt.add_parser(subs)
        args = parser.parse_args(["sourcehunt", "repo", "--reveng"])
        assert args.arch == "x86_64"

    def test_reveng_budget_flag(self):
        import argparse
        from clearwing.ui.commands import sourcehunt

        parser = argparse.ArgumentParser()
        subs = parser.add_subparsers()
        sourcehunt.add_parser(subs)
        args = parser.parse_args([
            "sourcehunt", "repo", "--reveng", "--reveng-budget", "campaign",
        ])
        assert args.reveng_budget == "campaign"

    def test_reveng_budget_default(self):
        import argparse
        from clearwing.ui.commands import sourcehunt

        parser = argparse.ArgumentParser()
        subs = parser.add_subparsers()
        sourcehunt.add_parser(subs)
        args = parser.parse_args(["sourcehunt", "repo", "--reveng"])
        assert args.reveng_budget == "deep"
