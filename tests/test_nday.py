"""Tests for N-day exploit pipeline (spec 015)."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from clearwing.sourcehunt.nday import NdayPipeline, NdayPipelineResult, NdayResult
from clearwing.sourcehunt.nday_builder import NdayBuild, NdayBuilder
from clearwing.sourcehunt.nday_filter import (
    NdayCandidate,
    NdayFilter,
    parse_cve_list,
)


# --- NdayCandidate tests -----------------------------------------------------


class TestNdayCandidate:
    def test_defaults(self):
        c = NdayCandidate(cve_id="CVE-2024-1234")
        assert c.cve_id == "CVE-2024-1234"
        assert c.patch_source == ""
        assert c.diff_text == ""
        assert c.exploitability == ""

    def test_parse_cve_list(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False,
        ) as f:
            f.write("# comment line\n")
            f.write("CVE-2024-1111 abc123 heap overflow\n")
            f.write("CVE-2024-2222 def456\n")
            f.write("CVE-2024-3333\n")
            f.write("\n")
            f.flush()
            candidates = parse_cve_list(f.name)

        assert len(candidates) == 3
        assert candidates[0].cve_id == "CVE-2024-1111"
        assert candidates[0].patch_source == "abc123"
        assert candidates[0].description == "heap overflow"
        assert candidates[1].cve_id == "CVE-2024-2222"
        assert candidates[1].patch_source == "def456"
        assert candidates[2].cve_id == "CVE-2024-3333"
        assert candidates[2].patch_source == ""

    def test_parse_cve_list_empty(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False,
        ) as f:
            f.write("# only comments\n\n")
            f.flush()
            candidates = parse_cve_list(f.name)
        assert candidates == []


# --- NdayFilter tests --------------------------------------------------------


class TestNdayFilter:
    @pytest.mark.asyncio
    async def test_filter_likely_exploitable(self):
        mock_llm = AsyncMock()
        mock_response = MagicMock()
        mock_response.first_text.return_value = '[{"cve_id": "CVE-2024-1111", "exploitability": "LIKELY_EXPLOITABLE", "reasoning": "heap overflow"}]'
        mock_llm.aask = AsyncMock(return_value=mock_response)

        nf = NdayFilter(mock_llm)
        candidates = [NdayCandidate(cve_id="CVE-2024-1111", diff_text="diff")]
        result = await nf.afilter(candidates)
        assert len(result) == 1
        assert result[0].exploitability == "LIKELY_EXPLOITABLE"

    @pytest.mark.asyncio
    async def test_filter_unlikely_excluded(self):
        mock_llm = AsyncMock()
        mock_response = MagicMock()
        mock_response.first_text.return_value = '[{"cve_id": "CVE-2024-1111", "exploitability": "UNLIKELY_EXPLOITABLE", "reasoning": "doc fix"}]'
        mock_llm.aask = AsyncMock(return_value=mock_response)

        nf = NdayFilter(mock_llm)
        candidates = [NdayCandidate(cve_id="CVE-2024-1111", diff_text="diff")]
        result = await nf.afilter(candidates)
        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_filter_empty_list(self):
        mock_llm = AsyncMock()
        nf = NdayFilter(mock_llm)
        result = await nf.afilter([])
        assert result == []

    @pytest.mark.asyncio
    async def test_filter_possibly_passes(self):
        mock_llm = AsyncMock()
        mock_response = MagicMock()
        mock_response.first_text.return_value = '[{"cve_id": "CVE-2024-1111", "exploitability": "POSSIBLY_EXPLOITABLE", "reasoning": "race condition"}]'
        mock_llm.aask = AsyncMock(return_value=mock_response)

        nf = NdayFilter(mock_llm)
        candidates = [NdayCandidate(cve_id="CVE-2024-1111")]
        result = await nf.afilter(candidates)
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_filter_llm_failure_defaults_possibly(self):
        mock_llm = AsyncMock()
        mock_llm.aask = AsyncMock(side_effect=RuntimeError("LLM down"))

        nf = NdayFilter(mock_llm)
        candidates = [NdayCandidate(cve_id="CVE-2024-1111")]
        result = await nf.afilter(candidates)
        assert len(result) == 1
        assert candidates[0].exploitability == "POSSIBLY_EXPLOITABLE"


# --- NdayBuilder tests -------------------------------------------------------


class TestNdayBuilder:
    def test_no_sandbox_returns_failure(self):
        builder = NdayBuilder()
        candidate = NdayCandidate(cve_id="CVE-2024-1111", patch_source="abc123")
        build = builder.build_targets(candidate)
        assert not build.build_success
        assert "No sandbox" in build.build_log

    def test_build_without_patch_source(self):
        mock_sandbox = MagicMock()
        mock_sandbox.exec.return_value = MagicMock(exit_code=0, stdout="", stderr="")
        mock_factory = MagicMock(return_value=mock_sandbox)

        builder = NdayBuilder(sandbox_factory=mock_factory)
        candidate = NdayCandidate(cve_id="CVE-2024-1111")
        build = builder.build_targets(candidate)
        assert build.build_success
        assert build.sandbox is mock_sandbox


# --- NdayPipeline tests ------------------------------------------------------


class TestNdayPipeline:
    def test_pipeline_result_defaults(self):
        r = NdayPipelineResult()
        assert r.total_cves == 0
        assert r.exploited == 0

    def test_nday_result_defaults(self):
        r = NdayResult(cve_id="CVE-2024-1111")
        assert r.status == "pending"
        assert r.exploit_result is None

    def test_build_nday_finding(self):
        pipeline = NdayPipeline(llm=MagicMock(), repo_path="/tmp/repo")
        candidate = NdayCandidate(
            cve_id="CVE-2024-1111",
            diff_text="--- a/src/foo.c\n+++ b/src/foo.c\n@@ -10,3 +10,3 @@\n",
            description="heap overflow in foo",
        )
        finding = pipeline._build_nday_finding(candidate)
        assert finding["id"] == "nday-CVE-2024-1111"
        assert finding["related_cve"] == "CVE-2024-1111"
        assert finding["severity"] == "critical"
        assert finding["evidence_level"] == "root_cause_explained"
        assert "CVE-2024-1111" in finding["description"]

    def test_finding_extracts_file_from_diff(self):
        pipeline = NdayPipeline(llm=MagicMock())
        candidate = NdayCandidate(
            cve_id="CVE-2024-1111",
            diff_text="--- a/net/ipv4/tcp.c\n+++ b/net/ipv4/tcp.c\n",
        )
        finding = pipeline._build_nday_finding(candidate)
        assert finding["file"] == "net/ipv4/tcp.c"

    def test_finding_has_nday_diff(self):
        pipeline = NdayPipeline(llm=MagicMock())
        candidate = NdayCandidate(
            cve_id="CVE-2024-1111", diff_text="the diff",
        )
        finding = pipeline._build_nday_finding(candidate)
        assert finding["nday_diff"] == "the diff"

    @pytest.mark.asyncio
    async def test_pipeline_skips_filtered(self):
        mock_llm = AsyncMock()
        mock_response = MagicMock()
        mock_response.first_text.return_value = '[{"cve_id": "CVE-2024-1111", "exploitability": "UNLIKELY_EXPLOITABLE", "reasoning": "doc"}]'
        mock_llm.aask = AsyncMock(return_value=mock_response)

        pipeline = NdayPipeline(llm=mock_llm)
        candidates = [NdayCandidate(cve_id="CVE-2024-1111")]
        result = await pipeline.arun(candidates)
        assert result.total_cves == 1
        assert result.filtered_cves == 0
        assert result.attempted == 0
        assert len(result.results) == 1
        assert result.results[0].status == "filtered"

    @pytest.mark.asyncio
    async def test_pipeline_single_cve_mocked(self):
        mock_llm = AsyncMock()
        mock_response = MagicMock()
        mock_response.first_text.return_value = '[{"cve_id": "CVE-2024-1111", "exploitability": "LIKELY_EXPLOITABLE", "reasoning": "heap"}]'
        mock_llm.aask = AsyncMock(return_value=mock_response)

        mock_exploit_result = MagicMock()
        mock_exploit_result.success = False
        mock_exploit_result.partial = False
        mock_exploit_result.cost_usd = 10.0

        mock_sandbox = MagicMock()
        mock_sandbox.exec.return_value = MagicMock(exit_code=0, stdout="", stderr="")
        mock_factory = MagicMock(return_value=mock_sandbox)

        with patch(
            "clearwing.sourcehunt.nday.AgenticExploiter",
        ) as mock_exploiter_cls:
            mock_exploiter = AsyncMock()
            mock_exploiter.aattempt = AsyncMock(return_value=mock_exploit_result)
            mock_exploiter_cls.return_value = mock_exploiter

            pipeline = NdayPipeline(llm=mock_llm, sandbox_factory=mock_factory)
            candidates = [NdayCandidate(cve_id="CVE-2024-1111")]
            result = await pipeline.arun(candidates)

        assert result.total_cves == 1
        assert result.attempted == 1
        assert result.failed == 1


# --- Validation tests --------------------------------------------------------


class TestNdayValidation:
    @pytest.mark.asyncio
    async def test_validate_succeed_vulnerable(self):
        pipeline = NdayPipeline(llm=MagicMock())
        mock_sandbox = MagicMock()
        mock_sandbox.exec.return_value = MagicMock(
            exit_code=139, stdout="", stderr="segfault",
        )
        mock_sandbox.write_file = MagicMock()

        exploit_result = MagicMock()
        exploit_result.exploit = "#!/bin/sh\n./vuln < crash"
        build = NdayBuild(cve_id="CVE-2024-1111", sandbox=mock_sandbox)

        vuln_ok, patch_ok = await pipeline._validate_exploit(exploit_result, build)
        assert vuln_ok is True

    @pytest.mark.asyncio
    async def test_validate_no_exploit_returns_false(self):
        pipeline = NdayPipeline(llm=MagicMock())
        exploit_result = MagicMock()
        exploit_result.exploit = ""
        build = NdayBuild(cve_id="CVE-2024-1111")

        vuln_ok, patch_ok = await pipeline._validate_exploit(exploit_result, build)
        assert vuln_ok is False
        assert patch_ok is False


# --- CLI tests ----------------------------------------------------------------


class TestNdayCLI:
    def test_nday_flag(self):
        import argparse
        from clearwing.ui.commands import sourcehunt

        parser = argparse.ArgumentParser()
        subs = parser.add_subparsers()
        sourcehunt.add_parser(subs)
        args = parser.parse_args(["sourcehunt", "repo", "--nday", "--cve", "CVE-2024-1111"])
        assert args.nday is True
        assert args.cve == "CVE-2024-1111"

    def test_cve_list_flag(self):
        import argparse
        from clearwing.ui.commands import sourcehunt

        parser = argparse.ArgumentParser()
        subs = parser.add_subparsers()
        sourcehunt.add_parser(subs)
        args = parser.parse_args(["sourcehunt", "repo", "--nday", "--cve-list", "cves.txt"])
        assert args.cve_list == "cves.txt"

    def test_recent_cves_flag(self):
        import argparse
        from clearwing.ui.commands import sourcehunt

        parser = argparse.ArgumentParser()
        subs = parser.add_subparsers()
        sourcehunt.add_parser(subs)
        args = parser.parse_args([
            "sourcehunt", "repo", "--nday", "--recent-cves", "--nday-days", "60",
        ])
        assert args.recent_cves is True
        assert args.nday_days == 60

    def test_nday_budget_flag(self):
        import argparse
        from clearwing.ui.commands import sourcehunt

        parser = argparse.ArgumentParser()
        subs = parser.add_subparsers()
        sourcehunt.add_parser(subs)
        args = parser.parse_args([
            "sourcehunt", "repo", "--nday", "--cve", "CVE-2024-1", "--nday-budget", "campaign",
        ])
        assert args.nday_budget == "campaign"

    def test_patch_commit_flag(self):
        import argparse
        from clearwing.ui.commands import sourcehunt

        parser = argparse.ArgumentParser()
        subs = parser.add_subparsers()
        sourcehunt.add_parser(subs)
        args = parser.parse_args([
            "sourcehunt", "repo", "--nday", "--cve", "CVE-2024-1", "--patch-commit", "abc123",
        ])
        assert args.patch_commit == "abc123"
