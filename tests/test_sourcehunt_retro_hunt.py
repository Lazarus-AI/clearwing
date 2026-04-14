"""Tests for the v0.3 CVE Retro-Hunt.

Uses a mocked LLM for rule generation and mocked subprocess for the Semgrep
invocation. Also verifies that the retro-hunter writes rules to a temp file
and parses Semgrep JSON output correctly.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from clearwing.sourcehunt.retro_hunt import (
    RetroHunter,
    RetroHuntResult,
    fetch_patch_diff,
)


def _mock_llm(payload: dict) -> MagicMock:
    llm = MagicMock()
    resp = MagicMock()
    resp.content = json.dumps(payload)
    llm.invoke.return_value = resp
    return llm


# --- fetch_patch_diff ------------------------------------------------------


class TestFetchPatchDiff:
    def test_local_file(self, tmp_path: Path):
        patch_file = tmp_path / "cve.patch"
        patch_file.write_text("--- a/foo.c\n+++ b/foo.c\n@@ -1 +1 @@\n-bug\n+fix\n")
        diff = fetch_patch_diff(str(patch_file))
        assert "--- a/foo.c" in diff

    def test_git_sha(self, tmp_path: Path):
        """When a repo_path is provided, the source is tried as a git SHA."""
        import subprocess
        repo = tmp_path / "repo"
        repo.mkdir()
        subprocess.run(["git", "-C", str(repo), "init", "-q", "-b", "main"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "t@t"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "t"], check=True)
        (repo / "x.c").write_text("int x;\n")
        subprocess.run(["git", "-C", str(repo), "add", "x.c"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "initial"], check=True)

        head = subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True,
        ).strip()
        diff = fetch_patch_diff(head, repo_path=str(repo))
        assert "x.c" in diff

    def test_url_source_raises(self):
        with pytest.raises(ValueError, match="URL patch sources are not fetched"):
            fetch_patch_diff("https://example.com/patch.diff")

    def test_unknown_source_raises(self):
        with pytest.raises(ValueError, match="could not resolve"):
            fetch_patch_diff("not-a-file-or-sha")

    def test_empty_source_raises(self):
        with pytest.raises(ValueError, match="empty patch source"):
            fetch_patch_diff("")


# --- RetroHunter rule generation -------------------------------------------


class TestRetroHunterRuleGeneration:
    def test_generate_rule_parses_json(self):
        llm = _mock_llm({
            "rule_id": "retro-hunt-test",
            "description": "unchecked memcpy length",
            "languages": ["c", "cpp"],
            "pattern": "memcpy($DST, $SRC, $LEN)",
            "severity": "ERROR",
        })
        hunter = RetroHunter(llm=llm, sidecar=MagicMock(available=False))
        rule_info = hunter._generate_rule("CVE-2024-1234", "--- a/x.c\n+++ b/x.c\n")
        assert rule_info["rule_id"] == "retro-hunt-test"
        assert "memcpy" in rule_info["pattern"]

    def test_generate_rule_bad_json_returns_none(self):
        llm = MagicMock()
        resp = MagicMock()
        resp.content = "sorry no json"
        llm.invoke.return_value = resp
        hunter = RetroHunter(llm=llm)
        assert hunter._generate_rule("CVE", "diff") is None

    def test_generate_rule_llm_exception_returns_none(self):
        llm = MagicMock()
        llm.invoke.side_effect = Exception("rate limited")
        hunter = RetroHunter(llm=llm)
        assert hunter._generate_rule("CVE", "diff") is None


# --- Rule YAML formatting --------------------------------------------------


class TestSemgrepRuleFormatting:
    def test_minimal_rule_yaml(self):
        hunter = RetroHunter(llm=MagicMock())
        yml = hunter._format_semgrep_rule({
            "rule_id": "rid",
            "description": "unchecked memcpy",
            "pattern": "memcpy($DST, $SRC, $LEN)",
            "severity": "ERROR",
            "languages": ["c"],
        })
        assert "rules:" in yml
        assert "id: rid" in yml
        assert "memcpy" in yml
        assert "- c" in yml

    def test_languages_string_becomes_list(self):
        hunter = RetroHunter(llm=MagicMock())
        yml = hunter._format_semgrep_rule({
            "rule_id": "rid",
            "description": "x",
            "pattern": "x",
            "severity": "INFO",
            "languages": "python",
        })
        assert "- python" in yml


# --- End-to-end with mocked Semgrep sidecar --------------------------------


class TestHuntEndToEnd:
    def test_hunt_produces_findings(self, tmp_path: Path):
        # Create a local patch file
        patch_file = tmp_path / "cve.patch"
        patch_file.write_text("--- a/x.c\n+++ b/x.c\n@@ -1 +1 @@\n-memcpy(buf, in, len);\n+memcpy(buf, in, min(len, sizeof(buf)));\n")

        llm = _mock_llm({
            "rule_id": "retro-hunt-memcpy",
            "description": "unchecked memcpy length",
            "pattern": "memcpy($DST, $SRC, $LEN)",
            "severity": "ERROR",
            "languages": ["c"],
        })

        # Fake SemgrepSidecar that returns one hit
        from clearwing.sourcehunt.semgrep_sidecar import SemgrepFinding
        fake_sidecar = MagicMock()
        fake_sidecar.available = True

        with patch("clearwing.sourcehunt.retro_hunt.SemgrepSidecar") as MockSidecar:
            mock_instance = MagicMock()
            mock_instance.run_scan.return_value = [
                SemgrepFinding(
                    file="src/codec.c",
                    line=42,
                    check_id="retro-hunt-memcpy",
                    severity="ERROR",
                    message="unchecked memcpy length",
                    code_snippet="memcpy(buf, input, user_len);",
                    cwe="CWE-787",
                )
            ]
            MockSidecar.return_value = mock_instance

            hunter = RetroHunter(llm=llm, sidecar=fake_sidecar)
            result = hunter.hunt(
                cve_id="CVE-2024-TEST",
                patch_source=str(patch_file),
                target_repo_path=str(tmp_path),
            )

        assert isinstance(result, RetroHuntResult)
        assert result.cve_id == "CVE-2024-TEST"
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f["related_cve"] == "CVE-2024-TEST"
        assert f["discovered_by"] == "retro_hunt"
        assert f["finding_type"] == "cve_variant"
        assert f["evidence_level"] == "static_corroboration"
        assert f["file"] == "src/codec.c"
        assert f["line_number"] == 42

    def test_hunt_with_semgrep_unavailable(self, tmp_path: Path):
        patch_file = tmp_path / "cve.patch"
        patch_file.write_text("--- a/x.c\n+++ b/x.c\n")

        llm = _mock_llm({
            "rule_id": "r", "description": "x",
            "pattern": "x", "severity": "WARNING", "languages": ["c"],
        })
        fake_sidecar = MagicMock(available=False)
        fake_sidecar.run_scan = MagicMock(return_value=[])

        with patch("clearwing.sourcehunt.retro_hunt.SemgrepSidecar") as MockSidecar:
            MockSidecar.return_value = fake_sidecar
            hunter = RetroHunter(llm=llm, sidecar=fake_sidecar)
            result = hunter.hunt(
                cve_id="CVE-2024-TEST",
                patch_source=str(patch_file),
                target_repo_path=str(tmp_path),
            )
        assert result.findings == []

    def test_hunt_fails_on_bad_patch_source(self, tmp_path: Path):
        hunter = RetroHunter(llm=MagicMock())
        result = hunter.hunt(
            cve_id="CVE-2024-TEST",
            patch_source="definitely-not-a-file",
            target_repo_path=str(tmp_path),
        )
        assert result.findings == []
        assert "could not fetch patch" in result.notes

    def test_hunt_fails_on_llm_rule_gen(self, tmp_path: Path):
        patch_file = tmp_path / "cve.patch"
        patch_file.write_text("--- a/x.c\n+++ b/x.c\n")

        llm = MagicMock()
        llm.invoke.side_effect = Exception("rate limited")
        hunter = RetroHunter(llm=llm)
        result = hunter.hunt(
            cve_id="CVE-2024-TEST",
            patch_source=str(patch_file),
            target_repo_path=str(tmp_path),
        )
        assert result.findings == []
        assert "LLM failed to generate a rule" in result.notes
