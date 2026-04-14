"""Tests for the v0.3 Commit Monitor.

Uses a throwaway git repo in tmp_path so we can make real commits and
exercise the scan_commit() path. The sourcehunt runner is injected via
runner_factory so tests don't call any LLMs.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from clearwing.sourcehunt.commit_monitor import (
    CommitMonitor,
    CommitMonitorConfig,
    CommitScanResult,
)


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, text=True, check=True,
    )
    return result.stdout.strip()


@pytest.fixture
def tiny_git_repo(tmp_path: Path) -> Path:
    """Create a minimal git repo with two commits so diffs work."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "test")

    (repo / "main.c").write_text("int main() { return 0; }\n")
    _git(repo, "add", "main.c")
    _git(repo, "commit", "-q", "-m", "initial")

    (repo / "util.c").write_text("int helper() { return 0; }\n")
    (repo / "main.c").write_text("int main() { return helper(); }\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "add util.c, main calls helper")

    return repo


def _mock_runner(findings: list[dict]):
    """Build a runner_factory that returns a mock runner with the given findings."""
    def factory(files):
        runner = MagicMock()
        result = MagicMock()
        result.findings = findings
        runner.run.return_value = result
        return runner
    return factory


class TestCommitMonitorBasics:
    def test_config_defaults(self, tmp_path):
        cfg = CommitMonitorConfig(repo_path=str(tmp_path))
        assert cfg.branch == "main"
        assert cfg.poll_interval_seconds == 300
        assert cfg.depth == "standard"

    def test_cancel_flag(self, tmp_path):
        monitor = CommitMonitor(CommitMonitorConfig(repo_path=str(tmp_path)))
        monitor.cancel()
        assert monitor._cancelled is True


class TestScanCommitEndToEnd:
    def test_scan_commit_finds_changed_files(self, tiny_git_repo):
        """scan_commit returns a result with the changed files list."""
        head = _git(tiny_git_repo, "rev-parse", "HEAD")
        monitor = CommitMonitor(CommitMonitorConfig(
            repo_path=str(tiny_git_repo),
            runner_factory=_mock_runner([]),
        ))
        result = monitor.scan_commit(head)
        assert isinstance(result, CommitScanResult)
        assert result.commit_sha == head
        assert "util.c" in result.changed_files
        assert "main.c" in result.changed_files

    def test_scan_commit_calls_runner_factory(self, tiny_git_repo):
        """The injected runner_factory is called and its findings are captured."""
        mock_findings = [
            {"id": "f1", "file": "util.c", "line_number": 1,
             "description": "test finding", "evidence_level": "suspicion"},
        ]
        head = _git(tiny_git_repo, "rev-parse", "HEAD")
        monitor = CommitMonitor(CommitMonitorConfig(
            repo_path=str(tiny_git_repo),
            runner_factory=_mock_runner(mock_findings),
        ))
        result = monitor.scan_commit(head)
        assert len(result.findings) == 1
        assert result.findings[0]["id"] == "f1"

    def test_scan_commit_has_duration(self, tiny_git_repo):
        head = _git(tiny_git_repo, "rev-parse", "HEAD")
        monitor = CommitMonitor(CommitMonitorConfig(
            repo_path=str(tiny_git_repo),
            runner_factory=_mock_runner([]),
        ))
        result = monitor.scan_commit(head)
        assert result.duration_seconds >= 0.0


class TestBlastRadiusExpansion:
    def test_empty_callgraph_returns_changed_files_as_is(self, tmp_path):
        """When the callgraph can't be built, blast_radius == changed_files."""
        # Create a repo with a file tree-sitter can't parse
        repo = tmp_path / "opaque_repo"
        repo.mkdir()
        (repo / "blob.bin").write_text("\x00\x01\x02")
        _git(repo, "init", "-q", "-b", "main")
        _git(repo, "config", "user.email", "t@t")
        _git(repo, "config", "user.name", "t")
        _git(repo, "add", ".")
        _git(repo, "commit", "-q", "-m", "bin")

        monitor = CommitMonitor(CommitMonitorConfig(
            repo_path=str(repo),
            runner_factory=_mock_runner([]),
        ))
        # _compute_blast_radius on non-source files: just returns input
        blast = monitor._compute_blast_radius(["blob.bin"])
        assert "blob.bin" in blast


class TestPollLoopCancellation:
    def test_run_respects_max_iterations(self, tiny_git_repo):
        """run() exits after max_iterations even if new commits keep coming."""
        monitor = CommitMonitor(CommitMonitorConfig(
            repo_path=str(tiny_git_repo),
            poll_interval_seconds=0,
            max_iterations=1,
            runner_factory=_mock_runner([]),
        ))
        # Mock the poll to always return a new SHA so the loop doesn't sleep forever
        import unittest.mock as mock
        with mock.patch.object(monitor, "_poll_for_new_commit",
                               return_value=_git(tiny_git_repo, "rev-parse", "HEAD")):
            results = monitor.run()
        # max_iterations=1 → at most 1 result
        assert len(results) <= 1


class TestGitHelpers:
    def test_changed_files_between_commits(self, tiny_git_repo):
        monitor = CommitMonitor(CommitMonitorConfig(
            repo_path=str(tiny_git_repo),
            runner_factory=_mock_runner([]),
        ))
        head = _git(tiny_git_repo, "rev-parse", "HEAD")
        parent = _git(tiny_git_repo, "rev-parse", "HEAD^")
        changed = monitor._changed_files(parent, head)
        assert "util.c" in changed
        assert "main.c" in changed

    def test_parent_sha(self, tiny_git_repo):
        monitor = CommitMonitor(CommitMonitorConfig(
            repo_path=str(tiny_git_repo),
            runner_factory=_mock_runner([]),
        ))
        head = _git(tiny_git_repo, "rev-parse", "HEAD")
        parent = monitor._parent_sha(head)
        assert parent != ""
        assert len(parent) == 40   # full SHA

    def test_parent_sha_of_root_commit_is_empty(self, tmp_path):
        repo = tmp_path / "single_commit_repo"
        repo.mkdir()
        _git(repo, "init", "-q", "-b", "main")
        _git(repo, "config", "user.email", "t@t")
        _git(repo, "config", "user.name", "t")
        (repo / "x.c").write_text("int x;\n")
        _git(repo, "add", "x.c")
        _git(repo, "commit", "-q", "-m", "first")
        monitor = CommitMonitor(CommitMonitorConfig(
            repo_path=str(repo),
            runner_factory=_mock_runner([]),
        ))
        head = _git(repo, "rev-parse", "HEAD")
        assert monitor._parent_sha(head) == ""
