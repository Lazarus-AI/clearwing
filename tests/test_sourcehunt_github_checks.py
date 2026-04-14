"""Production tests for GitHub Checks API integration.

Mocks subprocess.run so no actual `gh` or `git` calls happen.
Covers:
    - owner/repo detection from SSH and HTTPS remotes
    - severity → conclusion mapping
    - annotation construction with file + line + level
    - annotation count capped at 50 per API call, extras PATCHed
    - empty-findings → success conclusion
    - gh binary missing → no-op
    - CommitMonitor integration wiring
"""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

from clearwing.sourcehunt.github_checks import (
    CheckRunOutcome,
    GitHubChecksConfig,
    GitHubChecksPublisher,
    parse_owner_repo,
)


def _finding(**kwargs) -> dict:
    base = {
        "id": "f1",
        "file": "src/codec.c",
        "line_number": 47,
        "finding_type": "memory_safety_heap_overflow",
        "cwe": "CWE-787",
        "severity": "critical",
        "evidence_level": "crash_reproduced",
        "discovered_by": "hunter:memory_safety",
        "description": "memcpy with unchecked length",
        "crash_evidence": "ASan: heap-buffer-overflow",
        "verified": True,
    }
    base.update(kwargs)
    return base


# --- parse_owner_repo -------------------------------------------------------


class TestParseOwnerRepo:
    def test_https_url(self):
        assert parse_owner_repo("https://github.com/example/codec") == ("example", "codec")

    def test_https_url_with_git_suffix(self):
        assert parse_owner_repo("https://github.com/example/codec.git") == ("example", "codec")

    def test_ssh_shorthand(self):
        assert parse_owner_repo("git@github.com:example/codec.git") == ("example", "codec")

    def test_ssh_explicit(self):
        assert parse_owner_repo("ssh://git@github.com/example/codec.git") == ("example", "codec")

    def test_nested_owner(self):
        assert parse_owner_repo("https://github.com/my-org/my-repo") == ("my-org", "my-repo")

    def test_empty_returns_none(self):
        assert parse_owner_repo("") is None

    def test_malformed_returns_none(self):
        assert parse_owner_repo("not a url at all") is None


# --- Owner/repo detection from git remote ----------------------------------


class TestDetectOwnerRepo:
    def test_detect_from_git_remote(self):
        publisher = GitHubChecksPublisher(GitHubChecksConfig(repo_path="/tmp/repo"))
        fake_proc = MagicMock(returncode=0, stdout="https://github.com/acme/tool\n", stderr="")
        with patch("subprocess.run", return_value=fake_proc):
            result = publisher.detect_owner_repo()
        assert result == ("acme", "tool")

    def test_explicit_owner_repo_wins(self):
        publisher = GitHubChecksPublisher(
            GitHubChecksConfig(
                repo_path="/tmp/repo",
                owner="override",
                repo="explicit",
            )
        )
        # No subprocess call needed when both are set
        with patch("subprocess.run") as mock_run:
            result = publisher.detect_owner_repo()
            mock_run.assert_not_called()
        assert result == ("override", "explicit")

    def test_git_remote_failure_returns_none(self):
        publisher = GitHubChecksPublisher(GitHubChecksConfig(repo_path="/tmp/repo"))
        fake_proc = MagicMock(returncode=1, stdout="", stderr="not a git repo")
        with patch("subprocess.run", return_value=fake_proc):
            result = publisher.detect_owner_repo()
        assert result is None


# --- Conclusion mapping -----------------------------------------------------


class TestConclusionMapping:
    def test_no_findings_is_success(self):
        publisher = GitHubChecksPublisher(GitHubChecksConfig(repo_path="/tmp"))
        assert publisher._conclusion_from_findings([]) == "success"

    def test_critical_is_failure(self):
        publisher = GitHubChecksPublisher(GitHubChecksConfig(repo_path="/tmp"))
        assert publisher._conclusion_from_findings([_finding(severity="critical")]) == "failure"

    def test_high_is_failure(self):
        publisher = GitHubChecksPublisher(GitHubChecksConfig(repo_path="/tmp"))
        assert publisher._conclusion_from_findings([_finding(severity="high")]) == "failure"

    def test_medium_is_neutral(self):
        publisher = GitHubChecksPublisher(GitHubChecksConfig(repo_path="/tmp"))
        assert publisher._conclusion_from_findings([_finding(severity="medium")]) == "neutral"

    def test_info_only_is_neutral(self):
        publisher = GitHubChecksPublisher(GitHubChecksConfig(repo_path="/tmp"))
        assert publisher._conclusion_from_findings([_finding(severity="info")]) == "neutral"

    def test_mixed_picks_highest(self):
        publisher = GitHubChecksPublisher(GitHubChecksConfig(repo_path="/tmp"))
        findings = [
            _finding(severity="low"),
            _finding(severity="critical"),
            _finding(severity="medium"),
        ]
        assert publisher._conclusion_from_findings(findings) == "failure"

    def test_verified_severity_overrides(self):
        """severity_verified beats the original severity (verifier has the last word)."""
        publisher = GitHubChecksPublisher(GitHubChecksConfig(repo_path="/tmp"))
        f = _finding(severity="low", severity_verified="critical")
        assert publisher._conclusion_from_findings([f]) == "failure"


# --- Annotation construction ------------------------------------------------


class TestAnnotationConstruction:
    def test_basic_annotation(self):
        publisher = GitHubChecksPublisher(GitHubChecksConfig(repo_path="/tmp"))
        annotations = publisher._build_annotations([_finding()])
        assert len(annotations) == 1
        a = annotations[0]
        assert a["path"] == "src/codec.c"
        assert a["start_line"] == 47
        assert a["end_line"] == 47
        assert a["annotation_level"] == "failure"  # critical → failure
        assert "memcpy with unchecked length" in a["message"]
        assert "Evidence: crash_reproduced" in a["message"]

    def test_annotation_level_by_severity(self):
        publisher = GitHubChecksPublisher(GitHubChecksConfig(repo_path="/tmp"))
        cases = {
            "critical": "failure",
            "high": "failure",
            "medium": "warning",
            "low": "notice",
            "info": "notice",
        }
        for sev, expected_level in cases.items():
            ann = publisher._build_annotations([_finding(severity=sev)])[0]
            assert ann["annotation_level"] == expected_level, sev

    def test_findings_without_file_are_skipped(self):
        publisher = GitHubChecksPublisher(GitHubChecksConfig(repo_path="/tmp"))
        annotations = publisher._build_annotations(
            [
                _finding(file=None),
                _finding(line_number=None),
                _finding(),  # valid
            ]
        )
        assert len(annotations) == 1

    def test_end_line_defaults_to_start_line(self):
        publisher = GitHubChecksPublisher(GitHubChecksConfig(repo_path="/tmp"))
        ann = publisher._build_annotations([_finding(line_number=47, end_line=None)])[0]
        assert ann["start_line"] == 47
        assert ann["end_line"] == 47

    def test_end_line_distinct_when_set(self):
        publisher = GitHubChecksPublisher(GitHubChecksConfig(repo_path="/tmp"))
        ann = publisher._build_annotations([_finding(line_number=10, end_line=15)])[0]
        assert ann["start_line"] == 10
        assert ann["end_line"] == 15

    def test_crash_evidence_in_raw_details(self):
        publisher = GitHubChecksPublisher(GitHubChecksConfig(repo_path="/tmp"))
        ann = publisher._build_annotations(
            [
                _finding(crash_evidence="==1==ERROR: AddressSanitizer\nat 0xDEADBEEF"),
            ]
        )[0]
        assert "raw_details" in ann
        assert "AddressSanitizer" in ann["raw_details"]

    def test_annotation_includes_counter_argument(self):
        publisher = GitHubChecksPublisher(GitHubChecksConfig(repo_path="/tmp"))
        ann = publisher._build_annotations(
            [
                _finding(verifier_counter_argument="but the caller validates"),
            ]
        )[0]
        assert "counter-argument" in ann["message"]
        assert "but the caller validates" in ann["message"]


# --- Summary construction ---------------------------------------------------


class TestSummaryConstruction:
    def test_empty_summary(self):
        publisher = GitHubChecksPublisher(GitHubChecksConfig(repo_path="/tmp"))
        summary = publisher._build_summary([])
        assert "no findings" in summary.lower()

    def test_summary_has_severity_breakdown(self):
        publisher = GitHubChecksPublisher(GitHubChecksConfig(repo_path="/tmp"))
        findings = [
            _finding(severity="critical"),
            _finding(severity="critical"),
            _finding(severity="high"),
            _finding(severity="medium"),
        ]
        summary = publisher._build_summary(findings)
        assert "4 findings" in summary
        assert "**critical**: 2" in summary
        assert "**high**: 1" in summary
        assert "**medium**: 1" in summary

    def test_summary_has_evidence_breakdown(self):
        publisher = GitHubChecksPublisher(GitHubChecksConfig(repo_path="/tmp"))
        findings = [
            _finding(evidence_level="patch_validated"),
            _finding(evidence_level="crash_reproduced"),
            _finding(evidence_level="suspicion"),
        ]
        summary = publisher._build_summary(findings)
        assert "patch_validated" in summary
        assert "crash_reproduced" in summary

    def test_summary_has_discovered_by_breakdown(self):
        publisher = GitHubChecksPublisher(GitHubChecksConfig(repo_path="/tmp"))
        findings = [
            _finding(discovered_by="hunter:memory_safety"),
            _finding(discovered_by="hunter:memory_safety"),
            _finding(discovered_by="harness_generator"),
            _finding(discovered_by="variant_loop"),
        ]
        summary = publisher._build_summary(findings)
        assert "hunter:memory_safety" in summary
        assert "harness_generator" in summary
        assert "variant_loop" in summary


# --- Title construction -----------------------------------------------------


class TestTitleConstruction:
    def test_empty(self):
        publisher = GitHubChecksPublisher(GitHubChecksConfig(repo_path="/tmp"))
        title = publisher._build_title([])
        assert "no findings" in title.lower()

    def test_with_findings(self):
        publisher = GitHubChecksPublisher(GitHubChecksConfig(repo_path="/tmp"))
        findings = [
            _finding(severity="critical"),
            _finding(severity="high"),
            _finding(severity="medium"),
        ]
        title = publisher._build_title(findings)
        assert "3 findings" in title
        assert "1 critical" in title
        assert "1 high" in title
        assert "1 medium" in title


# --- Publish end-to-end -----------------------------------------------------


class TestPublishEndToEnd:
    def _setup(self, findings_list, gh_api_responses=None):
        """Return a publisher wired with mocked `gh api` calls."""
        publisher = GitHubChecksPublisher(
            GitHubChecksConfig(
                repo_path="/tmp/repo",
                owner="acme",
                repo="tool",
            )
        )

        responses = gh_api_responses or [{"id": 12345}]
        call_history = []

        def fake_run(cmd, *args, **kwargs):
            call_history.append(cmd)
            # Return responses in order
            idx = len(call_history) - 1
            if idx >= len(responses):
                # Overflow → empty response
                return MagicMock(returncode=1, stdout="", stderr="")
            resp = responses[idx]
            return MagicMock(
                returncode=0,
                stdout=json.dumps(resp),
                stderr="",
            )

        return publisher, fake_run, call_history

    def test_publish_success(self):
        publisher, fake_run, calls = self._setup([_finding()])
        with (
            patch("shutil.which", return_value="/usr/bin/gh"),
            patch("subprocess.run", side_effect=fake_run),
        ):
            outcome = publisher.publish("deadbeefcafe", [_finding()])
        assert outcome.published is True
        assert outcome.conclusion == "failure"
        assert outcome.check_run_id == "12345"
        assert outcome.finding_count == 1
        assert outcome.annotation_count == 1
        assert "acme/tool" in outcome.notes

    def test_publish_no_gh_cli(self):
        publisher = GitHubChecksPublisher(GitHubChecksConfig(repo_path="/tmp"))
        with patch("shutil.which", return_value=None):
            outcome = publisher.publish("sha", [_finding()])
        assert outcome.published is False
        assert "not found" in outcome.notes

    def test_publish_no_owner_repo(self):
        publisher = GitHubChecksPublisher(GitHubChecksConfig(repo_path="/tmp/repo"))
        fake_git_failure = MagicMock(returncode=1, stdout="", stderr="no origin")
        with (
            patch("shutil.which", return_value="/usr/bin/gh"),
            patch("subprocess.run", return_value=fake_git_failure),
        ):
            outcome = publisher.publish("sha", [_finding()])
        assert outcome.published is False
        assert "owner/repo" in outcome.notes

    def test_publish_clean_scan(self):
        """Zero findings → conclusion=success."""
        publisher, fake_run, _ = self._setup([])
        with (
            patch("shutil.which", return_value="/usr/bin/gh"),
            patch("subprocess.run", side_effect=fake_run),
        ):
            outcome = publisher.publish("sha", [])
        assert outcome.published is True
        assert outcome.conclusion == "success"
        assert outcome.annotation_count == 0

    def test_publish_paginates_annotations(self):
        """More than 50 annotations → multiple gh api calls (POST + PATCH+)."""
        findings = [_finding(id=f"f{i}", line_number=i + 1) for i in range(75)]
        # First call creates the check run (returns id), subsequent PATCHes
        # just need to return valid JSON.
        responses = [{"id": 99}] + [{"id": 99}] * 2
        publisher, fake_run, calls = self._setup(findings, responses)
        with (
            patch("shutil.which", return_value="/usr/bin/gh"),
            patch("subprocess.run", side_effect=fake_run),
        ):
            outcome = publisher.publish("sha", findings)
        assert outcome.published is True
        # 50 in the POST + 25 in a PATCH = 75
        assert outcome.annotation_count == 75
        # Two API calls total (POST + one PATCH)
        assert len(calls) == 2
        # First call is POST
        assert "--method" in calls[0] and "POST" in calls[0]
        # Second call is PATCH
        assert "--method" in calls[1] and "PATCH" in calls[1]

    def test_publish_api_failure_returns_unpublished(self):
        publisher = GitHubChecksPublisher(
            GitHubChecksConfig(
                repo_path="/tmp/repo",
                owner="acme",
                repo="tool",
            )
        )
        bad_proc = MagicMock(returncode=1, stdout="", stderr="API error")
        with (
            patch("shutil.which", return_value="/usr/bin/gh"),
            patch("subprocess.run", return_value=bad_proc),
        ):
            outcome = publisher.publish("sha", [_finding()])
        assert outcome.published is False
        assert "failed" in outcome.notes

    def test_publish_api_timeout(self):
        publisher = GitHubChecksPublisher(
            GitHubChecksConfig(
                repo_path="/tmp/repo",
                owner="acme",
                repo="tool",
            )
        )
        with (
            patch("shutil.which", return_value="/usr/bin/gh"),
            patch("subprocess.run", side_effect=subprocess.TimeoutExpired("gh", 60)),
        ):
            outcome = publisher.publish("sha", [_finding()])
        assert outcome.published is False


# --- CommitMonitor integration ---------------------------------------------


class TestCommitMonitorIntegration:
    def test_monitor_calls_publisher_when_enabled(self, tmp_path):
        """When enable_github_checks=True, scan_commit publishes a check run."""
        from clearwing.sourcehunt.commit_monitor import (
            CommitMonitor,
            CommitMonitorConfig,
        )

        # Set up a minimal git repo so _changed_files works
        repo = tmp_path / "repo"
        repo.mkdir()
        subprocess.run(["git", "-C", str(repo), "init", "-q", "-b", "main"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "t@t"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "t"], check=True)
        (repo / "main.c").write_text("int main() { return 0; }\n")
        subprocess.run(["git", "-C", str(repo), "add", "main.c"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "initial"], check=True)
        head = subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            text=True,
        ).strip()

        mock_publisher = MagicMock()
        mock_publisher.publish.return_value = CheckRunOutcome(
            published=True,
            conclusion="neutral",
            check_run_id="42",
            annotation_count=0,
            finding_count=0,
        )

        def runner_factory(files):
            runner = MagicMock()
            result = MagicMock(findings=[])
            runner.run.return_value = result
            return runner

        monitor = CommitMonitor(
            CommitMonitorConfig(
                repo_path=str(repo),
                enable_github_checks=True,
                github_checks_publisher=mock_publisher,
                runner_factory=runner_factory,
            )
        )
        result = monitor.scan_commit(head)
        # The publisher was called with the commit SHA
        mock_publisher.publish.assert_called_once()
        args = mock_publisher.publish.call_args
        assert args[0][0] == head
        # The outcome flows into the result
        assert result.check_run_outcome is not None
        assert result.check_run_outcome.published is True

    def test_monitor_no_op_when_disabled(self, tmp_path):
        from clearwing.sourcehunt.commit_monitor import (
            CommitMonitor,
            CommitMonitorConfig,
        )

        repo = tmp_path / "repo"
        repo.mkdir()
        subprocess.run(["git", "-C", str(repo), "init", "-q", "-b", "main"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "t@t"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "t"], check=True)
        (repo / "main.c").write_text("int main() { return 0; }\n")
        subprocess.run(["git", "-C", str(repo), "add", "main.c"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "initial"], check=True)
        head = subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            text=True,
        ).strip()

        monitor = CommitMonitor(
            CommitMonitorConfig(
                repo_path=str(repo),
                enable_github_checks=False,
                runner_factory=lambda files: MagicMock(
                    run=MagicMock(return_value=MagicMock(findings=[])),
                ),
            )
        )
        result = monitor.scan_commit(head)
        assert result.check_run_outcome is None

    def test_monitor_auto_constructs_publisher_when_none_supplied(self, tmp_path):
        """enable_github_checks=True without an explicit publisher → default one created."""
        from clearwing.sourcehunt.commit_monitor import (
            CommitMonitor,
            CommitMonitorConfig,
        )

        monitor = CommitMonitor(
            CommitMonitorConfig(
                repo_path=str(tmp_path),
                enable_github_checks=True,
            )
        )
        assert monitor._checks_publisher is not None
        assert monitor._checks_publisher.config.repo_path == str(tmp_path)
