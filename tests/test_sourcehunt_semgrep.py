"""Tests for the Semgrep sidecar.

Uses subprocess.run mocking so these don't require semgrep to be installed.
"""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

from clearwing.sourcehunt.semgrep_sidecar import (
    SemgrepFinding,
    SemgrepSidecar,
    finding_to_dict,
)

# --- SemgrepFinding dataclass ----------------------------------------------


class TestSemgrepFinding:
    def test_finding_to_dict_roundtrip(self):
        f = SemgrepFinding(
            file="app.py",
            line=23,
            check_id="python.lang.security.audit.dangerous-exec",
            severity="ERROR",
            message="dangerous exec call",
            code_snippet="exec(user_input)",
            cwe="CWE-95",
        )
        d = finding_to_dict(f)
        assert d["file"] == "app.py"
        assert d["line"] == 23
        assert d["severity"] == "ERROR"
        assert d["description"] == "dangerous exec call"  # convenience key


# --- Availability check -----------------------------------------------------


class TestSemgrepAvailability:
    def test_available_true_when_binary_found(self):
        with patch("shutil.which", return_value="/usr/local/bin/semgrep"):
            assert SemgrepSidecar().available is True

    def test_available_false_when_binary_missing(self):
        with patch("shutil.which", return_value=None):
            assert SemgrepSidecar().available is False


# --- run_scan mocking subprocess -------------------------------------------


_FAKE_SEMGREP_OUTPUT = {
    "results": [
        {
            "check_id": "python.lang.security.audit.sqli",
            "path": "/abs/repo/app.py",
            "start": {"line": 23, "col": 5},
            "end": {"line": 23, "col": 60},
            "extra": {
                "severity": "ERROR",
                "message": "SQL injection via f-string",
                "lines": 'cursor.execute(f"SELECT ... {title}")',
                "metadata": {"cwe": "CWE-89"},
            },
        },
        {
            "check_id": "python.lang.security.audit.hardcoded-secret",
            "path": "/abs/repo/config.py",
            "start": {"line": 5, "col": 1},
            "end": {"line": 5, "col": 30},
            "extra": {
                "severity": "WARNING",
                "message": "hardcoded secret",
                "lines": 'API_KEY = "abc123"',
                "metadata": {"cwe": ["CWE-798"]},
            },
        },
    ],
}


def _fake_proc(stdout: str, returncode: int = 1):
    """semgrep rc=1 means 'scan completed, findings present'."""
    proc = MagicMock()
    proc.stdout = stdout
    proc.stderr = ""
    proc.returncode = returncode
    return proc


class TestRunScanMocked:
    def test_not_available_returns_empty(self):
        with patch("shutil.which", return_value=None):
            findings = SemgrepSidecar().run_scan("/abs/repo")
        assert findings == []

    def test_happy_path(self):
        with (
            patch("shutil.which", return_value="/usr/bin/semgrep"),
            patch("subprocess.run", return_value=_fake_proc(json.dumps(_FAKE_SEMGREP_OUTPUT))),
        ):
            findings = SemgrepSidecar().run_scan("/abs/repo")
        assert len(findings) == 2
        assert findings[0].file == "app.py"
        assert findings[0].line == 23
        assert findings[0].check_id == "python.lang.security.audit.sqli"
        assert findings[0].severity == "ERROR"
        assert findings[0].cwe == "CWE-89"
        # Second finding has CWE as a list — we pick the first entry
        assert findings[1].cwe == "CWE-798"

    def test_rc_zero_is_clean_not_error(self):
        with (
            patch("shutil.which", return_value="/usr/bin/semgrep"),
            patch(
                "subprocess.run", return_value=_fake_proc(json.dumps({"results": []}), returncode=0)
            ),
        ):
            findings = SemgrepSidecar().run_scan("/abs/repo")
        assert findings == []

    def test_rc_gt_one_returns_empty(self):
        with (
            patch("shutil.which", return_value="/usr/bin/semgrep"),
            patch("subprocess.run", return_value=_fake_proc("", returncode=2)),
        ):
            findings = SemgrepSidecar().run_scan("/abs/repo")
        assert findings == []

    def test_timeout_returns_empty(self):
        with (
            patch("shutil.which", return_value="/usr/bin/semgrep"),
            patch("subprocess.run", side_effect=subprocess.TimeoutExpired("semgrep", 300)),
        ):
            findings = SemgrepSidecar().run_scan("/abs/repo")
        assert findings == []

    def test_invalid_json_returns_empty(self):
        with (
            patch("shutil.which", return_value="/usr/bin/semgrep"),
            patch("subprocess.run", return_value=_fake_proc("not json at all")),
        ):
            findings = SemgrepSidecar().run_scan("/abs/repo")
        assert findings == []

    def test_cli_args_include_config(self):
        with (
            patch("shutil.which", return_value="/usr/bin/semgrep"),
            patch(
                "subprocess.run", return_value=_fake_proc(json.dumps({"results": []}), returncode=0)
            ) as mock_run,
        ):
            SemgrepSidecar(config="p/python").run_scan("/abs/repo")
        cmd = mock_run.call_args[0][0]
        assert "--config" in cmd
        assert "p/python" in cmd
        assert "/abs/repo" in cmd


# --- Preprocessor integration ----------------------------------------------


class TestPreprocessorSemgrepIntegration:
    def test_preprocessor_skips_semgrep_when_binary_missing(self, tmp_path):
        """When semgrep isn't installed, run_semgrep=True is a no-op."""
        from clearwing.sourcehunt.preprocessor import Preprocessor

        (tmp_path / "main.py").write_text("def hi(): print('x')\n")
        with patch("shutil.which", return_value=None):
            pp = Preprocessor(
                repo_url=str(tmp_path),
                local_path=str(tmp_path),
                run_semgrep=True,
            )
            result = pp.run()
        assert result.semgrep_findings == []

    def test_preprocessor_applies_semgrep_hints(self, tmp_path):
        """When semgrep returns findings, semgrep_hint count per file is set."""
        from clearwing.sourcehunt.preprocessor import Preprocessor

        (tmp_path / "app.py").write_text("def f(): exec(input())\n")
        fake_output = {
            "results": [
                {
                    "check_id": "x",
                    "path": str(tmp_path / "app.py"),
                    "start": {"line": 1},
                    "extra": {
                        "severity": "ERROR",
                        "message": "exec on user input",
                        "metadata": {"cwe": "CWE-95"},
                    },
                },
                {
                    "check_id": "y",
                    "path": str(tmp_path / "app.py"),
                    "start": {"line": 1},
                    "extra": {
                        "severity": "WARNING",
                        "message": "another issue",
                        "metadata": {},
                    },
                },
            ],
        }
        with (
            patch("shutil.which", return_value="/usr/bin/semgrep"),
            patch("subprocess.run", return_value=_fake_proc(json.dumps(fake_output))),
        ):
            pp = Preprocessor(
                repo_url=str(tmp_path),
                local_path=str(tmp_path),
                run_semgrep=True,
            )
            result = pp.run()

        assert len(result.semgrep_findings) == 2
        app = next(ft for ft in result.file_targets if ft["path"] == "app.py")
        assert app["semgrep_hint"] == 2


# --- Ranker integration ----------------------------------------------------


class TestRankerSemgrepFloor:
    def test_semgrep_hint_floors_surface(self):
        """A file with semgrep_hint > 0 gets surface floored to 3."""
        import json as _json
        from unittest.mock import MagicMock

        from clearwing.sourcehunt.ranker import Ranker

        llm = MagicMock()
        response = MagicMock()
        response.content = _json.dumps(
            [
                {
                    "path": "foo.py",
                    "surface": 1,
                    "influence": 1,
                    "surface_rationale": "",
                    "influence_rationale": "",
                }
            ]
        )
        llm.invoke.return_value = response

        files = [
            {
                "path": "foo.py",
                "language": "python",
                "loc": 30,
                "tags": [],
                "static_hint": 0,
                "semgrep_hint": 3,  # semgrep flagged 3 issues
                "imports_by": 0,
                "transitive_callers": 0,
                "defines_constants": False,
                "surface": 0,
                "influence": 0,
                "reachability": 3,
                "priority": 0.0,
                "tier": "C",
            }
        ]
        Ranker(llm).rank(files)
        assert files[0]["surface"] == 3
