from __future__ import annotations

from pathlib import Path

import pytest

from clearwing.sourcehunt.paths import resolve_repo_file, safe_repo_relative_path
from clearwing.sourcehunt.poc_runner import PocRunner


@pytest.mark.parametrize(
    "reference",
    [
        "../outside.c",
        "/etc/passwd",
        r"C:\Windows\win.ini",
        r"C:relative-but-drive-rooted.c",
        r"\\server\share\source.c",
        "//server/share/source.c",
        "src/../../outside.c",
        "bad\x00name.c",
    ],
)
def test_safe_repo_relative_path_rejects_host_rooted_and_traversal(reference: str) -> None:
    assert safe_repo_relative_path(reference) is None


def test_safe_repo_relative_path_normalizes_location_and_windows_separator() -> None:
    assert safe_repo_relative_path(r"src\codec.c:17-19") == "src/codec.c"


def test_resolve_repo_file_rejects_symlink_escape(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("host secret", encoding="utf-8")
    link = repo / "source.c"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks are unavailable on this platform")
    assert resolve_repo_file(repo, "source.c") is None


class _NoExecSandbox:
    def __init__(self) -> None:
        self.calls = 0

    def exec(self, *args, **kwargs):
        self.calls += 1
        raise AssertionError("unsafe paths must be rejected before sandbox execution")

    def write_file(self, *args, **kwargs):
        raise AssertionError("unsafe paths must be rejected before sandbox writes")


def test_poc_runner_rejects_finding_path_before_shell_construction() -> None:
    sandbox = _NoExecSandbox()
    report = PocRunner(sandbox).replay(
        {"file": "../x'; touch /scratch/pwned; #.c", "poc": "x"},
        candidate_diff="--- a/x\n+++ b/x",
    )
    assert report["still_crashes"] is True
    assert "unsafe" in report["notes"]
    assert sandbox.calls == 0
