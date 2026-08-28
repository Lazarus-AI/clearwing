"""Build provenance shared by reports and telemetry."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from clearwing import __version__

_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")


def clearwing_commit_sha() -> str:
    """Return the Clearwing source revision, suffixed when the worktree is dirty."""

    injected = os.environ.get("CLEARWING_COMMIT_SHA", "").strip()
    if _COMMIT_RE.fullmatch(injected):
        return injected.lower()

    repository = Path(__file__).resolve().parent.parent
    try:
        head = subprocess.run(
            ["git", "-C", str(repository), "rev-parse", "--verify", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        dirty = subprocess.run(
            ["git", "-C", str(repository), "status", "--porcelain"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    sha = head.stdout.strip().lower()
    if head.returncode != 0 or not _COMMIT_RE.fullmatch(sha):
        return "unknown"
    if dirty.returncode == 0 and dirty.stdout.strip():
        return f"{sha}-dirty"
    return sha


def clearwing_build_provenance() -> dict[str, str]:
    """Return stable build metadata suitable for reports and span attributes."""

    return {"version": __version__, "commit_sha": clearwing_commit_sha()}
