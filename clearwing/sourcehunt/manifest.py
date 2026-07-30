"""Reproducible provenance metadata for sourcehunt run manifests."""

from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from clearwing import __version__


def _git_value(repo: Path, *arguments: str) -> str | None:
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    value = completed.stdout.strip()
    return value or None


def _git_dirty(repo: Path) -> bool | None:
    try:
        completed = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return bool(completed.stdout.strip())


def build_run_metadata(
    *,
    repo_path: str | Path,
    configuration: dict[str, Any],
    model_roles: dict[str, dict[str, str]],
    started_at: str | None,
    duration_seconds: float | None,
) -> dict[str, Any]:
    """Build stable, secret-free provenance fields for ``manifest.json``."""

    repo = Path(repo_path).resolve()
    canonical_config = json.dumps(
        configuration,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    ended_at = datetime.now(timezone.utc).isoformat()
    return {
        "schema_version": 2,
        "tool": "clearwing-sourcehunt",
        "tool_version": __version__,
        "started_at": started_at,
        "ended_at": ended_at,
        "duration_seconds": (
            round(duration_seconds, 3) if duration_seconds is not None else None
        ),
        "configuration_sha256": hashlib.sha256(canonical_config).hexdigest(),
        "configuration": configuration,
        "model_roles": model_roles,
        "target_git_sha": _git_value(repo, "rev-parse", "HEAD"),
        "target_git_branch": _git_value(repo, "rev-parse", "--abbrev-ref", "HEAD"),
        "target_git_dirty": _git_dirty(repo),
    }
