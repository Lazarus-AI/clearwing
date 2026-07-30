"""Path normalization and repository confinement for agent-controlled refs."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

_LOCATION_SUFFIX = re.compile(r":\d+(?:-\d+)?$")
_HOST_ROOTED = re.compile(r"^(?:[\\/]+|[A-Za-z]:)")


def normalize_repo_reference(reference: object) -> str:
    """Normalize an optional ``:line`` suffix without making the path trusted."""

    value = str(reference or "").strip()
    return _LOCATION_SUFFIX.sub("", value)


def safe_repo_relative_path(reference: object) -> str | None:
    """Return a normalized repo-relative path, rejecting host-rooted escapes.

    The check is host-independent: UNC paths and Windows drive paths are
    rejected even when Clearwing is running on POSIX.  Backslashes in ordinary
    relative Windows paths are normalized to POSIX separators for the sandbox.
    """

    value = normalize_repo_reference(reference)
    if not value or "\x00" in value or _HOST_ROOTED.match(value):
        return None
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or any(part in {"", ".."} for part in path.parts):
        return None
    cleaned = path.as_posix()
    return cleaned if cleaned not in {"", "."} else None


def resolve_repo_file(repo_root: str | Path, reference: object) -> Path | None:
    """Resolve an existing regular file only when it remains under *repo_root*.

    ``Path.resolve`` follows symlinks, so an in-repo link to a host file fails
    the containment check instead of becoming an outbound model context read.
    """

    relative = safe_repo_relative_path(reference)
    if relative is None:
        return None
    try:
        root = Path(repo_root).resolve()
        candidate = (root / relative).resolve()
        candidate.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return None
    return candidate if candidate.is_file() else None
