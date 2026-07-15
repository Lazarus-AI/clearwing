"""Reproducible repository snapshot capture."""

from __future__ import annotations

import hashlib
import os
import platform
import subprocess
from pathlib import Path
from typing import Any

from clearwing import __version__

from .models import RepositorySnapshot


class SnapshotError(RuntimeError):
    """Raised when a proof run cannot establish repository identity."""


def capture_snapshot(
    repo_path: str | Path,
    *,
    repo_url: str = "",
    build_configuration: str = "default",
    compiler: str = "",
    feature_flags: dict[str, Any] | None = None,
    tool_versions: dict[str, str] | None = None,
) -> RepositorySnapshot:
    """Capture commit, dirty tree, build scope, and toolchain identity."""

    root = Path(repo_path).expanduser().resolve()
    if not root.is_dir():
        raise SnapshotError(f"Repository path does not exist: {root}")

    commit_result = _git(root, "rev-parse", "HEAD", required=False)
    assert isinstance(commit_result, str)
    commit = commit_result.strip()
    if not repo_url:
        repo_result = _git(
            root,
            "remote",
            "get-url",
            "origin",
            required=False,
        )
        assert isinstance(repo_result, str)
        repo_url = repo_result.strip()

    versions = {
        "clearwing": __version__,
        "python": platform.python_version(),
        "platform": platform.platform(),
    }
    versions.update(tool_versions or {})

    return RepositorySnapshot(
        repo_path=str(root),
        repo_url=repo_url,
        commit=commit,
        dirty_tree_digest=_dirty_tree_digest(root),
        build_configuration=build_configuration,
        compiler=compiler,
        feature_flags=feature_flags or {},
        tool_versions=versions,
    )


def _dirty_tree_digest(root: Path) -> str | None:
    status = _git(
        root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        required=False,
        text=False,
    )
    assert isinstance(status, bytes)
    if not status:
        return None
    digest = hashlib.sha256()
    digest.update(status)
    entries = status.split(b"\0")
    for entry in entries:
        if not entry:
            continue
        decoded = entry.decode("utf-8", errors="surrogateescape")
        path_text = decoded[3:] if len(decoded) > 3 else ""
        if " -> " in path_text:
            path_text = path_text.rsplit(" -> ", 1)[-1]
        candidate = (root / path_text).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            continue
        if candidate.is_file():
            digest.update(path_text.encode("utf-8", errors="surrogateescape"))
            try:
                with candidate.open("rb") as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(block)
            except OSError:
                digest.update(b"<unreadable>")
    return digest.hexdigest()


def _git(
    root: Path,
    *arguments: str,
    required: bool,
    text: bool = True,
) -> str | bytes:
    try:
        result = subprocess.run(
            ["git", "-C", os.fspath(root), *arguments],
            check=False,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        if required:
            raise SnapshotError(f"Unable to run git: {exc}") from exc
        return "" if text else b""
    if result.returncode != 0:
        if required:
            error = result.stderr.decode("utf-8", errors="replace").strip()
            raise SnapshotError(error or "git command failed")
        return "" if text else b""
    if text:
        return result.stdout.decode("utf-8", errors="replace")
    return result.stdout
