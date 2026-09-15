"""Label-scoped force-kill of sandbox containers (Recursive SourceHunt §10.2).

The recursive watchdog abandons a unit that exceeds its hard timeout; this
helper additionally force-removes the *labelled* sandbox containers that unit
left behind, reclaiming their resources instead of waiting for the process-wide
registry safety net. Killing is scoped to a **label selector** (never all
`managed-by=clearwing` containers), so a run only reaps its own sandboxes and
never another concurrent run's / tenant's.

Pure stdlib + subprocess-injected, so it is unit-testable without a Docker
daemon. Best-effort: any docker error is swallowed and reported in the result;
the watchdog's abandon+retry does not depend on the kill succeeding.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from types import ModuleType
from typing import Optional


def format_label(key: str, value: str) -> str:
    """`key=value` as docker's `--filter label=` expects."""
    return f"{key}={value}"


@dataclass
class KillResult:
    selector: str
    container_ids: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def kill_by_label(
    label_selector: str,
    *,
    process: ModuleType = subprocess,
    env: Optional[dict] = None,
    timeout: int = 30,
) -> KillResult:
    """Force-remove every container carrying ``label_selector`` (``key=value``).

    1. ``docker ps -aq --filter label=<selector>`` → ids
    2. ``docker rm -f <ids>``

    ``env`` routes the docker CLI at the right daemon (e.g. the DinD socket via
    ``DOCKER_HOST``). Never raises: errors are collected on the result.
    """
    result = KillResult(selector=label_selector)
    if not label_selector or "=" not in label_selector:
        result.errors.append(f"invalid label selector: {label_selector!r}")
        return result

    try:
        listed = process.run(
            ["docker", "ps", "-aq", "--filter", f"label={label_selector}"],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except Exception as e:  # noqa: BLE001 - best-effort
        result.errors.append(f"list failed: {e}")
        return result
    if listed.returncode != 0:
        result.errors.append((listed.stderr or "docker ps failed").strip())
        return result

    ids = [line.strip() for line in (listed.stdout or "").splitlines() if line.strip()]
    result.container_ids = ids
    if not ids:
        return result  # nothing to kill — a clean no-op

    try:
        removed = process.run(
            ["docker", "rm", "-f", *ids],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except Exception as e:  # noqa: BLE001
        result.errors.append(f"rm failed: {e}")
        return result
    if removed.returncode != 0:
        result.errors.append((removed.stderr or "docker rm -f failed").strip())
        return result

    result.removed = [
        line.strip() for line in (removed.stdout or "").splitlines() if line.strip()
    ]
    return result
