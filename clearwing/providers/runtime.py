"""Provider routing installed for a single Clearwing process."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

_routing: dict[str, Any] | None = None


def install_runtime_routing(config: dict[str, Any]) -> None:
    """Install immutable provider routing before running one command."""
    global _routing
    if _routing is not None:
        raise RuntimeError("provider routing is already installed")
    if not isinstance(config, dict) or not config:
        raise ValueError("provider routing must be a non-empty object")
    _routing = deepcopy(config)


def runtime_routing() -> dict[str, Any] | None:
    """Return a private copy of the process provider routing, if configured."""
    return deepcopy(_routing)
