"""Path resolution for the Recursive SourceHunt persistent stores (§1).

The hunt ledger, prepare cache and recursion checkpoint are file-backed SQLite
DBs (see hunt_ledger / prepare_cache / recursive_orchestrator). This module
places them under a **tenant/namespace-scoped** directory so two tenants (or
missions) never share ledger verdicts / cached preprocess / checkpoints for the
same artifact — the isolation a host artifact store requires, realized
without a control-plane round trip.

Layout: ``<output_dir>/recursive-stores/<namespace>/<name>.db``
- ``namespace`` comes from ``CLEARWING_RECURSIVE_STORE_NAMESPACE`` (the deploy /
  bridge sets it per tenant); absent → ``default``. Sanitized to one safe path
  segment so a hostile value can never escape the directory.
- A per-store env override (e.g. ``CLEARWING_HUNT_LEDGER_PATH``) still wins, for
  a mounted volume or a shared DB.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

NAMESPACE_ENV = "CLEARWING_RECURSIVE_STORE_NAMESPACE"
_SAFE = re.compile(r"[^A-Za-z0-9._-]")


def sanitize_namespace(namespace: str | None) -> str:
    """One safe path segment; empty/None/all-unsafe → ``default``."""
    ns = _SAFE.sub("_", (namespace or "").strip())
    ns = ns.strip(".")  # never "." / ".." / leading-dot traversal
    return ns or "default"


def recursive_store_path(
    output_dir: str | os.PathLike[str],
    name: str,
    *,
    namespace: str | None = None,
    override: str | None = None,
) -> str:
    """Resolve a store DB path.

    ``override`` (a per-store env value) wins verbatim. Otherwise place ``name``
    under ``<output_dir>/recursive-stores/<sanitized namespace>/``. ``namespace``
    falls back to ``$CLEARWING_RECURSIVE_STORE_NAMESPACE``.
    """
    if override:
        return override
    ns = sanitize_namespace(namespace if namespace is not None else os.environ.get(NAMESPACE_ENV))
    return str(Path(output_dir) / "recursive-stores" / ns / name)
