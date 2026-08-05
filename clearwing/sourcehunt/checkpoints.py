"""Per-stage checkpoints for a single SourceHuntRunner run.

Writes a full, human-readable snapshot of the findings at each natural pipeline
phase boundary — end of hunt, end of verify, end of exploit — under
``<session_dir>/checkpoints/<stage>.json``. Each file is a superset of
``findings.json`` (``json.load``-simple) so it doubles as an eval artifact
showing how findings evolve across phases.

Serialization is LOSSLESS: findings are dataclasses (``clearwing.findings.types.Finding``)
serialized via ``dataclasses.asdict`` — unlike ``FindingsPool``'s deliberately
lossy discovery-time subset, this keeps every verify/exploit/patch field. Reload
uses the same tolerant ``__dataclass_fields__`` filter the pool uses.

These checkpoints power ``SourceHuntRunner(resume_session=...)``: a crashed run
resumes from the last completed phase instead of re-hunting from scratch.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Any

from clearwing.findings.types import Finding

logger = logging.getLogger(__name__)

# Ordered most- to least-complete. `latest_checkpoint` returns the first present.
STAGES = ("exploit", "verify", "hunt")

_CHECKPOINT_DIRNAME = "checkpoints"
_LEDGER_FILENAME = "spend-ledger.jsonl"


def _checkpoint_dir(session_dir: Path) -> Path:
    return Path(session_dir) / _CHECKPOINT_DIRNAME


def _finding_to_dict(finding: Any) -> dict[str, Any]:
    """Losslessly serialize a Finding dataclass (or pass through a plain dict)."""
    if isinstance(finding, Finding):
        return asdict(finding)
    if isinstance(finding, dict):
        return dict(finding)
    # Best effort for anything dataclass-like.
    if hasattr(finding, "__dict__"):
        return dict(finding.__dict__)
    raise TypeError(f"Cannot serialize finding of type {type(finding)!r}")


def _finding_from_dict(data: dict[str, Any]) -> Finding:
    """Rehydrate a Finding, ignoring unknown keys (tolerant, matches FindingsPool)."""
    return Finding(**{
        k: v for k, v in data.items()
        if k in Finding.__dataclass_fields__
    })


def write_stage_checkpoint(
    session_dir: Path | str,
    stage: str,
    *,
    findings: list[Any],
    budget_spent_usd: float,
    verified: list[Any] | None = None,
    rejected: list[Any] | None = None,
    exploited: list[Any] | None = None,
    session_id: str | None = None,
) -> Path:
    """Atomically write a stage checkpoint to ``checkpoints/<stage>.json``.

    Only the finding collections relevant to the stage are included:
      - hunt:    findings
      - verify:  findings + verified + rejected
      - exploit: findings + verified + rejected + exploited

    Returns the path written.
    """
    if stage not in STAGES:
        raise ValueError(f"unknown stage {stage!r}; expected one of {STAGES}")

    ckpt_dir = _checkpoint_dir(Path(session_dir))
    ckpt_dir.mkdir(parents=True, exist_ok=True)
    target = ckpt_dir / f"{stage}.json"

    payload: dict[str, Any] = {
        "stage": stage,
        "session_id": session_id or Path(session_dir).name,
        "budget_spent_usd": float(budget_spent_usd),
        "findings": [_finding_to_dict(f) for f in findings],
    }
    if verified is not None:
        payload["verified"] = [_finding_to_dict(f) for f in verified]
    if rejected is not None:
        payload["rejected"] = [_finding_to_dict(f) for f in rejected]
    if exploited is not None:
        payload["exploited"] = [_finding_to_dict(f) for f in exploited]

    # Atomic write: temp file in the same dir + os.replace (mirrors campaign.py).
    fd, tmp_path = tempfile.mkstemp(dir=str(ckpt_dir), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
        os.replace(tmp_path, str(target))
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return target


def load_stage_checkpoint(
    session_dir: Path | str,
    stage: str,
) -> dict[str, Any] | None:
    """Load a stage checkpoint, rehydrating finding lists into Finding objects.

    Returns a dict with keys ``stage``, ``session_id``, ``budget_spent_usd``,
    ``findings`` (list[Finding]) and, for verify/exploit stages, ``verified`` /
    ``rejected`` / ``exploited`` (list[Finding]). Returns None if absent.
    """
    target = _checkpoint_dir(Path(session_dir)) / f"{stage}.json"
    if not target.exists():
        return None
    data = json.loads(target.read_text(encoding="utf-8"))

    out: dict[str, Any] = {
        "stage": data.get("stage", stage),
        "session_id": data.get("session_id", ""),
        "budget_spent_usd": float(data.get("budget_spent_usd", 0.0)),
        "findings": [_finding_from_dict(d) for d in data.get("findings", [])],
    }
    for key in ("verified", "rejected", "exploited"):
        if key in data:
            out[key] = [_finding_from_dict(d) for d in data[key]]
    return out


def latest_checkpoint(session_dir: Path | str) -> str | None:
    """Return the most-complete checkpoint stage present, or None.

    Priority: exploit > verify > hunt (a later phase implies the earlier ones ran).
    """
    ckpt_dir = _checkpoint_dir(Path(session_dir))
    for stage in STAGES:
        if (ckpt_dir / f"{stage}.json").exists():
            return stage
    return None


def sum_prior_spend(session_dir: Path | str) -> float:
    """Reconstruct total settled spend from an existing spend-ledger.jsonl.

    Sums ``cost_usd`` over every ``call_settled`` event. Tolerant of malformed
    lines. Returns 0.0 if the ledger is absent.
    """
    ledger = Path(session_dir) / _LEDGER_FILENAME
    if not ledger.exists():
        return 0.0
    total = 0.0
    for line in ledger.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("event") == "call_settled":
            try:
                total += float(event.get("cost_usd", 0.0) or 0.0)
            except (TypeError, ValueError):
                continue
    return total


def resolve_session_dir(resume_session: str, default_output_dir: str | Path) -> Path:
    """Resolve a ``resume_session`` argument to a concrete session directory.

    Accepts either a bare session name (``sh-<uuid>`` → ``<output_dir>/<name>``)
    or a path (absolute or relative) that points directly at a session dir.
    """
    candidate = Path(resume_session)
    # A path-like argument (contains a separator or exists as given) is used directly.
    if candidate.parent != Path(".") or candidate.exists():
        return candidate
    return Path(default_output_dir) / resume_session
