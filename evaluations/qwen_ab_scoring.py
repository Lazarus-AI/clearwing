"""Hunter-only scoring + community sampling pins for the Qwen bake-off.

``findings.json`` mixes hunter ``record_finding`` hits with preprocessor
``source_analyzer`` dumps. Bake-off cells must score hunter findings only.
"""
from __future__ import annotations

from typing import Any

STATIC_DISCOVERED_BY = "source_analyzer"

# Qwen3 thinking generation_config. Pin on the wire via CLEARWING_* env
# (see AsyncLLMClient._wire_sampling); do not assume vLLM defaults.
COMMUNITY_TEMPERATURE = 1.0
COMMUNITY_TOP_P = 0.95
COMMUNITY_TOP_K = 20


def is_hunter_finding(finding: Any) -> bool:
    """True when *finding* is a hunter (or later-stage) hit, not static dump."""
    if finding is None:
        return False
    if isinstance(finding, dict):
        discovered = finding.get("discovered_by") or ""
    else:
        discovered = getattr(finding, "get", lambda *_: "")("discovered_by", "") or ""
        if not discovered:
            discovered = getattr(finding, "discovered_by", "") or ""
    return str(discovered).strip() != STATIC_DISCOVERED_BY


def count_findings(findings: list[Any] | None) -> dict[str, int]:
    rows = list(findings or [])
    n_hunter = sum(1 for row in rows if is_hunter_finding(row))
    n_static = len(rows) - n_hunter
    return {
        "n_findings": len(rows),
        "n_hunter_findings": n_hunter,
        "n_static_findings": n_static,
    }


def community_sampling_env() -> dict[str, str]:
    return {
        "CLEARWING_TEMPERATURE": str(COMMUNITY_TEMPERATURE),
        "CLEARWING_TOP_P": str(COMMUNITY_TOP_P),
        "CLEARWING_TOP_K": str(COMMUNITY_TOP_K),
    }
