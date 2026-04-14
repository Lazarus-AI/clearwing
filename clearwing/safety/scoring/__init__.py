from __future__ import annotations

from clearwing.safety.scoring.cvss import CVSSVector, CVSSCalculator, VULN_PRESETS
from clearwing.safety.scoring.dedup import Finding, FindingDeduplicator

__all__ = [
    "CVSSVector",
    "CVSSCalculator",
    "VULN_PRESETS",
    "Finding",
    "FindingDeduplicator",
]
