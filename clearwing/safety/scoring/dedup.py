from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class DedupRecord:
    """A normalized vulnerability finding."""

    id: str
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cve: str = ""
    target: str = ""
    port: int = 0
    service: str = ""
    evidence: str = ""
    remediation: str = ""
    duplicate_of: str | None = None  # id of the original if this is a dupe
    confidence: float = 1.0  # 0.0 - 1.0


class FindingDeduplicator:
    """Deduplicates vulnerability findings using multiple strategies."""

    def deduplicate(self, findings: list[DedupRecord]) -> list[DedupRecord]:
        """Remove duplicate findings, marking duplicates with duplicate_of field.

        Returns only unique findings, sorted by severity (critical first).
        """
        if not findings:
            return []

        unique: list[DedupRecord] = []
        seen_cves: dict[str, str] = {}  # cve -> finding id
        seen_signatures: dict[str, str] = {}  # signature -> finding id

        for finding in findings:
            # Strategy 1: Exact CVE match
            if finding.cve and finding.cve in seen_cves:
                finding.duplicate_of = seen_cves[finding.cve]
                continue

            # Strategy 2: Signature-based (normalized title + target + port)
            sig = self._signature(finding)
            if sig in seen_signatures:
                finding.duplicate_of = seen_signatures[sig]
                continue

            # Strategy 3: Fuzzy title match
            is_dupe = False
            for existing in unique:
                if self._is_similar(finding, existing):
                    finding.duplicate_of = existing.id
                    is_dupe = True
                    break

            if not is_dupe:
                unique.append(finding)
                if finding.cve:
                    seen_cves[finding.cve] = finding.id
                seen_signatures[sig] = finding.id

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        unique.sort(key=lambda f: (severity_order.get(f.severity, 5), -f.cvss_score))

        return unique

    def _signature(self, finding: DedupRecord) -> str:
        """Create a dedup signature from normalized fields."""
        title_norm = re.sub(r"[^a-z0-9]", "", finding.title.lower())
        return f"{title_norm}:{finding.target}:{finding.port}"

    def _is_similar(self, a: DedupRecord, b: DedupRecord) -> bool:
        """Check if two findings are similar enough to be duplicates."""
        # Same target and port, similar title
        if a.target != b.target:
            return False
        if a.port != b.port:
            return False

        # Normalize titles and check overlap
        a_words = set(re.sub(r"[^a-z0-9\s]", "", a.title.lower()).split())
        b_words = set(re.sub(r"[^a-z0-9\s]", "", b.title.lower()).split())

        if not a_words or not b_words:
            return False

        overlap = len(a_words & b_words)
        total = len(a_words | b_words)

        # Jaccard similarity > 0.6
        return (overlap / total) > 0.6 if total > 0 else False

    def merge_findings(self, groups: list[list[DedupRecord]]) -> list[DedupRecord]:
        """Merge multiple finding lists (from different scan phases) and deduplicate."""
        all_findings = []
        for group in groups:
            all_findings.extend(group)
        return self.deduplicate(all_findings)
