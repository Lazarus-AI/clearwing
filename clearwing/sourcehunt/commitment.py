"""Cryptographic commitment log for sourcehunt findings (spec 014).

SHA-3-224 commitments prove findings existed at a specific point in time
without revealing their contents. Follows the Glasswing pattern of committing
reports, PoCs, and exploits separately.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path


class CommitmentType(str, Enum):
    REPORT = "report"
    POC = "poc"
    EXPLOIT = "exploit"


@dataclass
class Commitment:
    finding_id: str
    digest: str
    algorithm: str
    commitment_type: str
    committed_at: str
    project: str = ""
    severity: str = ""
    cwe: str = ""


def _canonicalize(
    finding_id: str,
    document: str,
    commitment_type: str,
    committed_at: str,
) -> str:
    """Canonical JSON form that gets hashed.

    Must produce identical output for `generate_commitment` at commit
    time and `verify_commitment` at reveal time — any drift here
    breaks every commitment. Kept deliberately small: four fields,
    sort_keys so key order is irrelevant.
    """
    return json.dumps(
        {
            "finding_id": finding_id,
            "document": document,
            "type": commitment_type,
            "committed_at": committed_at,
        },
        sort_keys=True,
    )


def generate_commitment(
    finding_id: str,
    document: str,
    commitment_type: CommitmentType = CommitmentType.REPORT,
    project: str = "",
    severity: str = "",
    cwe: str = "",
) -> Commitment:
    # One now() call shared between the hash input and the stored
    # timestamp. Previously these were two separate now() calls, so the
    # hash input's `generated_at` differed from the stored
    # `committed_at` by microseconds — making verification fundamentally
    # impossible no matter what the caller supplied.
    committed_at = datetime.now(timezone.utc).isoformat()
    canonical = _canonicalize(
        finding_id=finding_id,
        document=document,
        commitment_type=commitment_type.value,
        committed_at=committed_at,
    )
    digest = hashlib.sha3_224(canonical.encode()).hexdigest()
    return Commitment(
        finding_id=finding_id,
        digest=digest,
        algorithm="sha3-224",
        commitment_type=commitment_type.value,
        committed_at=committed_at,
        project=project,
        severity=severity,
        cwe=cwe,
    )


def verify_commitment(document: str, commitment: Commitment) -> bool:
    """Re-hash `document` under `commitment`'s canonical form and compare.

    Reconstructs the exact canonical JSON that was hashed at commit
    time — `finding_id`, `document`, `type`, `committed_at` — and
    compares digests. Accepts a `Commitment` rather than a raw digest
    string because verification requires all four fields; passing just
    the digest would make the check silently wrong.
    """
    canonical = _canonicalize(
        finding_id=commitment.finding_id,
        document=document,
        commitment_type=commitment.commitment_type,
        committed_at=commitment.committed_at,
    )
    actual = hashlib.sha3_224(canonical.encode()).hexdigest()
    return actual == commitment.digest


def _build_report_document(finding: dict) -> str:
    return json.dumps(
        {
            "finding_id": finding.get("id", ""),
            "file": finding.get("file", ""),
            "line_number": finding.get("line_number", 0),
            "cwe": finding.get("cwe", ""),
            "severity": (finding.get("severity_verified") or finding.get("severity", "")),
            "description": finding.get("description", ""),
            "evidence_level": finding.get("evidence_level", ""),
        },
        sort_keys=True,
    )


def _default_log_path() -> Path:
    from clearwing.core.config import clearwing_home

    return clearwing_home() / "sourcehunt" / "commitments.jsonl"


class CommitmentLog:
    """Append-only JSONL log of cryptographic commitments."""

    def __init__(self, log_path: Path | None = None):
        self._path = Path(log_path) if log_path else _default_log_path()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def commit(self, commitment: Commitment) -> None:
        record = {
            "finding_id": commitment.finding_id,
            "digest": commitment.digest,
            "algorithm": commitment.algorithm,
            "commitment_type": commitment.commitment_type,
            "committed_at": commitment.committed_at,
            "project": commitment.project,
            "severity": commitment.severity,
            "cwe": commitment.cwe,
        }
        with self._lock:
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")

    def commit_finding(self, finding: dict, project: str = "") -> list[Commitment]:
        severity = finding.get("severity_verified") or finding.get("severity", "")
        cwe = finding.get("cwe", "")
        finding_id = finding.get("id", "")
        commitments: list[Commitment] = []

        report_doc = _build_report_document(finding)
        c = generate_commitment(
            finding_id,
            report_doc,
            commitment_type=CommitmentType.REPORT,
            project=project,
            severity=severity,
            cwe=cwe,
        )
        self.commit(c)
        commitments.append(c)

        poc = finding.get("poc") or finding.get("poc_code")
        if poc:
            poc_text = poc if isinstance(poc, str) else str(poc)
            c = generate_commitment(
                finding_id,
                poc_text,
                commitment_type=CommitmentType.POC,
                project=project,
                severity=severity,
                cwe=cwe,
            )
            self.commit(c)
            commitments.append(c)

        exploit = finding.get("exploit")
        if exploit:
            exploit_text = exploit if isinstance(exploit, str) else str(exploit)
            c = generate_commitment(
                finding_id,
                exploit_text,
                commitment_type=CommitmentType.EXPLOIT,
                project=project,
                severity=severity,
                cwe=cwe,
            )
            self.commit(c)
            commitments.append(c)

        return commitments

    def get_commitments(self, finding_id: str | None = None) -> list[Commitment]:
        if not self._path.exists():
            return []
        results: list[Commitment] = []
        with open(self._path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                if finding_id and record.get("finding_id") != finding_id:
                    continue
                results.append(
                    Commitment(
                        finding_id=record["finding_id"],
                        digest=record["digest"],
                        algorithm=record["algorithm"],
                        commitment_type=record["commitment_type"],
                        committed_at=record["committed_at"],
                        project=record.get("project", ""),
                        severity=record.get("severity", ""),
                        cwe=record.get("cwe", ""),
                    )
                )
        return results

    def format_public_table(self, fmt: str = "markdown") -> str:
        commitments = self.get_commitments()
        if not commitments:
            if fmt == "json":
                return "[]"
            return "No commitments recorded."

        if fmt == "json":
            return json.dumps(
                [
                    {
                        "date": c.committed_at,
                        "project": c.project,
                        "severity": c.severity,
                        "cwe": c.cwe,
                        "type": c.commitment_type,
                        "sha3_224": c.digest,
                    }
                    for c in commitments
                ],
                indent=2,
            )

        lines = [
            "| Date | Project | Severity | CWE | Type | SHA-3-224 |",
            "|------|---------|----------|-----|------|-----------|",
        ]
        for c in commitments:
            date_short = c.committed_at[:10] if c.committed_at else ""
            proj_short = c.project.rstrip("/").split("/")[-1] if c.project else ""
            lines.append(
                f"| {date_short} | {proj_short} | {c.severity} "
                f"| {c.cwe} | {c.commitment_type} | `{c.digest}` |"
            )
        return "\n".join(lines)
