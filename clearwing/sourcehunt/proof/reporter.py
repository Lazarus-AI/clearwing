"""Evidence-constrained proof-flow report compilation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Assumption, Candidate, Certificate, CertificateKind, Fact
from .store import ProofStore


class ProofReporter:
    def __init__(self, store: ProofStore):
        self.store = store

    def write(
        self,
        certificates: list[Certificate],
        candidates: list[Candidate],
        facts: list[Fact],
    ) -> dict[str, Path]:
        candidate_by_id = {candidate.logical_id: candidate for candidate in candidates}
        finding_payloads = [
            self.to_finding(
                certificate,
                candidate_by_id.get(certificate.candidate_id),
                facts,
            )
            for certificate in certificates
            if certificate.kind == CertificateKind.FINDING and certificate.validity == "current"
        ]
        findings_path = self.store.root / "findings.json"
        findings_path.write_text(
            json.dumps(finding_payloads, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        report_path = self.store.root / "report.md"
        report_path.write_text(
            self._markdown(certificates, candidate_by_id),
            encoding="utf-8",
        )
        sarif_path = self.store.root / "findings.sarif"
        sarif_path.write_text(
            json.dumps(
                self._sarif(finding_payloads),
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        return {
            "markdown": report_path,
            "json": findings_path,
            "sarif": sarif_path,
        }

    def to_finding(
        self,
        certificate: Certificate,
        candidate: Candidate | None,
        facts: list[Fact],
    ) -> dict[str, Any]:
        relevant = [
            fact for fact in facts if candidate is not None and fact.id in set(candidate.fact_ids)
        ]
        located = next((fact for fact in relevant if fact.location is not None), None)
        statement = (
            str(certificate.report_claims[-1].get("statement", ""))
            if certificate.report_claims
            else certificate.reason
        )
        return {
            "id": certificate.id,
            "engine": "proof",
            "candidate_id": certificate.candidate_id,
            "certificate_id": certificate.logical_id,
            "file": located.location.file if located and located.location else "",
            "line_number": located.location.line if located and located.location else 1,
            "finding_type": (candidate.suspected_mechanism if candidate else "proof_finding"),
            "title": candidate.title if candidate else certificate.candidate_id,
            "description": statement,
            "severity": certificate.severity or "info",
            "cwe": certificate.cwe,
            "verified": True,
            "evidence_level": "root_cause_explained",
            "discovered_by": "proof_flow",
            "evidence_ids": certificate.evidence_ids,
            "claim_ids": certificate.claim_ids,
            "proof_plan_ids": certificate.proof_plan_ids,
            "unresolved_obligation_ids": certificate.unresolved_obligation_ids,
            "assumption_ids": certificate.assumption_ids,
            "certificate_validity": certificate.validity,
        }

    def _markdown(
        self,
        certificates: list[Certificate],
        candidates: dict[str, Candidate],
    ) -> str:
        lines = [
            "# Clearwing Sourcehunt Proof Report",
            "",
            "Every factual claim below carries evidence identifiers. Unknown and "
            "blocked obligations are preserved rather than inferred away.",
            "",
        ]
        for certificate in certificates:
            candidate = candidates.get(certificate.candidate_id)
            lines.extend(
                [
                    f"## {candidate.title if candidate else certificate.candidate_id}",
                    "",
                    f"- Certificate: §{certificate.id}§",
                    f"- Decision: §{certificate.decision}§",
                    f"- Validity: §{certificate.validity}§",
                    f"- Reason: {certificate.reason}",
                    f"- Proof plans: {', '.join(certificate.proof_plan_ids) or 'none'}",
                    "",
                ]
            )
            assumptions = [
                assumption
                for assumption_id in certificate.assumption_ids
                if (assumption := self.store.get(Assumption, assumption_id)) is not None
            ]
            if assumptions:
                lines.extend(["### Assumptions", ""])
                for assumption in assumptions:
                    evidence = ", ".join(f"§{item}§" for item in assumption.evidence_ids) or "none"
                    lines.append(
                        f"- [{assumption.status.value}] {assumption.statement} "
                        f"Evidence: {evidence}."
                    )
                lines.append("")
            if certificate.validity == "stale":
                lines.extend(
                    [
                        "### Stale certificate",
                        "",
                        f"- Reason: {certificate.stale_reason or 'dependency changed'}",
                        f"- Invalidated by: {', '.join(certificate.invalidated_by) or 'unknown'}",
                        "",
                    ]
                )
            if certificate.report_claims:
                lines.extend(["### Audited claims", ""])
                for claim in certificate.report_claims:
                    statement = claim.get("statement") or claim.get("predicate")
                    evidence_ids = ", ".join(f"§{item}§" for item in claim.get("evidence_ids", []))
                    lines.append(f"- {statement} Evidence: {evidence_ids}.")
                lines.append("")
            if certificate.unresolved_obligation_ids:
                lines.extend(
                    [
                        "### Unresolved",
                        "",
                        *[
                            f"- §{obligation_id}§"
                            for obligation_id in certificate.unresolved_obligation_ids
                        ],
                        "",
                    ]
                )
            if certificate.blocked_obligation_ids:
                lines.extend(
                    [
                        "### Blocked",
                        "",
                        *[
                            f"- §{obligation_id}§"
                            for obligation_id in certificate.blocked_obligation_ids
                        ],
                        "",
                    ]
                )
        return "\n".join(lines).rstrip() + "\n"

    @staticmethod
    def _sarif(findings: list[dict[str, Any]]) -> dict[str, Any]:
        rules = {
            finding["finding_type"]: {
                "id": finding["finding_type"],
                "name": finding["finding_type"],
                "shortDescription": {"text": finding["title"]},
            }
            for finding in findings
        }
        return {
            "version": "2.1.0",
            "$schema": ("https://json.schemastore.org/sarif-2.1.0.json"),
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "clearwing-sourcehunt-proof",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": [
                        {
                            "ruleId": finding["finding_type"],
                            "level": _sarif_level(finding["severity"]),
                            "message": {"text": finding["description"]},
                            "locations": (
                                [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": finding["file"]},
                                            "region": {"startLine": finding["line_number"]},
                                        }
                                    }
                                ]
                                if finding["file"]
                                else []
                            ),
                            "properties": {
                                "certificate_id": finding["certificate_id"],
                                "evidence_ids": finding["evidence_ids"],
                            },
                        }
                        for finding in findings
                    ],
                }
            ],
        }


def _sarif_level(severity: str) -> str:
    return {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }.get(severity, "warning")
