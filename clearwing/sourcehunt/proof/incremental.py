"""Dependency-based invalidation for reusable certificates."""

from __future__ import annotations

from collections.abc import Iterable

from .graph import revise
from .models import Certificate
from .store import ProofStore


def invalidated_certificates(
    certificates: Iterable[Certificate],
    *,
    changed_files: Iterable[str] = (),
    changed_symbols: Iterable[str] = (),
    changed_assumptions: Iterable[str] = (),
    changed_evidence: Iterable[str] = (),
) -> list[str]:
    files = set(changed_files)
    symbols = set(changed_symbols)
    assumptions = set(changed_assumptions)
    evidence = set(changed_evidence)
    return sorted(
        {
            certificate.logical_id
            for certificate in certificates
            if certificate.validity == "current"
            and (
                files.intersection(certificate.dependency_files)
                or symbols.intersection(certificate.dependency_symbols)
                or assumptions.intersection(certificate.assumption_ids)
                or evidence.intersection(certificate.evidence_ids)
            )
        }
    )


def invalidate_certificates(
    store: ProofStore,
    certificates: Iterable[Certificate] | None = None,
    *,
    changed_files: Iterable[str] = (),
    changed_symbols: Iterable[str] = (),
    changed_assumptions: Iterable[str] = (),
    changed_evidence: Iterable[str] = (),
    reason: str = "A recorded dependency changed",
) -> list[Certificate]:
    """Persist stale successor revisions for every affected certificate."""

    latest = store.latest(Certificate)
    if certificates is None:
        current = list(latest.values())
    else:
        provided = {certificate.logical_id: certificate for certificate in certificates}
        current = [
            latest.get(logical_id, certificate) for logical_id, certificate in provided.items()
        ]
    file_values = set(changed_files)
    symbol_values = set(changed_symbols)
    assumption_values = set(changed_assumptions)
    evidence_values = set(changed_evidence)
    invalidated_ids = set(
        invalidated_certificates(
            current,
            changed_files=file_values,
            changed_symbols=symbol_values,
            changed_assumptions=assumption_values,
            changed_evidence=evidence_values,
        )
    )
    successors: list[Certificate] = []
    for certificate in current:
        if certificate.logical_id not in invalidated_ids:
            continue
        causes = sorted(
            [
                *(
                    f"file:{item}"
                    for item in file_values.intersection(certificate.dependency_files)
                ),
                *(
                    f"symbol:{item}"
                    for item in symbol_values.intersection(certificate.dependency_symbols)
                ),
                *(
                    f"assumption:{item}"
                    for item in assumption_values.intersection(certificate.assumption_ids)
                ),
                *(
                    f"evidence:{item}"
                    for item in evidence_values.intersection(certificate.evidence_ids)
                ),
            ]
        )
        successor = revise(
            certificate,
            validity="stale",
            invalidated_by=causes,
            stale_reason=reason,
        )
        store.append(successor)
        successors.append(successor)
    return successors
