"""Dependency-based invalidation for reusable certificates."""

from __future__ import annotations

from collections.abc import Iterable

from .models import Certificate


def invalidated_certificates(
    certificates: Iterable[Certificate],
    *,
    changed_files: Iterable[str] = (),
    changed_symbols: Iterable[str] = (),
) -> list[str]:
    files = set(changed_files)
    symbols = set(changed_symbols)
    return sorted(
        certificate.logical_id
        for certificate in certificates
        if files.intersection(certificate.dependency_files)
        or symbols.intersection(certificate.dependency_symbols)
    )
