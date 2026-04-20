"""Encrypted, access-logged storage for sensitive sourcehunt artifacts.

Exploits, PoCs, and transcripts are AES-256-GCM encrypted at rest with an
auto-generated key. Every store/retrieve operation is logged to an append-only
JSONL audit trail.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path

from clearwing.sourcehunt.disclosure_db import DisclosureDB
from clearwing.sourcehunt.state import DisclosureState

logger = logging.getLogger(__name__)

# Disclosure states that should keep tied artifacts alive through purge.
# Anything not in this set (DISCLOSED, CLOSED, REJECTED) is terminal and
# the artifact is eligible for retention-based deletion.
_ACTIVE_DISCLOSURE_STATES: frozenset[str] = frozenset(
    {
        DisclosureState.PENDING_REVIEW.value,
        DisclosureState.IN_REVIEW.value,
        DisclosureState.VALIDATED.value,
        DisclosureState.PENDING_DISCLOSURE.value,
    }
)


class ArtifactExportDenied(Exception):
    """Raised by `retrieve()` when `export_requires_approval=True` but no
    `approved_by` was supplied. The policy flag used to be silently
    ignored — now it actually gates the call."""


@dataclass
class ArtifactPolicy:
    encryption_at_rest: bool = True
    access_logged: bool = True
    retention_days: int = 180
    tied_to_disclosure: bool = True
    export_requires_approval: bool = True


def _default_base_dir() -> Path:
    from clearwing.core.config import clearwing_home

    return clearwing_home() / "sourcehunt" / "artifacts"


class ArtifactStore:
    """Encrypted, access-logged storage for sensitive artifacts."""

    def __init__(
        self,
        base_dir: Path | None = None,
        policy: ArtifactPolicy | None = None,
        audit_logger: object | None = None,
    ):
        self._base_dir = Path(base_dir) if base_dir else _default_base_dir()
        self._policy = policy or ArtifactPolicy()
        self._audit = audit_logger
        self._key: bytes = b""
        self._init_storage()

    def _init_storage(self) -> None:
        for subdir in ("exploits", "transcripts", "poc", "keys"):
            (self._base_dir / subdir).mkdir(parents=True, exist_ok=True)

        key_path = self._base_dir / "keys" / "master.key"
        if key_path.exists():
            self._key = key_path.read_bytes()
        else:
            self._key = os.urandom(32)
            key_path.write_bytes(self._key)
            os.chmod(key_path, 0o600)

    def _encrypt(self, data: bytes) -> bytes:
        if not self._policy.encryption_at_rest:
            return data
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        nonce = os.urandom(12)
        ct = AESGCM(self._key).encrypt(nonce, data, None)
        return nonce + ct

    def _decrypt(self, blob: bytes) -> bytes:
        if not self._policy.encryption_at_rest:
            return blob
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        nonce, ct = blob[:12], blob[12:]
        return AESGCM(self._key).decrypt(nonce, ct, None)

    def _log_access(
        self,
        action: str,
        finding_id: str,
        path: str,
        operator: str,
        approved_by: str | None = None,
    ) -> None:
        if not self._policy.access_logged:
            return
        entry = {
            "timestamp": time.time(),
            "action": action,
            "finding_id": finding_id,
            "path": path,
            "operator": operator,
            "approved_by": approved_by,
        }
        audit_path = self._base_dir / "audit.log"
        with open(audit_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    def _store(self, category: str, finding_id: str, data: bytes, operator: str) -> Path:
        safe_id = finding_id.replace("/", "_").replace("..", "_")
        out_path = self._base_dir / category / f"{safe_id}.enc"
        out_path.write_bytes(self._encrypt(data))
        self._log_access(f"store_{category}", finding_id, str(out_path), operator)
        return out_path

    def store_exploit(self, finding_id: str, data: bytes, operator: str = "system") -> Path:
        return self._store("exploits", finding_id, data, operator)

    def store_poc(self, finding_id: str, data: bytes, operator: str = "system") -> Path:
        return self._store("poc", finding_id, data, operator)

    def store_transcript(self, finding_id: str, data: bytes, operator: str = "system") -> Path:
        return self._store("transcripts", finding_id, data, operator)

    def retrieve(
        self,
        artifact_path: Path,
        operator: str = "system",
        approved_by: str | None = None,
    ) -> bytes:
        """Read and decrypt an artifact.

        `export_requires_approval` (default `True`) now gates this call:
        retrieve fails with `ArtifactExportDenied` unless `approved_by`
        is non-empty. Previously the policy flag was declared but never
        read — setting `export_requires_approval=True` did nothing.

        Also enforces path containment: `artifact_path` must resolve
        inside `self._base_dir` so an unvalidated caller can't feed
        `retrieve()` an arbitrary filesystem path (the decrypt would
        fail under GCM, but we shouldn't read the bytes at all).
        """
        artifact_path = Path(artifact_path)
        # Path containment — compare resolved forms so symlinks and
        # `..` components can't escape the artifact root.
        try:
            artifact_path.resolve().relative_to(self._base_dir.resolve())
        except ValueError:
            raise ArtifactExportDenied(
                f"artifact path outside artifact store: {artifact_path}"
            ) from None

        if self._policy.export_requires_approval and not approved_by:
            raise ArtifactExportDenied(
                "retrieve() requires `approved_by` when "
                "ArtifactPolicy.export_requires_approval is True. "
                "Pass the approver's identity or set the policy to False."
            )

        data = self._decrypt(artifact_path.read_bytes())
        finding_id = artifact_path.stem
        self._log_access(
            "retrieve",
            finding_id,
            str(artifact_path),
            operator,
            approved_by=approved_by,
        )
        return data

    def list_artifacts(self, finding_id: str) -> list[dict]:
        safe_id = finding_id.replace("/", "_").replace("..", "_")
        results = []
        for category in ("exploits", "transcripts", "poc"):
            p = self._base_dir / category / f"{safe_id}.enc"
            if p.exists():
                stat = p.stat()
                results.append(
                    {
                        "category": category,
                        "path": str(p),
                        "size_bytes": stat.st_size,
                        "modified": stat.st_mtime,
                    }
                )
        return results

    def purge_expired(self) -> int:
        """Delete artifacts whose mtime exceeds `retention_days`.

        When `tied_to_disclosure=True` (default), artifacts belonging
        to a finding that is still active in the disclosure DB
        (pending_review / in_review / pending_disclosure — anything
        not yet DISCLOSED, CLOSED, or REJECTED) are kept regardless
        of age. Previously this flag was silent config — purge
        deleted by mtime only and could wipe artifacts tied to an
        in-flight disclosure.
        """
        cutoff = time.time() - (self._policy.retention_days * 86400)
        open_finding_ids = (
            self._open_disclosure_finding_ids() if self._policy.tied_to_disclosure else set()
        )

        removed = 0
        for category in ("exploits", "transcripts", "poc"):
            cat_dir = self._base_dir / category
            if not cat_dir.exists():
                continue
            for f in cat_dir.iterdir():
                if not (f.is_file() and f.stat().st_mtime < cutoff):
                    continue
                # `stem` is the sanitized finding_id we stored under.
                if f.stem in open_finding_ids:
                    logger.debug(
                        "purge skipped %s — finding still in active disclosure",
                        f.name,
                    )
                    continue
                f.unlink()
                removed += 1
        return removed

    def _open_disclosure_finding_ids(self) -> set[str]:
        """Return finding ids still in a non-terminal disclosure state.

        Defensive: if the DB query fails (fresh install with no
        schema, sqlite locked, ...), `tied_to_disclosure` degrades to
        "no protection" rather than aborting purge. Logged at DEBUG.
        """
        try:
            db = DisclosureDB()
        except Exception:
            logger.debug(
                "tied_to_disclosure check unavailable; purge will not protect",
                exc_info=True,
            )
            return set()
        try:
            rows = db.get_queue()
            return {r["id"] for r in rows if r.get("state") in _ACTIVE_DISCLOSURE_STATES}
        except Exception:
            logger.debug("disclosure_db.get_queue failed", exc_info=True)
            return set()
        finally:
            db.close()
