"""Versioned proof-obligation graph with dependency invalidation."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from typing import Any, TypeVar, cast

from .models import (
    Assumption,
    Candidate,
    Claim,
    Evidence,
    Obligation,
    ObligationStatus,
    VersionedRecord,
)
from .store import ProofStore

RecordT = TypeVar("RecordT", bound=VersionedRecord)

_SATISFIED = {ObligationStatus.PROVEN, ObligationStatus.NOT_APPLICABLE}


def revise(record: RecordT, **updates: Any) -> RecordT:
    """Construct a validated immutable successor revision."""

    payload = record.model_dump(mode="python")
    payload.update(updates)
    payload.update(
        {
            "id": "",
            "logical_id": record.logical_id,
            "revision": record.revision + 1,
            "supersedes": record.id,
        }
    )
    return cast(RecordT, type(record).model_validate(payload))


class ProofGraph:
    """Authoritative in-memory view of append-only proof records."""

    def __init__(self, store: ProofStore, snapshot_id: str):
        self.store = store
        self.snapshot_id = snapshot_id
        self.candidates: dict[str, Candidate] = {}
        self.assumptions: dict[str, Assumption] = {}
        self.claims: dict[str, Claim] = {}
        self.evidence: dict[str, Evidence] = {}
        self.obligations: dict[str, Obligation] = {}
        self._dependents: dict[str, set[str]] = defaultdict(set)
        self.reload()

    def reload(self) -> None:
        self.candidates = self._latest_for_snapshot(Candidate)
        self.assumptions = self._latest_for_snapshot(Assumption)
        self.claims = self._latest_for_snapshot(Claim)
        self.evidence = self._latest_for_snapshot(Evidence)
        self.obligations = self._latest_for_snapshot(Obligation)
        self._reindex()

    def _latest_for_snapshot(self, model_type: type[RecordT]) -> dict[str, RecordT]:
        return {
            logical_id: record
            for logical_id, record in self.store.latest(model_type).items()
            if record.snapshot_id == self.snapshot_id
        }

    def _reindex(self) -> None:
        self._dependents = defaultdict(set)
        aliases = {obligation.id: logical_id for logical_id, obligation in self.obligations.items()}
        for logical_id, obligation in self.obligations.items():
            for dependency in obligation.dependencies:
                dependency_id = aliases.get(dependency, dependency)
                self._dependents[dependency_id].add(logical_id)
        self.validate()

    def add_candidate(self, candidate: Candidate) -> Candidate:
        self._check_snapshot(candidate)
        return self._add(candidate, self.candidates)

    def add_assumption(self, assumption: Assumption) -> Assumption:
        self._check_snapshot(assumption)
        return self._add(assumption, self.assumptions)

    def add_claim(self, claim: Claim) -> Claim:
        self._check_snapshot(claim)
        return self._add(claim, self.claims)

    def add_evidence(self, evidence: Evidence) -> Evidence:
        self._check_snapshot(evidence)
        return self._add(evidence, self.evidence)

    def add_obligation(self, obligation: Obligation) -> Obligation:
        self._check_snapshot(obligation)
        if self._resolve_candidate(obligation.candidate_id) is None:
            raise ValueError(f"Obligation references unknown candidate {obligation.candidate_id}")
        if obligation.logical_id in self.obligations:
            raise ValueError(
                f"Obligation {obligation.logical_id} already exists; "
                "append a successor revision instead"
            )
        self.obligations[obligation.logical_id] = obligation
        try:
            self._reindex()
        except Exception:
            self.obligations.pop(obligation.logical_id, None)
            self._reindex()
            raise
        self.store.append(obligation)
        return obligation

    def _add(self, record: RecordT, collection: dict[str, RecordT]) -> RecordT:
        if record.logical_id in collection:
            raise ValueError(
                f"{type(record).__name__} {record.logical_id} already exists; "
                "append a successor revision instead"
            )
        self.store.append(record)
        collection[record.logical_id] = record
        return record

    def resolve_obligation(
        self,
        obligation_id: str,
        status: ObligationStatus,
        *,
        supporting_claim_ids: Iterable[str] = (),
        contradicting_claim_ids: Iterable[str] = (),
        blocked_reason: str | None = None,
    ) -> Obligation:
        logical_id = self._resolve_obligation_id(obligation_id)
        current = self.obligations[logical_id]
        supporting = list(supporting_claim_ids)
        contradicting = list(contradicting_claim_ids)
        if status == ObligationStatus.PROVEN and not supporting:
            raise ValueError("A proven obligation requires at least one supporting claim")
        if status == ObligationStatus.DISPROVEN and not contradicting:
            raise ValueError("A disproven obligation requires at least one contradicting claim")
        successor = revise(
            current,
            status=status,
            supporting_claim_ids=supporting,
            contradicting_claim_ids=contradicting,
            blocked_reason=blocked_reason,
        )
        self.store.append(successor)
        self.obligations[logical_id] = successor
        if current.status in _SATISFIED and status not in _SATISFIED:
            self._invalidate_dependents(logical_id)
        self._reindex()
        return successor

    def update_claim(
        self,
        claim_id: str,
        *,
        status: ObligationStatus,
        supporting_evidence_ids: Iterable[str] = (),
        contradicting_evidence_ids: Iterable[str] = (),
        derivation_id: str | None = None,
    ) -> Claim:
        logical_id = self._resolve_record_id(self.claims, claim_id)
        current = self.claims[logical_id]
        successor = revise(
            current,
            status=status,
            supporting_evidence_ids=list(supporting_evidence_ids),
            contradicting_evidence_ids=list(contradicting_evidence_ids),
            derivation_id=derivation_id,
        )
        self.store.append(successor)
        self.claims[logical_id] = successor
        return successor

    def update_assumption(
        self,
        assumption_id: str,
        *,
        status: ObligationStatus,
        evidence_ids: Iterable[str] = (),
    ) -> Assumption:
        """Append an assumption revision and stale every conclusion using it."""

        logical_id = self._resolve_record_id(self.assumptions, assumption_id)
        current = self.assumptions[logical_id]
        successor = revise(
            current,
            status=status,
            evidence_ids=list(evidence_ids),
        )
        self.store.append(successor)
        self.assumptions[logical_id] = successor
        self._invalidate_assumption_users(current)
        from .incremental import invalidate_certificates

        invalidate_certificates(
            self.store,
            changed_assumptions=[current.id, current.logical_id],
            reason=f"Assumption {current.logical_id} was revised",
        )
        self._reindex()
        return successor

    def ready_obligations(self, candidate_id: str | None = None) -> list[Obligation]:
        ready: list[Obligation] = []
        candidate_aliases: set[str] | None = None
        if candidate_id is not None:
            candidate = self._resolve_candidate(candidate_id)
            if candidate is None:
                raise KeyError(candidate_id)
            candidate_aliases = {candidate.id, candidate.logical_id}
        for obligation in self.obligations.values():
            if candidate_aliases is not None and obligation.candidate_id not in candidate_aliases:
                continue
            if obligation.status not in {
                ObligationStatus.UNKNOWN,
                ObligationStatus.STALE,
            }:
                continue
            dependencies = [
                self.obligations[self._resolve_obligation_id(dependency)]
                for dependency in obligation.dependencies
            ]
            if all(dependency.status in _SATISFIED for dependency in dependencies):
                ready.append(obligation)
        return sorted(ready, key=lambda item: item.logical_id)

    def candidate_obligations(self, candidate_id: str) -> list[Obligation]:
        candidate = self._resolve_candidate(candidate_id)
        if candidate is None:
            raise KeyError(candidate_id)
        aliases = {candidate.id, candidate.logical_id}
        return sorted(
            (
                obligation
                for obligation in self.obligations.values()
                if obligation.candidate_id in aliases
            ),
            key=lambda item: item.logical_id,
        )

    def validate(self) -> None:
        """Reject dangling dependencies and obligation cycles."""

        aliases = {obligation.id: logical_id for logical_id, obligation in self.obligations.items()}
        for obligation in self.obligations.values():
            for dependency in obligation.dependencies:
                resolved = aliases.get(dependency, dependency)
                if resolved not in self.obligations:
                    raise ValueError(
                        f"Obligation {obligation.logical_id} has missing dependency {dependency}"
                    )
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(logical_id: str) -> None:
            if logical_id in visited:
                return
            if logical_id in visiting:
                raise ValueError(f"Proof obligation cycle includes {logical_id}")
            visiting.add(logical_id)
            obligation = self.obligations[logical_id]
            for dependency in obligation.dependencies:
                visit(aliases.get(dependency, dependency))
            visiting.remove(logical_id)
            visited.add(logical_id)

        for logical_id in self.obligations:
            visit(logical_id)

    def materialize(self, candidate_id: str) -> dict[str, Any]:
        candidate = self._resolve_candidate(candidate_id)
        if candidate is None:
            raise KeyError(candidate_id)
        obligations = self.candidate_obligations(candidate_id)
        payload = {
            "schema_version": 1,
            "snapshot_id": self.snapshot_id,
            "candidate": candidate.model_dump(mode="json"),
            "assumptions": [
                assumption.model_dump(mode="json")
                for assumption in self._candidate_assumptions(candidate)
            ],
            "obligations": [obligation.model_dump(mode="json") for obligation in obligations],
            "edges": [
                {
                    "from": dependency,
                    "to": obligation.logical_id,
                    "kind": "requires",
                }
                for obligation in obligations
                for dependency in obligation.dependencies
            ]
            + [
                {
                    "from": assumption.logical_id,
                    "to": candidate.logical_id,
                    "kind": "assumed_by",
                }
                for assumption in self._candidate_assumptions(candidate)
            ],
        }
        self.store.write_graph(candidate.logical_id, payload)
        return payload

    def _invalidate_dependents(self, logical_id: str) -> None:
        queue = list(self._dependents.get(logical_id, ()))
        seen: set[str] = set()
        while queue:
            dependent_id = queue.pop(0)
            if dependent_id in seen:
                continue
            seen.add(dependent_id)
            current = self.obligations[dependent_id]
            if current.status != ObligationStatus.STALE:
                successor = revise(
                    current,
                    status=ObligationStatus.STALE,
                    supporting_claim_ids=[],
                    contradicting_claim_ids=[],
                    blocked_reason=f"Dependency {logical_id} is no longer satisfied",
                )
                self.store.append(successor)
                self.obligations[dependent_id] = successor
            queue.extend(self._dependents.get(dependent_id, ()))

    def _invalidate_assumption_users(self, assumption: Assumption) -> None:
        assumption_aliases = {assumption.id, assumption.logical_id}
        stale_claim_aliases: set[str] = set()
        for logical_id, claim in list(self.claims.items()):
            if not assumption_aliases.intersection(claim.assumption_ids):
                continue
            stale_claim = revise(
                claim,
                status=ObligationStatus.STALE,
                supporting_evidence_ids=[],
                contradicting_evidence_ids=[],
            )
            self.store.append(stale_claim)
            self.claims[logical_id] = stale_claim
            stale_claim_aliases.update({claim.id, claim.logical_id})

        directly_stale: list[str] = []
        for logical_id, obligation in list(self.obligations.items()):
            claim_ids = {
                *obligation.supporting_claim_ids,
                *obligation.contradicting_claim_ids,
            }
            if not claim_ids.intersection(stale_claim_aliases):
                continue
            stale_obligation = revise(
                obligation,
                status=ObligationStatus.STALE,
                supporting_claim_ids=[],
                contradicting_claim_ids=[],
                blocked_reason=(
                    f"Assumption {assumption.logical_id} changed after this obligation was resolved"
                ),
            )
            self.store.append(stale_obligation)
            self.obligations[logical_id] = stale_obligation
            directly_stale.append(logical_id)
        for logical_id in directly_stale:
            self._invalidate_dependents(logical_id)

    def _candidate_assumptions(self, candidate: Candidate) -> list[Assumption]:
        aliases = set(candidate.assumption_ids)
        candidate_aliases = {candidate.id, candidate.logical_id}
        return sorted(
            (
                assumption
                for assumption in self.assumptions.values()
                if assumption.id in aliases
                or assumption.logical_id in aliases
                or candidate_aliases.intersection(assumption.required_by)
            ),
            key=lambda assumption: assumption.logical_id,
        )

    def _check_snapshot(self, record: VersionedRecord) -> None:
        if record.snapshot_id != self.snapshot_id:
            raise ValueError(
                f"Record snapshot {record.snapshot_id} does not match graph "
                f"snapshot {self.snapshot_id}"
            )

    def _resolve_obligation_id(self, record_id: str) -> str:
        return self._resolve_record_id(self.obligations, record_id)

    @staticmethod
    def _resolve_record_id(
        records: dict[str, RecordT],
        record_id: str,
    ) -> str:
        if record_id in records:
            return record_id
        for logical_id, record in records.items():
            if record.id == record_id:
                return logical_id
        raise KeyError(record_id)

    def _resolve_candidate(self, candidate_id: str) -> Candidate | None:
        if candidate_id in self.candidates:
            return self.candidates[candidate_id]
        for candidate in self.candidates.values():
            if candidate.id == candidate_id:
                return candidate
        return None
