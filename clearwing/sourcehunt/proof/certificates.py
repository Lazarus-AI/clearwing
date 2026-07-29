"""Evidence-gated finding, rejection, and incomplete certificates."""

from __future__ import annotations

from collections.abc import Iterable

from .graph import ProofGraph
from .models import (
    Action,
    ActionStatus,
    Candidate,
    Certificate,
    CertificateKind,
    Claim,
    Evidence,
    Fact,
    Obligation,
    ObligationStatus,
    ThreatModel,
)
from .plans import ProofPlanRegistry
from .store import ProofStore


class EvidencePolicy:
    """Prevent evidence from being cited for claim types it cannot establish."""

    _RUNTIME_KINDS = {
        "sanitizer_crash",
        "sanitizer_uaf",
        "symbolic_memory_violation",
        "debugger_memory_violation",
        "authorization_differential",
        "cryptographic_differential",
        "injection_differential",
        "race_detector_violation",
        "bounded_resource_exhaustion",
        "fault_injection_violation",
        "configuration_differential",
        "patch_differential",
        "protocol_transition_violation",
    }
    _REACHABILITY_KINDS = {
        "static_reachability",
        "static_reachability_path",
        "taint_path",
        "taint_reachability_path",
        "coverage_trace",
        "complete_unreachability_proof",
        "bounded_model_judgment",
        "falsification_counterexample",
        "protocol_transition_violation",
    }

    def accepts(self, predicate: str, evidence: Evidence) -> bool:
        if predicate.startswith("runtime_confirms_"):
            return evidence.kind in self._RUNTIME_KINDS
        if "attacker" in predicate or "reachable" in predicate:
            return evidence.kind in self._REACHABILITY_KINDS
        if "security_boundary" in predicate:
            return evidence.kind in {
                "threat_model_evidence",
                "authorization_differential",
                "bounded_model_judgment",
                "falsification_counterexample",
            }
        if evidence.kind in {"sanitizer_crash", "sanitizer_uaf"} and (
            "reach" in predicate or "attacker" in predicate
        ):
            return False
        return True


class CertificateCompiler:
    """Compile graph state without allowing conclusions to outrun evidence."""

    def __init__(
        self,
        store: ProofStore,
        graph: ProofGraph,
        *,
        plan_registry: ProofPlanRegistry | None = None,
        evidence_policy: EvidencePolicy | None = None,
    ):
        self.store = store
        self.graph = graph
        self.plan_registry = plan_registry or ProofPlanRegistry()
        self.evidence_policy = evidence_policy or EvidencePolicy()

    def compile(
        self,
        candidate: Candidate,
        *,
        threat_model: ThreatModel | None,
        facts: list[Fact],
        falsification_action_ids: Iterable[str] = (),
        budget_exhausted: bool = False,
        persist: bool = True,
    ) -> Certificate:
        obligations = self.graph.candidate_obligations(candidate.logical_id)
        falsification_ids = list(falsification_action_ids)
        audited, invalid_obligations = self._audit_obligations(obligations)
        rejection = next(
            (
                obligation
                for obligation in obligations
                if obligation.decisive_rejection
                and obligation.status == ObligationStatus.DISPROVEN
                and obligation.logical_id not in invalid_obligations
            ),
            None,
        )
        evidence = self._candidate_evidence(obligations)
        report_claims = self._report_claims(obligations)
        assumption_ids = set(candidate.assumption_ids)
        for claim_id in audited:
            claim = self._claim(claim_id)
            if claim is not None:
                assumption_ids.update(claim.assumption_ids)
        dependencies = [fact for fact in facts if fact.id in set(candidate.fact_ids)]
        files = sorted({fact.location.file for fact in dependencies if fact.location is not None})
        symbols = sorted(
            {
                fact.subject
                for fact in dependencies
                if fact.kind in {"function", "variable", "field", "parameter"}
            }
        )

        if rejection is not None:
            kind = CertificateKind.REJECTION
            decision = "disproven"
            reason = f"Decisive proof obligation was disproven: {rejection.predicate}"
            severity = None
        else:
            hard_evidence_missing = self._missing_hard_evidence(candidate, evidence)
            falsification_complete = self._falsification_complete(falsification_ids)
            mandatory_complete = all(
                obligation.status
                in {
                    ObligationStatus.PROVEN,
                    ObligationStatus.NOT_APPLICABLE,
                }
                for obligation in obligations
                if obligation.mandatory
            )
            threat_boundary_proven = any(
                obligation.predicate.endswith("security_boundary")
                and obligation.status == ObligationStatus.PROVEN
                for obligation in obligations
            ) or not any("spatial_safety" == family for family in candidate.invariant_families)
            if (
                obligations
                and mandatory_complete
                and not invalid_obligations
                and not hard_evidence_missing
                and falsification_complete
                and threat_model is not None
                and threat_boundary_proven
            ):
                kind = CertificateKind.FINDING
                decision = "confirmed"
                reason = "All mandatory class-specific obligations are proven."
                severity = _severity(candidate, evidence)
            else:
                kind = CertificateKind.INCOMPLETE
                decision = "incomplete"
                reasons: list[str] = []
                if budget_exhausted:
                    reasons.append("run budget exhausted")
                if not obligations:
                    reasons.append("no applicable proof plan")
                if invalid_obligations:
                    reasons.append("one or more proven obligations lack valid evidence")
                if hard_evidence_missing:
                    reasons.append(
                        "missing decisive evidence: " + ", ".join(sorted(hard_evidence_missing))
                    )
                if not falsification_complete:
                    reasons.append("finite falsification plan is incomplete")
                if threat_model is None:
                    reasons.append("threat model is missing")
                if not threat_boundary_proven:
                    reasons.append("security boundary is not proven")
                if not mandatory_complete:
                    reasons.append("mandatory obligations remain unresolved")
                kind = CertificateKind.INCOMPLETE
                severity = None
                reason = "; ".join(reasons) or "proof requirements remain unresolved"

        unresolved = [
            obligation.logical_id
            for obligation in obligations
            if obligation.status
            in {
                ObligationStatus.UNKNOWN,
                ObligationStatus.STALE,
                ObligationStatus.CONFLICTING_EVIDENCE,
            }
            or obligation.logical_id in invalid_obligations
        ]
        blocked = [
            obligation.logical_id
            for obligation in obligations
            if obligation.status == ObligationStatus.BLOCKED
        ]
        certificate = Certificate(
            snapshot_id=candidate.snapshot_id,
            kind=kind,
            candidate_id=candidate.logical_id,
            proof_plan_ids=candidate.proof_plan_ids,
            decision=decision,
            reason=reason,
            threat_model_id=(threat_model.logical_id if threat_model is not None else None),
            claim_ids=sorted(audited),
            evidence_ids=sorted(evidence),
            assumption_ids=sorted(assumption_ids),
            unresolved_obligation_ids=sorted(set(unresolved)),
            blocked_obligation_ids=sorted(set(blocked)),
            falsification_action_ids=falsification_ids,
            dependency_files=files,
            dependency_symbols=symbols,
            severity=severity,
            cwe=_cwe(candidate),
            report_claims=report_claims,
        )
        if persist:
            self.store.append(certificate)
        return certificate

    def _audit_obligations(
        self,
        obligations: list[Obligation],
    ) -> tuple[set[str], set[str]]:
        audited_claims: set[str] = set()
        invalid: set[str] = set()
        for obligation in obligations:
            if obligation.status not in {
                ObligationStatus.PROVEN,
                ObligationStatus.DISPROVEN,
            }:
                continue
            claim_ids = (
                obligation.supporting_claim_ids
                if obligation.status == ObligationStatus.PROVEN
                else obligation.contradicting_claim_ids
            )
            valid_for_obligation = False
            for claim_id in claim_ids:
                claim = self._claim(claim_id)
                if claim is None:
                    continue
                valid_evidence = [
                    item
                    for evidence_id in claim.supporting_evidence_ids
                    if (item := self._evidence(evidence_id)) is not None
                    and self.evidence_policy.accepts(obligation.predicate, item)
                ]
                if valid_evidence:
                    valid_for_obligation = True
                    audited_claims.add(claim.logical_id)
            if not valid_for_obligation:
                invalid.add(obligation.logical_id)
        return audited_claims, invalid

    def _candidate_evidence(self, obligations: list[Obligation]) -> set[str]:
        evidence_ids: set[str] = set()
        for obligation in obligations:
            for claim_id in [
                *obligation.supporting_claim_ids,
                *obligation.contradicting_claim_ids,
            ]:
                claim = self._claim(claim_id)
                if claim is None:
                    continue
                for evidence_id in claim.supporting_evidence_ids:
                    evidence = self._evidence(evidence_id)
                    if evidence is not None:
                        evidence_ids.add(evidence.logical_id)
        return evidence_ids

    def _report_claims(self, obligations: list[Obligation]) -> list[dict[str, object]]:
        report_claims: list[dict[str, object]] = []
        for obligation in obligations:
            for claim_id in [
                *obligation.supporting_claim_ids,
                *obligation.contradicting_claim_ids,
            ]:
                claim = self._claim(claim_id)
                if claim is None or claim.status != ObligationStatus.PROVEN:
                    continue
                valid_evidence = [
                    evidence.logical_id
                    for evidence_id in claim.supporting_evidence_ids
                    if (evidence := self._evidence(evidence_id)) is not None
                    and self.evidence_policy.accepts(obligation.predicate, evidence)
                ]
                if not valid_evidence:
                    continue
                report_claims.append(
                    {
                        "claim_id": claim.logical_id,
                        "predicate": claim.predicate,
                        "statement": claim.object,
                        "evidence_ids": sorted(valid_evidence),
                        "assumption_ids": claim.assumption_ids,
                    }
                )
        return report_claims

    def _missing_hard_evidence(
        self,
        candidate: Candidate,
        evidence_ids: set[str],
    ) -> set[str]:
        evidence_kinds = {
            evidence.kind
            for evidence_id in evidence_ids
            if (evidence := self._evidence(evidence_id)) is not None
        }
        missing: set[str] = set()
        for plan_id in candidate.proof_plan_ids:
            plan = self.plan_registry.get(plan_id)
            if plan.decisive_evidence_kinds and not plan.decisive_evidence_kinds & evidence_kinds:
                missing.add(plan_id)
        return missing

    def _falsification_complete(self, action_ids: list[str]) -> bool:
        if not action_ids:
            return False
        for action_id in action_ids:
            action = self.store.get(Action, action_id)
            if action is None or action.status != ActionStatus.COMPLETED:
                return False
        return True

    def _claim(self, claim_id: str) -> Claim | None:
        if claim_id in self.graph.claims:
            return self.graph.claims[claim_id]
        for claim in self.graph.claims.values():
            if claim.id == claim_id:
                return claim
        return None

    def _evidence(self, evidence_id: str) -> Evidence | None:
        if evidence_id in self.graph.evidence:
            return self.graph.evidence[evidence_id]
        for evidence in self.graph.evidence.values():
            if evidence.id == evidence_id:
                return evidence
        return None


def _severity(candidate: Candidate, evidence_ids: set[str]) -> str:
    del evidence_ids
    if "authority_safety" in candidate.invariant_families:
        return "high"
    if {
        "spatial_safety",
        "temporal_safety",
    } & set(candidate.invariant_families):
        return "high"
    return "medium"


def _cwe(candidate: Candidate) -> str | None:
    families = set(candidate.invariant_families)
    if "spatial_safety" in families:
        return "CWE-787"
    if "temporal_safety" in families:
        return "CWE-416"
    if "authority_safety" in families:
        return "CWE-862"
    if "cryptographic_safety" in families:
        return "CWE-327"
    if "injection_safety" in families:
        return "CWE-74"
    return None
