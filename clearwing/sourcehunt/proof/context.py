"""Deterministic, bounded context packets for atomic model judgments."""

from __future__ import annotations

import json
import re

from .models import (
    Assumption,
    Candidate,
    Claim,
    CompletenessManifest,
    ContextPacket,
    Evidence,
    Fact,
    Obligation,
    ThreatModel,
)


class ContextPacketBuilder:
    def __init__(self, *, max_tokens: int = 6000, max_excerpt_chars: int = 1200):
        self.max_tokens = max_tokens
        self.max_excerpt_chars = max_excerpt_chars

    def build(
        self,
        candidate: Candidate,
        obligation: Obligation,
        facts: list[Fact],
        evidence: list[Evidence],
        claims: list[Claim],
        completeness: CompletenessManifest,
        threat_model: ThreatModel | None = None,
        assumptions: list[Assumption] | None = None,
        evaluation_hints: dict[str, object] | None = None,
    ) -> ContextPacket:
        candidate_fact_ids = set(candidate.fact_ids)
        relevant_facts = [fact for fact in facts if fact.id in candidate_fact_ids]
        relevant_facts.sort(
            key=lambda fact: (
                -self._relevance(fact, obligation),
                fact.location.file if fact.location else "",
                fact.location.line if fact.location else 0,
                fact.id,
            )
        )
        threat_payload = threat_model.model_dump(mode="json") if threat_model is not None else None
        assumption_aliases = set(candidate.assumption_ids)
        candidate_aliases = {candidate.id, candidate.logical_id}
        relevant_assumptions = sorted(
            (
                assumption
                for assumption in assumptions or []
                if assumption.id in assumption_aliases
                or assumption.logical_id in assumption_aliases
                or candidate_aliases.intersection(assumption.required_by)
            ),
            key=lambda assumption: assumption.logical_id,
        )
        assumption_summaries = [
            {
                "assumption_id": assumption.id,
                "logical_id": assumption.logical_id,
                "kind": assumption.kind,
                "statement": assumption.statement,
                "status": assumption.status,
                "scope": assumption.scope,
                "evidence_ids": assumption.evidence_ids,
            }
            for assumption in relevant_assumptions
        ]
        excerpts: list[dict[str, object]] = []
        selected_fact_ids: list[str] = []
        token_count = self._estimate_tokens(
            json.dumps(
                {
                    "question": obligation.description + obligation.predicate,
                    "threat_model": threat_payload,
                    "assumptions": assumption_summaries,
                    "evaluation_hints": evaluation_hints or {},
                    "completeness": completeness.model_dump(mode="json"),
                    "permitted_outputs": [
                        "proven",
                        "disproven",
                        "unknown",
                        "blocked",
                        "conflicting_evidence",
                    ],
                },
                sort_keys=True,
                default=str,
            )
        )
        if token_count > self.max_tokens:
            raise ValueError(
                "Context packet budget is too small for its mandatory threat "
                "model and completeness manifest"
            )
        relevant_claims = sorted(
            (claim for claim in claims if claim.subject in candidate_aliases),
            key=lambda claim: (
                -self._text_relevance(
                    f"{claim.predicate} {claim.object}",
                    obligation,
                ),
                claim.id,
            ),
        )
        evidence_by_id = {
            identifier: item for item in evidence for identifier in (item.id, item.logical_id)
        }
        claim_ids: list[str] = []
        evidence_ids: list[str] = []
        claim_summaries: list[dict[str, object]] = []
        evidence_summaries: list[dict[str, object]] = []
        selected_evidence: set[str] = set()
        for claim in relevant_claims:
            summary: dict[str, object] = {
                "claim_id": claim.id,
                "predicate": claim.predicate,
                "object": claim.object,
                "status": claim.status,
                "supporting_evidence_ids": claim.supporting_evidence_ids,
                "contradicting_evidence_ids": claim.contradicting_evidence_ids,
            }
            summary_tokens = self._estimate_tokens(json.dumps(summary, sort_keys=True, default=str))
            if token_count + summary_tokens > self.max_tokens:
                continue
            claim_ids.append(claim.id)
            claim_summaries.append(summary)
            token_count += summary_tokens
            for evidence_id in [
                *claim.supporting_evidence_ids,
                *claim.contradicting_evidence_ids,
            ]:
                item = evidence_by_id.get(evidence_id)
                if item is None or item.id in selected_evidence:
                    continue
                evidence_summary = self._evidence_summary(item)
                evidence_tokens = self._estimate_tokens(
                    json.dumps(evidence_summary, sort_keys=True, default=str)
                )
                if token_count + evidence_tokens > self.max_tokens:
                    continue
                selected_evidence.add(item.id)
                evidence_ids.append(item.id)
                evidence_summaries.append(evidence_summary)
                token_count += evidence_tokens
        for fact in relevant_facts:
            excerpt = self._fact_excerpt(fact)
            excerpt_tokens = self._estimate_tokens(json.dumps(excerpt, sort_keys=True, default=str))
            if token_count + excerpt_tokens > self.max_tokens:
                continue
            excerpts.append(excerpt)
            selected_fact_ids.append(fact.id)
            token_count += excerpt_tokens

        return ContextPacket(
            snapshot_id=candidate.snapshot_id,
            candidate_id=candidate.logical_id,
            obligation_id=obligation.logical_id,
            question=(
                f"{obligation.description}\nResolve only this predicate: {obligation.predicate}"
            ),
            fact_ids=selected_fact_ids,
            evidence_ids=evidence_ids,
            claim_ids=claim_ids,
            assumption_ids=[assumption.id for assumption in relevant_assumptions],
            evidence_summaries=evidence_summaries,
            claim_summaries=claim_summaries,
            assumption_summaries=assumption_summaries,
            evaluation_hints=evaluation_hints or {},
            threat_model=threat_payload,
            excerpts=excerpts,
            permitted_outputs=[
                "proven",
                "disproven",
                "unknown",
                "blocked",
                "conflicting_evidence",
            ],
            token_count=token_count,
            completeness=completeness,
        )

    def _relevance(self, fact: Fact, obligation: Obligation) -> int:
        terms = {
            term
            for term in re.findall(
                r"[a-z][a-z0-9_]+",
                f"{obligation.predicate} {obligation.description}".lower(),
            )
            if len(term) >= 4
        }
        haystack = " ".join(
            [
                fact.kind,
                fact.subject,
                fact.predicate,
                json.dumps(fact.properties, default=str),
            ]
        ).lower()
        score = sum(1 for term in terms if term in haystack)
        kind_boosts = {
            "guard": {"guard", "bound", "prevent"},
            "sentinel_use": {"sentinel", "reserved", "domain"},
            "assignment": {"domain", "identifier", "reach"},
            "memory_access": {"memory", "access", "object"},
            "memory_write": {"memory", "write", "object"},
            "call": {"reach", "call", "path"},
            "variable": {"type", "domain", "bound"},
            "field": {"type", "domain", "bound"},
        }
        score += len(kind_boosts.get(fact.kind, set()) & terms) * 3
        return score

    @staticmethod
    def _text_relevance(text: str, obligation: Obligation) -> int:
        terms = set(
            re.findall(
                r"[a-z][a-z0-9_]+",
                f"{obligation.predicate} {obligation.description}".lower(),
            )
        )
        lowered = text.lower()
        return sum(term in lowered for term in terms if len(term) >= 4)

    def _fact_excerpt(self, fact: Fact) -> dict[str, object]:
        properties = json.dumps(
            fact.properties,
            sort_keys=True,
            default=str,
        )
        if len(properties) > self.max_excerpt_chars:
            properties = properties[: self.max_excerpt_chars] + "…"
        return {
            "fact_id": fact.id,
            "kind": fact.kind,
            "subject": fact.subject,
            "predicate": fact.predicate,
            "location": (fact.location.model_dump(mode="json") if fact.location else None),
            "properties": properties,
            "provenance": fact.provenance.producer,
        }

    def _evidence_summary(self, evidence: Evidence) -> dict[str, object]:
        observations = json.dumps(
            evidence.observations,
            sort_keys=True,
            default=str,
        )
        if len(observations) > self.max_excerpt_chars:
            observations = observations[: self.max_excerpt_chars] + "…"
        return {
            "evidence_id": evidence.id,
            "kind": evidence.kind,
            "observations": observations,
            "artifact_uri": evidence.artifact_uri,
            "artifact_digest": evidence.artifact_digest,
            "reliability": evidence.reliability,
            "provenance": evidence.provenance.producer,
        }

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        return max(1, (len(text) + 3) // 4)
