"""Bounded exploratory lane that can only emit structured candidates."""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from pydantic import Field

from clearwing.llm.native import response_text

from .models import Candidate, CompletenessManifest, Fact, StrictModel

_INVARIANT_FAMILIES = {
    "spatial_safety",
    "temporal_safety",
    "parser_safety",
    "authority_safety",
    "state_machine_safety",
    "cryptographic_safety",
    "representation_domain_safety",
    "injection_safety",
    "concurrency_safety",
    "resource_safety",
}


class ExploratoryProposal(StrictModel):
    title: str
    suspected_mechanism: str
    invariant_families: list[str]
    cited_fact_ids: list[str]
    source_symbols: list[str] = Field(default_factory=list)
    transformations: list[str] = Field(default_factory=list)
    state_sinks: list[str] = Field(default_factory=list)
    impact_sinks: list[str] = Field(default_factory=list)
    suspected_invariants: list[str] = Field(default_factory=list)
    unresolved_questions: list[str] = Field(default_factory=list)


class ExplorationOutput(StrictModel):
    proposals: list[ExploratoryProposal] = Field(default_factory=list)
    ignored_areas: list[str] = Field(default_factory=list)
    proposed_new_invariant_families: list[str] = Field(default_factory=list)


class ExploratoryLane:
    SYSTEM_PROMPT = """You are the bounded exploratory lane of a vulnerability
hunt. Look for architectural trust transitions and interactions not already
captured by common source/sink patterns. You may propose hypotheses only.
Every proposal must cite supplied fact IDs and name unresolved questions.
Never claim a vulnerability, reachability, or impact. Use an existing
invariant family whenever possible."""

    def __init__(self, llm: Any, *, max_facts: int = 240):
        self.llm = llm
        self.max_facts = max_facts

    async def explore(
        self,
        snapshot_id: str,
        facts: list[Fact],
        completeness: CompletenessManifest,
    ) -> tuple[list[Candidate], ExplorationOutput, dict[str, Any]]:
        selected = self._select_facts(facts)
        packet = {
            "snapshot_id": snapshot_id,
            "facts": [
                {
                    "id": fact.id,
                    "kind": fact.kind,
                    "subject": fact.subject,
                    "location": (fact.location.model_dump(mode="json") if fact.location else None),
                    "properties": fact.properties,
                }
                for fact in selected
            ],
            "completeness": completeness.model_dump(mode="json"),
            "permitted_result": "candidate proposals only",
        }
        response = await self.llm.aask_text(
            system=self.SYSTEM_PROMPT,
            user=json.dumps(packet, indent=2, default=str),
            response_schema=ExplorationOutput,
            response_schema_name="ExploratoryCandidateProposals",
        )
        output = ExplorationOutput.model_validate_json(response_text(response))
        allowed = {fact.id for fact in selected}
        candidates: list[Candidate] = []
        for proposal in output.proposals:
            if not proposal.cited_fact_ids:
                continue
            if not set(proposal.cited_fact_ids) <= allowed:
                continue
            invariant_families = [
                family for family in proposal.invariant_families if family in _INVARIANT_FAMILIES
            ]
            if not invariant_families:
                continue
            candidates.append(
                Candidate(
                    snapshot_id=snapshot_id,
                    title=proposal.title,
                    invariant_families=invariant_families,
                    suspected_mechanism=proposal.suspected_mechanism,
                    source_symbols=proposal.source_symbols,
                    transformations=proposal.transformations,
                    state_sinks=proposal.state_sinks,
                    impact_sinks=proposal.impact_sinks,
                    suspected_invariants=proposal.suspected_invariants,
                    fact_ids=proposal.cited_fact_ids,
                    generator="bounded-exploratory-lane",
                    generator_version="1",
                    experimental=True,
                )
            )
        return candidates, output, packet

    def _select_facts(self, facts: list[Fact]) -> list[Fact]:
        by_kind: dict[str, list[Fact]] = defaultdict(list)
        for fact in facts:
            by_kind[fact.kind].append(fact)
        selected: list[Fact] = []
        kinds = sorted(by_kind)
        while len(selected) < self.max_facts and kinds:
            remaining: list[str] = []
            for kind in kinds:
                bucket = by_kind[kind]
                if bucket:
                    selected.append(bucket.pop(0))
                    if len(selected) >= self.max_facts:
                        break
                if bucket:
                    remaining.append(kind)
            kinds = remaining
        return selected
