"""Invariant-oriented candidate generators and threat-model seeds."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Protocol, cast

from .models import Assumption, Candidate, Fact, ObligationStatus, ThreatModel


@dataclass(frozen=True)
class CandidateGenerationResult:
    candidates: list[Candidate]
    duplicates: list[dict[str, str]]


class CandidateGenerator(Protocol):
    name: str
    version: str

    def generate(self, snapshot_id: str, facts: list[Fact]) -> list[Candidate]: ...


class ReservedSentinelGenerator:
    """Find live identifiers that may alias a reserved representation value."""

    name = "reserved-sentinel-domain"
    version = "1"

    def generate(self, snapshot_id: str, facts: list[Fact]) -> list[Candidate]:
        sentinels = [fact for fact in facts if fact.kind == "sentinel_use"]
        assignments = [fact for fact in facts if fact.kind == "assignment"]
        variables = [fact for fact in facts if fact.kind in {"variable", "field"}]
        guards = [fact for fact in facts if fact.kind == "guard"]
        accesses = [fact for fact in facts if fact.kind in {"memory_access", "memory_write"}]
        calls = [fact for fact in facts if fact.kind == "call"]

        by_storage: dict[str, list[Fact]] = defaultdict(list)
        for sentinel in sentinels:
            expression = _expression(sentinel)
            for symbol in _storage_symbols(expression):
                by_storage[symbol].append(sentinel)

        candidates: list[Candidate] = []
        for storage_symbol, sentinel_facts in sorted(by_storage.items()):
            writes = [
                fact
                for fact in assignments
                if storage_symbol in str(fact.properties.get("lhs", ""))
            ]
            if not writes:
                continue
            sources = sorted(
                {
                    identifier
                    for fact in writes
                    for identifier in _identifiers(str(fact.properties.get("rhs", "")))
                    if identifier != storage_symbol and identifier not in _NOISE_IDENTIFIERS
                }
            )
            source = _best_source(sources)
            representation_facts = [
                fact
                for fact in variables
                if storage_symbol.lower() in fact.subject.lower()
                or storage_symbol in _expression(fact)
            ]
            source_domain_facts = [
                fact
                for fact in facts
                if source
                and (
                    (fact.kind in {"variable", "field", "parameter"} and source in fact.subject)
                    or (fact.kind == "counter_update" and source in _expression(fact))
                )
            ]
            relevant_guards = [fact for fact in guards if source and source in _expression(fact)]
            relevant_accesses = [
                fact
                for fact in accesses
                if storage_symbol in _expression(fact) or _shares_function(fact, writes)
            ]
            downstream_calls = [
                fact
                for fact in calls
                if _shares_function(fact, writes)
                or any(
                    keyword in str(fact.properties.get("callee", "")).lower()
                    for keyword in ("block", "filter", "write", "copy", "neighbor")
                )
            ]
            relevant = _unique_facts(
                [
                    *sentinel_facts,
                    *writes,
                    *representation_facts,
                    *source_domain_facts,
                    *relevant_guards,
                    *relevant_accesses,
                    *downstream_calls,
                ]
            )
            invariant_families = [
                "representation_domain_safety",
                "state_machine_safety",
            ]
            if relevant_accesses or downstream_calls:
                invariant_families.append("spatial_safety")
            candidates.append(
                Candidate(
                    snapshot_id=snapshot_id,
                    title=(f"Live identifier may alias reserved sentinel in {storage_symbol}"),
                    invariant_families=invariant_families,
                    suspected_mechanism="live_identifier_aliases_reserved_sentinel",
                    source_symbols=[source] if source else [],
                    transformations=[
                        f"{source or 'live identifier'} is stored in {storage_symbol}"
                    ],
                    state_sinks=[storage_symbol],
                    impact_sinks=sorted(
                        {
                            str(fact.properties.get("callee") or fact.subject)
                            for fact in downstream_calls
                        }
                    ),
                    suspected_invariants=[
                        "valid identifier domain does not intersect reserved sentinel domain",
                        "ownership and state comparisons preserve the sentinel distinction",
                    ],
                    fact_ids=[fact.id for fact in relevant],
                    generator=self.name,
                    generator_version=self.version,
                    experimental=not bool(representation_facts),
                )
            )
        return candidates


class AllocationAccessGenerator:
    """Find allocation/access extent contrasts in the same bounded scope."""

    name = "allocation-access-contrast"
    version = "2"

    def generate(self, snapshot_id: str, facts: list[Fact]) -> list[Candidate]:
        allocations = [fact for fact in facts if fact.kind == "allocation"]
        writes = [fact for fact in facts if fact.kind == "memory_write"]
        casts = [fact for fact in facts if fact.kind == "cast"]
        assignments = [fact for fact in facts if fact.kind == "assignment"]
        lengths = [fact for fact in facts if fact.kind == "length"]
        guards = [fact for fact in facts if fact.kind == "guard"]
        calls = [
            fact
            for fact in facts
            if fact.kind in {"call", "call_edge", "reachability", "taint_path"}
        ]
        candidates: list[Candidate] = []
        for allocation in allocations:
            related_writes = [
                write
                for write in writes
                if _same_scope(allocation, write) and _allocation_may_feed_access(allocation, write)
            ]
            for write in related_writes:
                allocation_expression = _expression(allocation)
                write_expression = _expression(write)
                allocation_extent = str(
                    allocation.properties.get("extent") or allocation_expression
                )
                write_extent = str(write.properties.get("extent") or write_expression)
                allocation_target = str(allocation.properties.get("target") or "")
                write_target = str(write.properties.get("target") or "")
                allocation_ids = set(
                    allocation.properties.get("extent_symbols") or _identifiers(allocation_extent)
                )
                write_ids = set(
                    write.properties.get("extent_symbols")
                    or write.properties.get("offset_symbols")
                    or _identifiers(write_extent)
                )
                local_casts = [fact for fact in casts if _same_scope(fact, allocation)]
                local_assignments = [fact for fact in assignments if _same_scope(fact, allocation)]
                local_lengths = [
                    fact
                    for fact in lengths
                    if _same_file_function(fact, allocation)
                    and fact.subject in allocation_ids | write_ids
                ]
                relevant_symbols = allocation_ids | write_ids
                local_guards = [
                    fact
                    for fact in guards
                    if _same_scope(fact, allocation)
                    and relevant_symbols.intersection(
                        set(
                            fact.properties.get("guarded_symbols")
                            or _identifiers(_expression(fact))
                        )
                    )
                ]
                local_calls = [fact for fact in calls if _same_file_function(fact, allocation)]
                source_symbols = sorted(relevant_symbols)
                target = write_target or allocation_target or "memory object"
                candidates.append(
                    Candidate(
                        snapshot_id=snapshot_id,
                        title=f"Allocation and write extents for {target} require a bounds proof",
                        invariant_families=[
                            "spatial_safety",
                            "representation_domain_safety",
                        ],
                        suspected_mechanism="allocation_access_extent_contrast",
                        source_symbols=source_symbols,
                        transformations=[
                            _expression(fact) for fact in local_casts + local_assignments
                        ],
                        state_sinks=[allocation_target or allocation_expression],
                        impact_sinks=[write_target or write_expression],
                        suspected_invariants=["accessed region is a subset of allocated region"],
                        fact_ids=[
                            fact.id
                            for fact in _unique_facts(
                                [
                                    allocation,
                                    write,
                                    *local_casts,
                                    *local_assignments,
                                    *local_lengths,
                                    *local_guards,
                                    *local_calls,
                                ]
                            )
                        ],
                        generator=self.name,
                        generator_version=self.version,
                        experimental=not bool(
                            allocation.properties.get("extent")
                            and write.properties.get("extent")
                            and allocation_target
                            and write_target
                        ),
                    )
                )
        return candidates


class InjectionBoundaryGenerator:
    name = "interpreter-boundary"
    version = "2"
    _SINKS = {
        "eval",
        "exec",
        "system",
        "popen",
        "execute",
        "executemany",
        "deserialize",
        "loads",
        "render_template_string",
        "yaml_load",
    }
    _ENCODERS = {
        "escape",
        "parameterize",
        "quote",
        "sanitize",
        "shellescape",
    }

    def generate(self, snapshot_id: str, facts: list[Fact]) -> list[Candidate]:
        candidates: list[Candidate] = []
        for fact in facts:
            callee = str(fact.properties.get("callee", "")).lower()
            if fact.kind != "call" or callee not in self._SINKS:
                continue
            expression = _expression(fact)
            sources = [
                identifier
                for identifier in _identifiers(expression)
                if any(
                    token in identifier.lower()
                    for token in ("input", "request", "user", "arg", "data", "query")
                )
            ]
            local_counterfacts = [
                item
                for item in facts
                if item.id != fact.id
                and _same_scope(item, fact)
                and (
                    item.kind == "encoding"
                    or (
                        item.kind == "call"
                        and any(
                            marker in str(item.properties.get("callee", "")).lower()
                            for marker in self._ENCODERS
                        )
                    )
                    or item.kind == "guard"
                )
            ]
            candidates.append(
                Candidate(
                    snapshot_id=snapshot_id,
                    title=f"Interpreter boundary at {callee} requires encoding proof",
                    invariant_families=["injection_safety"],
                    suspected_mechanism="untrusted_data_reaches_interpreter_boundary",
                    source_symbols=sorted(set(sources)),
                    impact_sinks=[callee],
                    suspected_invariants=["untrusted data cannot alter interpreted structure"],
                    fact_ids=[fact.id, *[item.id for item in local_counterfacts]],
                    generator=self.name,
                    generator_version=self.version,
                    experimental=not bool(sources),
                )
            )
        return candidates


class TemporalSafetyGenerator:
    name = "release-use-contrast"
    version = "2"
    _RELEASES = {"free", "delete", "drop", "close", "release", "unref"}

    def generate(self, snapshot_id: str, facts: list[Fact]) -> list[Candidate]:
        releases = [
            fact
            for fact in facts
            if fact.kind == "call"
            and str(fact.properties.get("callee", "")).lower() in self._RELEASES
        ]
        accesses = [
            fact for fact in facts if fact.kind in {"memory_access", "memory_write", "call"}
        ]
        candidates: list[Candidate] = []
        for release in releases:
            released = [
                identifier
                for identifier in _identifiers(_expression(release))
                if identifier.lower() not in self._RELEASES
            ]
            if not released:
                continue
            later = [
                fact
                for fact in accesses
                if _same_scope(release, fact)
                and fact.location
                and release.location
                and fact.location.line > release.location.line
                and any(symbol in _expression(fact) for symbol in released)
            ]
            if not later:
                continue
            first_use = later[0]
            intervening = [
                fact
                for fact in facts
                if fact.location
                and release.location
                and first_use.location
                and _same_file_function(fact, release)
                and release.location.line < fact.location.line < first_use.location.line
                and fact.id != release.id
            ]
            candidates.append(
                Candidate(
                    snapshot_id=snapshot_id,
                    title=f"Released object may be used again: {released[0]}",
                    invariant_families=["temporal_safety"],
                    suspected_mechanism="dereference_after_release",
                    source_symbols=[released[0]],
                    transformations=[_expression(release)],
                    impact_sinks=[_expression(later[0])],
                    suspected_invariants=["object is live at every dereference"],
                    fact_ids=[
                        release.id,
                        *[fact.id for fact in intervening],
                        *[fact.id for fact in later],
                    ],
                    generator=self.name,
                    generator_version=self.version,
                    experimental=True,
                )
            )
        return candidates


class AuthorizationBoundaryGenerator:
    name = "authorization-contrast"
    version = "2"
    _PROTECTED = {
        "delete",
        "update",
        "transfer",
        "withdraw",
        "set_role",
        "grant",
        "admin",
        "read_secret",
    }

    def generate(self, snapshot_id: str, facts: list[Fact]) -> list[Candidate]:
        guards = [fact for fact in facts if fact.kind in {"guard", "authorization_policy"}]
        candidates: list[Candidate] = []
        for fact in facts:
            callee = str(fact.properties.get("callee", "")).lower()
            if fact.kind != "call" or not any(protected in callee for protected in self._PROTECTED):
                continue
            local_guards = [
                guard
                for guard in guards
                if _same_scope(fact, guard)
                and any(
                    token in _expression(guard).lower()
                    for token in ("auth", "permit", "role", "owner", "principal")
                )
            ]
            candidates.append(
                Candidate(
                    snapshot_id=snapshot_id,
                    title=f"Protected operation {callee} requires policy proof",
                    invariant_families=["authority_safety"],
                    suspected_mechanism="protected_operation_authorization_contrast",
                    state_sinks=[callee],
                    suspected_invariants=["requested operation is permitted for the principal"],
                    fact_ids=[fact.id, *[guard.id for guard in local_guards]],
                    generator=self.name,
                    generator_version=self.version,
                    experimental=True,
                )
            )
        return candidates


class CryptographicPropertyGenerator:
    name = "cryptographic-precondition"
    version = "2"
    _MARKERS = {
        "md5": "collision_resistant_hash_required",
        "sha1": "collision_resistant_hash_required",
        "ecb": "message_pattern_confidentiality_required",
        "random": "unpredictable_randomness_required",
        "nonce": "nonce_uniqueness_required",
    }

    def generate(self, snapshot_id: str, facts: list[Fact]) -> list[Candidate]:
        candidates: list[Candidate] = []
        for fact in facts:
            if fact.kind not in {"call", "assignment"}:
                continue
            expression = _expression(fact).lower()
            marker = next(
                (item for item in self._MARKERS if item in expression),
                None,
            )
            if marker is None:
                continue
            local_contracts = [
                item
                for item in facts
                if item.id != fact.id
                and _same_scope(item, fact)
                and item.kind in {"crypto_contract", "crypto_precondition", "guard"}
            ]
            candidates.append(
                Candidate(
                    snapshot_id=snapshot_id,
                    title=f"Cryptographic use of {marker} requires a property proof",
                    invariant_families=["cryptographic_safety"],
                    suspected_mechanism=f"cryptographic_precondition:{marker}",
                    impact_sinks=[expression],
                    suspected_invariants=[self._MARKERS[marker]],
                    fact_ids=[fact.id, *[item.id for item in local_contracts]],
                    generator=self.name,
                    generator_version=self.version,
                    experimental=True,
                )
            )
        return candidates


class ParserBoundaryGenerator:
    name = "parser-boundary-contrast"
    version = "2"

    def generate(self, snapshot_id: str, facts: list[Fact]) -> list[Candidate]:
        guards = [fact for fact in facts if fact.kind == "guard"]
        candidates: list[Candidate] = []
        for fact in facts:
            if fact.kind not in {"memory_access", "memory_write"}:
                continue
            expression = _expression(fact)
            identifiers = sorted(
                set(fact.properties.get("offset_symbols", []))
                | set(fact.properties.get("extent_symbols", []))
                | set(_identifiers(expression))
            )
            extents = [
                identifier
                for identifier in identifiers
                if any(
                    token in identifier.lower()
                    for token in ("cursor", "offset", "len", "size", "count", "index")
                )
            ]
            if not extents:
                continue
            local_guards = [
                guard
                for guard in guards
                if _same_scope(fact, guard)
                and any(extent in _expression(guard) for extent in extents)
            ]
            local_boundaries = [
                item
                for item in facts
                if item.kind in {"parser_boundary", "range_violation"} and _same_scope(fact, item)
            ]
            if not local_guards and len(set(extents)) < 2:
                continue
            candidates.append(
                Candidate(
                    snapshot_id=snapshot_id,
                    title="Parser access requires a validated-boundary proof",
                    invariant_families=["parser_safety", "spatial_safety"],
                    suspected_mechanism="parser_extent_boundary_contrast",
                    source_symbols=extents,
                    impact_sinks=[expression],
                    suspected_invariants=[
                        "cursor plus requested length is within the validated boundary"
                    ],
                    fact_ids=[
                        fact.id,
                        *[guard.id for guard in local_guards],
                        *[item.id for item in local_boundaries],
                    ],
                    generator=self.name,
                    generator_version=self.version,
                    experimental=True,
                )
            )
        return candidates


class StateMachineGenerator:
    name = "state-transition"
    version = "2"

    def generate(self, snapshot_id: str, facts: list[Fact]) -> list[Candidate]:
        candidates: list[Candidate] = []
        for fact in facts:
            if fact.kind != "assignment":
                continue
            lhs = str(fact.properties.get("lhs", "")).lower()
            if not any(
                token in lhs for token in ("state", "status", "phase", "authenticated", "session")
            ):
                continue
            if "[" in lhs or any(storage in lhs for storage in ("table", "map", "buffer", "cache")):
                continue
            local_state_facts = [
                item
                for item in facts
                if item.id != fact.id
                and _same_scope(item, fact)
                and item.kind in {"guard", "state_model", "state_transition"}
            ]
            candidates.append(
                Candidate(
                    snapshot_id=snapshot_id,
                    title=f"State transition at {lhs} requires transition proof",
                    invariant_families=["state_machine_safety"],
                    suspected_mechanism="security_state_transition",
                    transformations=[_expression(fact)],
                    state_sinks=[lhs],
                    suspected_invariants=[
                        "transition is permitted from the current authenticated state"
                    ],
                    fact_ids=[fact.id, *[item.id for item in local_state_facts]],
                    generator=self.name,
                    generator_version=self.version,
                    experimental=True,
                )
            )
        return candidates


class ConcurrencyResourceGenerator:
    name = "concurrency-resource"
    version = "2"
    _THREAD_MARKERS = {"pthread_create", "thread", "spawn", "go"}

    def generate(self, snapshot_id: str, facts: list[Fact]) -> list[Candidate]:
        candidates: list[Candidate] = []
        loops = [fact for fact in facts if fact.kind == "loop"]
        allocations = [fact for fact in facts if fact.kind == "allocation"]
        for allocation in allocations:
            local_loops = [loop for loop in loops if _same_scope(loop, allocation)]
            if not local_loops:
                continue
            local_limits = [
                fact
                for fact in facts
                if _same_scope(fact, allocation) and fact.kind in {"guard", "resource_limit"}
            ]
            candidates.append(
                Candidate(
                    snapshot_id=snapshot_id,
                    title="Loop-driven allocation requires a resource bound",
                    invariant_families=["resource_safety"],
                    suspected_mechanism="attacker_driven_unbounded_allocation",
                    transformations=[_expression(loop) for loop in local_loops],
                    impact_sinks=[_expression(allocation)],
                    suspected_invariants=[
                        "attacker-influenced work remains within a bounded resource limit"
                    ],
                    fact_ids=[
                        allocation.id,
                        *[loop.id for loop in local_loops],
                        *[fact.id for fact in local_limits],
                    ],
                    generator=self.name,
                    generator_version=self.version,
                    experimental=True,
                )
            )
        thread_calls = [
            fact
            for fact in facts
            if fact.kind == "call"
            and any(
                marker in str(fact.properties.get("callee", "")).lower()
                for marker in self._THREAD_MARKERS
            )
        ]
        writes = [fact for fact in facts if fact.kind == "memory_write"]
        for thread in thread_calls:
            local_writes = [write for write in writes if _same_scope(thread, write)]
            if not local_writes:
                continue
            synchronization = [
                fact
                for fact in facts
                if _same_scope(fact, thread)
                and (
                    fact.kind == "synchronization"
                    or (
                        fact.kind == "call"
                        and any(
                            token in str(fact.properties.get("callee", "")).lower()
                            for token in ("lock", "mutex", "atomic", "semaphore")
                        )
                    )
                )
            ]
            candidates.append(
                Candidate(
                    snapshot_id=snapshot_id,
                    title="Concurrent shared write requires synchronization proof",
                    invariant_families=["concurrency_safety"],
                    suspected_mechanism="shared_write_across_concurrent_execution",
                    state_sinks=[_expression(write) for write in local_writes],
                    suspected_invariants=[
                        "shared-state invariants hold for every permitted schedule"
                    ],
                    fact_ids=[
                        thread.id,
                        *[write.id for write in local_writes],
                        *[fact.id for fact in synchronization],
                    ],
                    generator=self.name,
                    generator_version=self.version,
                    experimental=True,
                )
            )
        return candidates


class CandidatePipeline:
    """Run deterministic generators and merge structurally identical output."""

    def __init__(self, generators: list[CandidateGenerator] | None = None):
        self.generators = generators or [
            ReservedSentinelGenerator(),
            AllocationAccessGenerator(),
            InjectionBoundaryGenerator(),
            TemporalSafetyGenerator(),
            AuthorizationBoundaryGenerator(),
            CryptographicPropertyGenerator(),
            ParserBoundaryGenerator(),
            StateMachineGenerator(),
            ConcurrencyResourceGenerator(),
        ]

    def generate(
        self,
        snapshot_id: str,
        facts: list[Fact],
    ) -> CandidateGenerationResult:
        merged: dict[str, Candidate] = {}
        duplicates: list[dict[str, str]] = []
        for generator in self.generators:
            for generated in generator.generate(snapshot_id, facts):
                candidate = _attach_related_taint(generated, facts)
                existing = merged.get(candidate.logical_id)
                if existing is None:
                    merged[candidate.logical_id] = candidate
                    continue
                duplicates.append(
                    {
                        "candidate_id": candidate.logical_id,
                        "generator": generator.name,
                        "merged_into": existing.logical_id,
                    }
                )
                payload = existing.model_dump(mode="python")
                payload.update(
                    {
                        "id": "",
                        "fact_ids": sorted(set(existing.fact_ids) | set(candidate.fact_ids)),
                        "evidence_ids": sorted(
                            set(existing.evidence_ids) | set(candidate.evidence_ids)
                        ),
                        "invariant_families": sorted(
                            set(existing.invariant_families) | set(candidate.invariant_families)
                        ),
                        "impact_sinks": sorted(
                            set(existing.impact_sinks) | set(candidate.impact_sinks)
                        ),
                        "experimental": existing.experimental and candidate.experimental,
                    }
                )
                merged[candidate.logical_id] = Candidate.model_validate(payload)
        return CandidateGenerationResult(
            candidates=sorted(merged.values(), key=lambda item: item.logical_id),
            duplicates=duplicates,
        )


class ThreatModelBuilder:
    """Create a conservative, explicit threat model for one candidate."""

    def build(self, candidate: Candidate, facts: list[Fact]) -> ThreatModel:
        relevant = {fact.id: fact for fact in facts if fact.id in candidate.fact_ids}
        text = " ".join(_expression(fact).lower() for fact in relevant.values())
        parser_like = any(
            token in text
            for token in (
                "parse",
                "decode",
                "packet",
                "request",
                "input",
                "deserialize",
                "read",
            )
        )
        memory_like = "spatial_safety" in candidate.invariant_families
        return ThreatModel(
            snapshot_id=candidate.snapshot_id,
            attacker_principal=("untrusted_input_supplier" if parser_like else "unknown"),
            attacker_capabilities=(
                ["provide data to the affected parser or decoder"]
                if parser_like
                else ["unknown; attacker control remains an obligation"]
            ),
            trust_boundaries=["untrusted input to application processing boundary"],
            protected_assets=(
                ["process memory integrity", "application availability"]
                if memory_like
                else ["application security state"]
            ),
            required_privileges=[],
            deployment_assumptions=[
                "the affected component and code path are enabled",
                "the input reaches the suspected transformation",
            ],
            capability_gained=["unknown until impact obligations are resolved"],
            security_properties_violated=(
                ["memory safety"] if memory_like else ["state integrity"]
            ),
        )


class AssumptionBuilder:
    """Turn implicit threat-model premises into first-class graph records."""

    def build(
        self,
        candidate: Candidate,
        threat_model: ThreatModel,
    ) -> list[Assumption]:
        assumptions: list[Assumption] = []
        for statement in threat_model.deployment_assumptions:
            assumptions.append(
                Assumption(
                    snapshot_id=candidate.snapshot_id,
                    kind="deployment",
                    statement=statement,
                    status=ObligationStatus.UNKNOWN,
                    scope={
                        "candidate_id": candidate.logical_id,
                        "threat_model_id": threat_model.logical_id,
                    },
                    required_by=[candidate.logical_id],
                )
            )
        return assumptions


def _expression(fact: Fact) -> str:
    return str(
        fact.properties.get("expression")
        or fact.properties.get("excerpt")
        or fact.properties.get("rhs")
        or fact.object
        or ""
    )


def _identifiers(expression: str) -> list[str]:
    return re.findall(r"[A-Za-z_]\w*", expression)


_NOISE_IDENTIFIERS = {
    "memset",
    "memcpy",
    "sizeof",
    "int",
    "unsigned",
    "return",
    "NULL",
    "true",
    "false",
}


def _storage_symbols(expression: str) -> list[str]:
    identifiers = _identifiers(expression)
    preferred = [
        identifier
        for identifier in identifiers
        if any(
            token in identifier.lower()
            for token in (
                "table",
                "owner",
                "state",
                "slot",
                "map",
                "index",
                "id",
                "slice",
            )
        )
        and identifier not in _NOISE_IDENTIFIERS
    ]
    if preferred:
        return sorted(set(preferred))
    return sorted(
        {identifier for identifier in identifiers if identifier not in _NOISE_IDENTIFIERS}
    )[:2]


def _best_source(sources: list[str]) -> str:
    for source in sources:
        if any(
            token in source.lower()
            for token in ("count", "num", "id", "index", "serial", "sequence")
        ):
            return source
    return sources[0] if sources else ""


def _same_scope(left: Fact, right: Fact) -> bool:
    if left.location is None or right.location is None:
        return False
    if left.location.file != right.location.file:
        return False
    if left.location.function and right.location.function:
        return left.location.function == right.location.function
    return abs(left.location.line - right.location.line) <= 80


def _same_file_function(left: Fact, right: Fact) -> bool:
    if left.location is None or right.location is None:
        return False
    return (
        left.location.file == right.location.file
        and bool(left.location.function)
        and left.location.function == right.location.function
    )


def _allocation_may_feed_access(allocation: Fact, access: Fact) -> bool:
    allocation_target = str(allocation.properties.get("target") or "")
    access_target = str(access.properties.get("target") or "")
    if allocation_target and access_target:
        return _canonical_target(allocation_target) == _canonical_target(access_target)
    allocation_symbols = set(
        allocation.properties.get("extent_symbols") or _identifiers(_expression(allocation))
    )
    access_symbols = set(
        access.properties.get("extent_symbols")
        or access.properties.get("offset_symbols")
        or _identifiers(_expression(access))
    )
    return bool(allocation_symbols & access_symbols)


def _canonical_target(value: str) -> str:
    return re.sub(r"\s+", "", value).removeprefix("&")


def _shares_function(fact: Fact, others: list[Fact]) -> bool:
    return any(_same_scope(fact, other) for other in others)


def _unique_facts(facts: list[Fact]) -> list[Fact]:
    return list({fact.id: fact for fact in facts}.values())


def _attach_related_taint(candidate: Candidate, facts: list[Fact]) -> Candidate:
    """Attach only taint paths that share an explicit candidate endpoint."""

    endpoints = {
        item.lower()
        for item in [
            *candidate.source_symbols,
            *candidate.state_sinks,
            *candidate.impact_sinks,
        ]
        if item
    }
    if not endpoints:
        return candidate
    related: list[str] = []
    for fact in facts:
        if fact.kind != "taint_path":
            continue
        path_endpoints = {
            str(fact.properties.get(key, "")).lower()
            for key in ("variable", "source_function", "sink_function")
            if fact.properties.get(key)
        }
        if any(
            endpoint == path_endpoint or endpoint in path_endpoint or path_endpoint in endpoint
            for endpoint in endpoints
            for path_endpoint in path_endpoints
        ):
            related.append(fact.id)
    if not related:
        return candidate
    payload = candidate.model_dump(mode="python")
    payload.update(
        {
            "id": "",
            "fact_ids": sorted(set(candidate.fact_ids) | set(related)),
        }
    )
    return cast(Candidate, Candidate.model_validate(payload))
