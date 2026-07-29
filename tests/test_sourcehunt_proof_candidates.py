"""Invariant generators and composable proof-plan tests."""

from __future__ import annotations

from clearwing.sourcehunt.proof import (
    AuthorizationBoundaryGenerator,
    CandidatePipeline,
    ConcurrencyResourceGenerator,
    CryptographicPropertyGenerator,
    Fact,
    InjectionBoundaryGenerator,
    ParserBoundaryGenerator,
    ProofPlanRegistry,
    Provenance,
    SourceLocation,
    StateMachineGenerator,
    TemporalSafetyGenerator,
    ThreatModelBuilder,
)


def _fact(
    kind: str,
    line: int,
    *,
    subject: str = "codec.c",
    function: str = "decode_slice",
    **properties,
) -> Fact:
    return Fact(
        snapshot_id="snapshot-1",
        kind=kind,
        subject=subject,
        properties=properties,
        location=SourceLocation(
            file="libavcodec/h264_slice.c",
            line=line,
            function=function,
        ),
        provenance=Provenance(producer="test"),
    )


def test_sentinel_generator_builds_composed_ffmpeg_style_candidate() -> None:
    facts = [
        _fact(
            "sentinel_use",
            10,
            expression="memset(h->slice_table, -1, table_size);",
            values=["-1"],
        ),
        _fact(
            "field",
            11,
            subject="slice_table",
            type="uint16_t *",
            integer_width=16,
            excerpt="uint16_t *slice_table;",
        ),
        _fact(
            "assignment",
            40,
            subject="h->slice_table[mb_xy]",
            lhs="h->slice_table[mb_xy]",
            rhs="sl->slice_num",
            excerpt="h->slice_table[mb_xy] = sl->slice_num;",
        ),
        _fact(
            "guard",
            35,
            expression="if (sl->slice_num >= 0xFFFF) return AVERROR_INVALIDDATA;",
        ),
        _fact(
            "call",
            70,
            callee="deblock_mb",
            excerpt="deblock_mb(h, mb_xy);",
        ),
        _fact(
            "memory_access",
            71,
            expression="h->slice_table[neighbor_xy]",
        ),
    ]

    result = CandidatePipeline().generate("snapshot-1", facts)

    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.suspected_mechanism == "live_identifier_aliases_reserved_sentinel"
    assert candidate.source_symbols == ["slice_num"]
    assert candidate.state_sinks == ["slice_table"]
    assert set(candidate.invariant_families) == {
        "representation_domain_safety",
        "state_machine_safety",
        "spatial_safety",
    }
    # A guard is evidence to adjudicate, not a reason to suppress the candidate.
    assert facts[3].id in candidate.fact_ids


def test_proof_plan_composition_builds_a_dag() -> None:
    candidate = CandidatePipeline().generate(
        "snapshot-1",
        [
            _fact(
                "sentinel_use",
                10,
                expression="memset(h->owner_table, -1, size);",
            ),
            _fact(
                "assignment",
                20,
                lhs="h->owner_table[index]",
                rhs="state_id",
                excerpt="h->owner_table[index] = state_id;",
            ),
            _fact("memory_access", 30, expression="h->owner_table[neighbor]"),
        ],
    ).candidates[0]
    registry = ProofPlanRegistry()
    plans = registry.select(candidate)
    obligations = registry.instantiate(candidate, plans)
    by_predicate = {obligation.predicate: obligation for obligation in obligations}

    assert "representation-domain-collision-v1" in {plan.id for plan in plans}
    assert "memory-write-v1" in {plan.id for plan in plans}
    semantic = by_predicate["collision_changes_security_relevant_state"]
    access = by_predicate["incorrect_state_reaches_memory_access"]
    assert semantic.logical_id in access.dependencies
    assert all(obligation.candidate_id == candidate.logical_id for obligation in obligations)


def test_default_registry_covers_every_planned_invariant_family() -> None:
    registry = ProofPlanRegistry()
    covered = set().union(
        *(plan.invariant_families for plan in registry.plans.values())
    )

    assert {
        "representation_domain_safety",
        "spatial_safety",
        "parser_safety",
        "authority_safety",
        "temporal_safety",
        "state_machine_safety",
        "cryptographic_safety",
        "injection_safety",
        "concurrency_safety",
        "resource_safety",
    } <= covered


def test_threat_model_is_conservative_about_remote_reachability() -> None:
    facts = [
        _fact(
            "sentinel_use",
            10,
            expression="memset(decoder->state_table, -1, size);",
        ),
        _fact(
            "assignment",
            20,
            lhs="decoder->state_table[index]",
            rhs="slice_num",
            excerpt="decoder->state_table[index] = slice_num;",
        ),
    ]
    candidate = CandidatePipeline().generate("snapshot-1", facts).candidates[0]
    threat = ThreatModelBuilder().build(candidate, facts)

    assert threat.attacker_principal == "untrusted_input_supplier"
    assert "remote" not in " ".join(threat.attacker_capabilities).lower()
    assert threat.capability_gained == [
        "unknown until impact obligations are resolved"
    ]


def test_injection_generator_requires_an_interpreter_sink() -> None:
    generator = InjectionBoundaryGenerator()
    candidates = generator.generate(
        "snapshot-1",
        [
            _fact("call", 10, callee="execute", expression="execute(user_query)"),
            _fact("call", 11, callee="escape", expression="escape(user_query)"),
        ],
    )

    assert [item.suspected_mechanism for item in candidates] == [
        "untrusted_data_reaches_interpreter_boundary"
    ]
    assert candidates[0].source_symbols == ["user_query"]


def test_temporal_generator_requires_a_later_same_scope_use() -> None:
    generator = TemporalSafetyGenerator()
    candidates = generator.generate(
        "snapshot-1",
        [
            _fact("call", 10, callee="free", expression="free(packet)"),
            _fact("memory_access", 12, expression="packet[index]"),
            _fact(
                "memory_access",
                14,
                expression="packet[index]",
                function="other_function",
            ),
        ],
    )

    assert len(candidates) == 1
    assert candidates[0].suspected_mechanism == "dereference_after_release"
    assert candidates[0].source_symbols == ["packet"]


def test_authorization_generator_records_nearby_policy_evidence() -> None:
    generator = AuthorizationBoundaryGenerator()
    guard = _fact("guard", 20, expression="if (!user.is_owner) return denied")
    candidates = generator.generate(
        "snapshot-1",
        [
            guard,
            _fact("call", 25, callee="delete_account", expression="delete_account(id)"),
            _fact("call", 30, callee="log_event", expression="log_event(id)"),
        ],
    )

    assert len(candidates) == 1
    assert guard.id in candidates[0].fact_ids
    assert candidates[0].invariant_families == ["authority_safety"]


def test_crypto_generator_only_uses_explicit_crypto_markers() -> None:
    generator = CryptographicPropertyGenerator()
    candidates = generator.generate(
        "snapshot-1",
        [
            _fact("call", 10, callee="sha1", expression="sha1(signature_input)"),
            _fact("call", 11, callee="hash", expression="hash(cache_key)"),
        ],
    )

    assert len(candidates) == 1
    assert candidates[0].suspected_mechanism == "cryptographic_precondition:sha1"


def test_parser_generator_requires_an_extent_bearing_access() -> None:
    generator = ParserBoundaryGenerator()
    guard = _fact("guard", 10, expression="if (offset >= packet_size) return error")
    candidates = generator.generate(
        "snapshot-1",
        [
            guard,
            _fact("memory_access", 12, expression="packet[offset]"),
            _fact("memory_access", 13, expression="table[slot]"),
        ],
    )

    assert len(candidates) == 1
    assert set(candidates[0].source_symbols) == {"offset"}
    assert guard.id in candidates[0].fact_ids


def test_state_machine_generator_requires_security_state_assignment() -> None:
    generator = StateMachineGenerator()
    candidates = generator.generate(
        "snapshot-1",
        [
            _fact("assignment", 10, lhs="session.state", rhs="AUTHENTICATED"),
            _fact("assignment", 11, lhs="response_count", rhs="response_count + 1"),
        ],
    )

    assert len(candidates) == 1
    assert candidates[0].suspected_mechanism == "security_state_transition"


def test_concurrency_resource_generator_requires_a_loop_or_thread_contrast() -> None:
    generator = ConcurrencyResourceGenerator()
    candidates = generator.generate(
        "snapshot-1",
        [
            _fact("loop", 10, expression="while (request.more)"),
            _fact("allocation", 12, expression="malloc(request.size)"),
            _fact("call", 20, callee="pthread_create", expression="pthread_create(...)"),
            _fact("memory_write", 21, expression="shared[index] = value"),
            _fact(
                "allocation",
                30,
                expression="malloc(fixed_size)",
                function="unrelated",
            ),
        ],
    )

    assert {item.suspected_mechanism for item in candidates} == {
        "attacker_driven_unbounded_allocation",
        "shared_write_across_concurrent_execution",
    }


def test_every_structured_generator_selects_a_nonempty_proof_plan() -> None:
    facts = [
        _fact("call", 10, callee="execute", expression="execute(user_input)"),
        _fact("call", 20, callee="free", expression="free(packet)"),
        _fact("memory_access", 21, expression="packet[offset]"),
        _fact("call", 30, callee="delete_account", expression="delete_account(id)"),
        _fact("call", 40, callee="sha1", expression="sha1(message)"),
        _fact("assignment", 50, lhs="session.state", rhs="AUTHENTICATED"),
        _fact("loop", 60, expression="while (request.more)"),
        _fact("allocation", 61, expression="malloc(request.size)"),
    ]
    registry = ProofPlanRegistry()

    candidates = CandidatePipeline().generate("snapshot-1", facts).candidates

    assert candidates
    assert all(registry.select(candidate) for candidate in candidates)
