import jsonschema
import pytest

from clearwing.agent.tools.hunt.potentials import build_potential_tools
from clearwing.agent.tools.hunt.sandbox import HunterContext


def test_minimal_potential_can_be_enriched_incrementally(tmp_path) -> None:
    ctx = HunterContext(repo_path=str(tmp_path))
    tools = {tool.name: tool for tool in build_potential_tools(ctx)}

    tools["flag_potential"].invoke(
        {
            "file": "routers/private/hook_pre_receive.go",
            "line": 62,
            "hypothesis": "A read-only deploy key may reach a write-capable path.",
            "priority": "high",
        }
    )
    potential_id = ctx.potentials[0]["id"]

    assert ctx.potentials[0]["security_invariant"] == ""
    assert ctx.potentials[0]["open_questions"] == []
    assert ctx.potentials[0]["note"] == ctx.potentials[0]["hypothesis"]

    result = tools["update_potential"].invoke(
        {
            "potential_id": potential_id,
            "observation": "The deploy-key ID is propagated into HookOptions.",
            "security_invariant": "Read-only deploy keys must not authorize writes.",
            "open_questions": ["Does proc-receive preserve the deploy-key mode?"],
        }
    )

    assert "Updated" in result
    assert ctx.potentials[0]["observations"] == [
        "The deploy-key ID is propagated into HookOptions."
    ]
    assert ctx.potentials[0]["security_invariant"] == (
        "Read-only deploy keys must not authorize writes."
    )


def test_defer_potential_preserves_missing_evidence(tmp_path) -> None:
    ctx = HunterContext(repo_path=str(tmp_path))
    tools = {tool.name: tool for tool in build_potential_tools(ctx)}
    tools["flag_potential"].invoke(
        {
            "file": "src/auth.go",
            "line": 42,
            "hypothesis": "A cached permission may cross resource boundaries.",
        }
    )
    potential_id = ctx.potentials[0]["id"]

    result = tools["defer_potential"].invoke(
        {
            "potential_id": potential_id,
            "reason": "Dynamic reachability is not established.",
            "missing_evidence": ["A request reaching both resources in one session"],
        }
    )

    assert "Deferred potential" in result
    assert ctx.potentials == []
    assert ctx.potential_history[0]["status"] == "unresolved"
    assert ctx.potential_history[0]["deferred_reason"] == (
        "Dynamic reachability is not established."
    )
    assert ctx.potential_history[0]["missing_evidence"] == [
        "A request reaching both resources in one session"
    ]


def test_dismiss_potential_preserves_auditable_ruled_out_lead(tmp_path) -> None:
    ctx = HunterContext(repo_path=str(tmp_path))
    tools = {tool.name: tool for tool in build_potential_tools(ctx)}

    result = tools["flag_potential"].invoke(
        {
            "file": "src/parser.c",
            "line": 42,
            "note": "length reaches memcpy",
            "hypothesis": "CWE-787",
            "security_invariant": "copy length must not exceed destination capacity",
            "open_questions": ["Can an untrusted caller control the length?"],
            "disproof_conditions": ["Every caller bounds the length before dispatch"],
            "priority": "high",
        }
    )
    potential_id = ctx.potentials[0]["id"]

    assert "Queue: 1 unresolved" in result
    assert ctx.potentials[0]["security_invariant"] == (
        "copy length must not exceed destination capacity"
    )
    assert ctx.potentials[0]["verification"] == {
        "attacker_control": "unknown",
        "reachability": "unknown",
        "guard_behavior": "unknown",
        "impact": "unknown",
    }

    dismissed = tools["dismiss_potential"].invoke(
        {
            "potential_id": potential_id,
            "resolution": "caller checks the length before dispatch",
            "disproof_condition": "Every caller bounds the length before dispatch",
            "evidence": ["src/caller.c:88 checks length <= sizeof(destination)"],
        }
    )

    assert "ruled out" in dismissed
    assert ctx.potentials == []
    assert ctx.potential_history[0]["status"] == "safe"
    assert ctx.potential_history[0]["resolution_evidence"] == [
        "src/caller.c:88 checks length <= sizeof(destination)"
    ]


def test_dismissed_potential_cannot_be_dismissed_twice(tmp_path) -> None:
    ctx = HunterContext(repo_path=str(tmp_path))
    tools = {tool.name: tool for tool in build_potential_tools(ctx)}
    tools["flag_potential"].invoke(
        {
            "file": "src/parser.c",
            "line": 42,
            "note": "unclear bounds",
            "hypothesis": "CWE-787",
            "security_invariant": "copy length must be bounded",
            "open_questions": ["Where is the length validated?"],
            "disproof_conditions": ["All reachable callers validate the length"],
        }
    )
    potential_id = ctx.potentials[0]["id"]
    args = {
        "potential_id": potential_id,
        "resolution": "caller validates the length",
        "disproof_condition": "All reachable callers validate the length",
        "evidence": ["src/caller.c:88 validates the length"],
    }

    tools["dismiss_potential"].invoke(args)
    result = tools["dismiss_potential"].invoke(args)

    assert "No potential found" in result
    assert ctx.potentials == []


def test_potential_preserves_complete_security_invariant_map(tmp_path) -> None:
    ctx = HunterContext(repo_path=str(tmp_path))
    tools = {tool.name: tool for tool in build_potential_tools(ctx)}

    tools["flag_potential"].invoke(
        {
            "file": "src/verify.c",
            "line": 90,
            "hypothesis": "Digest metadata may not constrain verification.",
            "security_boundary": "verify_signature",
            "security_invariant": "Digest identity and length must agree.",
            "attacker_inputs": ["signature", "digest", "digest length"],
            "required_relationships": ["digest length matches digest OID"],
            "observed_checks": ["signature integers are range checked"],
            "missing_checks": ["no digest OID/length consistency check found"],
        }
    )

    potential = ctx.potentials[0]
    assert potential["security_boundary"] == "verify_signature"
    assert potential["attacker_inputs"] == ["signature", "digest", "digest length"]
    assert potential["required_relationships"] == ["digest length matches digest OID"]
    assert potential["observed_checks"] == ["signature integers are range checked"]
    assert potential["missing_checks"] == ["no digest OID/length consistency check found"]


def test_dismissal_without_recorded_disproof_is_rejected(tmp_path) -> None:
    ctx = HunterContext(repo_path=str(tmp_path))
    tools = {tool.name: tool for tool in build_potential_tools(ctx)}
    tools["flag_potential"].invoke(
        {
            "file": "src/parser.c",
            "line": 42,
            "hypothesis": "length may exceed the destination",
            "disproof_conditions": ["All callers validate the length"],
        }
    )

    result = tools["dismiss_potential"].invoke(
        {
            "potential_id": ctx.potentials[0]["id"],
            "resolution": "looks safe",
            "disproof_condition": "No crash was observed",
            "evidence": ["src/parser.c:42 looks safe"],
        }
    )

    assert "not dismissed" in result
    assert len(ctx.potentials) == 1
    assert ctx.potential_history == []


def test_dismiss_tool_requires_lifecycle_dominance_instructions(tmp_path) -> None:
    ctx = HunterContext(repo_path=str(tmp_path))
    tools = {tool.name: tool for tool in build_potential_tools(ctx)}

    description = tools["dismiss_potential"].description
    assert "dominates every subsequent attacker-controlled mutation" in description
    assert "every security-sensitive use" in description
    assert "all reachable states" in description


def test_malformed_potential_arguments_are_rejected_before_state_mutation(tmp_path) -> None:
    ctx = HunterContext(repo_path=str(tmp_path))
    tools = {tool.name: tool for tool in build_potential_tools(ctx)}

    with pytest.raises(jsonschema.ValidationError, match="is not one of"):
        tools["flag_potential"].invoke(
            {
                "file": "this",
                "line": 18,
                "note": "this",
                "hypothesis": "x",
                "security_invariant": "authorization must remain scoped to the resource",
                "open_questions": ["Is the input attacker controlled?"],
                "disproof_conditions": ["The input is assigned by trusted server code"],
                "priority": "0</parameter>\n</invoke>\n",
            }
        )

    assert ctx.potentials == []


def test_potentials_are_ranked_by_typed_impact_and_evidence(tmp_path) -> None:
    ctx = HunterContext(repo_path=str(tmp_path))
    tools = {tool.name: tool for tool in build_potential_tools(ctx)}

    tools["flag_potential"].invoke(
        {
            "file": "src/allocate.c",
            "line": 10,
            "hypothesis": "A large allocation may exhaust memory.",
            "impact_class": "resource_exhaustion",
            "novelty": "distinct",
            "security_invariant": "Untrusted sizes must be bounded.",
            "required_relationships": ["size <= configured limit"],
            "missing_checks": ["No configured limit found"],
        }
    )
    resource_id = ctx.potentials[0]["id"]
    tools["update_potential"].invoke(
        {
            "potential_id": resource_id,
            "attacker_control": "supported",
            "reachability": "supported",
            "guard_behavior": "supported",
            "impact": "supported",
        }
    )

    tools["flag_potential"].invoke(
        {
            "file": "src/copy.c",
            "line": 20,
            "hypothesis": "A copy extent may exceed the live destination.",
            "impact_class": "memory_corruption",
            "novelty": "distinct",
            "security_invariant": "Copy extent must fit the live destination.",
            "required_relationships": ["copy_len <= destination_len"],
            "missing_checks": ["No dominating extent check found"],
        }
    )

    assert ctx.potentials[0]["file"] == "src/copy.c"
    assert ctx.potentials[0]["priority_score"] > ctx.potentials[1]["priority_score"]
    assert ctx.potentials[1]["id"] == resource_id


def test_update_potential_recomputes_priority_from_verification_evidence(tmp_path) -> None:
    ctx = HunterContext(repo_path=str(tmp_path))
    tools = {tool.name: tool for tool in build_potential_tools(ctx)}
    tools["flag_potential"].invoke(
        {
            "file": "src/auth.c",
            "line": 42,
            "hypothesis": "Authorization may be scoped to the wrong resource.",
            "impact_class": "authorization_bypass",
        }
    )
    potential_id = ctx.potentials[0]["id"]
    initial_score = ctx.potentials[0]["priority_score"]

    tools["update_potential"].invoke(
        {
            "potential_id": potential_id,
            "attacker_control": "supported",
            "reachability": "supported",
            "guard_behavior": "supported",
            "impact": "supported",
            "novelty": "distinct",
        }
    )

    assert ctx.potentials[0]["priority_score"] == initial_score + 40
    assert ctx.potentials[0]["priority"] == "high"


def test_update_potential_reopens_an_unresolved_historical_lead(tmp_path) -> None:
    ctx = HunterContext(repo_path=str(tmp_path))
    tools = {tool.name: tool for tool in build_potential_tools(ctx)}
    tools["flag_potential"].invoke(
        {
            "file": "src/hash.c",
            "line": 42,
            "hypothesis": "Predictable hash state may enable collision flooding.",
        }
    )
    potential_id = ctx.potentials[0]["id"]
    tools["defer_potential"].invoke(
        {
            "potential_id": potential_id,
            "reason": "Reachability is not established.",
            "missing_evidence": ["A reachable weak-seed configuration"],
        }
    )

    result = tools["update_potential"].invoke(
        {
            "potential_id": potential_id,
            "action": "reopen",
            "reason": "A supported configuration reaches the weak-seed path.",
            "observation": "src/config.h:19 enables the fallback on the supported target.",
            "reachability": "supported",
        }
    )

    assert "Reopened" in result
    assert ctx.potential_history == []
    assert ctx.potentials[0]["id"] == potential_id
    assert ctx.potentials[0]["status"] == "examined"
    assert ctx.potentials[0]["verification"]["reachability"] == "supported"
    assert ctx.potentials[0]["reopen_events"][0]["previous_deferred_reason"] == (
        "Reachability is not established."
    )


def test_update_potential_closes_active_lead_as_unresolved(tmp_path) -> None:
    ctx = HunterContext(repo_path=str(tmp_path))
    tools = {tool.name: tool for tool in build_potential_tools(ctx)}
    tools["flag_potential"].invoke(
        {
            "file": "src/parser.c",
            "line": 88,
            "hypothesis": "A parser length may reach a copy unchecked.",
        }
    )
    potential_id = ctx.potentials[0]["id"]

    result = tools["update_potential"].invoke(
        {
            "potential_id": potential_id,
            "action": "close",
            "reason": "The remaining caller evidence is outside this bounded hunt.",
            "missing_evidence": ["Caller validation at dispatch"],
        }
    )

    assert "Closed potential" in result
    assert ctx.potentials == []
    assert ctx.potential_history[0]["status"] == "unresolved"
    assert ctx.potential_history[0]["missing_evidence"] == [
        "Caller validation at dispatch"
    ]


def test_flag_potential_returns_existing_active_duplicate(tmp_path) -> None:
    ctx = HunterContext(repo_path=str(tmp_path))
    tools = {tool.name: tool for tool in build_potential_tools(ctx)}
    args = {
        "file": "src/jv.c",
        "line": 1217,
        "hypothesis": "A predictable hash seed permits colliding keys and quadratic lookup.",
        "security_boundary": "Object construction from untrusted keys.",
        "security_invariant": "Hash bucket distribution must resist attacker concentration.",
    }
    tools["flag_potential"].invoke(args)
    potential_id = ctx.potentials[0]["id"]

    duplicate = tools["flag_potential"].invoke(args)

    assert duplicate["ok"] is False
    assert duplicate["error"]["code"] == "POTENTIAL_ALREADY_EXISTS"
    assert duplicate["error"]["potential_id"] == potential_id
    assert duplicate["error"]["status"] == "open"
    assert len(ctx.potentials) == 1


def test_flag_potential_returns_existing_unresolved_duplicate(tmp_path) -> None:
    ctx = HunterContext(repo_path=str(tmp_path))
    tools = {tool.name: tool for tool in build_potential_tools(ctx)}
    args = {
        "file": "src/jv.c",
        "line": 1217,
        "hypothesis": "A predictable hash seed permits colliding keys and quadratic lookup.",
        "security_boundary": "Object construction from untrusted keys.",
        "security_invariant": "Hash bucket distribution must resist attacker concentration.",
    }
    tools["flag_potential"].invoke(args)
    potential_id = ctx.potentials[0]["id"]
    tools["defer_potential"].invoke(
        {"potential_id": potential_id, "reason": "Reachability remains unknown."}
    )

    duplicate = tools["flag_potential"].invoke(args)

    assert duplicate["error"]["code"] == "POTENTIAL_ALREADY_EXISTS"
    assert duplicate["error"]["potential_id"] == potential_id
    assert duplicate["error"]["status"] == "unresolved"
    assert ctx.potentials == []
    assert len(ctx.potential_history) == 1


def test_flag_potential_detects_paraphrased_historical_duplicate(tmp_path) -> None:
    ctx = HunterContext(repo_path=str(tmp_path))
    tools = {tool.name: tool for tool in build_potential_tools(ctx)}
    tools["flag_potential"].invoke(
        {
            "file": "src/jv.c",
            "line": 1217,
            "hypothesis": (
                "A predictable getpid and time hash seed lets attacker-chosen JSON keys "
                "land in one bucket, making linear chain scans quadratic."
            ),
            "security_boundary": "Object construction from untrusted JSON keys.",
            "security_invariant": "Hash distribution must be unpredictable to attackers.",
            "attacker_inputs": ["JSON object keys"],
            "required_relationships": ["seed remains unpredictable"],
            "missing_checks": ["no bucket chain cap"],
            "impact_class": "resource_exhaustion",
        }
    )
    potential_id = ctx.potentials[0]["id"]
    tools["defer_potential"].invoke(
        {"potential_id": potential_id, "reason": "Practical reachability is unknown."}
    )

    duplicate = tools["flag_potential"].invoke(
        {
            "file": "src/jv.c",
            "line": 1217,
            "hypothesis": (
                "Weak fallback hash seeding permits adversarial JSON keys to concentrate "
                "in the same bucket and trigger quadratic object construction."
            ),
            "security_boundary": "Parsing attacker-controlled keys into an object.",
            "security_invariant": (
                "Bucket distribution must resist attacker concentration and long chains."
            ),
            "attacker_inputs": ["attacker-controlled JSON key strings"],
            "required_relationships": ["hash seed cannot be predicted"],
            "missing_checks": ["bucket chains have no length limit"],
            "impact_class": "resource_exhaustion",
        }
    )

    assert duplicate["error"]["code"] == "POTENTIAL_ALREADY_EXISTS"
    assert duplicate["error"]["potential_id"] == potential_id
    assert len(ctx.potential_history) == 1
