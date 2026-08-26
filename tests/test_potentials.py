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
    assert ctx.potentials[0]["deferred_reason"] == "Dynamic reachability is not established."
    assert ctx.potentials[0]["missing_evidence"] == [
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
    assert ctx.potential_history[0]["status"] == "dismissed"
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
