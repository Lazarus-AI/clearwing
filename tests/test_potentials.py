from clearwing.agent.tools.hunt.potentials import build_potential_tools
from clearwing.agent.tools.hunt.sandbox import HunterContext


def test_dismiss_potential_removes_ruled_out_lead(tmp_path) -> None:
    ctx = HunterContext(repo_path=str(tmp_path))
    tools = {tool.name: tool for tool in build_potential_tools(ctx)}

    result = tools["flag_potential"].invoke(
        {
            "file": "src/parser.c",
            "line": 42,
            "note": "length reaches memcpy",
            "hypothesis": "CWE-787",
            "priority": "high",
        }
    )
    potential_id = ctx.potentials[0]["id"]

    assert "Queue: 1 unresolved" in result

    dismissed = tools["dismiss_potential"].invoke(
        {
            "potential_id": potential_id,
            "resolution": "caller checks the length before dispatch",
        }
    )

    assert "ruled out" in dismissed
    assert ctx.potentials == []


def test_dismissed_potential_cannot_be_dismissed_twice(tmp_path) -> None:
    ctx = HunterContext(repo_path=str(tmp_path))
    tools = {tool.name: tool for tool in build_potential_tools(ctx)}
    tools["flag_potential"].invoke(
        {
            "file": "src/parser.c",
            "line": 42,
            "note": "unclear bounds",
            "hypothesis": "CWE-787",
        }
    )
    potential_id = ctx.potentials[0]["id"]
    args = {"potential_id": potential_id, "resolution": "caller validates the length"}

    tools["dismiss_potential"].invoke(args)
    result = tools["dismiss_potential"].invoke(args)

    assert "No potential found" in result
    assert ctx.potentials == []
