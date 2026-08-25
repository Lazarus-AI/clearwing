from clearwing.agent.tools.hunt.potentials import build_potential_tools
from clearwing.agent.tools.hunt.sandbox import HunterContext


def test_potential_lifecycle_open_to_clear(tmp_path) -> None:
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

    assert "Queue: 1 open" in result
    assert ctx.potentials[0]["status"] == "open"

    updated = tools["update_potential"].invoke(
        {
            "potential_id": potential_id,
            "status": "clear",
            "resolution": "caller checks the length before dispatch",
        }
    )

    assert "marked clear" in updated
    assert ctx.potentials[0]["status"] == "clear"
    assert ctx.potentials[0]["resolution"] == "caller checks the length before dispatch"


def test_potential_cannot_be_resolved_twice(tmp_path) -> None:
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
    args = {"potential_id": potential_id, "status": "unknown", "resolution": "no caller found"}

    tools["update_potential"].invoke(args)
    result = tools["update_potential"].invoke(
        {**args, "status": "clear", "resolution": "later ruled out"}
    )

    assert "already unknown" in result
    assert ctx.potentials[0]["status"] == "unknown"
