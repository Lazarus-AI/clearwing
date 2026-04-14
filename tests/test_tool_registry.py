"""Snapshot test for the network-agent tool registry.

Phase 4 reorg moves `clearwing/agent/tools/*.py` into domain subdirectories
(scan/, exploit/, hunt/, recon/, ops/, data/, meta/). This test locks the
baseline so the reorg can't silently drop or re-register any tools.

The `get_all_tools()` aggregator is consumed by `agent/graph.py` as the
full tool bind-list for the ReAct loop. Any accidental rename or drop
becomes a test failure here rather than a silent degradation of the
network-agent's capabilities.

The source-hunt pipeline has its own tool registry driven by
`build_hunter_agent()` in `clearwing/sourcehunt/hunter.py` — those are
intentionally NOT counted here.
"""

from __future__ import annotations

from clearwing.agent.tools import get_all_tools

# Locked baseline as of Phase 4 start. Update this only when deliberately
# adding or removing a tool from the network-agent registry.
EXPECTED_TOOL_COUNT = 63


EXPECTED_TOOL_NAMES: frozenset[str] = frozenset(
    {
        # scanner_tools
        "scan_ports",
        "detect_services",
        "scan_vulnerabilities",
        "detect_os",
        # exploit_tools
        "exploit_vulnerability",
        "enumerate_privesc",
        "crack_password",
        "metasploit_exploit",
        "metasploit_list_sessions",
        "metasploit_run_command",
        # kali_docker_tool
        "kali_setup",
        "kali_execute",
        "kali_install_tool",
        "kali_cleanup",
        # reporting_tools
        "generate_report",
        "save_report",
        "query_scan_history",
        "search_cves",
        # utility_tools
        "validate_target",
        "calculate_severity",
        # dynamic_tool_creator
        "create_custom_tool",
        "list_custom_tools",
        # memory_tools
        "recall_target_history",
        "store_knowledge",
        "search_knowledge",
        # skill_tools
        "load_skills",
        # knowledge_tools
        "query_knowledge_graph",
    }
)


class TestToolRegistry:
    def test_get_all_tools_count_matches_baseline(self):
        tools = get_all_tools()
        assert len(tools) == EXPECTED_TOOL_COUNT, (
            f"get_all_tools() returned {len(tools)} tools, "
            f"expected {EXPECTED_TOOL_COUNT}. If you intentionally added or "
            f"removed a tool, update EXPECTED_TOOL_COUNT in this test."
        )

    def test_core_tool_names_are_present(self):
        """The non-optional tools must always be present. Optional tools
        (browser, proxy, analysis, mcp, etc.) are gated by dependency
        availability and aren't asserted here."""
        tools = get_all_tools()
        names = {t.name for t in tools}
        missing = EXPECTED_TOOL_NAMES - names
        assert not missing, f"core tools missing from registry: {missing}"

    def test_tool_names_are_unique(self):
        """No tool registers twice — `LangGraph.bind_tools()` uses the name
        as a key and silent collisions would drop tools."""
        tools = get_all_tools()
        names = [t.name for t in tools]
        dupes = {n for n in names if names.count(n) > 1}
        assert not dupes, f"duplicate tool names in registry: {dupes}"
