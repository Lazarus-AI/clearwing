"""Regression tests for R1: extracting build_react_graph from create_agent.

These tests assert that:
1. build_react_graph is importable and has the expected signature.
2. create_agent still produces a working compiled graph (delegates to
   build_react_graph internally).
3. build_react_graph accepts a custom state schema, system prompt, tool list,
   and state-updater callback — proving the seam for sourcehunt agents.
4. The default pentest state-updater maps tool outputs to the expected fields.
"""

from __future__ import annotations

from typing import Annotated
from unittest.mock import MagicMock, patch

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages
from typing_extensions import TypedDict

from clearwing.agent.graph import (
    _default_pentest_state_updater,
    build_react_graph,
    create_agent,
)
from clearwing.agent.state import AgentState


class CustomState(TypedDict):
    """Module-level TypedDict so Python 3.14 lazy annotations resolve correctly."""

    messages: Annotated[list[BaseMessage], add_messages]
    custom_field: str


class TestDefaultPentestStateUpdater:
    """The default state updater preserves the exact pentest behavior."""

    def test_scan_ports_appends(self):
        state = {"open_ports": [{"port": 22}]}
        data = [{"port": 80, "service": "http"}]
        result = _default_pentest_state_updater("scan_ports", data, state)
        assert result == {"open_ports": [{"port": 22}, {"port": 80, "service": "http"}]}

    def test_detect_services_appends(self):
        state = {"services": []}
        data = [{"port": 22, "service": "ssh"}]
        result = _default_pentest_state_updater("detect_services", data, state)
        assert result == {"services": [{"port": 22, "service": "ssh"}]}

    def test_scan_vulnerabilities_appends(self):
        state = {"vulnerabilities": []}
        data = [{"cve": "CVE-2024-0001"}]
        result = _default_pentest_state_updater("scan_vulnerabilities", data, state)
        assert result == {"vulnerabilities": [{"cve": "CVE-2024-0001"}]}

    def test_detect_os_sets_string(self):
        result = _default_pentest_state_updater("detect_os", "Linux 5.15", {})
        assert result == {"os_info": "Linux 5.15"}

    def test_exploit_vulnerability_appends_dict(self):
        state = {"exploit_results": []}
        data = {"cve": "CVE-2024-0001", "success": True}
        result = _default_pentest_state_updater("exploit_vulnerability", data, state)
        assert result == {"exploit_results": [data]}

    def test_kali_setup_sets_container_id(self):
        result = _default_pentest_state_updater("kali_setup", "abc123def456", {})
        assert result == {"kali_container_id": "abc123def456"}

    def test_unknown_tool_returns_empty(self):
        result = _default_pentest_state_updater("some_other_tool", [1, 2, 3], {})
        assert result == {}

    def test_wrong_data_type_returns_empty(self):
        # scan_ports with a string instead of list → no update
        result = _default_pentest_state_updater("scan_ports", "not a list", {})
        assert result == {}


class TestBuildReactGraphSignature:
    """build_react_graph exposes the expected parameters."""

    def test_signature_has_required_kwargs(self):
        import inspect

        sig = inspect.signature(build_react_graph)
        params = sig.parameters
        # Positional / required
        assert "llm_with_tools" in params
        assert "tools" in params
        assert "system_prompt_fn" in params
        # Keyword
        assert "state_schema" in params
        assert "model_name" in params
        assert "session_id" in params
        assert "state_updater_fn" in params
        assert "knowledge_graph_populator_fn" in params
        assert "input_guardrail_tool_names" in params
        assert "output_guardrail_tool_names" in params

    def test_state_schema_default_is_agent_state(self):
        import inspect

        sig = inspect.signature(build_react_graph)
        assert sig.parameters["state_schema"].default is AgentState


class TestBuildReactGraphMinimal:
    """Build a graph with a custom state schema, prompt, and tools — no LLM call."""

    def test_compiles_with_custom_state_and_tools(self):
        from langchain_core.tools import tool

        @tool
        def custom_tool(x: str) -> str:
            """Echo the input."""
            return f"echo: {x}"

        mock_llm = MagicMock()
        mock_llm.invoke = MagicMock(return_value=MagicMock(content="ok", tool_calls=[]))

        def custom_prompt_fn(state):
            return "you are a test agent"

        captured_args = {}

        def custom_updater(tool_name, data, state):
            captured_args["called"] = (tool_name, data)
            return {"custom_field": str(data)}

        graph = build_react_graph(
            llm_with_tools=mock_llm,
            tools=[custom_tool],
            system_prompt_fn=custom_prompt_fn,
            state_schema=CustomState,
            model_name="test-model",
            session_id=None,
            state_updater_fn=custom_updater,
            # Disable knowledge graph and audit so the test doesn't touch disk
            knowledge_graph_populator_fn=lambda *a, **k: {},
            enable_knowledge_graph=False,
            enable_audit=False,
            enable_episodic_memory=False,
        )
        # Compiled graph should have nodes assistant + tools
        assert graph is not None
        # MemorySaver checkpointer is attached
        assert hasattr(graph, "checkpointer") or hasattr(graph, "get_state")


class TestCreateAgentDelegatesToBuildReactGraph:
    """create_agent uses build_react_graph internally with pentest defaults."""

    def test_create_agent_returns_compiled_graph(self):
        # Patch the LLM creation to avoid network/auth
        with patch("clearwing.agent.graph._create_llm") as mock_create_llm:
            mock_llm = MagicMock()
            mock_llm.bind_tools = MagicMock(return_value=MagicMock())
            mock_create_llm.return_value = mock_llm
            graph = create_agent(model_name="claude-sonnet-4-6")
            assert graph is not None
            mock_create_llm.assert_called_once()

    def test_create_agent_passes_custom_tools(self):
        from langchain_core.tools import tool

        @tool
        def my_extra_tool(x: int) -> int:
            """Doubler."""
            return x * 2

        with patch("clearwing.agent.graph._create_llm") as mock_create_llm:
            mock_llm = MagicMock()
            bound = MagicMock()
            mock_llm.bind_tools = MagicMock(return_value=bound)
            mock_create_llm.return_value = mock_llm
            create_agent(custom_tools=[my_extra_tool])
            # bind_tools was called with a list including my_extra_tool
            call_args = mock_llm.bind_tools.call_args
            tool_list = call_args[0][0] if call_args[0] else call_args[1].get("tools", [])
            assert my_extra_tool in tool_list
