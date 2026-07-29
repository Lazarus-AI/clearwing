"""Tests for the native agent runtime."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from clearwing.agent.graph import create_agent
from clearwing.agent.prompts import build_system_prompt
from clearwing.agent.state import AgentState
from clearwing.agent.tooling import tool
from clearwing.agent.tools import get_all_tools
from clearwing.agent.tools.meta.reporting_tools import generate_report
from clearwing.agent.tools.meta.utility_tools import calculate_severity, validate_target
from clearwing.agent.tools.scan.scanner_tools import detect_os, detect_services, scan_ports


class TestAgentState:
    def test_state_instantiation(self):
        state: AgentState = {
            "messages": [],
            "target": "192.168.1.1",
            "open_ports": [],
            "services": [],
            "vulnerabilities": [],
            "exploit_results": [],
            "os_info": None,
            "kali_container_id": None,
            "custom_tool_names": [],
        }
        assert state["target"] == "192.168.1.1"
        assert state["messages"] == []
        assert state["open_ports"] == []

    def test_state_with_data(self):
        state: AgentState = {
            "messages": [],
            "target": "10.0.0.1",
            "open_ports": [{"port": 22, "protocol": "tcp", "state": "open", "service": "SSH"}],
            "services": [{"port": 22, "service": "SSH", "version": "7.4"}],
            "vulnerabilities": [{"cve": "CVE-2018-15473", "cvss": 5.3}],
            "exploit_results": [],
            "os_info": "Linux/Unix",
            "kali_container_id": None,
            "custom_tool_names": ["my_tool"],
        }
        assert len(state["open_ports"]) == 1
        assert state["os_info"] == "Linux/Unix"
        assert "my_tool" in state["custom_tool_names"]


class TestSystemPrompt:
    def test_empty_state(self):
        state = {
            "target": None,
            "open_ports": [],
            "services": [],
            "vulnerabilities": [],
            "exploit_results": [],
            "os_info": None,
            "kali_container_id": None,
            "custom_tool_names": [],
        }
        prompt = build_system_prompt(state)
        assert "No scan data yet." in prompt
        assert "Clearwing Agent" in prompt

    def test_populated_state(self):
        state = {
            "target": "10.0.0.1",
            "open_ports": [{"port": 80, "protocol": "tcp", "service": "HTTP"}],
            "services": [{"service": "HTTP", "port": 80, "version": "2.4"}],
            "vulnerabilities": [{"cve": "CVE-2017-5638", "cvss": 10.0}],
            "exploit_results": [{"success": True}],
            "os_info": "Linux/Unix",
            "kali_container_id": "abc123def456",
            "custom_tool_names": ["my_scanner"],
        }
        prompt = build_system_prompt(state)
        assert "10.0.0.1" in prompt
        assert "80/tcp" in prompt
        assert "CVE-2017-5638" in prompt
        assert "Linux/Unix" in prompt
        assert "abc123def456" in prompt
        assert "my_scanner" in prompt


class TestToolList:
    def test_get_all_tools(self):
        tools = get_all_tools()
        assert len(tools) >= 20
        tool_names = [t.name for t in tools]
        assert "scan_ports" in tool_names
        assert "detect_services" in tool_names
        assert "exploit_vulnerability" in tool_names
        assert "kali_setup" in tool_names
        assert "generate_report" in tool_names
        assert "validate_target" in tool_names
        assert "create_custom_tool" in tool_names


class TestGraphConstruction:
    def test_create_agent(self):
        with patch("clearwing.agent.graph._create_llm") as mock_create_llm:
            mock_llm = MagicMock()
            mock_create_llm.return_value = mock_llm
            graph = create_agent(model_name="claude-sonnet-4-6")
            assert graph is not None
            mock_create_llm.assert_called_once_with(
                "claude-sonnet-4-6",
                base_url=None,
                api_key=None,
            )
            # The native client is threaded straight through — no bind_tools.
            assert graph.llm is mock_llm
            assert graph.native_tools

    def test_create_agent_with_custom_tools(self):
        @tool
        def dummy_tool(x: str) -> str:
            """A dummy tool."""
            return x

        with patch("clearwing.agent.graph._create_llm") as mock_create_llm:
            mock_llm = MagicMock()
            mock_create_llm.return_value = mock_llm
            graph = create_agent(model_name="claude-sonnet-4-6", custom_tools=[dummy_tool])
            assert graph is not None
            # The custom tool is registered in the runtime's tool map and its
            # NativeToolSpec is built for the LLM call.
            assert "dummy_tool" in graph.tools
            assert any(spec.name == "dummy_tool" for spec in graph.native_tools)

    def test_create_agent_with_custom_endpoint(self):
        with patch("clearwing.agent.graph._create_llm") as mock_create_llm:
            mock_llm = MagicMock()
            mock_create_llm.return_value = mock_llm
            graph = create_agent(
                model_name="my-model",
                base_url="http://localhost:8000/v1",
                api_key="test-key",
            )
            assert graph is not None
            mock_create_llm.assert_called_once_with(
                "my-model",
                base_url="http://localhost:8000/v1",
                api_key="test-key",
            )


class TestScannerToolWrapping:
    @pytest.mark.asyncio
    async def test_scan_ports_wraps_scanner(self):
        mock_result = [{"port": 22, "protocol": "tcp", "state": "open", "service": "SSH"}]

        mock_scanner = MagicMock()
        mock_scanner.scan = AsyncMock(return_value=mock_result)
        mock_class = MagicMock(return_value=mock_scanner)

        with patch("clearwing.scanning.PortScanner", mock_class):
            await scan_ports.ainvoke(
                {
                    "target": "192.168.1.1",
                    "ports": [22],
                    "scan_type": "connect",
                    "threads": 10,
                }
            )
            mock_scanner.scan.assert_called_once_with("192.168.1.1", [22], "connect", 10)

    @pytest.mark.asyncio
    async def test_detect_services_wraps_scanner(self):
        ports = [{"port": 80, "service": "HTTP"}]
        mock_result = [{"port": 80, "service": "HTTP", "banner": "Apache", "version": "2.4"}]

        mock_scanner = MagicMock()
        mock_scanner.detect = AsyncMock(return_value=mock_result)
        mock_class = MagicMock(return_value=mock_scanner)

        with patch("clearwing.scanning.ServiceScanner", mock_class):
            await detect_services.ainvoke(
                {
                    "target": "192.168.1.1",
                    "open_ports": ports,
                }
            )
            mock_scanner.detect.assert_called_once_with("192.168.1.1", ports)

    @pytest.mark.asyncio
    async def test_detect_os_wraps_scanner(self):
        mock_scanner = MagicMock()
        mock_scanner.detect = AsyncMock(return_value="Linux/Unix")
        mock_class = MagicMock(return_value=mock_scanner)

        with patch("clearwing.scanning.OSScanner", mock_class):
            await detect_os.ainvoke({"target": "192.168.1.1"})
            mock_scanner.detect.assert_called_once_with("192.168.1.1")


class TestUtilityTools:
    def test_validate_target_ip(self):
        result = validate_target.invoke({"ip_or_cidr": "192.168.1.1"})
        assert result["valid"] is True
        assert result["is_cidr"] is False
        assert result["ips"] == ["192.168.1.1"]

    def test_validate_target_invalid(self):
        result = validate_target.invoke({"ip_or_cidr": "not-an-ip"})
        assert result["valid"] is False

    def test_validate_target_cidr(self):
        result = validate_target.invoke({"ip_or_cidr": "192.168.1.0/30"})
        assert result["valid"] is True
        assert result["is_cidr"] is True
        assert len(result["ips"]) == 2  # /30 has 2 usable hosts

    def test_calculate_severity(self):
        assert calculate_severity.invoke({"cvss_score": 9.5}) == "CRITICAL"
        assert calculate_severity.invoke({"cvss_score": 7.5}) == "HIGH"
        assert calculate_severity.invoke({"cvss_score": 5.0}) == "MEDIUM"
        assert calculate_severity.invoke({"cvss_score": 2.0}) == "LOW"
        assert calculate_severity.invoke({"cvss_score": 0.0}) == "NONE"


class TestReportingTools:
    def test_generate_report(self):
        scan_data = {
            "target": "192.168.1.1",
            "open_ports": [{"port": 22, "protocol": "tcp", "state": "open", "service": "SSH"}],
            "services": [],
            "vulnerabilities": [],
            "exploits": [],
            "os_info": "Linux/Unix",
        }
        result = generate_report.invoke({"format": "text", "scan_data": scan_data})
        assert "192.168.1.1" in result
        assert "CLEARWING SCAN REPORT" in result


class _FakeUsage:
    def __init__(self, prompt=0, completion=0, total=0):
        self.prompt_tokens = prompt
        self.completion_tokens = completion
        self.total_tokens = total


class _FakeResponse:
    """Minimal stand-in for a genai ChatResponse."""

    def __init__(self, text="", tool_calls=None, usage=None):
        self.first_text = text
        self.texts = [text] if text else []
        self.tool_calls = tool_calls or []
        self.usage = usage or _FakeUsage()
        self.provider_model_name = "fake-model"
        self.reasoning_content = None


class _FakeNativeClient:
    """Records the ChatMessage history it is handed and replays scripted responses."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []  # each entry: (messages, system, tools)

    async def achat_stream(self, *, messages, system=None, tools=None, on_text_delta=None):
        self.calls.append((list(messages), system, tools))
        resp = self._responses.pop(0)
        if on_text_delta and resp.first_text:
            on_text_delta(resp.first_text)
        return resp

    async def achat(self, *, messages, system=None, tools=None, **kwargs):
        return await self.achat_stream(messages=messages, system=system, tools=tools)


class TestNativeToolLoopRoundTrip:
    """The riskiest path: a multi-turn tool call over the native client.

    Asserts that genai ``ToolCall`` objects are consumed by ``.fn_name`` /
    ``.fn_arguments`` / ``.call_id``, that the assistant + tool result turns
    round-trip into well-formed ChatMessages (assistant carries ``tool_calls``,
    tool result carries ``tool_response_call_id``), and that usage is tracked.
    """

    @pytest.mark.asyncio
    async def test_tool_call_executes_and_round_trips(self):
        import json

        from genai_pyo3 import ToolCall

        from clearwing.agent.graph import build_react_graph

        seen_args = {}

        @tool
        def echo_tool(value: str) -> str:
            """Echo the value."""
            seen_args["value"] = value
            return f"echoed:{value}"

        # Turn 1: model asks to call echo_tool. Turn 2: model responds with text.
        tc = ToolCall("call-1", "echo_tool", json.dumps({"value": "hello"}))
        client = _FakeNativeClient(
            [
                _FakeResponse(text="", tool_calls=[tc], usage=_FakeUsage(10, 5, 15)),
                _FakeResponse(text="all done", usage=_FakeUsage(3, 2, 5)),
            ]
        )

        graph = build_react_graph(
            llm_with_tools=client,
            tools=[echo_tool],
            system_prompt_fn=lambda state: "sys",
            model_name="fake-model",
            session_id=None,
            enable_knowledge_graph=False,
            enable_audit=False,
            enable_episodic_memory=False,
            enable_context_summarizer=False,
        )

        config = {"configurable": {"thread_id": "t1"}}
        events = []
        async for event in graph.astream(
            {"messages": [{"role": "user", "content": "please echo hello"}]}, config
        ):
            events.append(event)

        # The tool actually ran with the decoded arguments.
        assert seen_args == {"value": "hello"}

        # Two LLM turns were made.
        assert len(client.calls) == 2

        # On the SECOND call, the history sent to the model must contain the
        # assistant tool-call turn and the paired tool-result turn.
        second_messages = client.calls[1][0]
        roles = [m.role for m in second_messages]
        assert "assistant" in roles
        assert "tool" in roles

        assistant_msg = next(m for m in second_messages if m.role == "assistant")
        assert assistant_msg.tool_calls  # carries the tool_calls
        assert assistant_msg.tool_calls[0].call_id == "call-1"

        tool_msg = next(m for m in second_messages if m.role == "tool")
        assert tool_msg.tool_response_call_id == "call-1"
        assert "echoed:hello" in tool_msg.content

        # Final state carries the assistant's closing text and usage.
        final = graph.get_state(config).values
        last = final["messages"][-1]
        assert last.type == "ai"
        assert last.text == "all done"
        assert final.get("total_tokens", 0) > 0
