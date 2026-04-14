"""Tests for the LangGraph agent."""
import pytest
from unittest.mock import patch, AsyncMock, MagicMock


class TestAgentState:
    def test_state_instantiation(self):
        from vulnexploit.agent.state import AgentState

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
        from vulnexploit.agent.state import AgentState

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
        from vulnexploit.agent.prompts import build_system_prompt

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
        assert "VulnExploit Agent" in prompt

    def test_populated_state(self):
        from vulnexploit.agent.prompts import build_system_prompt

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
        from vulnexploit.agent.tools import get_all_tools

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
        from vulnexploit.agent.graph import create_agent

        with patch("langchain_anthropic.ChatAnthropic") as mock_llm:
            mock_instance = MagicMock()
            mock_instance.bind_tools.return_value = mock_instance
            mock_llm.return_value = mock_instance

            graph = create_agent(model_name="claude-sonnet-4-6")
            assert graph is not None
            mock_llm.assert_called_once_with(model="claude-sonnet-4-6")

    def test_create_agent_with_custom_tools(self):
        from vulnexploit.agent.graph import create_agent
        from langchain_core.tools import tool

        @tool
        def dummy_tool(x: str) -> str:
            """A dummy tool."""
            return x

        with patch("langchain_anthropic.ChatAnthropic") as mock_llm:
            mock_instance = MagicMock()
            mock_instance.bind_tools.return_value = mock_instance
            mock_llm.return_value = mock_instance

            graph = create_agent(model_name="claude-sonnet-4-6", custom_tools=[dummy_tool])
            assert graph is not None
            # Verify bind_tools was called with list containing our tool
            bound_tools = mock_instance.bind_tools.call_args[0][0]
            assert dummy_tool in bound_tools

    def test_create_agent_with_custom_endpoint(self):
        import sys
        from vulnexploit.agent.graph import create_agent

        mock_openai_module = MagicMock()
        mock_llm_class = MagicMock()
        mock_instance = MagicMock()
        mock_instance.bind_tools.return_value = mock_instance
        mock_llm_class.return_value = mock_instance
        mock_openai_module.ChatOpenAI = mock_llm_class

        with patch.dict(sys.modules, {"langchain_openai": mock_openai_module}):
            graph = create_agent(
                model_name="my-model",
                base_url="http://localhost:8000/v1",
                api_key="test-key",
            )
            assert graph is not None
            mock_llm_class.assert_called_once_with(
                model="my-model",
                base_url="http://localhost:8000/v1",
                api_key="test-key",
            )


class TestScannerToolWrapping:
    # NOTE: scanner_tools imports from vulnexploit.scanning (the canonical
    # module), not the deprecated vulnexploit.scanners shim. Patching the
    # real import path at `vulnexploit.scanning.*` is what matters.

    @pytest.mark.asyncio
    async def test_scan_ports_wraps_scanner(self):
        from vulnexploit.agent.tools.scanner_tools import scan_ports

        mock_result = [{"port": 22, "protocol": "tcp", "state": "open", "service": "SSH"}]

        mock_scanner = MagicMock()
        mock_scanner.scan = AsyncMock(return_value=mock_result)
        mock_class = MagicMock(return_value=mock_scanner)

        with patch("vulnexploit.scanning.PortScanner", mock_class):
            await scan_ports.ainvoke({
                "target": "192.168.1.1",
                "ports": [22],
                "scan_type": "connect",
                "threads": 10,
            })
            mock_scanner.scan.assert_called_once_with("192.168.1.1", [22], "connect", 10)

    @pytest.mark.asyncio
    async def test_detect_services_wraps_scanner(self):
        from vulnexploit.agent.tools.scanner_tools import detect_services

        ports = [{"port": 80, "service": "HTTP"}]
        mock_result = [{"port": 80, "service": "HTTP", "banner": "Apache", "version": "2.4"}]

        mock_scanner = MagicMock()
        mock_scanner.detect = AsyncMock(return_value=mock_result)
        mock_class = MagicMock(return_value=mock_scanner)

        with patch("vulnexploit.scanning.ServiceScanner", mock_class):
            await detect_services.ainvoke({
                "target": "192.168.1.1",
                "open_ports": ports,
            })
            mock_scanner.detect.assert_called_once_with("192.168.1.1", ports)

    @pytest.mark.asyncio
    async def test_detect_os_wraps_scanner(self):
        from vulnexploit.agent.tools.scanner_tools import detect_os

        mock_scanner = MagicMock()
        mock_scanner.detect = AsyncMock(return_value="Linux/Unix")
        mock_class = MagicMock(return_value=mock_scanner)

        with patch("vulnexploit.scanning.OSScanner", mock_class):
            await detect_os.ainvoke({"target": "192.168.1.1"})
            mock_scanner.detect.assert_called_once_with("192.168.1.1")


class TestUtilityTools:
    def test_validate_target_ip(self):
        from vulnexploit.agent.tools.utility_tools import validate_target

        result = validate_target.invoke({"ip_or_cidr": "192.168.1.1"})
        assert result["valid"] is True
        assert result["is_cidr"] is False
        assert result["ips"] == ["192.168.1.1"]

    def test_validate_target_invalid(self):
        from vulnexploit.agent.tools.utility_tools import validate_target

        result = validate_target.invoke({"ip_or_cidr": "not-an-ip"})
        assert result["valid"] is False

    def test_validate_target_cidr(self):
        from vulnexploit.agent.tools.utility_tools import validate_target

        result = validate_target.invoke({"ip_or_cidr": "192.168.1.0/30"})
        assert result["valid"] is True
        assert result["is_cidr"] is True
        assert len(result["ips"]) == 2  # /30 has 2 usable hosts

    def test_calculate_severity(self):
        from vulnexploit.agent.tools.utility_tools import calculate_severity

        assert calculate_severity.invoke({"cvss_score": 9.5}) == "CRITICAL"
        assert calculate_severity.invoke({"cvss_score": 7.5}) == "HIGH"
        assert calculate_severity.invoke({"cvss_score": 5.0}) == "MEDIUM"
        assert calculate_severity.invoke({"cvss_score": 2.0}) == "LOW"
        assert calculate_severity.invoke({"cvss_score": 0.0}) == "NONE"


class TestReportingTools:
    def test_generate_report(self):
        from vulnexploit.agent.tools.reporting_tools import generate_report

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
        assert "VULNEXPLOIT SCAN REPORT" in result
