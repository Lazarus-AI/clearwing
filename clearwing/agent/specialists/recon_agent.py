from __future__ import annotations

from clearwing.agent.graph import _create_llm, build_react_graph
from clearwing.agent.state import AgentState
from clearwing.agent.tools.ops.kali_docker_tool import kali_execute, kali_install_tool, kali_setup
from clearwing.agent.tools.scan.scanner_tools import (
    detect_os,
    detect_services,
    scan_ports,
    scan_vulnerabilities,
)

RECON_PROMPT = """You are a reconnaissance specialist for penetration testing. Your role is to:
1. Scan for open ports on the target
2. Detect services and their versions
3. Identify the operating system
4. Enumerate interesting findings

Use only scanning tools. Do not attempt exploitation.
Be thorough but efficient. Report all findings clearly.

Target: {target}
"""


class ReconAgent:
    """Reconnaissance specialist sub-graph."""

    def __init__(self, model_name: str = "claude-sonnet-4-6"):
        self.model_name = model_name

    def build_graph(self):
        tools = [
            scan_ports,
            detect_services,
            scan_vulnerabilities,
            detect_os,
            kali_setup,
            kali_execute,
            kali_install_tool,
        ]
        llm = _create_llm(self.model_name)

        def system_prompt(state: AgentState) -> str:
            return RECON_PROMPT.format(target=state.get("target", "unknown"))

        return build_react_graph(
            llm_with_tools=llm.bind_tools(tools),
            tools=tools,
            system_prompt_fn=system_prompt,
            state_schema=AgentState,
            model_name=self.model_name,
        )
