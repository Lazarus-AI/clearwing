from __future__ import annotations

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import SystemMessage
from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import ToolNode, tools_condition
from langgraph.checkpoint.memory import MemorySaver

from clearwing.agent.state import AgentState

RECON_PROMPT = """You are a reconnaissance specialist for penetration testing. Your role is to:
1. Scan for open ports on the target
2. Detect services and their versions
3. Identify the operating system
4. Enumerate interesting findings

Use only scanning tools — do NOT attempt exploitation.
Be thorough but efficient. Report all findings clearly.

Target: {target}
"""


class ReconAgent:
    """Reconnaissance specialist sub-graph."""

    def __init__(self, model_name: str = "claude-sonnet-4-6"):
        self.model_name = model_name

    def build_graph(self):
        """Build and compile the recon sub-graph."""
        from clearwing.agent.tools.scanner_tools import (
            scan_ports, detect_services, scan_vulnerabilities, detect_os,
        )
        from clearwing.agent.tools.kali_docker_tool import (
            kali_setup, kali_execute, kali_install_tool,
        )

        tools = [scan_ports, detect_services, scan_vulnerabilities, detect_os,
                 kali_setup, kali_execute, kali_install_tool]

        llm = ChatAnthropic(model=self.model_name)
        llm_with_tools = llm.bind_tools(tools)

        def assistant(state: AgentState):
            target = state.get("target", "unknown")
            sys_prompt = RECON_PROMPT.format(target=target)
            messages = [SystemMessage(content=sys_prompt)] + state["messages"]
            response = llm_with_tools.invoke(messages)
            return {"messages": [response]}

        graph = StateGraph(AgentState)
        graph.add_node("assistant", assistant)
        graph.add_node("tools", ToolNode(tools))
        graph.add_edge(START, "assistant")
        graph.add_conditional_edges("assistant", tools_condition)
        graph.add_edge("tools", "assistant")

        return graph.compile(checkpointer=MemorySaver())
