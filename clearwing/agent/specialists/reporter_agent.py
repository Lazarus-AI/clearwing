from __future__ import annotations

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import SystemMessage
from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import ToolNode, tools_condition
from langgraph.checkpoint.memory import MemorySaver

from clearwing.agent.state import AgentState

REPORTER_PROMPT = """You are a penetration testing report writer. Your role is to:
1. Synthesize all findings into a comprehensive report
2. Categorize findings by severity (Critical, High, Medium, Low, Info)
3. Include remediation recommendations for each finding
4. Generate executive summary and technical details

Use the reporting tools to generate and save the final report.

Target: {target}
Findings summary:
- Open ports: {port_count}
- Services: {service_count}
- Vulnerabilities: {vuln_count}
- Exploit results: {exploit_count}
"""


class ReporterAgent:
    """Report generation specialist sub-graph."""

    def __init__(self, model_name: str = "claude-sonnet-4-6"):
        self.model_name = model_name

    def build_graph(self):
        """Build and compile the reporter sub-graph."""
        from clearwing.agent.tools.reporting_tools import (
            generate_report, save_report, query_scan_history, search_cves,
        )

        tools = [generate_report, save_report, query_scan_history, search_cves]

        llm = ChatAnthropic(model=self.model_name)
        llm_with_tools = llm.bind_tools(tools)

        def assistant(state: AgentState):
            target = state.get("target", "unknown")
            sys_prompt = REPORTER_PROMPT.format(
                target=target,
                port_count=len(state.get("open_ports", [])),
                service_count=len(state.get("services", [])),
                vuln_count=len(state.get("vulnerabilities", [])),
                exploit_count=len(state.get("exploit_results", [])),
            )
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
