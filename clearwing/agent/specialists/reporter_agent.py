from __future__ import annotations

from clearwing.agent.graph import _create_llm, build_react_graph
from clearwing.agent.state import AgentState
from clearwing.agent.tools.meta.reporting_tools import (
    generate_report,
    query_scan_history,
    save_report,
    search_cves,
)

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
        tools = [generate_report, save_report, query_scan_history, search_cves]
        llm = _create_llm(self.model_name)

        def system_prompt(state: AgentState) -> str:
            return REPORTER_PROMPT.format(
                target=state.get("target", "unknown"),
                port_count=len(state.get("open_ports", [])),
                service_count=len(state.get("services", [])),
                vuln_count=len(state.get("vulnerabilities", [])),
                exploit_count=len(state.get("exploit_results", [])),
            )

        return build_react_graph(
            llm_with_tools=llm.bind_tools(tools),
            tools=tools,
            system_prompt_fn=system_prompt,
            state_schema=AgentState,
            model_name=self.model_name,
        )
