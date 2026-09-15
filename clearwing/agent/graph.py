from __future__ import annotations

import re
from typing import Any

from clearwing.agent.runtime import NativeAgentGraph, populate_knowledge_graph
from clearwing.agent.state import AgentState
from clearwing.agent.tooling import ensure_agent_tool
from clearwing.capabilities import capabilities
from clearwing.llm.native import AsyncLLMClient
from clearwing.providers import ProviderManager, resolve_llm_endpoint

from .prompts import build_system_prompt
from .tools import get_all_tools, get_custom_tools


# Matches an nmap "open port" line, e.g.
#   22/tcp   open  ssh     OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
_NMAP_OPEN_LINE = re.compile(r"^\s*(\d{1,5})/(tcp|udp)\s+open\s+(\S+)\s*(.*)$", re.IGNORECASE)


def _findings_from_nmap(output: str) -> list[dict]:
    """Extract structured findings from nmap -sV style output.

    Kali/nmap output reaches the graph as free text via kali_execute, so it never
    populates the findings list on its own and the local operator model often narrates
    "recorded findings" without emitting a record_finding tool call. Parsing the open
    ports deterministically guarantees the run reports what the scan actually found.
    Only lines that look like an nmap open-port row match, so non-nmap kali_execute
    output yields nothing.
    """
    findings: list[dict] = []
    for line in output.splitlines():
        match = _NMAP_OPEN_LINE.match(line)
        if not match:
            continue
        port = int(match.group(1))
        proto = match.group(2).lower()
        service = match.group(3).strip()
        version = match.group(4).strip()
        findings.append(
            {
                "port": port,
                "protocol": proto,
                "service": service,
                "version": version,
                "severity": "info",
                "description": f"Open {service} on {port}/{proto}"
                + (f" ({version})" if version else ""),
                "source": "nmap",
            }
        )
    return findings


def _default_pentest_state_updater(tool_name: str, data: Any, state: dict) -> dict:
    if tool_name == "scan_ports" and isinstance(data, list):
        return {"open_ports": state.get("open_ports", []) + data}
    if tool_name == "detect_services" and isinstance(data, list):
        return {"services": state.get("services", []) + data}
    if tool_name == "scan_vulnerabilities" and isinstance(data, list):
        return {"vulnerabilities": state.get("vulnerabilities", []) + data}
    if tool_name == "record_finding" and isinstance(data, dict):
        return {"vulnerabilities": state.get("vulnerabilities", []) + [data]}
    if tool_name == "kali_execute" and isinstance(data, dict):
        output = data.get("output")
        if isinstance(output, str):
            parsed = _findings_from_nmap(output)
            if parsed:
                existing = state.get("vulnerabilities", [])
                seen = {(v.get("port"), v.get("service")) for v in existing if isinstance(v, dict)}
                fresh = [f for f in parsed if (f["port"], f["service"]) not in seen]
                if fresh:
                    return {"vulnerabilities": existing + fresh}
    if tool_name == "detect_os" and isinstance(data, str):
        return {"os_info": data}
    if tool_name == "exploit_vulnerability" and isinstance(data, dict):
        return {"exploit_results": state.get("exploit_results", []) + [data]}
    if tool_name == "kali_setup" and isinstance(data, str):
        return {"kali_container_id": data}
    return {}


_DEFAULT_PENTEST_GUARDRAIL_TOOLS = frozenset(
    {
        "scan_ports",
        "detect_services",
        "scan_vulnerabilities",
        "detect_os",
    }
)

_DEFAULT_OUTPUT_GUARDRAIL_TOOLS = frozenset({"kali_execute"})


def build_react_graph(
    llm_with_tools: AsyncLLMClient,
    tools: list,
    system_prompt_fn,
    *,
    state_schema=AgentState,
    model_name: str = "claude-sonnet-4-6",
    session_id: str = None,
    state_updater_fn=None,
    knowledge_graph_populator_fn=None,
    input_guardrail_tool_names=None,
    output_guardrail_tool_names=None,
    enable_cost_tracker: bool = True,
    enable_episodic_memory: bool = True,
    enable_audit: bool = True,
    enable_knowledge_graph: bool = True,
    enable_input_guardrail: bool = True,
    enable_output_guardrail: bool = True,
    enable_event_bus: bool = True,
    enable_context_summarizer: bool = True,
    agent_limits=None,
):
    del state_schema
    if state_updater_fn is None:
        state_updater_fn = _default_pentest_state_updater
    if knowledge_graph_populator_fn is None:
        knowledge_graph_populator_fn = populate_knowledge_graph
    if input_guardrail_tool_names is None:
        input_guardrail_tool_names = _DEFAULT_PENTEST_GUARDRAIL_TOOLS
    if output_guardrail_tool_names is None:
        output_guardrail_tool_names = _DEFAULT_OUTPUT_GUARDRAIL_TOOLS

    # `llm_with_tools` is now a bare AsyncLLMClient (no ChatModel `bind_tools`
    # facade). The native client threads the tool list through each `achat`
    # call rather than binding it, so build the NativeToolSpec list here once
    # and hand both the client and the specs to the runtime.
    native_tools = [ensure_agent_tool(t) for t in tools]

    return NativeAgentGraph(
        llm=llm_with_tools,
        native_tools=native_tools,
        tools=tools,
        system_prompt_fn=system_prompt_fn,
        model_name=model_name,
        session_id=session_id,
        state_updater_fn=state_updater_fn,
        knowledge_graph_populator_fn=knowledge_graph_populator_fn,
        input_guardrail_tool_names=input_guardrail_tool_names,
        output_guardrail_tool_names=output_guardrail_tool_names,
        enable_cost_tracker=enable_cost_tracker,
        enable_episodic_memory=enable_episodic_memory,
        enable_audit=enable_audit,
        enable_knowledge_graph=enable_knowledge_graph and capabilities.has("knowledge"),
        enable_input_guardrail=enable_input_guardrail,
        enable_output_guardrail=enable_output_guardrail,
        enable_event_bus=enable_event_bus,
        enable_context_summarizer=enable_context_summarizer,
        agent_limits=agent_limits,
    )


def _create_llm(
    model_name: str,
    base_url: str | None = None,
    api_key: str | None = None,
    provider_manager: ProviderManager | None = None,
    task: str = "default",
) -> AsyncLLMClient:
    if provider_manager is not None:
        return provider_manager.get_native_client(task)
    endpoint = resolve_llm_endpoint(
        cli_model=model_name,
        cli_base_url=base_url,
        cli_api_key=api_key,
    )
    return ProviderManager.for_endpoint(endpoint).get_native_client("default")


def create_agent(
    model_name: str = "claude-sonnet-4-6",
    custom_tools: list = None,
    session_id: str = None,
    base_url: str = None,
    api_key: str = None,
    provider_manager: ProviderManager | None = None,
):
    all_tools = get_all_tools()
    if custom_tools:
        all_tools.extend(custom_tools)

    runtime_tools = get_custom_tools()
    for rt in runtime_tools:
        if rt not in all_tools:
            all_tools.append(rt)

    # No `bind_tools` step: the native client takes the tool list per-call.
    # `build_react_graph` builds the NativeToolSpec list from `all_tools`.
    agent_limits = None
    if provider_manager is None:
        llm = _create_llm(model_name, base_url=base_url, api_key=api_key)
    else:
        llm = _create_llm(
            model_name,
            base_url=base_url,
            api_key=api_key,
            provider_manager=provider_manager,
        )
        agent_limits = provider_manager.get_agent_limits("default")

    return build_react_graph(
        llm_with_tools=llm,
        tools=all_tools,
        system_prompt_fn=build_system_prompt,
        state_schema=AgentState,
        model_name=model_name,
        session_id=session_id,
        agent_limits=agent_limits,
    )
