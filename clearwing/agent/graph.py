from __future__ import annotations

from typing import Any

from clearwing.agent.runtime import NativeAgentGraph, populate_knowledge_graph
from clearwing.agent.state import AgentState
from clearwing.capabilities import capabilities
from clearwing.llm import ChatModel
from clearwing.providers import ProviderManager, resolve_llm_endpoint

from .prompts import build_system_prompt
from .tools import get_all_tools, get_custom_tools


def _default_pentest_state_updater(tool_name: str, data: Any, state: dict) -> dict:
    if tool_name == "scan_ports" and isinstance(data, list):
        return {"open_ports": state.get("open_ports", []) + data}
    if tool_name == "detect_services" and isinstance(data, list):
        return {"services": state.get("services", []) + data}
    if tool_name == "scan_vulnerabilities" and isinstance(data, list):
        return {"vulnerabilities": state.get("vulnerabilities", []) + data}
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
    llm_with_tools: ChatModel,
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

    return NativeAgentGraph(
        llm_with_tools=llm_with_tools,
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
    )


def _create_llm(
    model_name: str,
    base_url: str | None = None,
    api_key: str | None = None,
) -> ChatModel:
    endpoint = resolve_llm_endpoint(
        cli_model=model_name,
        cli_base_url=base_url,
        cli_api_key=api_key,
    )
    return ProviderManager.for_endpoint(endpoint).get_llm("default")


def create_agent(
    model_name: str = "claude-sonnet-4-6",
    custom_tools: list = None,
    session_id: str = None,
    base_url: str = None,
    api_key: str = None,
):
    all_tools = get_all_tools()
    if custom_tools:
        all_tools.extend(custom_tools)

    runtime_tools = get_custom_tools()
    for rt in runtime_tools:
        if rt not in all_tools:
            all_tools.append(rt)

    llm = _create_llm(model_name, base_url=base_url, api_key=api_key)
    llm_with_tools = llm.bind_tools(all_tools)

    return build_react_graph(
        llm_with_tools=llm_with_tools,
        tools=all_tools,
        system_prompt_fn=build_system_prompt,
        state_schema=AgentState,
        model_name=model_name,
        session_id=session_id,
    )
