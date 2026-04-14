import asyncio
import logging
import re
import json
import ast
from typing import Any

import networkx as nx

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import SystemMessage
from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import ToolNode, tools_condition
from langgraph.checkpoint.memory import MemorySaver

logger = logging.getLogger(__name__)

from .state import AgentState
from .prompts import build_system_prompt
from .tools import get_all_tools, get_custom_tools

# --- Graceful imports for Phase 1 modules ---

try:
    from clearwing.safety.guardrails import InputGuardrail, OutputGuardrail
except ImportError:
    InputGuardrail = None
    OutputGuardrail = None

try:
    from clearwing.data.memory import EpisodicMemory, ContextSummarizer
except ImportError:
    EpisodicMemory = None
    ContextSummarizer = None

try:
    from clearwing.observability.telemetry import CostTracker
except ImportError:
    CostTracker = None

try:
    from clearwing.core.events import EventBus, EventType
except ImportError:
    EventBus = None
    EventType = None

# --- Graceful imports for Phase 2 modules ---

try:
    from clearwing.safety.audit import AuditLogger
except ImportError:
    AuditLogger = None

try:
    from clearwing.data.knowledge import KnowledgeGraph
except ImportError:
    KnowledgeGraph = None

# --- Flag detection ---

FLAG_PATTERNS = [
    re.compile(r'flag\{[^}]+\}', re.IGNORECASE),
    re.compile(r'FLAG\{[^}]+\}'),
    re.compile(r'HTB\{[^}]+\}'),
    re.compile(r'CTF\{[^}]+\}'),
    re.compile(r'[A-Fa-f0-9]{32}'),
]


def detect_flags(text: str) -> list[dict]:
    """Detect CTF-style flags in text."""
    flags = []
    for pattern in FLAG_PATTERNS:
        for match in pattern.finditer(text):
            flags.append({"flag": match.group(), "pattern": pattern.pattern})
    return flags


def _parse_tool_output(content: str) -> Any:
    """Try to parse tool output as JSON or Python literal."""
    try:
        return json.loads(content)
    except Exception:
        try:
            return ast.literal_eval(content)
        except Exception:
            return content


def _populate_knowledge_graph(kg, tool_name: str, content: str, state: dict) -> dict:
    """Auto-populate the knowledge graph from scan tool results and return graph data."""
    target = state.get("target", "")
    if not target:
        return {}

    try:
        # Ensure target entity exists
        kg.add_target(target)
        data = _parse_tool_output(content)

        if tool_name == "scan_ports" and isinstance(data, list):
            for port_info in data:
                port = port_info.get("port")
                proto = port_info.get("protocol", "tcp")
                if port:
                    kg.add_port(target, port, proto)

        elif tool_name == "detect_services" and isinstance(data, list):
            for svc_info in data:
                port = svc_info.get("port")
                proto = svc_info.get("protocol", "tcp")
                service = svc_info.get("service", "unknown")
                version = svc_info.get("version", "")
                if port and service:
                    port_id = f"{target}:{port}/{proto}"
                    kg.add_port(target, port, proto)
                    kg.add_service(port_id, service, version)

        elif tool_name == "scan_vulnerabilities" and isinstance(data, list):
            for vuln in data:
                cve = vuln.get("cve", "")
                cvss = vuln.get("cvss", 0.0)
                port = vuln.get("port")
                service = vuln.get("service", "unknown")
                if cve:
                    # Try to find which service this belongs to
                    service_id = f"{target}:{port}/tcp:{service}" if port else service
                    kg.add_vulnerability(service_id, cve, cvss)

        elif tool_name == "detect_os" and isinstance(data, str):
            kg.add_target(target, os=data)

        elif tool_name == "exploit_vulnerability" and isinstance(data, dict):
            cve = data.get("cve", "unknown")
            success = data.get("success", False)
            exploit = data.get("exploit", "unknown")
            kg.add_exploit_result(cve, exploit, success=success)

        kg.save()
        return nx.node_link_data(kg._graph)
    except Exception:
        logger.debug("Knowledge graph population failed", exc_info=True)
        return {}


def _default_pentest_state_updater(tool_name: str, data: Any, state: dict) -> dict:
    """Default tool-result → state-update mapping for the network-pentest agent.

    Sourcehunt and other agent flavors pass their own updater to build_react_graph().
    """
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


_DEFAULT_PENTEST_GUARDRAIL_TOOLS = frozenset({
    "scan_ports", "detect_services", "scan_vulnerabilities", "detect_os",
})

_DEFAULT_OUTPUT_GUARDRAIL_TOOLS = frozenset({"kali_execute"})


def build_react_graph(
    llm_with_tools,
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
    """Build and compile a ReAct graph with shared cost/audit/memory/guardrails.

    This is the parameterized core that powers the network-pentest `create_agent()`
    AND the sourcehunt hunter/verifier/exploiter agents. The pentest defaults are
    applied unless callers override them.

    Args:
        llm_with_tools: An LLM already bound to its tool set via .bind_tools().
        tools: The tool list (used to build the ToolNode).
        system_prompt_fn: Callable[[state_dict], str] — builds the system prompt
            from the current state. For pentest agents this is build_system_prompt.
            For sourcehunt agents this is a hunter/verifier-specific builder.
        state_schema: TypedDict class describing the state. Defaults to AgentState
            for pentest; sourcehunt passes SourceHuntState.
        model_name: Model identifier for cost tracker / audit logging.
        session_id: Audit log session id; if None, audit is disabled.
        state_updater_fn: Optional Callable[[tool_name, parsed_data, state], dict]
            that returns extra state updates from a tool result. Defaults to the
            pentest scanner mappings; sourcehunt passes a record_finding-aware fn.
        knowledge_graph_populator_fn: Optional Callable[[kg, tool_name, content,
            state], dict] for auto-populating a knowledge graph from tool output.
            Defaults to _populate_knowledge_graph (pentest network entities).
            Pass `lambda *a, **k: {}` to disable.
        input_guardrail_tool_names: Set of tool names whose output gets an
            input-guardrail check. Defaults to pentest scanner tools.
        output_guardrail_tool_names: Set of tool names whose args get an
            output-guardrail check. Defaults to {"kali_execute"}.
        enable_*: Toggle individual subsystems off without removing the wiring.

    Returns:
        Compiled StateGraph with MemorySaver checkpointer.
    """
    if state_updater_fn is None:
        state_updater_fn = _default_pentest_state_updater
    if knowledge_graph_populator_fn is None:
        knowledge_graph_populator_fn = _populate_knowledge_graph
    if input_guardrail_tool_names is None:
        input_guardrail_tool_names = _DEFAULT_PENTEST_GUARDRAIL_TOOLS
    if output_guardrail_tool_names is None:
        output_guardrail_tool_names = _DEFAULT_OUTPUT_GUARDRAIL_TOOLS

    cost_tracker = CostTracker() if (enable_cost_tracker and CostTracker) else None
    episodic_memory = EpisodicMemory() if (enable_episodic_memory and EpisodicMemory) else None
    context_summarizer = (
        ContextSummarizer() if (enable_context_summarizer and ContextSummarizer) else None
    )
    event_bus = EventBus() if (enable_event_bus and EventBus) else None
    input_guardrail = InputGuardrail() if (enable_input_guardrail and InputGuardrail) else None
    output_guardrail = OutputGuardrail() if (enable_output_guardrail and OutputGuardrail) else None

    audit_logger = None
    if enable_audit and AuditLogger and session_id:
        try:
            audit_logger = AuditLogger(session_id)
        except Exception:
            logger.warning("Failed to initialize AuditLogger", exc_info=True)

    knowledge_graph = None
    if enable_knowledge_graph and KnowledgeGraph:
        try:
            knowledge_graph = KnowledgeGraph(persist_path="~/.clearwing/knowledge_graph.json")
        except Exception:
            logger.warning("Failed to initialize KnowledgeGraph", exc_info=True)

    def assistant(state):
        messages = list(state["messages"])

        if context_summarizer and context_summarizer.should_summarize(messages):
            try:
                loop = asyncio.get_event_loop()
                if not loop.is_running():
                    messages = loop.run_until_complete(
                        context_summarizer.summarize(messages, llm_with_tools)
                    )
            except Exception:
                logger.debug("Context summarization failed", exc_info=True)

        sys_prompt = system_prompt_fn(state)
        full_messages = [SystemMessage(content=sys_prompt)] + messages
        response = llm_with_tools.invoke(full_messages)

        state_updates = {"messages": [response]}

        if cost_tracker:
            usage = getattr(response, "response_metadata", {}).get("usage", {})
            if usage:
                input_tokens = usage.get("input_tokens", 0)
                output_tokens = usage.get("output_tokens", 0)
                cost_tracker.record_llm_call(input_tokens, output_tokens, model_name)
                state_updates["total_cost_usd"] = cost_tracker.total_cost_usd
                state_updates["total_tokens"] = cost_tracker.input_tokens + cost_tracker.output_tokens

                if audit_logger:
                    audit_logger.log_llm_call(
                        model=model_name,
                        input_tokens=input_tokens,
                        output_tokens=output_tokens,
                        cost_usd=cost_tracker.total_cost_usd,
                    )

        if event_bus and EventType:
            content_text = response.content if isinstance(response.content, str) else ""
            event_bus.emit_message(content_text[:200], "agent")

        if isinstance(response.content, str):
            found_flags = detect_flags(response.content)
            if found_flags:
                existing_flags = list(state.get("flags_found", []))
                state_updates["flags_found"] = existing_flags + found_flags
                if event_bus:
                    for f in found_flags:
                        event_bus.emit_flag(f["flag"], "LLM response")

        return state_updates

    base_tool_node = ToolNode(tools)

    def guarded_tools_node(state):
        last_message = state["messages"][-1]
        tool_calls = getattr(last_message, "tool_calls", [])

        for tc in tool_calls:
            tool_name = tc.get("name", "")
            tool_args = tc.get("args", {})

            if event_bus and EventType:
                event_bus.emit(EventType.TOOL_START, {
                    "tool": tool_name,
                    "args": tool_args,
                })

            if output_guardrail and tool_name in output_guardrail_tool_names:
                command = tool_args.get("command", "")
                result = output_guardrail.check_command(command)
                if not result.passed:
                    if event_bus:
                        event_bus.emit_message(
                            f"Guardrail blocked: {result.reason}", "warning"
                        )

        result = base_tool_node.invoke(state)

        result_messages = result.get("messages", [])
        state_updates = {"messages": result_messages}
        new_flags = []

        for i, msg in enumerate(result_messages):
            content = msg.content if hasattr(msg, "content") else str(msg)
            tool_name = getattr(msg, "name", "unknown")

            if input_guardrail and tool_name in input_guardrail_tool_names:
                gr = input_guardrail.check(content)
                if not gr.passed and event_bus:
                    event_bus.emit_message(
                        f"Input guardrail warning: {gr.reason}", "warning"
                    )

            if episodic_memory:
                target = state.get("target", "unknown")
                episodic_memory.record(
                    target=target,
                    event_type=f"tool:{tool_name}",
                    content=content[:500],
                )

            if cost_tracker:
                cost_tracker.record_tool_call(tool_name, 0)

            if audit_logger:
                tc_args = {}
                if i < len(tool_calls):
                    tc_args = tool_calls[i].get("args", {})
                audit_logger.log_tool_call(
                    tool_name=tool_name,
                    args=tc_args,
                    result=content[:2000],
                )

            if knowledge_graph and knowledge_graph_populator_fn:
                graph_data = knowledge_graph_populator_fn(
                    knowledge_graph, tool_name, content, state,
                )
                if graph_data:
                    state_updates["graph_data"] = graph_data

            data = _parse_tool_output(content)
            extra_updates = state_updater_fn(tool_name, data, state) or {}
            for k, v in extra_updates.items():
                state_updates[k] = v

            found_flags = detect_flags(content)
            if found_flags:
                new_flags.extend(found_flags)

            if event_bus and EventType:
                event_bus.emit(EventType.TOOL_RESULT, {
                    "tool": tool_name,
                    "content_length": len(content),
                    "flags_found": len(found_flags),
                })

        if new_flags:
            existing_flags = state.get("flags_found", [])
            state_updates["flags_found"] = existing_flags + new_flags
            if event_bus and EventType:
                event_bus.emit(EventType.FLAG_FOUND, {"flags": new_flags})

        return state_updates

    graph = StateGraph(state_schema)
    graph.add_node("assistant", assistant)
    graph.add_node("tools", guarded_tools_node)

    graph.add_edge(START, "assistant")
    graph.add_conditional_edges("assistant", tools_condition)
    graph.add_edge("tools", "assistant")

    checkpointer = MemorySaver()
    return graph.compile(checkpointer=checkpointer)


def _create_llm(model_name: str, base_url: str = None, api_key: str = None) -> BaseChatModel:
    """Create an LLM instance.

    When *base_url* is provided the model is accessed via the OpenAI-compatible
    API (works with vLLM, Ollama, MLX, OpenRouter, etc.).  Otherwise the
    default Anthropic provider is used.
    """
    if base_url:
        try:
            from langchain_openai import ChatOpenAI
        except ImportError:
            raise ImportError(
                "langchain-openai is required for custom endpoints. "
                "Install with: pip install langchain-openai"
            )
        kwargs: dict = {"model": model_name, "base_url": base_url}
        if api_key:
            kwargs["api_key"] = api_key
        else:
            # Some local servers don't need a key; set a dummy to avoid errors
            kwargs["api_key"] = "not-needed"
        return ChatOpenAI(**kwargs)

    from langchain_anthropic import ChatAnthropic
    kwargs = {"model": model_name}
    if api_key:
        kwargs["api_key"] = api_key
    return ChatAnthropic(**kwargs)


def create_agent(model_name: str = "claude-sonnet-4-6", custom_tools: list = None,
                  session_id: str = None, base_url: str = None, api_key: str = None):
    """Create and compile a LangGraph agent for the network-pentest workflow.

    Thin wrapper around build_react_graph() that supplies the pentest defaults:
    - All built-in pentest tools via get_all_tools() + runtime custom tools
    - build_system_prompt for the system prompt
    - The default scanner state-update map and knowledge-graph populator
    - AgentState as the state schema

    Args:
        model_name: Model name / identifier.
        custom_tools: Additional tool functions to include.
        session_id: Optional session ID for audit logging.
        base_url: Optional OpenAI-compatible API base URL
                  (for vLLM, Ollama, MLX, OpenRouter, etc.).
        api_key: Optional API key for the endpoint.

    Returns:
        Compiled StateGraph with MemorySaver checkpointer.
    """
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
