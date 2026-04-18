from __future__ import annotations

import ast
import asyncio
import json
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import networkx as nx

from clearwing.capabilities import capabilities
from clearwing.core.events import EventBus, EventType
from clearwing.data.knowledge import KnowledgeGraph
from clearwing.data.memory import ContextSummarizer, EpisodicMemory
from clearwing.llm.chat import BaseMessage, SystemMessage, ToolMessage, extract_text_content
from clearwing.llm.native import strip_think_tags
from clearwing.observability.telemetry import CostTracker
from clearwing.safety.audit import AuditLogger
from clearwing.safety.guardrails import InputGuardrail, OutputGuardrail

from .tooling import AgentTool, InterruptRequest, tool_execution_context

logger = logging.getLogger(__name__)


FLAG_PATTERNS = [
    re.compile(r"flag\{[^}]+\}", re.IGNORECASE),
    re.compile(r"FLAG\{[^}]+\}"),
    re.compile(r"HTB\{[^}]+\}"),
    re.compile(r"CTF\{[^}]+\}"),
    re.compile(r"[A-Fa-f0-9]{32}"),
]


def detect_flags(text: str) -> list[dict[str, str]]:
    flags = []
    for pattern in FLAG_PATTERNS:
        for match in pattern.finditer(text):
            flags.append({"flag": match.group(), "pattern": pattern.pattern})
    return flags


def _parse_tool_output(content: str) -> Any:
    try:
        return json.loads(content)
    except Exception:
        try:
            return ast.literal_eval(content)
        except Exception:
            return content


@dataclass(slots=True)
class Command:
    resume: bool


@dataclass(slots=True)
class GraphInterrupt:
    value: str


@dataclass(slots=True)
class GraphTask:
    interrupts: list[GraphInterrupt] = field(default_factory=list)


@dataclass(slots=True)
class GraphStateSnapshot:
    values: dict[str, Any]
    next: tuple[str, ...] = ()
    tasks: list[GraphTask] = field(default_factory=list)


@dataclass(slots=True)
class _PendingToolResume:
    tool_calls: list[dict[str, Any]]
    prompt: str


class NativeAgentGraph:
    def __init__(
        self,
        *,
        llm_with_tools: Any,
        tools: list[AgentTool],
        system_prompt_fn: Callable[[dict[str, Any]], str],
        model_name: str,
        session_id: str | None,
        state_updater_fn: Callable[[str, Any, dict[str, Any]], dict[str, Any]],
        knowledge_graph_populator_fn: Callable[[Any, str, str, dict[str, Any]], dict[str, Any]]
        | None,
        input_guardrail_tool_names: set[str] | frozenset[str],
        output_guardrail_tool_names: set[str] | frozenset[str],
        enable_cost_tracker: bool,
        enable_episodic_memory: bool,
        enable_audit: bool,
        enable_knowledge_graph: bool,
        enable_input_guardrail: bool,
        enable_output_guardrail: bool,
        enable_event_bus: bool,
        enable_context_summarizer: bool,
    ) -> None:
        self.llm_with_tools = llm_with_tools
        self.tools = {tool.name: tool for tool in tools}
        self.system_prompt_fn = system_prompt_fn
        self.model_name = model_name
        self.state_updater_fn = state_updater_fn
        self.knowledge_graph_populator_fn = knowledge_graph_populator_fn
        self.input_guardrail_tool_names = set(input_guardrail_tool_names)
        self.output_guardrail_tool_names = set(output_guardrail_tool_names)
        self.on_text_delta: Any = None  # optional streaming callback
        self._state: dict[str, dict[str, Any]] = {}
        self._pending: dict[str, _PendingToolResume | None] = {}

        self.cost_tracker = (
            CostTracker() if enable_cost_tracker and capabilities.has("telemetry") else None
        )
        self.episodic_memory = (
            EpisodicMemory() if enable_episodic_memory and capabilities.has("memory") else None
        )
        self.context_summarizer = (
            ContextSummarizer()
            if enable_context_summarizer and capabilities.has("memory")
            else None
        )
        self.event_bus = EventBus() if enable_event_bus and capabilities.has("events") else None
        self.input_guardrail = (
            InputGuardrail() if enable_input_guardrail and capabilities.has("guardrails") else None
        )
        self.output_guardrail = (
            OutputGuardrail()
            if enable_output_guardrail and capabilities.has("guardrails")
            else None
        )
        self.audit_logger = None
        if enable_audit and capabilities.has("audit") and session_id:
            try:
                self.audit_logger = AuditLogger(session_id)
            except Exception:
                logger.warning("Failed to initialize AuditLogger", exc_info=True)

        self.knowledge_graph = None
        if enable_knowledge_graph and capabilities.has("knowledge"):
            try:
                self.knowledge_graph = KnowledgeGraph(
                    persist_path="~/.clearwing/knowledge_graph.json"
                )
            except Exception:
                logger.warning("Failed to initialize KnowledgeGraph", exc_info=True)

    async def astream(
        self, input_data: dict[str, Any] | Command, config: dict, stream_mode: str = "values"
    ):
        del stream_mode
        thread_id = self._thread_id(config)
        if isinstance(input_data, Command):
            async for event in self._aresume(thread_id, input_data.resume):
                yield event
            return

        state = self._get_or_create_state(thread_id)
        self._merge_input(state, input_data)
        async for event in self._arun_loop(thread_id):
            yield event

    async def ainvoke(
        self, input_data: dict[str, Any] | Command, config: dict
    ) -> GraphStateSnapshot:
        async for _ in self.astream(input_data, config):
            pass
        return self.get_state(config)

    def get_state(self, config: dict) -> GraphStateSnapshot:
        thread_id = self._thread_id(config)
        state = self._get_or_create_state(thread_id)
        pending = self._pending.get(thread_id)
        if pending is None:
            return GraphStateSnapshot(values=state, next=(), tasks=[])
        return GraphStateSnapshot(
            values=state,
            next=("tools",),
            tasks=[GraphTask(interrupts=[GraphInterrupt(value=pending.prompt)])],
        )

    async def _aresume(self, thread_id: str, approved: bool):
        pending = self._pending.get(thread_id)
        if pending is None:
            return
        self._pending[thread_id] = None
        state = self._get_or_create_state(thread_id)
        tool_events, paused = await self._arun_tool_calls(
            state, pending.tool_calls, resume_decision=approved
        )
        for event in tool_events:
            yield event
        if paused:
            return
        async for event in self._arun_loop(thread_id):
            yield event

    async def _arun_loop(self, thread_id: str):
        state = self._get_or_create_state(thread_id)
        while True:
            assistant_event = await self._aassistant_step(state)
            yield assistant_event
            last = state["messages"][-1]
            tool_calls = getattr(last, "tool_calls", []) or []
            if not tool_calls:
                break
            tool_events, paused = await self._arun_tool_calls(
                state, tool_calls, resume_decision=Ellipsis
            )
            for event in tool_events:
                yield event
            if paused:
                break

    async def _aassistant_step(self, state: dict[str, Any]) -> dict[str, Any]:
        messages = list(state.get("messages", []))
        if self.context_summarizer and self.context_summarizer.should_summarize(messages):
            try:
                messages = await self.context_summarizer.summarize(messages, self.llm_with_tools)
            except Exception:
                logger.debug("Context summarization failed", exc_info=True)

        sys_prompt = self.system_prompt_fn(state)
        full_messages: list[BaseMessage] = [SystemMessage(content=sys_prompt), *messages]
        response = await self.llm_with_tools.ainvoke(
            full_messages, on_text_delta=self.on_text_delta
        )
        state.setdefault("messages", []).append(response)

        usage = getattr(response, "response_metadata", {}).get("usage", {})
        if self.cost_tracker and usage:
            input_tokens = usage.get("input_tokens", 0)
            output_tokens = usage.get("output_tokens", 0)
            self.cost_tracker.record_llm_call(input_tokens, output_tokens, self.model_name)
            state["total_cost_usd"] = self.cost_tracker.total_cost_usd
            state["total_tokens"] = self.cost_tracker.input_tokens + self.cost_tracker.output_tokens
            if self.audit_logger:
                self.audit_logger.log_llm_call(
                    model=self.model_name,
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    cost_usd=self.cost_tracker.total_cost_usd,
                )

        if self.event_bus:
            self.event_bus.emit_message(strip_think_tags(response.text)[:200], "agent")

        response_text = extract_text_content(response.content)
        if response_text:
            found_flags = detect_flags(response_text)
            if found_flags:
                existing_flags = list(state.get("flags_found", []))
                state["flags_found"] = existing_flags + found_flags
                if self.event_bus:
                    for found in found_flags:
                        self.event_bus.emit_flag(found["flag"], "LLM response")

        return dict(state)

    async def _arun_tool_calls(
        self,
        state: dict[str, Any],
        tool_calls: list[dict[str, Any]],
        *,
        resume_decision: object,
    ) -> tuple[list[dict[str, Any]], bool]:
        events: list[dict[str, Any]] = []
        result_messages: list[BaseMessage] = []
        new_flags: list[dict[str, str]] = []

        for index, tool_call in enumerate(tool_calls):
            tool_name = str(tool_call.get("name", ""))
            tool_args = tool_call.get("args", {}) or {}
            if self.event_bus:
                self.event_bus.emit(EventType.TOOL_START, {"tool": tool_name, "args": tool_args})

            if self.output_guardrail and tool_name in self.output_guardrail_tool_names:
                command = tool_args.get("command", "")
                result = self.output_guardrail.check_command(command)
                if not result.passed and self.event_bus:
                    self.event_bus.emit_message(f"Guardrail blocked: {result.reason}", "warning")

            tool = self.tools.get(tool_name)
            if tool is None:
                content = json.dumps({"error": f"unknown tool: {tool_name}"})
            else:
                try:
                    content = await self._ainvoke_tool(tool, tool_args, resume_decision)
                except InterruptRequest as exc:
                    self._pending[self._find_thread_id_for_state(state)] = _PendingToolResume(
                        tool_calls=tool_calls[index:],
                        prompt=exc.prompt,
                    )
                    return events, True
                except Exception as exc:
                    content = json.dumps({"error": str(exc)})

            if not isinstance(content, str):
                content = json.dumps(content)

            message = ToolMessage(
                content=content,
                name=tool_name,
                tool_call_id=tool_call.get("id"),
            )
            result_messages.append(message)

            if self.input_guardrail and tool_name in self.input_guardrail_tool_names:
                gr = self.input_guardrail.check(content)
                if not gr.passed and self.event_bus:
                    self.event_bus.emit_message(f"Input guardrail warning: {gr.reason}", "warning")

            if self.episodic_memory:
                target = state.get("target") or "unknown"
                self.episodic_memory.record(
                    target=target,
                    event_type=f"tool:{tool_name}",
                    content=content[:500],
                )

            if self.cost_tracker:
                self.cost_tracker.record_tool_call(tool_name, 0)

            if self.audit_logger:
                self.audit_logger.log_tool_call(
                    tool_name=tool_name, args=tool_args, result=content[:2000]
                )

            if self.knowledge_graph and self.knowledge_graph_populator_fn:
                graph_data = self.knowledge_graph_populator_fn(
                    self.knowledge_graph,
                    tool_name,
                    content,
                    state,
                )
                if graph_data:
                    state["graph_data"] = graph_data

            data = _parse_tool_output(content)
            extra_updates = self.state_updater_fn(tool_name, data, state) or {}
            for key, value in extra_updates.items():
                state[key] = value

            found_flags = detect_flags(content)
            if found_flags:
                new_flags.extend(found_flags)

            if self.event_bus:
                self.event_bus.emit(
                    EventType.TOOL_RESULT,
                    {
                        "tool": tool_name,
                        "content_length": len(content),
                        "flags_found": len(found_flags),
                    },
                )

        state.setdefault("messages", []).extend(result_messages)
        if new_flags:
            existing_flags = list(state.get("flags_found", []))
            state["flags_found"] = existing_flags + new_flags
            if self.event_bus:
                self.event_bus.emit(EventType.FLAG_FOUND, {"flags": new_flags})

        events.append(dict(state))
        return events, False

    async def _ainvoke_tool(
        self, tool: AgentTool, arguments: dict[str, Any], resume_decision: object
    ) -> Any:
        with tool_execution_context(resume_decision=resume_decision):
            if asyncio.iscoroutinefunction(tool.func):
                return await tool.func(**arguments)
            return await asyncio.to_thread(tool.func, **arguments)

    def _merge_input(self, state: dict[str, Any], input_data: dict[str, Any]) -> None:
        for key, value in input_data.items():
            if key == "messages":
                state.setdefault("messages", []).extend(value)
            else:
                state[key] = value

    def _get_or_create_state(self, thread_id: str) -> dict[str, Any]:
        return self._state.setdefault(thread_id, {"messages": []})

    def _thread_id(self, config: dict) -> str:
        return config.get("configurable", {}).get("thread_id", "default")

    def _find_thread_id_for_state(self, state: dict[str, Any]) -> str:
        for thread_id, existing_state in self._state.items():
            if existing_state is state:
                return thread_id
        raise KeyError("state not registered")


def populate_knowledge_graph(kg, tool_name: str, content: str, state: dict) -> dict:
    target = state.get("target", "")
    if not target:
        return {}

    try:
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
