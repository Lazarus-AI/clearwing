"""Operator agent — autonomous wrapper around the ReAct pentest loop.

The Operator accepts a set of user-provided goals, drives the inner ReAct
agent to completion, and only escalates to the real user when:
  1. All goals are completed.
  2. The inner agent asks a question the Operator cannot answer from its
     goals, context, or general knowledge.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field

from clearwing.agent.attack_chain import AttackChain, AttackTechnique, default_chain, infer_technique
from clearwing.agent.graph import _create_llm, create_agent
from clearwing.agent.runtime import Command

logger = logging.getLogger(__name__)

_FATAL_PATTERNS = (
    "401",
    "403",
    "404",
    "Unauthorized",
    "authentication_error",
    "invalid x-api-key",
    "invalid api key",
    "model_not_found",
    "does not exist",
    "key not allowed to access model",
    "key_model_access_denied",
)


def _is_fatal_llm_error(err: str) -> bool:
    """Return True if the error indicates a non-recoverable LLM config issue."""
    err_lower = err.lower()
    return any(p.lower() in err_lower for p in _FATAL_PATTERNS)


class LLMFatalError(RuntimeError):
    """Raised when the LLM backend has a non-recoverable configuration error."""


_REFUSAL_PATTERNS = (
    "i can't help",
    "i cannot help",
    "i'm not able to",
    "i am not able to",
    "i can't provide",
    "i cannot provide",
    "i can't assist with",
    "i cannot assist with",
    "i'm unable to",
    "i won't help",
    "i will not help",
    "against my guidelines",
    "violates my",
    "not something i can",
    "i can't write exploit",
    "i can't generate exploit",
    "i must decline",
    "as an ai",
)


def _is_model_refusal(response: str) -> bool:
    """Detect if the model refused to perform a security task."""
    if not response:
        return False
    first_500 = response[:500].lower()
    return any(p in first_500 for p in _REFUSAL_PATTERNS)


@dataclass
class OperatorConfig:
    """Configuration for the Operator agent."""

    # Required
    goals: list[str]
    target: str

    # Model settings
    model: str = "claude-sonnet-4-6"
    operator_model: str = ""  # model for the operator LLM; defaults to self.model
    base_url: str | None = None
    api_key: str | None = None

    # Behaviour
    max_turns: int = 100  # max inner-agent turns before force-stop
    timeout_minutes: int = 60
    cost_limit: float = 0.0  # 0 = no limit
    auto_approve_scans: bool = True  # auto-approve non-destructive scan tools
    auto_approve_exploits: bool = False  # require user for exploit approval
    lhost: str = "host.docker.internal"  # callback listener address reachable from target
    lport: int = 9999  # callback listener port

    # Callbacks
    on_message: Callable[[str, str], None] | None = None  # (role, content)
    on_tool_result: Callable[[str, str], None] | None = None  # (tool_name, content)
    on_escalate: Callable[[str], str] | None = None  # question -> user answer
    on_complete: Callable[[OperatorResult], None] | None = None
    on_technique: Callable[[AttackTechnique], None] | None = None  # ATT&CK chain updates


@dataclass
class OperatorResult:
    """Result of an Operator-driven session."""

    goals: list[str]
    target: str
    status: str  # completed, escalated, timeout, error, cost_limit
    turns: int = 0
    findings: list[dict] = field(default_factory=list)
    flags_found: list[dict] = field(default_factory=list)
    cost_usd: float = 0.0
    tokens_used: int = 0
    duration_seconds: float = 0.0
    escalation_question: str = ""  # non-empty if status == "escalated"
    error: str = ""
    conversation_summary: str = ""
    attack_chain: list[dict] = field(default_factory=list)  # ATT&CK technique summary


# Categories of questions the operator can answer autonomously
_OPERATOR_SYSTEM_PROMPT = """\
You are the Operator, an autonomous supervisor driving a penetration testing \
agent. You have been given a set of goals by the user and your job is to \
drive the inner agent to accomplish them.

## Your goals
{goals}

## Target
{target}

## Rules
1. When the inner agent produces output, decide what instruction to give it next.
2. If the agent asks a question you can answer from the goals, context, or \
   general pentesting knowledge, answer it directly.
3. If the agent asks something only the real user can answer (credentials, \
   scope clarifications, legal authorization details, custom environment info), \
   respond EXACTLY with: ESCALATE: <the question to ask the user>
4. If all goals appear to be accomplished, respond EXACTLY with: GOALS_COMPLETE
5. Keep your instructions concise and actionable.
6. Do NOT repeat instructions the agent has already completed.
7. Track progress — if the agent gets stuck or loops, try a different approach.
8. When approving exploits, use your judgment based on the goals. If the goals \
   say "exploit" or "gain access", approve exploitation. If the goals only \
   mention scanning/assessment, do not approve exploitation.

## Current progress
{progress}
"""


class OperatorAgent:
    """Autonomous operator that drives the ReAct agent loop.

    Usage::

        config = OperatorConfig(
            goals=["Scan for open ports", "Find vulnerabilities", "Generate report"],
            target="10.0.0.1",
        )
        operator = OperatorAgent(config)
        result = operator.run()
    """

    # Max consecutive turns where the agent produces text but calls no tools
    _MAX_STALL_TURNS = 3

    def __init__(self, config: OperatorConfig):
        self.config = config
        self._turns = 0
        self._progress: list[str] = []
        self._escalated = False
        self._consecutive_stalls = 0
        self.attack_chain = default_chain()

    def run(self) -> OperatorResult:
        """Run the operator loop to completion (sync wrapper over :meth:`arun`)."""
        return asyncio.run(self.arun())

    async def arun(self) -> OperatorResult:
        """Run the operator loop to completion."""
        start = time.time()
        session_id = uuid.uuid4().hex[:8]

        # Create inner agent
        graph = create_agent(
            model_name=self.config.model,
            session_id=session_id,
            base_url=self.config.base_url,
            api_key=self.config.api_key,
        )
        config = {"configurable": {"thread_id": f"operator-{session_id}"}}

        # Create operator LLM for decision-making
        op_model = self.config.operator_model or self.config.model
        operator_llm = _create_llm(
            op_model,
            base_url=self.config.base_url,
            api_key=self.config.api_key,
        )

        # Build initial goal message
        goal_text = self._format_goals()
        initial_input = {
            "messages": [{"role": "user", "content": goal_text}],
            "target": self.config.target,
            "open_ports": [],
            "services": [],
            "vulnerabilities": [],
            "exploit_results": [],
            "os_info": None,
            "kali_container_id": None,
            "custom_tool_names": [],
            "session_id": session_id,
            "flags_found": [],
            "loaded_skills": [],
            "paused": False,
            "total_cost_usd": 0.0,
            "total_tokens": 0,
        }

        deadline = start + self.config.timeout_minutes * 60
        input_msg = initial_input
        self._consecutive_errors = 0

        try:
            while self._turns < self.config.max_turns:
                # Check timeout
                if time.time() > deadline:
                    return self._build_result(
                        graph,
                        config,
                        start,
                        "timeout",
                        error=f"Timed out after {self.config.timeout_minutes} minutes",
                    )

                # Check cost limit
                if self.config.cost_limit > 0:
                    state = graph.get_state(config)
                    sv = state.values if hasattr(state, "values") else {}
                    if sv.get("total_cost_usd", 0) >= self.config.cost_limit:
                        return self._build_result(
                            graph,
                            config,
                            start,
                            "cost_limit",
                            error="Cost limit reached",
                        )

                # Run one turn of the inner agent
                self._turns += 1
                logger.debug(
                    "━━━ Turn %d/%d | cost=$%.4f | stalls=%d | elapsed=%.0fs ━━━",
                    self._turns, self.config.max_turns,
                    (graph.get_state(config).values or {}).get("total_cost_usd", 0)
                    if self.config.cost_limit > 0 else 0,
                    self._consecutive_stalls,
                    time.time() - start,
                )
                agent_response, tool_called = await self._arun_inner_turn(graph, config, input_msg)

                if not agent_response:
                    # Agent produced no output — might be done
                    break

                self._emit("agent", agent_response)
                self._progress.append(f"Turn {self._turns}: {agent_response[:200]}")

                # Detect stall: agent produces text but never calls tools
                if tool_called:
                    self._consecutive_stalls = 0
                else:
                    self._consecutive_stalls += 1
                    if self._consecutive_stalls >= self._MAX_STALL_TURNS:
                        return self._build_result(
                            graph, config, start, "error",
                            error=f"STALLED: Agent produced {self._consecutive_stalls} "
                            f"consecutive responses without calling any tools. "
                            f"The model may not support tool-calling or is stuck "
                            f"planning without executing. "
                            f"Last response: {agent_response[:200]}",
                        )

                # Detect model refusals (model won't do security tasks)
                if _is_model_refusal(agent_response):
                    self._consecutive_refusals = getattr(self, "_consecutive_refusals", 0) + 1
                    if self._consecutive_refusals >= 2:
                        return self._build_result(
                            graph, config, start, "error",
                            error=f"MODEL REFUSED: The model declined to perform "
                            f"exploitation tasks ({self._consecutive_refusals} consecutive "
                            f"refusals). Use a model with security research permissions. "
                            f"Last response: {agent_response[:200]}",
                        )
                else:
                    self._consecutive_refusals = 0

                # Handle interrupts (approval requests)
                state = graph.get_state(config)
                if state.next:
                    handled = await self._ahandle_interrupt(state, graph, config)
                    if not handled:
                        # Needs user escalation for approval
                        return self._build_result(
                            graph,
                            config,
                            start,
                            "escalated",
                            escalation_question="Exploit approval required — "
                            "please review and re-run with auto_approve_exploits=True "
                            "if authorized.",
                        )
                    continue

                # Ask the operator LLM what to do next
                decision = await self._adecide_next(operator_llm, agent_response)
                logger.debug("[turn %d] operator decision: %s", self._turns, decision[:300])

                if decision.startswith("GOALS_COMPLETE"):
                    logger.info("Operator declared GOALS_COMPLETE at turn %d", self._turns)
                    return self._build_result(graph, config, start, "completed")

                if decision.startswith("ESCALATE:"):
                    question = decision[len("ESCALATE:") :].strip()
                    # Try the callback first
                    if self.config.on_escalate:
                        answer = self.config.on_escalate(question)
                        if answer:
                            input_msg = {"messages": [{"role": "user", "content": answer}]}
                            continue

                    return self._build_result(
                        graph,
                        config,
                        start,
                        "escalated",
                        escalation_question=question,
                    )

                # Feed the operator's decision back as a HumanMessage
                self._emit("operator", decision)
                input_msg = {"messages": [{"role": "user", "content": decision}]}

            # Exhausted max turns
            return self._build_result(
                graph,
                config,
                start,
                "completed",
                error=f"Reached max turns ({self.config.max_turns})",
            )

        except KeyboardInterrupt:
            return self._build_result(graph, config, start, "error", error="Interrupted by user")
        except LLMFatalError as e:
            return self._build_result(
                graph, config, start, "error",
                error=f"FATAL LLM error (check model/key config): {e}",
            )
        except Exception as e:
            return self._build_result(graph, config, start, "error", error=str(e))

    def _format_goals(self) -> str:
        """Format goals into the initial instruction for the inner agent."""
        goal_lines = "\n".join(f"  {i + 1}. {g}" for i, g in enumerate(self.config.goals))
        approval_note = ""
        if self.config.auto_approve_exploits:
            approval_note = (
                "\n\nIMPORTANT: You have FULL AUTHORIZATION to run exploits without "
                "asking for permission. Do NOT ask for approval — execute immediately. "
                "All exploit actions are pre-approved by the operator."
            )
        network_note = (
            f"\n\nNETWORK: The target can reach the operator at "
            f"LHOST={self.config.lhost} LPORT={self.config.lport}. "
            f"Use this address for any callbacks, reverse shells, or exfiltration. "
            f"Do NOT use 127.0.0.1 — that resolves to the target itself."
        )
        return (
            f"TARGET: {self.config.target}\n\n"
            f"You are being operated autonomously. Complete the following goals:\n"
            f"{goal_lines}\n\n"
            f"Work through these goals systematically. Report your findings as you go. "
            f"If you need information you cannot obtain yourself, ask clearly."
            f"{approval_note}"
            f"{network_note}"
        )

    async def _arun_inner_turn(self, graph, config: dict, input_msg: dict) -> tuple[str, bool]:
        """Run one turn of the inner ReAct agent and extract its response text.

        Returns (response_text, tool_called) — tool_called is True if any tool
        was invoked during this turn.
        """
        last_ai_content = ""
        tool_called = False
        tools_invoked: list[str] = []
        tool_calls_with_args: list[tuple[str, dict]] = []  # (name, args) for technique inference
        try:
            async for event in graph.astream(input_msg, config, stream_mode="values"):
                msgs = event.get("messages", [])
                if msgs:
                    last = msgs[-1]
                    if hasattr(last, "type") and last.type == "tool":
                        tool_called = True
                        tool_name = getattr(last, "name", None) or "unknown"
                        tool_content = str(getattr(last, "content", ""))
                        tools_invoked.append(tool_name)
                        logger.debug(
                            "[turn %d] tool result: %s → %s",
                            self._turns, tool_name, tool_content[:200],
                        )
                        if self.config.on_tool_result:
                            try:
                                self.config.on_tool_result(tool_name, tool_content)
                            except Exception:
                                pass
                    if hasattr(last, "content") and last.type == "ai":
                        # Check for tool_calls on the AI message itself
                        if getattr(last, "tool_calls", None):
                            tool_called = True
                            for tc in last.tool_calls:
                                if isinstance(tc, dict):
                                    tc_name = tc.get("name", "unknown")
                                    tc_args = tc.get("args", {})
                                else:
                                    tc_name = getattr(tc, "name", "unknown")
                                    tc_args = getattr(tc, "args", {})
                                tools_invoked.append(tc_name)
                                tool_calls_with_args.append((tc_name, tc_args if isinstance(tc_args, dict) else {}))
                                logger.debug("[turn %d] tool call: %s", self._turns, tc_name)
                        content = last.content
                        if isinstance(content, list):
                            text_parts = [
                                c["text"]
                                for c in content
                                if isinstance(c, dict) and c.get("type") == "text"
                            ]
                            content = "\n".join(text_parts)
                        if content:
                            last_ai_content = content
        except Exception as e:
            logger.warning("Inner agent error: %s", e)
            err_str = str(e)
            if _is_fatal_llm_error(err_str):
                raise LLMFatalError(err_str) from e
            self._consecutive_errors += 1
            if self._consecutive_errors >= 3:
                raise LLMFatalError(
                    f"3 consecutive LLM errors, aborting. Last: {err_str}"
                ) from e
            last_ai_content = f"[Agent error: {e}]"

        if not last_ai_content.startswith("[Agent error:"):
            self._consecutive_errors = 0

        # Infer ATT&CK techniques from tool invocations
        for tc_name, tc_args in tool_calls_with_args:
            technique_id = infer_technique(tc_name, tc_args)
            if technique_id:
                evidence = f"{tc_name}({', '.join(f'{k}=...' for k in list(tc_args)[:3])})"
                tech = self.attack_chain.advance(technique_id, "completed", evidence=evidence)
                if tech and self.config.on_technique:
                    try:
                        self.config.on_technique(tech)
                    except Exception:
                        logger.debug("on_technique callback failed", exc_info=True)

        logger.debug(
            "[turn %d] summary: tools_called=%s, tools=%s, response=%s",
            self._turns,
            tool_called,
            tools_invoked or "(none)",
            last_ai_content[:150],
        )
        return last_ai_content, tool_called

    async def _ahandle_interrupt(self, state, graph, config: dict) -> bool:
        """Handle an interrupt (approval request) from the inner agent.

        Returns True if handled, False if needs user escalation.
        """
        tasks = getattr(state, "tasks", None)
        if not tasks:
            return True

        for task in tasks:
            interrupts = getattr(task, "interrupts", None)
            if not interrupts:
                continue
            for intr in interrupts:
                prompt = str(intr.value)
                self._emit("approval", prompt)

                # Decide whether to auto-approve
                is_scan = any(
                    kw in prompt.lower()
                    for kw in ["scan", "detect", "enumerate", "fingerprint", "nmap"]
                )
                if is_scan and self.config.auto_approve_scans:
                    await graph.ainvoke(Command(resume=True), config)
                    self._progress.append(f"Auto-approved scan: {prompt[:100]}")
                    return True

                if self.config.auto_approve_exploits:
                    await graph.ainvoke(Command(resume=True), config)
                    self._progress.append(f"Auto-approved exploit: {prompt[:100]}")
                    return True

                # Cannot auto-approve — need user
                return False

        return True

    async def _adecide_next(self, operator_llm, agent_response: str) -> str:
        """Ask the operator LLM what instruction to give the inner agent next."""
        progress_text = "\n".join(self._progress[-20:]) if self._progress else "No progress yet."
        goals_text = "\n".join(f"  {i + 1}. {g}" for i, g in enumerate(self.config.goals))

        system = _OPERATOR_SYSTEM_PROMPT.format(
            goals=goals_text,
            target=self.config.target,
            progress=progress_text,
        )

        user = (
            f"The inner agent just responded:\n\n{agent_response[:3000]}\n\n"
            f"What should I tell the agent to do next? "
            f"Reply with GOALS_COMPLETE if all goals are done, "
            f"ESCALATE: <question> if you need to ask the real user, "
            f"or give the next instruction."
        )

        try:
            # Native LLM surface: `aask_text` returns a genai ``ChatResponse``.
            # Works against both today's ``ChatModel`` (delegates to its client)
            # and a bare ``AsyncLLMClient`` once operator wiring is repointed.
            from clearwing.llm.native import response_text

            response = await operator_llm.aask_text(system=system, user=user)
            return response_text(response).strip()
        except Exception as e:
            logger.error("Operator LLM error: %s", e)
            err_str = str(e)
            if _is_fatal_llm_error(err_str):
                raise LLMFatalError(err_str) from e
            return "Continue with the next goal."

    def _build_result(
        self,
        graph,
        config: dict,
        start: float,
        status: str,
        error: str = "",
        escalation_question: str = "",
    ) -> OperatorResult:
        """Build the final OperatorResult from the current state."""
        state = graph.get_state(config)
        sv = state.values if hasattr(state, "values") else {}

        result = OperatorResult(
            goals=self.config.goals,
            target=self.config.target,
            status=status,
            turns=self._turns,
            findings=sv.get("vulnerabilities", [])
            + [
                {
                    "description": f"Exploitable: {e.get('vulnerability', '?')}",
                    "severity": "critical",
                }
                for e in sv.get("exploit_results", [])
                if e.get("success")
            ],
            flags_found=sv.get("flags_found", []),
            cost_usd=sv.get("total_cost_usd", 0.0),
            tokens_used=sv.get("total_tokens", 0),
            duration_seconds=round(time.time() - start, 2),
            escalation_question=escalation_question,
            error=error,
            conversation_summary="\n".join(self._progress[-30:]),
            attack_chain=self.attack_chain.summary(),
        )

        if self.config.on_complete:
            try:
                self.config.on_complete(result)
            except Exception:
                logger.debug("on_complete callback failed", exc_info=True)

        return result

    def _emit(self, role: str, content: str) -> None:
        """Emit a message via the callback if configured."""
        if self.config.on_message:
            try:
                self.config.on_message(role, content)
            except Exception:
                logger.debug("on_message callback failed", exc_info=True)
