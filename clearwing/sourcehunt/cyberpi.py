"""CyberPi anti-corruption adapter for Sourcehunt discovery."""

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from clearwing.llm import AsyncLLMClient, ChatMessage, NativeToolSpec
from clearwing.llm.budget import BudgetReservation, current_spend_metadata

from .hunt_engine import HuntAssignment, HuntOutcome
from .hunter import HunterTrajectoryLogger

logger = logging.getLogger(__name__)

_PROTOCOL_VERSION = 1
_MAX_MESSAGE_BYTES = 10 * 1024 * 1024
_ALLOWED_TOOLS = frozenset(
    {"execute", "read_file", "write_file", "record_trace_step", "record_finding"}
)


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


class CyberPiError(RuntimeError):
    """Raised when the CyberPi sidecar violates its protocol or cannot run."""


@dataclass(frozen=True, slots=True)
class CyberPiModel:
    provider: str
    model: str
    api: str
    base_url: str
    api_key: str
    reasoning: bool
    cost: dict[str, float]


class CyberPiHuntEngine:
    """Run Pi with only Clearwing-owned tools and state transitions."""

    def __init__(
        self,
        build_hunter: Callable[[HuntAssignment, Any], Any],
        *,
        command: Sequence[str] | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self._build_hunter = build_hunter
        self._command = tuple(command) if command is not None else self.default_command()
        self._environ = dict(environ) if environ is not None else None

    @staticmethod
    def default_command() -> tuple[str, ...]:
        from .cyberpi_runtime import CyberPiRuntime

        return CyberPiRuntime().command()

    async def hunt(self, assignment: HuntAssignment, sandbox: Any) -> HuntOutcome:
        if sandbox is None:
            raise CyberPiError("CyberPi requires an isolated Sourcehunt sandbox")

        native_hunter, context = self._build_hunter(assignment, sandbox)
        process: asyncio.subprocess.Process | None = None
        active_reservations: dict[str, BudgetReservation] = {}
        active_calls: set[str] = set()
        stderr_task: asyncio.Task[None] | None = None
        trajectory: HunterTrajectoryLogger | None = None
        trajectory_finished = False
        runtime_dir = tempfile.TemporaryDirectory(prefix="clearwing-cyberpi-")
        try:
            model = self._model_from_client(native_hunter.llm)
            tools = [tool for tool in native_hunter.tools if tool.name in _ALLOWED_TOOLS]
            missing_tools = {"execute", "read_file", "record_trace_step", "record_finding"} - {
                tool.name for tool in tools
            }
            if missing_tools:
                raise CyberPiError(
                    "CyberPi requires Clearwing's deep hunt tools; missing "
                    + ", ".join(sorted(missing_tools))
                )
            trajectory = HunterTrajectoryLogger.for_hunter(
                context,
                prompt=native_hunter.prompt,
                initial_messages=[
                    ChatMessage("user", self._initial_user_message(native_hunter, assignment))
                ],
                tools=tools,
                engine="cyberpi",
            )
            process = await self._start_process(model.api_key, cwd=runtime_dir.name)
            assert process.stdin is not None
            assert process.stdout is not None
            assert process.stderr is not None
            stderr_task = asyncio.create_task(self._drain_stderr(process.stderr))

            await self._write_message(
                process.stdin,
                {
                    "type": "start",
                    "protocol": _PROTOCOL_VERSION,
                    "assignment": {
                        "session_id": assignment.session_id,
                        "target": assignment.file_target.get("path", ""),
                        "work_item_id": assignment.work_item_id,
                        "budget_usd": assignment.budget_usd,
                    },
                    "model": {
                        "provider": model.provider,
                        "id": model.model,
                        "api": model.api,
                        "base_url": model.base_url,
                        "reasoning": model.reasoning,
                        "thinking_level": "max",
                        "temperature": 1.0,
                        "top_p": 0.95,
                        "cost": model.cost,
                        "max_output_tokens": self._max_output_tokens(native_hunter),
                    },
                    "system_prompt": native_hunter.prompt,
                    "user_message": self._initial_user_message(native_hunter, assignment),
                    "max_turns": native_hunter.max_steps,
                    "tools": [self._serialize_tool(tool) for tool in tools],
                },
            )
            outcome = await self._run_protocol(
                assignment=assignment,
                native_hunter=native_hunter,
                context=context,
                tools=tools,
                process=process,
                active_reservations=active_reservations,
                active_calls=active_calls,
                trajectory=trajectory,
            )
            trajectory_finished = True

            try:
                process.stdin.close()
                await process.stdin.wait_closed()
            except (BrokenPipeError, ConnectionResetError):
                pass
            return_code = await process.wait()
            await stderr_task
            stderr_task = None
            if return_code != 0:
                raise CyberPiError(self._process_error(return_code))
            return outcome
        except BaseException as exc:
            self._fail_active_reservations(native_hunter.llm, active_reservations, exc)
            if trajectory is not None and not trajectory_finished:
                trajectory.log(
                    "finish",
                    {
                        "step": 0,
                        "status": "error",
                        "error_type": type(exc).__name__,
                        "findings": [
                            self._serialize_finding(finding) for finding in context.findings
                        ],
                    },
                )
            raise
        finally:
            if process is not None and process.returncode is None:
                process.kill()
                await process.wait()
            if stderr_task is not None:
                stderr_task.cancel()
                await asyncio.gather(stderr_task, return_exceptions=True)
            active_calls.clear()
            try:
                context.cleanup_variants()
            except Exception:
                logger.debug("Variant sandbox cleanup failed", exc_info=True)
            runtime_dir.cleanup()

    async def _run_protocol(
        self,
        *,
        assignment: HuntAssignment,
        native_hunter: Any,
        context: Any,
        tools: list[NativeToolSpec],
        process: asyncio.subprocess.Process,
        active_reservations: dict[str, BudgetReservation],
        active_calls: set[str],
        trajectory: HunterTrajectoryLogger,
    ) -> HuntOutcome:
        assert process.stdin is not None
        assert process.stdout is not None

        usage = self._empty_usage()
        step = 0
        while True:
            message = await self._read_message(process.stdout)
            message_type = message.get("type")
            if message_type == "tool_call":
                tool_call = self._trajectory_tool_call(message)
                trajectory.log("tool_call", {"step": step, "tool_call": tool_call})
                result = await self._invoke_tool(tools, message)
                tool_output = result.get("result")
                tool_summary = (
                    tool_output
                    if isinstance(tool_output, str)
                    else json.dumps(tool_output, sort_keys=True, default=str)
                )
                trajectory.log(
                    "tool_result",
                    {
                        "step": step,
                        "tool_call": tool_call,
                        "tool_output": tool_output,
                        "tool_summary": tool_summary,
                        "repeated_skip": False,
                    },
                )
                trajectory.log(
                    "message",
                    {
                        "step": step,
                        "message": {
                            "role": "tool",
                            "content": tool_summary,
                            "tool_calls": [],
                            "tool_response_call_id": tool_call["call_id"],
                        },
                    },
                )
                await self._write_message(process.stdin, result)
                continue
            if message_type == "model_call":
                step += 1
                request_id = self._message_id(message, "model call")
                if request_id in active_calls:
                    raise CyberPiError(f"Duplicate CyberPi model call id: {request_id}")
                authorization, reservation = self._authorize_model_call(native_hunter.llm, message)
                active_calls.add(request_id)
                if reservation is not None:
                    active_reservations[request_id] = reservation
                await self._write_message(process.stdin, authorization)
                continue
            if message_type == "model_result":
                call_usage = self._require_usage(message.get("usage"))
                succeeded = message.get("ok")
                if not isinstance(succeeded, bool):
                    raise CyberPiError("CyberPi model result is missing its status")
                if succeeded and assignment.budget_usd > 0 and int(call_usage["total_tokens"]) < 1:
                    raise CyberPiError("CyberPi returned unmetered usage for a budgeted hunt")
                self._accumulate_usage(usage, call_usage)
                cost = self._settle_model_call(
                    native_hunter.llm,
                    active_reservations,
                    active_calls,
                    message,
                    call_usage,
                    succeeded=succeeded,
                )
                usage["cost_usd"] += cost
                request_id = self._message_id(message, "model result")
                await self._write_message(
                    process.stdin,
                    {"type": "model_result_ack", "id": request_id},
                )
                if not succeeded:
                    detail = str(message.get("error") or "provider request failed")
                    raise CyberPiError(f"CyberPi model call failed: {detail[:2000]}")
                continue
            if message_type == "trajectory":
                self._log_assistant_trajectory(trajectory, message, step)
                continue
            if message_type == "complete":
                if active_calls:
                    raise CyberPiError("CyberPi completed with an unsettled model call")
                model_calls = message.get("model_calls")
                if (
                    not isinstance(model_calls, int)
                    or isinstance(model_calls, bool)
                    or model_calls < 1
                ):
                    raise CyberPiError("CyberPi completed without a model call")
                outcome = HuntOutcome(
                    findings=tuple(context.findings),
                    cost_usd=float(usage["cost_usd"]),
                    tokens_used=int(usage["total_tokens"]),
                    stop_reason=self._stop_reason(message, native_hunter.max_steps),
                )
                trajectory.log(
                    "finish",
                    {
                        "step": step,
                        "status": outcome.stop_reason,
                        "findings": [self._serialize_finding(finding) for finding in context.findings],
                        "total_input_tokens": int(usage["input_tokens"]),
                        "total_output_tokens": int(usage["output_tokens"]),
                        "total_cost_usd": float(usage["cost_usd"]),
                    },
                )
                return outcome
            if message_type == "error":
                detail = str(message.get("message") or "CyberPi sidecar failed")
                raise CyberPiError(detail[:2000])
            raise CyberPiError(f"Unexpected CyberPi message type: {message_type!r}")

    async def _start_process(self, api_key: str, *, cwd: str) -> asyncio.subprocess.Process:
        self._check_runtime_installed()
        if self._environ is not None:
            env = dict(self._environ)
        else:
            inherited = (
                "ALL_PROXY",
                "HTTP_PROXY",
                "HTTPS_PROXY",
                "NO_PROXY",
                "NODE_EXTRA_CA_CERTS",
                "PATH",
                "SSL_CERT_DIR",
                "SSL_CERT_FILE",
                "TMPDIR",
            )
            env = {name: os.environ[name] for name in inherited if name in os.environ}
        env["HOME"] = cwd
        env["PI_OFFLINE"] = "1"
        env["CLEARWING_CYBERPI_API_KEY"] = api_key
        try:
            return await asyncio.create_subprocess_exec(
                *self._command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                cwd=cwd,
                limit=_MAX_MESSAGE_BYTES + 1,
            )
        except FileNotFoundError as exc:
            raise CyberPiError(
                "CyberPi runtime is not available. Run `clearwing cyberpi install`, "
                "then verify it with `clearwing cyberpi doctor`."
            ) from exc

    def _check_runtime_installed(self) -> None:
        if len(self._command) < 2 or Path(self._command[1]).name != "index.mjs":
            return
        package_dir = Path(self._command[1]).parent
        dependency = package_dir / "node_modules" / "@earendil-works" / "pi-coding-agent"
        if dependency.is_dir():
            from .cyberpi_runtime import CyberPiRuntime, CyberPiRuntimeError

            try:
                CyberPiRuntime(runtime_dir=package_dir).require_ready(include_docker=False)
            except CyberPiRuntimeError as exc:
                raise CyberPiError(str(exc)) from exc
            return
        raise CyberPiError(
            "CyberPi runtime is not installed. Run `clearwing cyberpi install`, "
            "then verify it with `clearwing cyberpi doctor`."
        )

    @staticmethod
    def _model_from_client(client: Any) -> CyberPiModel:
        if not isinstance(client, AsyncLLMClient):
            raise CyberPiError("CyberPi requires a configured native LLM client")
        provider = client.provider_name.strip().lower()
        if provider in {"openai", "openai_compat", "openai_resp"}:
            target = f"{client.base_url or ''} {client.model_name}".lower()
            if "token-plan.cn-beijing.maas.aliyuncs.com" in target:
                provider = "qwen-token-plan-cn"
            elif "token-plan.ap-southeast-1.maas.aliyuncs.com" in target:
                provider = (
                    "qwen-token-plan-individual"
                    if client.model_name == "deepseek-v4-flash-0731"
                    else "qwen-token-plan"
                )
            elif "openrouter.ai" in target:
                provider = "openrouter"
            elif "fireworks.ai" in target:
                provider = "fireworks"
            elif "together.xyz" in target or "together.ai" in target:
                provider = "together"
            elif "deepseek" in target:
                provider = "deepseek"
            else:
                provider = "openai"
        api = "openai-responses" if client.provider_name == "openai_resp" else "openai-completions"
        if provider == "anthropic":
            api = "anthropic-messages"
        if provider == "gemini":
            provider = "google"
            api = "google-generative-ai"
        base_url = client.base_url or {
            "anthropic": "https://api.anthropic.com",
            "deepseek": "https://api.deepseek.com",
            "google": "https://generativelanguage.googleapis.com",
            "openai": "https://api.openai.com/v1",
            "openrouter": "https://openrouter.ai/api/v1",
        }.get(provider, "")
        if provider not in {
            "anthropic",
            "deepseek",
            "fireworks",
            "google",
            "openai",
            "openrouter",
            "qwen-token-plan",
            "qwen-token-plan-cn",
            "qwen-token-plan-individual",
            "together",
        }:
            raise CyberPiError(f"CyberPi does not support provider {client.provider_name!r}")
        ledger = client.spend_ledger
        if ledger is not None and ledger.enforcing:
            pricing = ledger.validate_model(
                model=client.model_name,
                provider=client.provider_name,
                supports_output_limit=True,
            )
            cost = {
                "input": pricing.input_per_million,
                "output": pricing.output_per_million,
                "cacheRead": pricing.cached_input_per_million,
                "cacheWrite": pricing.input_per_million,
            }
        else:
            cost = {}
        return CyberPiModel(
            provider=provider,
            model=client.model_name,
            api=api,
            base_url=base_url,
            api_key=client.api_key,
            reasoning=bool(client.reasoning_effort),
            cost=cost,
        )

    @staticmethod
    def _max_output_tokens(native_hunter: Any) -> int:
        client = native_hunter.llm
        requested = getattr(native_hunter, "max_output_tokens", None)
        ledger = client.spend_ledger
        if ledger is not None and ledger.enforcing:
            ledger_cap = int(ledger.default_max_output_tokens)
            return min(ledger_cap, requested) if requested else ledger_cap
        return int(requested or 8192)

    @staticmethod
    def _initial_user_message(native_hunter: Any, assignment: HuntAssignment) -> str:
        return native_hunter.initial_user_message or (
            f"Hunt for vulnerabilities in {assignment.file_target.get('path', 'unknown')}."
        )

    @staticmethod
    def _serialize_tool(tool: NativeToolSpec) -> dict[str, Any]:
        if tool.name not in _ALLOWED_TOOLS:
            raise CyberPiError(f"Tool is not authorized for CyberPi: {tool.name}")
        return {"name": tool.name, "description": tool.description, "schema": tool.schema}

    @staticmethod
    async def _invoke_tool(tools: list[NativeToolSpec], message: dict[str, Any]) -> dict[str, Any]:
        request_id = message.get("id")
        name = message.get("name")
        if not isinstance(request_id, str) or not request_id:
            raise CyberPiError("CyberPi tool call is missing a valid id")
        if not isinstance(name, str):
            raise CyberPiError("CyberPi tool call is missing a valid name")
        tool = next((candidate for candidate in tools if candidate.name == name), None)
        if tool is None:
            return {
                "type": "tool_result",
                "id": request_id,
                "ok": False,
                "result": {"error": f"unknown tool: {name}"},
            }
        arguments = message.get("arguments")
        if not isinstance(arguments, dict):
            return {
                "type": "tool_result",
                "id": request_id,
                "ok": False,
                "result": {"error": "tool arguments must be a JSON object"},
            }
        allowed = set(tool.schema.get("properties", {}))
        required = set(tool.schema.get("required", []))
        unknown = sorted(set(arguments) - allowed)
        missing = sorted(required - set(arguments))
        invalid = sorted(
            key
            for key, value in arguments.items()
            if key in allowed
            and not CyberPiHuntEngine._matches_schema(
                value, tool.schema["properties"][key], tool.schema
            )
        )
        if unknown:
            result: Any = {"error": f"unknown arguments: {', '.join(unknown)}"}
            ok = False
        elif missing:
            result = {"error": f"missing required arguments: {', '.join(missing)}"}
            ok = False
        elif invalid:
            result = {"error": f"invalid argument types: {', '.join(invalid)}"}
            ok = False
        elif name == "write_file" and not CyberPiHuntEngine._is_scratch_path(arguments.get("path")):
            result = {"error": "write_file is restricted to /scratch"}
            ok = False
        else:
            try:
                result = await tool.ainvoke(arguments)
                ok = not (isinstance(result, dict) and "error" in result)
            except Exception as exc:
                result = {"error": f"{type(exc).__name__}: {exc}"}
                ok = False
        return {"type": "tool_result", "id": request_id, "ok": ok, "result": result}

    @staticmethod
    def _matches_schema(value: Any, schema: dict[str, Any], root: dict[str, Any]) -> bool:
        reference = schema.get("$ref")
        if isinstance(reference, str) and reference.startswith("#/$defs/"):
            resolved = root.get("$defs", {}).get(reference.rsplit("/", 1)[-1])
            return isinstance(resolved, dict) and CyberPiHuntEngine._matches_schema(
                value, resolved, root
            )
        variants = schema.get("anyOf")
        if isinstance(variants, list):
            return any(
                isinstance(variant, dict)
                and CyberPiHuntEngine._matches_schema(value, variant, root)
                for variant in variants
            )
        if "enum" in schema and value not in schema["enum"]:
            return False
        expected = schema.get("type")
        if expected == "null":
            return value is None
        if expected == "string":
            return isinstance(value, str)
        if expected == "boolean":
            return isinstance(value, bool)
        if expected == "integer":
            return isinstance(value, int) and not isinstance(value, bool)
        if expected == "number":
            return isinstance(value, (int, float)) and not isinstance(value, bool)
        if expected == "array":
            item_schema = schema.get("items")
            return isinstance(value, list) and (
                not isinstance(item_schema, dict)
                or all(CyberPiHuntEngine._matches_schema(item, item_schema, root) for item in value)
            )
        if expected == "object":
            return isinstance(value, dict)
        return True

    @staticmethod
    def _is_scratch_path(value: Any) -> bool:
        if not isinstance(value, str):
            return False
        path = PurePosixPath(value)
        scratch = PurePosixPath("/scratch")
        return (
            path.is_absolute()
            and ".." not in path.parts
            and (path == scratch or scratch in path.parents)
        )

    @staticmethod
    def _trajectory_tool_call(message: dict[str, Any]) -> dict[str, Any]:
        request_id = CyberPiHuntEngine._message_id(message, "tool call")
        name = message.get("name")
        if not isinstance(name, str) or not name:
            raise CyberPiError("CyberPi tool call is missing a valid name")
        arguments = message.get("arguments")
        return {
            "call_id": request_id,
            "fn_name": name,
            "fn_arguments": arguments,
            "fn_arguments_json": json.dumps(arguments, sort_keys=True, default=str),
        }

    @staticmethod
    def _log_assistant_trajectory(
        trajectory: HunterTrajectoryLogger,
        message: dict[str, Any],
        current_step: int,
    ) -> None:
        step = message.get("step")
        assistant = message.get("message")
        reasoning = message.get("reasoning_content", "")
        usage = message.get("usage")
        model = message.get("model")
        if (
            not isinstance(step, int)
            or isinstance(step, bool)
            or step < 1
            or step > current_step
            or not isinstance(assistant, dict)
            or assistant.get("role") != "assistant"
            or not isinstance(reasoning, str)
            or not isinstance(usage, dict)
            or not isinstance(model, str)
        ):
            raise CyberPiError("CyberPi emitted an invalid trajectory event")
        trajectory.log(
            "message",
            {
                "step": step,
                "message": assistant,
                "reasoning_content": reasoning,
                "usage": usage,
                "model": model,
            },
        )

    @staticmethod
    def _serialize_finding(finding: Any) -> dict[str, Any]:
        return {
            "id": finding.get("id"),
            "file": finding.get("file"),
            "line_number": finding.get("line_number"),
            "severity": finding.get("severity"),
            "cwe": finding.get("cwe"),
            "description": finding.get("description"),
            "evidence_level": finding.get("evidence_level"),
        }

    @staticmethod
    async def _write_message(writer: asyncio.StreamWriter, message: dict[str, Any]) -> None:
        encoded = json.dumps(message, separators=(",", ":"), default=str, allow_nan=False).encode(
            "utf-8"
        )
        if len(encoded) > _MAX_MESSAGE_BYTES:
            raise CyberPiError("CyberPi message exceeds the protocol size limit")
        writer.write(encoded + b"\n")
        await writer.drain()

    @staticmethod
    async def _read_message(reader: asyncio.StreamReader) -> dict[str, Any]:
        try:
            line = await reader.readline()
        except ValueError as exc:
            raise CyberPiError("CyberPi message exceeds the protocol size limit") from exc
        if not line:
            raise CyberPiError("CyberPi sidecar closed before returning a result")
        if len(line) > _MAX_MESSAGE_BYTES:
            raise CyberPiError("CyberPi message exceeds the protocol size limit")
        try:
            message = json.loads(line, parse_constant=_reject_json_constant)
        except (json.JSONDecodeError, ValueError) as exc:
            raise CyberPiError("CyberPi sidecar emitted malformed JSON") from exc
        if not isinstance(message, dict):
            raise CyberPiError("CyberPi sidecar message must be a JSON object")
        return message

    @staticmethod
    async def _drain_stderr(reader: asyncio.StreamReader) -> None:
        while await reader.read(8192):
            pass

    @staticmethod
    def _message_id(message: dict[str, Any], kind: str) -> str:
        request_id = message.get("id")
        if not isinstance(request_id, str) or not request_id:
            raise CyberPiError(f"CyberPi {kind} is missing a valid id")
        return request_id

    @staticmethod
    def _require_usage(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise CyberPiError("CyberPi completed without measurable usage")
        token_fields = ("input_tokens", "output_tokens", "total_tokens")
        if any(
            not isinstance(value.get(key), int) or isinstance(value.get(key), bool)
            for key in token_fields
        ):
            raise CyberPiError("CyberPi completed without measurable usage")
        cached = value.get("cached_input_tokens", 0)
        cost = value.get("cost_usd")
        if not isinstance(cached, int) or isinstance(cached, bool):
            raise CyberPiError("CyberPi completed without measurable usage")
        if not isinstance(cost, (int, float)) or isinstance(cost, bool):
            raise CyberPiError("CyberPi completed without measurable usage")
        if (
            not math.isfinite(float(cost))
            or any(int(value[key]) < 0 for key in token_fields)
            or cached < 0
            or float(cost) < 0
        ):
            raise CyberPiError("CyberPi returned invalid usage")
        if cached > int(value["input_tokens"]) or int(value["total_tokens"]) != int(
            value["input_tokens"]
        ) + int(value["output_tokens"]):
            raise CyberPiError("CyberPi returned invalid usage")
        return value

    @staticmethod
    def _empty_usage() -> dict[str, Any]:
        return {
            "input_tokens": 0,
            "output_tokens": 0,
            "cached_input_tokens": 0,
            "total_tokens": 0,
            "cost_usd": 0.0,
        }

    @staticmethod
    def _accumulate_usage(total: dict[str, Any], usage: dict[str, Any]) -> None:
        total["input_tokens"] += int(usage["input_tokens"])
        total["output_tokens"] += int(usage["output_tokens"])
        total["cached_input_tokens"] += int(usage.get("cached_input_tokens") or 0)
        total["total_tokens"] += int(usage["total_tokens"])

    @staticmethod
    def _stop_reason(message: dict[str, Any], max_turns: int) -> str:
        reason = str(message.get("stop_reason") or "completed")
        if reason not in {
            "aborted",
            "budget_exhausted",
            "completed",
            "length",
            "max_steps",
            "stop",
        }:
            raise CyberPiError(f"CyberPi completed with an invalid stop reason: {reason}")
        turns = message.get("turns", 0)
        if not isinstance(turns, int) or isinstance(turns, bool) or turns < 0:
            raise CyberPiError("CyberPi completed with an invalid turn count")
        if reason == "aborted" and turns >= max_turns:
            return "max_steps"
        return {"stop": "completed", "length": "max_steps"}.get(reason, reason)

    @staticmethod
    def _process_error(return_code: int) -> str:
        return f"CyberPi sidecar exited with status {return_code}"

    @staticmethod
    def _authorize_model_call(
        client: AsyncLLMClient,
        message: dict[str, Any],
    ) -> tuple[dict[str, Any], BudgetReservation | None]:
        request_id = CyberPiHuntEngine._message_id(message, "model call")
        input_bytes = message.get("input_bytes")
        requested_max_tokens = message.get("max_tokens")
        if (
            not isinstance(input_bytes, int)
            or isinstance(input_bytes, bool)
            or input_bytes < 0
            or input_bytes > _MAX_MESSAGE_BYTES
        ):
            raise CyberPiError("CyberPi model call has an invalid input size")
        if (
            not isinstance(requested_max_tokens, int)
            or isinstance(requested_max_tokens, bool)
            or requested_max_tokens < 1
            or requested_max_tokens > 1_000_000
        ):
            raise CyberPiError("CyberPi model call has an invalid output limit")
        ledger = client.spend_ledger
        if ledger is None:
            return {
                "type": "model_authorization",
                "id": request_id,
                "max_tokens": requested_max_tokens,
            }, None
        reservation = ledger.reserve_call(
            model=client.model_name,
            provider=client.provider_name,
            stage="hunt",
            input_token_upper_bound=input_bytes + 512,
            requested_max_output_tokens=requested_max_tokens,
            supports_output_limit=True,
            metadata=current_spend_metadata(),
        )
        return {
            "type": "model_authorization",
            "id": request_id,
            "max_tokens": reservation.max_output_tokens
            if ledger.enforcing
            else requested_max_tokens,
        }, reservation

    @staticmethod
    def _settle_model_call(
        client: AsyncLLMClient,
        active_reservations: dict[str, BudgetReservation],
        active_calls: set[str],
        message: dict[str, Any],
        usage: dict[str, Any],
        *,
        succeeded: bool,
    ) -> float:
        request_id = CyberPiHuntEngine._message_id(message, "model result")
        if request_id not in active_calls:
            raise CyberPiError(f"CyberPi returned an unknown model call id: {request_id}")
        ledger = client.spend_ledger
        reservation = active_reservations.get(request_id)
        if reservation is not None and ledger is not None:
            if succeeded:
                cost = ledger.settle_call(
                    reservation,
                    input_tokens=int(usage["input_tokens"]),
                    output_tokens=int(usage["output_tokens"]),
                    cached_input_tokens=int(usage.get("cached_input_tokens") or 0),
                    provider_cost_usd=(None if ledger.enforcing else float(usage["cost_usd"])),
                )
            else:
                ledger.fail_call(reservation, error="CyberPiProviderError")
                cost = reservation.reserved_usd if ledger.enforcing else float(usage["cost_usd"])
        elif ledger is not None:
            raise CyberPiError(f"CyberPi lost the budget reservation for: {request_id}")
        else:
            cost = float(usage["cost_usd"])
        active_calls.remove(request_id)
        active_reservations.pop(request_id, None)
        return float(cost)

    @staticmethod
    def _fail_active_reservations(
        client: Any,
        reservations: dict[str, BudgetReservation],
        exc: BaseException,
    ) -> None:
        ledger = client.spend_ledger if isinstance(client, AsyncLLMClient) else None
        if ledger is None:
            return
        for reservation in reservations.values():
            ledger.fail_call(reservation, error=type(exc).__name__)
        reservations.clear()


__all__ = ["CyberPiError", "CyberPiHuntEngine", "CyberPiModel"]
