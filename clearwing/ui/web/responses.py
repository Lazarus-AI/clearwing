"""OpenAI-compatible /v1/responses endpoint with SSE streaming.

Translates Clearwing's OperatorAgent into the OpenAI Responses API wire format,
allowing any OpenAI-compatible client (Open WebUI, openai SDK, etc.) to drive
vulnerability assessments.

Approval gates surface as a regular assistant message asking for confirmation;
the user replies in the next turn to continue.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse

from clearwing.agent.operator import OperatorAgent, OperatorConfig, OperatorResult
from clearwing.core.events import EventBus, EventType

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1")

# In-memory session state keyed by response ID
_sessions: dict[str, dict[str, Any]] = {}


def _sse(event: str, data: dict) -> str:
    """Format a Server-Sent Event."""
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def _response_object(
    response_id: str,
    status: str = "in_progress",
    output: list | None = None,
    model: str = "",
    usage: dict | None = None,
) -> dict:
    return {
        "id": response_id,
        "object": "response",
        "status": status,
        "output": output or [],
        "model": model,
        "usage": usage or {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
        "created_at": int(time.time()),
    }


@router.post("/responses")
async def create_response(request: Request):
    """Create a response — streams SSE events as the agent works."""
    body = await request.json()

    input_data = body.get("input")
    if not input_data:
        raise HTTPException(status_code=400, detail="input is required")

    model = body.get("model", "claude-sonnet-4-6")
    stream = body.get("stream", True)

    # Extract target and goals from the input messages
    target, goals = _parse_input(input_data)

    response_id = f"resp_{uuid.uuid4().hex[:24]}"

    if not stream:
        # Synchronous mode — run to completion and return
        result = await _run_sync(response_id, target, goals, model, body)
        return result

    # Streaming mode
    return StreamingResponse(
        _stream_agent(response_id, target, goals, model, body),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


def _parse_input(input_data: str | list) -> tuple[str, list[str]]:
    """Extract target and goals from OpenAI-style input.

    Supports:
    - Simple string: treated as a single goal, target extracted if prefixed
    - Message list: last user message(s) become goals
    """
    if isinstance(input_data, str):
        # Convention: "target:10.0.0.1 scan for vulnerabilities"
        if input_data.startswith("target:"):
            parts = input_data.split(" ", 1)
            target = parts[0].removeprefix("target:")
            goals = [parts[1]] if len(parts) > 1 else ["Perform vulnerability assessment"]
        else:
            target = ""
            goals = [input_data]
        return target, goals

    # Message list format
    messages = input_data if isinstance(input_data, list) else [input_data]
    user_messages = [
        m["content"] for m in messages
        if isinstance(m, dict) and m.get("role") == "user"
    ]

    # Check if this is a continuation (approval reply)
    last_msg = user_messages[-1] if user_messages else ""

    # Try to find a previously stored session that's waiting for approval
    for sid, session in _sessions.items():
        if session.get("status") == "awaiting_approval":
            if last_msg.lower().strip() in ("yes", "y", "approve", "continue", "go"):
                session["approval_event"].set()
                session["status"] = "running"
                # Return a simple ack
                return session["target"], []
            elif last_msg.lower().strip() in ("no", "n", "deny", "stop", "cancel"):
                session["status"] = "cancelled"
                session["approval_event"].set()
                return session["target"], []

    # Extract target from first message if it contains "target:" prefix
    target = ""
    goals = []
    for msg in user_messages:
        if msg.startswith("target:"):
            parts = msg.split(" ", 1)
            target = parts[0].removeprefix("target:")
            if len(parts) > 1:
                goals.append(parts[1])
        else:
            goals.append(msg)

    if not goals:
        goals = ["Perform vulnerability assessment"]

    return target, goals


async def _stream_agent(
    response_id: str,
    target: str,
    goals: list[str],
    model: str,
    body: dict,
):
    """Async generator that yields SSE events as the Operator runs."""

    # Emit response.created
    resp_obj = _response_object(response_id, status="in_progress", model=model)
    yield _sse("response.created", resp_obj)

    # Track output items
    output_items: list[dict] = []
    item_idx = 0

    # Set up event collection from the bus
    event_queue: asyncio.Queue = asyncio.Queue()
    approval_event = asyncio.Event()

    _sessions[response_id] = {
        "status": "running",
        "target": target,
        "goals": goals,
        "approval_event": approval_event,
    }

    bus = EventBus()
    handlers = {}

    def make_handler(event_name: str):
        def handler(data):
            event_queue.put_nowait((event_name, data))
        return handler

    listen_events = {
        EventType.MESSAGE: "message",
        EventType.TOOL_START: "tool_start",
        EventType.TOOL_RESULT: "tool_result",
        EventType.APPROVAL_NEEDED: "approval_needed",
        EventType.COST_UPDATE: "cost_update",
        EventType.ERROR: "error",
    }
    for et, name in listen_events.items():
        h = make_handler(name)
        handlers[et] = h
        bus.subscribe(et, h)

    def on_tool_result(tool_name: str, content: str):
        event_queue.put_nowait(("tool_result_full", {"tool": tool_name, "content": content}))

    async def run_operator():
        config = OperatorConfig(
            goals=goals,
            target=target or "unknown",
            model=model,
            base_url=body.get("base_url"),
            api_key=body.get("api_key"),
            max_turns=body.get("max_turns", 50),
            timeout_minutes=body.get("timeout_minutes", 30),
            auto_approve_exploits=body.get("auto_approve_exploits", False),
            on_tool_result=on_tool_result,
        )
        operator = OperatorAgent(config)
        return await operator.arun()

    task = asyncio.create_task(run_operator())

    try:
        while not task.done():
            try:
                event_name, data = await asyncio.wait_for(event_queue.get(), timeout=0.5)
            except (asyncio.TimeoutError, asyncio.QueueEmpty):
                continue

            if event_name == "message":
                content = data.get("content", "") if isinstance(data, dict) else str(data)
                if not content:
                    continue
                # Emit as output text
                item = {
                    "type": "message",
                    "id": f"msg_{uuid.uuid4().hex[:12]}",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": content}],
                }
                output_items.append(item)
                yield _sse("response.output_item.added", {
                    "output_index": item_idx,
                    "item": item,
                })
                yield _sse("response.output_text.delta", {
                    "output_index": item_idx,
                    "content_index": 0,
                    "delta": content,
                })
                yield _sse("response.output_text.done", {
                    "output_index": item_idx,
                    "content_index": 0,
                    "text": content,
                })
                item_idx += 1

            elif event_name == "tool_start":
                tool_name = data.get("tool", "unknown") if isinstance(data, dict) else "unknown"
                args = data.get("args", {}) if isinstance(data, dict) else {}
                item = {
                    "type": "function_call",
                    "id": f"fc_{uuid.uuid4().hex[:12]}",
                    "name": tool_name,
                    "arguments": json.dumps(args) if isinstance(args, dict) else str(args),
                }
                output_items.append(item)
                yield _sse("response.output_item.added", {
                    "output_index": item_idx,
                    "item": item,
                })
                item_idx += 1

            elif event_name == "tool_result_full":
                # Full content from on_tool_result callback
                tool_name = data.get("tool", "unknown") if isinstance(data, dict) else "unknown"
                content = data.get("content", "") if isinstance(data, dict) else str(data)
                item = {
                    "type": "function_call_output",
                    "id": f"fco_{uuid.uuid4().hex[:12]}",
                    "output": content[:4000],
                }
                output_items.append(item)
                yield _sse("response.output_item.added", {
                    "output_index": item_idx,
                    "item": item,
                })
                item_idx += 1

            elif event_name == "tool_result":
                # EventBus fallback (content_length only) — skip, we use on_tool_result
                continue

            elif event_name == "approval_needed":
                # Surface as an assistant message — user replies to continue
                prompt = data.get("prompt", "Approve this action?") if isinstance(data, dict) else str(data)
                approval_msg = f"⚠️ APPROVAL NEEDED: {prompt}\n\nReply 'yes' to approve or 'no' to deny."
                item = {
                    "type": "message",
                    "id": f"msg_{uuid.uuid4().hex[:12]}",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": approval_msg}],
                }
                output_items.append(item)
                yield _sse("response.output_item.added", {
                    "output_index": item_idx,
                    "item": item,
                })
                yield _sse("response.output_text.done", {
                    "output_index": item_idx,
                    "content_index": 0,
                    "text": approval_msg,
                })
                item_idx += 1

                # Mark session as waiting and pause stream
                _sessions[response_id]["status"] = "awaiting_approval"
                # End this stream — client sends a new /responses to approve
                break

            elif event_name == "error":
                err_msg = data.get("message", str(data)) if isinstance(data, dict) else str(data)
                yield _sse("error", {"type": "server_error", "message": err_msg})

        # Drain remaining events
        while not event_queue.empty():
            try:
                event_queue.get_nowait()
            except asyncio.QueueEmpty:
                break

        # Get result if task completed
        if task.done() and not task.cancelled():
            try:
                result: OperatorResult = task.result()
                status = "completed"
                usage = {
                    "input_tokens": result.tokens_used // 2,  # approximate split
                    "output_tokens": result.tokens_used // 2,
                    "total_tokens": result.tokens_used,
                }
                # Surface operator errors as visible output
                if result.error:
                    err_item = {
                        "type": "message",
                        "id": f"msg_{uuid.uuid4().hex[:12]}",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": f"Error: {result.error}"}],
                    }
                    output_items.append(err_item)
                    yield _sse("response.output_item.added", {
                        "output_index": item_idx,
                        "item": err_item,
                    })
                    status = "failed"
            except Exception as e:
                status = "failed"
                usage = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
                yield _sse("error", {"type": "server_error", "message": str(e)})
        else:
            status = "incomplete"
            usage = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}

        # Emit response.completed
        final = _response_object(response_id, status=status, output=output_items, model=model, usage=usage)
        yield _sse("response.completed", final)
        logger.info(
            "Response %s finished: status=%s, items=%d, tokens=%d",
            response_id, status, len(output_items), usage.get("total_tokens", 0),
        )

    finally:
        # Unsubscribe from bus
        for et, h in handlers.items():
            bus.unsubscribe(et, h)
        if response_id in _sessions:
            _sessions[response_id]["status"] = "done"


async def _run_sync(
    response_id: str,
    target: str,
    goals: list[str],
    model: str,
    body: dict,
) -> dict:
    """Non-streaming: run to completion and return the full response object."""
    config = OperatorConfig(
        goals=goals,
        target=target or "unknown",
        model=model,
        base_url=body.get("base_url"),
        api_key=body.get("api_key"),
        max_turns=body.get("max_turns", 50),
        timeout_minutes=body.get("timeout_minutes", 30),
        auto_approve_exploits=body.get("auto_approve_exploits", False),
    )
    operator = OperatorAgent(config)
    result = await operator.arun()

    output = [{
        "type": "message",
        "id": f"msg_{uuid.uuid4().hex[:12]}",
        "role": "assistant",
        "content": [{"type": "output_text", "text": result.conversation_summary or "Assessment complete."}],
    }]

    return _response_object(
        response_id,
        status="completed",
        output=output,
        model=model,
        usage={
            "input_tokens": result.tokens_used // 2,
            "output_tokens": result.tokens_used // 2,
            "total_tokens": result.tokens_used,
        },
    )
