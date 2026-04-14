"""FastAPI web UI backend for Clearwing."""

import asyncio
import json
import logging
import time
import uuid
from typing import Any, Optional

logger = logging.getLogger(__name__)


def create_app():
    """Create and configure the FastAPI application."""
    try:
        from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
        from fastapi.middleware.cors import CORSMiddleware
        from fastapi.responses import JSONResponse
    except ImportError:
        raise ImportError(
            "FastAPI is required for the web UI. "
            "Install with: pip install 'clearwing[web]'"
        )

    app = FastAPI(
        title="Clearwing API",
        description="REST and WebSocket API for the Clearwing penetration testing agent",
        version="1.0.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # In-memory session registry
    _sessions: dict[str, dict[str, Any]] = {}

    # ---------------------------------------------------------------
    # REST endpoints
    # ---------------------------------------------------------------

    @app.get("/api/health")
    async def health():
        return {"status": "ok", "service": "clearwing"}

    @app.get("/api/sessions")
    async def list_sessions():
        """List all known sessions."""
        try:
            from clearwing.data.memory import SessionStore
            store = SessionStore()
            sessions = store.list_sessions()
            return [
                {
                    "session_id": s.session_id,
                    "target": s.target,
                    "model": s.model,
                    "status": s.status,
                    "start_time": str(s.start_time),
                    "cost_usd": s.cost_usd,
                    "token_count": s.token_count,
                }
                for s in sessions
            ]
        except ImportError:
            return []

    @app.get("/api/sessions/{session_id}")
    async def get_session(session_id: str):
        """Get details for a specific session."""
        try:
            from clearwing.data.memory import SessionStore
            store = SessionStore()
            session = store.load(session_id)
            if not session:
                raise HTTPException(status_code=404, detail="Session not found")
            return {
                "session_id": session.session_id,
                "target": session.target,
                "model": session.model,
                "status": session.status,
                "start_time": str(session.start_time),
                "cost_usd": session.cost_usd,
                "token_count": session.token_count,
                "open_ports": session.open_ports,
                "services": session.services,
                "vulnerabilities": session.vulnerabilities,
                "exploit_results": session.exploit_results,
                "flags_found": session.flags_found,
            }
        except ImportError:
            raise HTTPException(status_code=500, detail="SessionStore not available")

    @app.get("/api/metrics")
    async def get_metrics():
        """Get current metrics in JSON format."""
        try:
            from clearwing.observability.telemetry import CostTracker
            tracker = CostTracker()
            summary = tracker.get_summary()
            return {
                "input_tokens": summary.input_tokens,
                "output_tokens": summary.output_tokens,
                "total_cost_usd": summary.total_cost_usd,
                "tool_calls": summary.tool_calls,
            }
        except ImportError:
            return {"error": "CostTracker not available"}

    @app.get("/api/metrics/prometheus")
    async def get_prometheus_metrics():
        """Get metrics in Prometheus exposition format."""
        try:
            from clearwing.observability import MetricsCollector
            collector = MetricsCollector()
            return JSONResponse(
                content=collector.format_prometheus(),
                media_type="text/plain",
            )
        except ImportError:
            return JSONResponse(content="# no metrics available\n", media_type="text/plain")

    @app.post("/api/operate")
    async def start_operator(request_body: dict):
        """Start an autonomous Operator agent session.

        Request body:
        {
            "target": "10.0.0.1",
            "goals": ["Scan ports", "Find vulnerabilities"],
            "model": "claude-sonnet-4-6",
            "max_turns": 50,
            "timeout_minutes": 30,
            "auto_approve_exploits": false
        }
        """
        target = request_body.get("target")
        goals = request_body.get("goals", [])
        if not target or not goals:
            raise HTTPException(status_code=400, detail="target and goals are required")

        session_id = uuid.uuid4().hex[:8]
        _sessions[session_id] = {
            "status": "running",
            "target": target,
            "goals": goals,
            "result": None,
        }

        # Run operator in background
        async def run_operator():
            try:
                from clearwing.agent.operator import OperatorAgent, OperatorConfig

                config = OperatorConfig(
                    goals=goals,
                    target=target,
                    model=request_body.get("model", "claude-sonnet-4-6"),
                    base_url=request_body.get("base_url"),
                    api_key=request_body.get("api_key"),
                    max_turns=request_body.get("max_turns", 50),
                    timeout_minutes=request_body.get("timeout_minutes", 30),
                    auto_approve_exploits=request_body.get("auto_approve_exploits", False),
                )
                operator = OperatorAgent(config)
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(None, operator.run)
                _sessions[session_id]["status"] = result.status
                _sessions[session_id]["result"] = {
                    "status": result.status,
                    "turns": result.turns,
                    "findings": result.findings,
                    "flags_found": result.flags_found,
                    "cost_usd": result.cost_usd,
                    "tokens_used": result.tokens_used,
                    "duration_seconds": result.duration_seconds,
                    "escalation_question": result.escalation_question,
                    "error": result.error,
                }
            except Exception as e:
                _sessions[session_id]["status"] = "error"
                _sessions[session_id]["result"] = {"error": str(e)}

        asyncio.create_task(run_operator())

        return {"session_id": session_id, "status": "running"}

    @app.get("/api/operate/{session_id}")
    async def get_operator_status(session_id: str):
        """Get the status of an operator session."""
        if session_id not in _sessions:
            raise HTTPException(status_code=404, detail="Session not found")
        return _sessions[session_id]

    # ---------------------------------------------------------------
    # WebSocket endpoint for real-time streaming
    # ---------------------------------------------------------------

    @app.websocket("/ws/agent")
    async def agent_websocket(websocket: WebSocket):
        """WebSocket endpoint for interactive agent sessions.

        Protocol:
        - Client sends: {"type": "start", "target": "10.0.0.1", "model": "..."}
        - Client sends: {"type": "message", "content": "scan ports"}
        - Client sends: {"type": "approve", "approved": true}
        - Server sends: {"type": "agent_message", "content": "..."}
        - Server sends: {"type": "tool_start", "tool": "scan_ports", "args": {...}}
        - Server sends: {"type": "tool_result", "tool": "scan_ports", "content": "..."}
        - Server sends: {"type": "flag_found", "flag": "...", "context": "..."}
        - Server sends: {"type": "cost_update", "cost_usd": 0.05, "tokens": 1000}
        - Server sends: {"type": "approval_needed", "prompt": "..."}
        - Server sends: {"type": "error", "message": "..."}
        - Server sends: {"type": "complete"}
        """
        await websocket.accept()

        message_queue: asyncio.Queue = asyncio.Queue()

        # Subscribe to EventBus and forward events to the WebSocket
        try:
            from clearwing.core.events import EventBus, EventType
            bus = EventBus()

            def on_event(event_type_name: str):
                def handler(data):
                    try:
                        message_queue.put_nowait({
                            "type": event_type_name,
                            "data": data if isinstance(data, (dict, list, str, int, float, bool, type(None))) else str(data),
                        })
                    except Exception:
                        logger.debug("Failed to enqueue event", exc_info=True)
                return handler

            handlers = {}
            event_map = {
                EventType.MESSAGE: "agent_message",
                EventType.TOOL_START: "tool_start",
                EventType.TOOL_RESULT: "tool_result",
                EventType.FLAG_FOUND: "flag_found",
                EventType.COST_UPDATE: "cost_update",
                EventType.ERROR: "error",
                EventType.APPROVAL_NEEDED: "approval_needed",
            }
            for et, name in event_map.items():
                h = on_event(name)
                handlers[et] = h
                bus.subscribe(et, h)

        except ImportError:
            bus = None
            handlers = {}

        graph = None
        config = None

        try:
            while True:
                # Check for queued events to send
                try:
                    while not message_queue.empty():
                        msg = message_queue.get_nowait()
                        await websocket.send_json(msg)
                except asyncio.QueueEmpty:
                    pass

                # Receive client message with timeout
                try:
                    raw = await asyncio.wait_for(websocket.receive_text(), timeout=0.1)
                    data = json.loads(raw)
                except asyncio.TimeoutError:
                    continue
                except (WebSocketDisconnect, json.JSONDecodeError):
                    break

                msg_type = data.get("type")

                if msg_type == "start":
                    # Initialize agent
                    from clearwing.agent import create_agent
                    from langchain_core.messages import HumanMessage

                    model = data.get("model", "claude-sonnet-4-6")
                    target = data.get("target", "")
                    session_id = uuid.uuid4().hex[:8]

                    graph = create_agent(
                        model_name=model,
                        session_id=session_id,
                        base_url=data.get("base_url"),
                        api_key=data.get("api_key"),
                    )
                    config = {"configurable": {"thread_id": f"ws-{session_id}"}}

                    await websocket.send_json({
                        "type": "started",
                        "session_id": session_id,
                        "target": target,
                        "model": model,
                    })

                elif msg_type == "message" and graph and config:
                    from langchain_core.messages import HumanMessage

                    content = data.get("content", "")
                    input_msg = {"messages": [HumanMessage(content=content)]}

                    # Run agent in thread pool to avoid blocking
                    loop = asyncio.get_event_loop()

                    def run_agent():
                        last_content = ""
                        for event in graph.stream(input_msg, config, stream_mode="values"):
                            msgs = event.get("messages", [])
                            if msgs:
                                last = msgs[-1]
                                if hasattr(last, "content") and last.type == "ai":
                                    c = last.content
                                    if isinstance(c, list):
                                        c = "\n".join(
                                            p["text"] for p in c
                                            if isinstance(p, dict) and p.get("type") == "text"
                                        )
                                    if c:
                                        last_content = c
                        return last_content

                    try:
                        result = await loop.run_in_executor(None, run_agent)
                        if result:
                            await websocket.send_json({
                                "type": "agent_message",
                                "data": {"content": result},
                            })
                    except Exception as e:
                        await websocket.send_json({
                            "type": "error",
                            "data": {"message": str(e)},
                        })

                elif msg_type == "approve" and graph and config:
                    from langgraph.types import Command
                    approved = data.get("approved", False)
                    try:
                        loop = asyncio.get_event_loop()
                        await loop.run_in_executor(
                            None, lambda: graph.invoke(Command(resume=approved), config)
                        )
                    except Exception as e:
                        await websocket.send_json({
                            "type": "error",
                            "data": {"message": str(e)},
                        })

        except WebSocketDisconnect:
            pass
        finally:
            # Cleanup subscriptions
            if bus and handlers:
                for et, h in handlers.items():
                    bus.unsubscribe(et, h)

    return app
