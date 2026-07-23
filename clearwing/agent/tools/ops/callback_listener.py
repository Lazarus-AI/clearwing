"""Short-lived HTTP callbacks for out-of-band exploit verification."""

from __future__ import annotations

import logging
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from clearwing.agent.tooling import tool

logger = logging.getLogger(__name__)

_LISTENER_TTL_SECONDS = 600
_MAX_BODY_BYTES = 1024 * 1024
_callbacks: dict[str, dict] = {}
_servers: dict[int, ThreadingHTTPServer] = {}
_state_lock = threading.Lock()


class _CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def _handle(self) -> None:
        parts = self.path.split("?", 1)[0].strip("/").split("/")
        token = parts[1] if len(parts) == 2 and parts[0] == "callback" else ""
        with _state_lock:
            known = token in _callbacks
        if not known:
            self.send_error(404)
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400, "invalid Content-Length")
            return
        if content_length < 0 or content_length > _MAX_BODY_BYTES:
            self.send_error(413)
            return

        body = self.rfile.read(content_length).decode("utf-8", errors="replace")
        callback = {
            "received": True,
            "timestamp": time.time(),
            "source_ip": self.client_address[0],
            "request_body": body,
            "method": self.command,
            "path": self.path,
        }
        with _state_lock:
            _callbacks[token] = callback
        logger.info("Callback received for token %s from %s", token, self.client_address[0])
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK\n")

    def log_message(self, format: str, *args: object) -> None:
        logger.debug("CallbackListener: %s", format % args)


def _stop_listener(port: int) -> bool:
    with _state_lock:
        server = _servers.pop(port, None)
    if server is None:
        return False
    server.shutdown()
    server.server_close()
    return True


def _auto_shutdown(port: int) -> None:
    time.sleep(_LISTENER_TTL_SECONDS)
    if _stop_listener(port):
        logger.debug("Callback listener on port %d expired", port)


@tool
def start_callback_listener(port: int = 9999, lhost: str = "host.docker.internal") -> dict:
    """Start a short-lived HTTP callback listener for blind exploit proof.

    ``lhost`` is the address the target uses to reach this process. For a
    Docker target it is commonly ``host.docker.internal`` or the Docker host
    gateway, never the target's own 127.0.0.1. The returned callback URL has a
    cryptographically random token and accepts GET or POST while recording the
    request body for later verification.
    """
    if not isinstance(port, int) or isinstance(port, bool) or not 1024 <= port <= 65526:
        return {"status": "error", "message": "port must be between 1024 and 65526"}
    if (
        not isinstance(lhost, str)
        or not lhost.strip()
        or len(lhost) > 255
        or "://" in lhost
        or any(char.isspace() for char in lhost)
    ):
        return {"status": "error", "message": "lhost must be a host name or address"}

    server = None
    bound_port = None
    for candidate in range(port, port + 10):
        with _state_lock:
            already_bound = candidate in _servers
        if already_bound:
            continue
        try:
            server = ThreadingHTTPServer(("0.0.0.0", candidate), _CallbackHandler)
            bound_port = candidate
            break
        except OSError:
            continue
    if server is None or bound_port is None:
        return {
            "status": "error",
            "message": f"could not bind a callback listener in range {port}-{port + 9}",
        }

    token = secrets.token_urlsafe(18)
    with _state_lock:
        _callbacks[token] = {"received": False}
        _servers[bound_port] = server
    threading.Thread(target=server.serve_forever, daemon=True).start()
    threading.Thread(target=_auto_shutdown, args=(bound_port,), daemon=True).start()

    callback_url = f"http://{lhost.strip()}:{bound_port}/callback/{token}"
    return {
        "status": "listening",
        "port": bound_port,
        "token": token,
        "callback_url": callback_url,
        "message": (
            f"Listening on 0.0.0.0:{bound_port}. Use check_callback_received with the "
            "returned token."
        ),
    }


@tool
def check_callback_received(token: str, timeout: int = 10) -> dict:
    """Wait briefly for a callback token returned by start_callback_listener."""
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 0 <= timeout <= 60:
        return {"received": False, "error": True, "message": "timeout must be 0 to 60 seconds"}
    with _state_lock:
        known = token in _callbacks
    if not known:
        return {
            "received": False,
            "error": True,
            "message": "unknown callback token; start a listener and use its returned token",
        }

    deadline = time.monotonic() + timeout
    while True:
        with _state_lock:
            entry = dict(_callbacks.get(token, {}))
        if entry.get("received"):
            return entry
        if time.monotonic() >= deadline:
            return {
                "received": False,
                "message": "No callback received before the timeout.",
            }
        time.sleep(0.25)


@tool
def reset_callback_listeners() -> dict:
    """Stop all callback listeners and remove callback tokens for this process."""
    with _state_lock:
        ports = list(_servers)
        cleared_tokens = len(_callbacks)
        _callbacks.clear()
    stopped = sum(_stop_listener(port) for port in ports)
    return {"cleared_tokens": cleared_tokens, "stopped_servers": stopped}
