"""GitHub webhook receiver for the Commit Monitor.

Implements a minimal HTTP server (stdlib `http.server`) that:
    1. Listens for POST /webhook requests from GitHub
    2. Verifies the HMAC-SHA256 signature against a shared secret
    3. Parses the push payload and extracts (repo_full_name, head_sha)
    4. Invokes a scan callback in a background thread so the handler
       returns 200 OK within GitHub's 10-second timeout

This complements the poll-based CommitMonitor. Production deployment:
    - Put this behind a reverse proxy (nginx, Caddy) with TLS termination
    - Set the shared secret on both sides (`GITHUB_WEBHOOK_SECRET` env var)
    - Only deliver `push` events from the target repository

No Flask / FastAPI dependency — stdlib http.server is enough for this
small footprint and makes packaging simpler.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Optional

logger = logging.getLogger(__name__)


# --- Config -----------------------------------------------------------------


@dataclass
class WebhookConfig:
    """Configuration for the webhook server."""
    host: str = "0.0.0.0"
    port: int = 8787
    path: str = "/webhook"
    secret: str = ""                     # shared secret, HMAC-SHA256
    allowed_repos: list[str] = field(default_factory=list)
                                          # e.g. ["owner/repo"]; empty = allow all
    allowed_branches: list[str] = field(default_factory=list)
                                          # e.g. ["main"]; empty = allow all
    # Callback invoked in a worker thread when a push is accepted.
    # Signature: (repo_full_name: str, commit_sha: str, payload: dict) -> None
    on_push: Optional[Callable] = None


@dataclass
class WebhookStats:
    """Running counters for observability — exposed via get_stats()."""
    received: int = 0
    signature_failures: int = 0
    unsupported_events: int = 0
    filtered_repo: int = 0
    filtered_branch: int = 0
    dispatched: int = 0
    handler_errors: int = 0


# --- HMAC verification -----------------------------------------------------


def verify_signature(
    secret: str,
    body_bytes: bytes,
    signature_header: str,
) -> bool:
    """Verify a GitHub HMAC-SHA256 signature.

    GitHub sends the signature in the `X-Hub-Signature-256` header as
    `sha256=<hex>`. Uses hmac.compare_digest for constant-time comparison.
    """
    if not secret or not signature_header:
        return False
    if not signature_header.startswith("sha256="):
        return False
    expected_hex = signature_header[len("sha256="):]
    mac = hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256)
    computed_hex = mac.hexdigest()
    return hmac.compare_digest(expected_hex, computed_hex)


# --- Payload parsing -------------------------------------------------------


def parse_push_payload(payload: dict) -> Optional[dict]:
    """Extract (repo_full_name, head_sha, ref) from a GitHub push payload.

    GitHub's push event schema:
        repository.full_name
        after (head sha)
        ref (e.g. "refs/heads/main")

    Returns None on malformed payloads rather than raising.
    """
    try:
        repo = payload.get("repository") or {}
        full_name = repo.get("full_name")
        head_sha = payload.get("after")
        ref = payload.get("ref", "")
        if not full_name or not head_sha:
            return None
        return {
            "full_name": full_name,
            "head_sha": head_sha,
            "ref": ref,
            "branch": ref.split("/")[-1] if ref.startswith("refs/heads/") else "",
        }
    except Exception:
        return None


# --- HTTP handler ----------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    """Request handler. Attached config + stats come from the server instance."""

    # Silence the default stderr request log — we do our own logging
    def log_message(self, format, *args):
        logger.debug("webhook: " + format, *args)

    def _respond(self, status: int, body: str) -> None:
        body_bytes = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)

    def do_GET(self):
        """Health-check endpoint."""
        if self.path in ("/health", "/healthz"):
            self._respond(200, "ok\n")
            return
        self._respond(404, "not found\n")

    def do_POST(self):
        server: WebhookServer = self.server  # type: ignore[assignment]
        config = server.config
        stats = server.stats

        if self.path != config.path:
            self._respond(404, "not found\n")
            return

        # Read the body (cap at 10 MB — GitHub pushes shouldn't exceed this)
        content_length = int(self.headers.get("Content-Length") or 0)
        if content_length > 10 * 1024 * 1024:
            self._respond(413, "payload too large\n")
            return
        body_bytes = self.rfile.read(content_length) if content_length else b""

        stats.received += 1

        # Verify the HMAC signature
        signature_header = self.headers.get("X-Hub-Signature-256", "")
        if not verify_signature(config.secret, body_bytes, signature_header):
            stats.signature_failures += 1
            logger.warning("webhook: signature verification failed")
            self._respond(401, "invalid signature\n")
            return

        # Only process `push` events; respond 204 to anything else
        event_type = self.headers.get("X-GitHub-Event", "")
        if event_type != "push":
            stats.unsupported_events += 1
            logger.debug("webhook: ignoring event type %s", event_type)
            self._respond(204, "")
            return

        # Parse the payload
        try:
            payload = json.loads(body_bytes.decode("utf-8"))
        except json.JSONDecodeError:
            logger.warning("webhook: malformed JSON payload")
            self._respond(400, "malformed json\n")
            return

        push_info = parse_push_payload(payload)
        if push_info is None:
            logger.debug("webhook: unparseable push payload")
            self._respond(400, "unparseable push\n")
            return

        # Apply repo / branch filters
        if config.allowed_repos and push_info["full_name"] not in config.allowed_repos:
            stats.filtered_repo += 1
            logger.debug("webhook: repo %s not in allowlist", push_info["full_name"])
            self._respond(204, "")
            return

        if config.allowed_branches and push_info["branch"] not in config.allowed_branches:
            stats.filtered_branch += 1
            logger.debug("webhook: branch %s not in allowlist", push_info["branch"])
            self._respond(204, "")
            return

        # Dispatch the callback in a background thread so GitHub gets a
        # prompt 202 Accepted and doesn't hit its 10-second timeout.
        if config.on_push is not None:
            def _run():
                try:
                    config.on_push(
                        push_info["full_name"],
                        push_info["head_sha"],
                        payload,
                    )
                except Exception:
                    with server._stats_lock:
                        stats.handler_errors += 1
                    logger.warning("webhook: on_push callback raised", exc_info=True)

            thread = threading.Thread(target=_run, daemon=True)
            thread.start()
            with server._stats_lock:
                stats.dispatched += 1
            self._respond(
                202,
                f"accepted {push_info['full_name']} @ {push_info['head_sha'][:8]}\n",
            )
            return

        # No callback configured — acknowledge but do nothing
        self._respond(204, "")


# --- Server ----------------------------------------------------------------


class WebhookServer(ThreadingHTTPServer):
    """ThreadingHTTPServer subclass carrying a WebhookConfig + WebhookStats."""

    allow_reuse_address = True

    def __init__(self, config: WebhookConfig):
        self.config = config
        self.stats = WebhookStats()
        self._stats_lock = threading.Lock()
        super().__init__((config.host, config.port), _Handler)

    def get_stats(self) -> WebhookStats:
        with self._stats_lock:
            # Return a shallow copy so callers don't race
            return WebhookStats(**self.stats.__dict__)


def serve_forever(config: WebhookConfig) -> WebhookServer:
    """Start the webhook server and block until interrupted.

    Returns the WebhookServer instance so the caller can access stats or
    shut it down via `server.shutdown()` from another thread.
    """
    server = WebhookServer(config)
    logger.info(
        "Webhook server listening on %s:%d%s",
        config.host, config.port, config.path,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Webhook server shutting down")
    finally:
        server.server_close()
    return server


# --- CommitMonitor integration helper --------------------------------------


def commit_monitor_on_push_factory(monitor) -> Callable:
    """Build an on_push callback that invokes CommitMonitor.scan_commit().

    Usage:
        from clearwing.sourcehunt.commit_monitor import CommitMonitor
        from clearwing.sourcehunt.webhook_server import (
            WebhookConfig, commit_monitor_on_push_factory, serve_forever,
        )

        monitor = CommitMonitor(...)
        serve_forever(WebhookConfig(
            port=8787, secret="s3cret",
            on_push=commit_monitor_on_push_factory(monitor),
        ))
    """
    def on_push(full_name: str, commit_sha: str, payload: dict) -> None:
        logger.info(
            "webhook dispatch: %s @ %s", full_name, commit_sha[:8],
        )
        try:
            monitor.scan_commit(commit_sha)
        except Exception:
            logger.warning("scan_commit failed in webhook handler", exc_info=True)

    return on_push
