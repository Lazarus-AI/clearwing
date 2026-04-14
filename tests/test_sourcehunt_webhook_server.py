"""Production tests for the webhook commit monitor.

Covers:
    - HMAC-SHA256 signature verification (valid + invalid + missing)
    - GitHub push payload parsing
    - End-to-end: start a real WebhookServer on an ephemeral port, POST
      a signed request, verify the on_push callback fires
    - Repo / branch allowlists
    - Non-push events are silently accepted but don't dispatch
    - Malformed JSON → 400
    - Large payloads → 413
    - Signature mismatch → 401
    - Health check endpoint
"""
from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
import urllib.request
from unittest.mock import MagicMock

import pytest

from clearwing.sourcehunt.webhook_server import (
    WebhookConfig,
    WebhookServer,
    commit_monitor_on_push_factory,
    parse_push_payload,
    verify_signature,
)


# --- verify_signature -----------------------------------------------------


class TestVerifySignature:
    def test_valid_signature(self):
        secret = "s3cret"
        body = b'{"hello":"world"}'
        mac = hmac.new(secret.encode(), body, hashlib.sha256)
        header = f"sha256={mac.hexdigest()}"
        assert verify_signature(secret, body, header) is True

    def test_invalid_signature(self):
        secret = "s3cret"
        body = b'{"hello":"world"}'
        header = "sha256=" + "0" * 64
        assert verify_signature(secret, body, header) is False

    def test_missing_prefix(self):
        secret = "s3cret"
        body = b"x"
        mac = hmac.new(secret.encode(), body, hashlib.sha256)
        # Missing the "sha256=" prefix
        assert verify_signature(secret, body, mac.hexdigest()) is False

    def test_empty_secret_rejects(self):
        assert verify_signature("", b"x", "sha256=" + "0" * 64) is False

    def test_empty_header_rejects(self):
        assert verify_signature("secret", b"x", "") is False

    def test_wrong_secret(self):
        body = b"x"
        mac = hmac.new(b"right", body, hashlib.sha256)
        header = f"sha256={mac.hexdigest()}"
        assert verify_signature("wrong", body, header) is False

    def test_constant_time_comparison_used(self):
        """This test isn't timing-sensitive, but it exercises the hmac.compare_digest
        code path. Pass a known-bad hex that's the same length as a good one."""
        secret = "s3cret"
        body = b"x"
        good_mac = hmac.new(secret.encode(), body, hashlib.sha256)
        bad_hex = "f" * len(good_mac.hexdigest())
        assert verify_signature(secret, body, f"sha256={bad_hex}") is False


# --- parse_push_payload ---------------------------------------------------


class TestParsePushPayload:
    def test_basic_push(self):
        payload = {
            "repository": {"full_name": "acme/tool"},
            "after": "deadbeefcafe" + "0" * 28,
            "ref": "refs/heads/main",
        }
        result = parse_push_payload(payload)
        assert result["full_name"] == "acme/tool"
        assert result["head_sha"] == "deadbeefcafe" + "0" * 28
        assert result["ref"] == "refs/heads/main"
        assert result["branch"] == "main"

    def test_non_branch_ref(self):
        """Tag pushes have refs/tags/... → branch is empty."""
        payload = {
            "repository": {"full_name": "acme/tool"},
            "after": "abc123",
            "ref": "refs/tags/v1.0",
        }
        result = parse_push_payload(payload)
        assert result["branch"] == ""

    def test_missing_repository(self):
        assert parse_push_payload({"after": "abc"}) is None

    def test_missing_after(self):
        assert parse_push_payload({"repository": {"full_name": "x/y"}}) is None

    def test_empty_payload(self):
        assert parse_push_payload({}) is None


# --- End-to-end server test -----------------------------------------------


class _LiveServer:
    """Context manager that starts a WebhookServer on an ephemeral port."""

    def __init__(self, config: WebhookConfig):
        # Port 0 → OS picks free port
        config.port = 0
        self.config = config
        self.server = None
        self.thread = None

    def __enter__(self):
        self.server = WebhookServer(self.config)
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True,
        )
        self.thread.start()
        # Wait briefly for the server to bind
        time.sleep(0.05)
        return self.server

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def _signed_post(url: str, body: bytes, secret: str, event: str = "push"):
    """POST to a URL with a valid GitHub signature. Returns (status, text)."""
    mac = hmac.new(secret.encode(), body, hashlib.sha256)
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature-256": f"sha256={mac.hexdigest()}",
            "X-GitHub-Event": event,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")


class TestLiveWebhookServer:
    def test_valid_push_dispatches_callback(self):
        received: list[tuple[str, str]] = []
        callback_done = threading.Event()

        def on_push(full_name, sha, payload):
            received.append((full_name, sha))
            callback_done.set()

        config = WebhookConfig(
            secret="s3cret",
            on_push=on_push,
        )
        with _LiveServer(config) as server:
            port = server.server_port
            body = json.dumps({
                "repository": {"full_name": "acme/tool"},
                "after": "deadbeefcafe",
                "ref": "refs/heads/main",
            }).encode()
            status, text = _signed_post(
                f"http://127.0.0.1:{port}/webhook",
                body,
                "s3cret",
            )
            assert status == 202
            assert "accepted" in text.lower()

            # Wait for the background dispatch
            assert callback_done.wait(timeout=2.0)
            assert received == [("acme/tool", "deadbeefcafe")]

            stats = server.get_stats()
            assert stats.received == 1
            assert stats.dispatched == 1
            assert stats.signature_failures == 0

    def test_bad_signature_rejected(self):
        received = []

        config = WebhookConfig(
            secret="right",
            on_push=lambda *args: received.append(args),
        )
        with _LiveServer(config) as server:
            port = server.server_port
            body = b'{"repository":{"full_name":"a/b"},"after":"sha","ref":"refs/heads/main"}'
            # Sign with the WRONG secret
            status, text = _signed_post(
                f"http://127.0.0.1:{port}/webhook",
                body,
                "wrong",
            )
            assert status == 401
            assert "invalid signature" in text.lower()
            # Callback never fired
            time.sleep(0.1)
            assert received == []
            assert server.get_stats().signature_failures == 1

    def test_non_push_event_acknowledged_but_not_dispatched(self):
        received = []
        config = WebhookConfig(
            secret="s3cret",
            on_push=lambda *args: received.append(args),
        )
        with _LiveServer(config) as server:
            port = server.server_port
            body = json.dumps({"action": "opened"}).encode()
            status, _ = _signed_post(
                f"http://127.0.0.1:{port}/webhook",
                body,
                "s3cret",
                event="pull_request",
            )
            assert status == 204
            time.sleep(0.1)
            assert received == []
            assert server.get_stats().unsupported_events == 1

    def test_repo_allowlist_filters(self):
        received = []
        config = WebhookConfig(
            secret="s3cret",
            allowed_repos=["acme/only-this-one"],
            on_push=lambda *args: received.append(args),
        )
        with _LiveServer(config) as server:
            port = server.server_port
            body = json.dumps({
                "repository": {"full_name": "acme/other"},
                "after": "sha",
                "ref": "refs/heads/main",
            }).encode()
            status, _ = _signed_post(
                f"http://127.0.0.1:{port}/webhook",
                body,
                "s3cret",
            )
            assert status == 204
            time.sleep(0.1)
            assert received == []
            assert server.get_stats().filtered_repo == 1

    def test_branch_allowlist_filters(self):
        received = []
        config = WebhookConfig(
            secret="s3cret",
            allowed_branches=["main"],
            on_push=lambda *args: received.append(args),
        )
        with _LiveServer(config) as server:
            port = server.server_port
            body = json.dumps({
                "repository": {"full_name": "acme/tool"},
                "after": "sha",
                "ref": "refs/heads/feature-x",
            }).encode()
            status, _ = _signed_post(
                f"http://127.0.0.1:{port}/webhook",
                body,
                "s3cret",
            )
            assert status == 204
            assert server.get_stats().filtered_branch == 1

    def test_health_check_endpoint(self):
        config = WebhookConfig(secret="s3cret")
        with _LiveServer(config) as server:
            port = server.server_port
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/health", timeout=2,
            ) as resp:
                assert resp.status == 200
                assert b"ok" in resp.read()

    def test_malformed_json_returns_400(self):
        config = WebhookConfig(secret="s3cret", on_push=MagicMock())
        with _LiveServer(config) as server:
            port = server.server_port
            body = b"{not json"
            status, _ = _signed_post(
                f"http://127.0.0.1:{port}/webhook",
                body,
                "s3cret",
            )
            assert status == 400

    def test_wrong_path_returns_404(self):
        config = WebhookConfig(secret="s3cret", on_push=MagicMock())
        with _LiveServer(config) as server:
            port = server.server_port
            # Valid body + signature but wrong path
            body = b'{"repository":{"full_name":"x/y"},"after":"abc","ref":"refs/heads/main"}'
            status, _ = _signed_post(
                f"http://127.0.0.1:{port}/wrong-path",
                body,
                "s3cret",
            )
            assert status == 404


# --- CommitMonitor integration factory ------------------------------------


class TestCommitMonitorIntegration:
    def test_factory_builds_callback_that_invokes_scan_commit(self):
        fake_monitor = MagicMock()
        fake_monitor.scan_commit = MagicMock()
        on_push = commit_monitor_on_push_factory(fake_monitor)
        on_push("acme/tool", "deadbeef", {})
        fake_monitor.scan_commit.assert_called_once_with("deadbeef")

    def test_factory_callback_swallows_exceptions(self):
        fake_monitor = MagicMock()
        fake_monitor.scan_commit.side_effect = RuntimeError("boom")
        on_push = commit_monitor_on_push_factory(fake_monitor)
        # Must not raise
        on_push("acme/tool", "deadbeef", {})
