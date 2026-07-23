"""Tests for short-lived out-of-band callback tools."""

import socket
import urllib.request

from clearwing.agent.tools.ops.callback_listener import (
    check_callback_received,
    reset_callback_listeners,
    start_callback_listener,
)


def _available_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_callback_listener_captures_post_body():
    started = start_callback_listener(port=_available_port(), lhost="127.0.0.1")
    try:
        assert started["status"] == "listening"
        request = urllib.request.Request(
            started["callback_url"],
            data=b"uid=1000(test)\nLinux target 6.8.0",
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=2) as response:  # noqa: S310
            assert response.status == 200

        callback = check_callback_received(token=started["token"], timeout=1)
        assert callback["received"] is True
        assert "uid=1000" in callback["request_body"]
        assert "Linux target" in callback["request_body"]
    finally:
        reset_callback_listeners()


def test_callback_listener_rejects_unknown_token_and_unsafe_bounds():
    assert check_callback_received(token="invented", timeout=0)["error"] is True
    assert start_callback_listener(port=80)["status"] == "error"
    assert start_callback_listener(lhost="http://example.test")["status"] == "error"
