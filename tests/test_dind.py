"""Tests for clearwing.sandbox.dind — Docker daemon resolution logic."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from clearwing.sandbox.dind import (
    _CLEARWING_ENV,
    _DEFAULT_SOCKET,
    _ROOTLESS_SOCKET,
    get_docker_client,
    get_docker_host,
    get_subprocess_env,
)


class TestGetDockerHost:
    """Resolution priority: CLEARWING_DOCKER_HOST > DOCKER_HOST > rootless socket > default."""

    def test_clearwing_env_takes_priority(self, monkeypatch):
        monkeypatch.setenv(_CLEARWING_ENV, "tcp://sidecar:2375")
        monkeypatch.setenv("DOCKER_HOST", "unix:///other.sock")
        assert get_docker_host() == "tcp://sidecar:2375"

    def test_docker_host_fallback(self, monkeypatch):
        monkeypatch.delenv(_CLEARWING_ENV, raising=False)
        monkeypatch.setenv("DOCKER_HOST", "tcp://remote:2376")
        assert get_docker_host() == "tcp://remote:2376"

    def test_rootless_socket_when_exists(self, monkeypatch, tmp_path):
        monkeypatch.delenv(_CLEARWING_ENV, raising=False)
        monkeypatch.delenv("DOCKER_HOST", raising=False)
        # Patch os.path.exists to simulate rootless socket present
        real_exists = os.path.exists

        def fake_exists(path):
            if path == _ROOTLESS_SOCKET:
                return True
            if path == _DEFAULT_SOCKET:
                return False
            return real_exists(path)

        with patch("clearwing.sandbox.dind.os.path.exists", side_effect=fake_exists):
            result = get_docker_host()
        assert result == f"unix://{_ROOTLESS_SOCKET}"

    def test_default_socket_returns_none(self, monkeypatch):
        monkeypatch.delenv(_CLEARWING_ENV, raising=False)
        monkeypatch.delenv("DOCKER_HOST", raising=False)

        def fake_exists(path):
            if path == _ROOTLESS_SOCKET:
                return False
            if path == _DEFAULT_SOCKET:
                return True
            return False

        with patch("clearwing.sandbox.dind.os.path.exists", side_effect=fake_exists):
            result = get_docker_host()
        assert result is None

    def test_nothing_available_returns_none(self, monkeypatch):
        monkeypatch.delenv(_CLEARWING_ENV, raising=False)
        monkeypatch.delenv("DOCKER_HOST", raising=False)
        with patch("clearwing.sandbox.dind.os.path.exists", return_value=False):
            assert get_docker_host() is None

    def test_whitespace_env_ignored(self, monkeypatch):
        monkeypatch.setenv(_CLEARWING_ENV, "   ")
        monkeypatch.delenv("DOCKER_HOST", raising=False)
        with patch("clearwing.sandbox.dind.os.path.exists", return_value=False):
            assert get_docker_host() is None


class TestGetDockerClient:
    """Client factory connects to resolved host and health-checks."""

    @patch("clearwing.sandbox.dind.get_docker_host", return_value="tcp://sidecar:2375")
    def test_connects_to_explicit_host(self, mock_host):
        mock_client = MagicMock()
        mock_client.ping.return_value = True
        with patch("docker.DockerClient", return_value=mock_client) as mock_ctor:
            client = get_docker_client(timeout=1)
        mock_ctor.assert_called_once_with(base_url="tcp://sidecar:2375")
        assert client is mock_client

    @patch("clearwing.sandbox.dind.get_docker_host", return_value=None)
    def test_falls_back_to_from_env(self, mock_host):
        mock_client = MagicMock()
        mock_client.ping.return_value = True
        with patch("docker.from_env", return_value=mock_client) as mock_from_env:
            client = get_docker_client(timeout=1)
        mock_from_env.assert_called_once()
        assert client is mock_client

    @patch("clearwing.sandbox.dind.get_docker_host", return_value="tcp://slow:2375")
    def test_retries_until_healthy(self, mock_host):
        mock_client = MagicMock()
        call_count = [0]

        def flaky_ping():
            call_count[0] += 1
            if call_count[0] < 3:
                raise ConnectionError("not ready")
            return True

        mock_client.ping.side_effect = flaky_ping
        with patch("docker.DockerClient", return_value=mock_client):
            client = get_docker_client(timeout=10)
        assert client is mock_client
        assert call_count[0] >= 3


class TestGetSubprocessEnv:
    """Subprocess env merges DOCKER_HOST when resolved."""

    @patch("clearwing.sandbox.dind.get_docker_host", return_value="tcp://sidecar:2375")
    def test_sets_docker_host(self, mock_host):
        env = get_subprocess_env()
        assert env["DOCKER_HOST"] == "tcp://sidecar:2375"
        assert "PATH" in env  # preserves existing env

    @patch("clearwing.sandbox.dind.get_docker_host", return_value=None)
    def test_no_override_when_default(self, mock_host, monkeypatch):
        monkeypatch.delenv("DOCKER_HOST", raising=False)
        env = get_subprocess_env()
        assert "DOCKER_HOST" not in env
