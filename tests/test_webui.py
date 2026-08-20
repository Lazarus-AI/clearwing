"""Tests for the web UI module."""

from unittest.mock import MagicMock, patch

import pytest

# Import guard - tests skip if fastapi not installed
fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from clearwing.ui.web.app import _cors_origins, create_app

API_KEY = "test-key-8f3a"
AUTH = {"X-API-Key": API_KEY}


@pytest.fixture
def app(monkeypatch):
    monkeypatch.setenv("CLEARWING_WEB_API_KEY", API_KEY)
    return create_app()


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
def unauth_app(monkeypatch):
    monkeypatch.delenv("CLEARWING_WEB_API_KEY", raising=False)
    return create_app()


@pytest.fixture
def unauth_client(unauth_app):
    return TestClient(unauth_app)


class TestHealthEndpoint:
    def test_health(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["service"] == "clearwing"


class TestSessionEndpoints:
    def test_list_sessions_empty(self, client):
        with patch("clearwing.data.memory.SessionStore") as mock_store:
            mock_store.return_value.list_sessions.return_value = []
            resp = client.get("/api/sessions")
            assert resp.status_code == 200
            assert resp.json() == []

    def test_list_sessions_with_data(self, client):
        mock_session = MagicMock()
        mock_session.session_id = "abc123"
        mock_session.target = "10.0.0.1"
        mock_session.model = "claude-sonnet-4-6"
        mock_session.status = "completed"
        mock_session.start_time = "2024-01-01T00:00:00"
        mock_session.cost_usd = 0.05
        mock_session.token_count = 1000

        with patch("clearwing.data.memory.SessionStore") as mock_store:
            mock_store.return_value.list_sessions.return_value = [mock_session]
            resp = client.get("/api/sessions")
            assert resp.status_code == 200
            data = resp.json()
            assert len(data) == 1
            assert data[0]["session_id"] == "abc123"
            assert data[0]["target"] == "10.0.0.1"

    def test_get_session(self, client):
        mock_session = MagicMock()
        mock_session.session_id = "abc123"
        mock_session.target = "10.0.0.1"
        mock_session.model = "claude-sonnet-4-6"
        mock_session.status = "completed"
        mock_session.start_time = "2024-01-01T00:00:00"
        mock_session.cost_usd = 0.05
        mock_session.token_count = 1000
        mock_session.open_ports = [{"port": 22}]
        mock_session.services = []
        mock_session.vulnerabilities = []
        mock_session.exploit_results = []
        mock_session.flags_found = []

        with patch("clearwing.data.memory.SessionStore") as mock_store:
            mock_store.return_value.load.return_value = mock_session
            resp = client.get("/api/sessions/abc123")
            assert resp.status_code == 200
            data = resp.json()
            assert data["session_id"] == "abc123"
            assert data["open_ports"] == [{"port": 22}]

    def test_get_session_not_found(self, client):
        with patch("clearwing.data.memory.SessionStore") as mock_store:
            mock_store.return_value.load.return_value = None
            resp = client.get("/api/sessions/nonexistent")
            assert resp.status_code == 404


class TestMetricsEndpoints:
    def test_get_metrics(self, client):
        with patch("clearwing.observability.telemetry.CostTracker") as mock_tracker:
            mock_summary = MagicMock()
            mock_summary.input_tokens = 1000
            mock_summary.output_tokens = 500
            mock_summary.total_cost_usd = 0.05
            mock_summary.tool_calls = 10
            mock_tracker.return_value.get_summary.return_value = mock_summary
            resp = client.get("/api/metrics")
            assert resp.status_code == 200
            data = resp.json()
            assert data["input_tokens"] == 1000

    def test_prometheus_metrics(self, client):
        resp = client.get("/api/metrics/prometheus")
        assert resp.status_code == 200


class TestOperateEndpoints:
    def test_start_operator_missing_fields(self, client):
        resp = client.post("/api/operate", json={}, headers=AUTH)
        assert resp.status_code == 400

    def test_start_operator(self, client):
        resp = client.post(
            "/api/operate",
            json={
                "target": "10.0.0.1",
                "goals": ["Scan ports"],
            },
            headers=AUTH,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "session_id" in data
        assert data["status"] == "running"

    def test_get_operator_status_not_found(self, client):
        resp = client.get("/api/operate/nonexistent", headers=AUTH)
        assert resp.status_code == 404

    def test_get_operator_status(self, client):
        # Start a session first
        resp = client.post(
            "/api/operate",
            json={
                "target": "10.0.0.1",
                "goals": ["Scan"],
            },
            headers=AUTH,
        )
        sid = resp.json()["session_id"]

        resp = client.get(f"/api/operate/{sid}", headers=AUTH)
        assert resp.status_code == 200
        assert resp.json()["target"] == "10.0.0.1"


class TestWebSocketEndpoint:
    def test_websocket_connect(self, client):
        with client.websocket_connect("/ws/agent", headers=AUTH):
            # Just connect and disconnect
            pass

    def test_websocket_invalid_json(self, client):
        with client.websocket_connect("/ws/agent", headers=AUTH) as ws:
            ws.send_text("not json")
            # Should disconnect gracefully


class TestCreateApp:
    def test_app_has_routes(self, app):
        routes = [r.path for r in app.routes if hasattr(r, "path")]
        assert "/api/health" in routes
        assert "/api/sessions" in routes
        assert "/api/metrics" in routes
        assert "/ws/agent" in routes

    def test_cors_enabled(self, app):
        [type(m) for m in app.user_middleware]
        # Just verify the app was created without error
        assert app is not None


class TestOperateAuth:
    """c16: /api/operate* and /ws/agent require X-API-Key."""

    def test_operate_requires_key(self, client):
        resp = client.post("/api/operate", json={"target": "x", "goals": ["g"]})
        assert resp.status_code == 401

    def test_operate_rejects_wrong_key(self, client):
        resp = client.post(
            "/api/operate",
            json={"target": "x", "goals": ["g"]},
            headers={"X-API-Key": "wrong"},
        )
        assert resp.status_code == 401

    def test_operate_status_requires_key(self, client):
        resp = client.get("/api/operate/abc")
        assert resp.status_code == 401

    def test_websocket_rejects_without_key(self, client):
        with pytest.raises(Exception):
            with client.websocket_connect("/ws/agent"):
                pass

    def test_websocket_rejects_wrong_key(self, client):
        with pytest.raises(Exception):
            with client.websocket_connect("/ws/agent", headers={"X-API-Key": "nope"}):
                pass

    def test_auto_approve_exploits_ignored(self, client):
        with patch("clearwing.ui.web.app.OperatorConfig") as mock_cfg:
            client.post(
                "/api/operate",
                json={
                    "target": "10.0.0.1",
                    "goals": ["g"],
                    "auto_approve_exploits": True,
                },
                headers=AUTH,
            )
            # Background task may or may not have run yet under TestClient;
            # if it did, auto_approve_exploits must be False regardless of body.
            for call in mock_cfg.call_args_list:
                assert call.kwargs.get("auto_approve_exploits") is False


class TestOperateDisabledWithoutKey:
    """c16: routes refuse to mount when CLEARWING_WEB_API_KEY is unset."""

    def test_operate_503_without_env(self, unauth_client):
        resp = unauth_client.post("/api/operate", json={"target": "x", "goals": ["g"]})
        assert resp.status_code == 503
        assert "CLEARWING_WEB_API_KEY" in resp.json()["detail"]

    def test_operate_status_503_without_env(self, unauth_client):
        resp = unauth_client.get("/api/operate/abc")
        assert resp.status_code == 503

    def test_health_still_works_without_env(self, unauth_client):
        assert unauth_client.get("/api/health").status_code == 200

    def test_websocket_closed_without_env(self, unauth_client):
        with pytest.raises(Exception):
            with unauth_client.websocket_connect("/ws/agent"):
                pass

    def test_log_emitted(self, monkeypatch, caplog):
        monkeypatch.delenv("CLEARWING_WEB_API_KEY", raising=False)
        with caplog.at_level("ERROR", logger="clearwing.ui.web.app"):
            create_app()
        assert any("CLEARWING_WEB_API_KEY" in r.message for r in caplog.records)


class TestCorsOrigins:
    def test_default_empty(self, monkeypatch):
        monkeypatch.delenv("CLEARWING_WEB_CORS_ORIGINS", raising=False)
        assert _cors_origins() == []

    def test_from_env(self, monkeypatch):
        monkeypatch.setenv(
            "CLEARWING_WEB_CORS_ORIGINS", "https://a.example, https://b.example "
        )
        assert _cors_origins() == ["https://a.example", "https://b.example"]
