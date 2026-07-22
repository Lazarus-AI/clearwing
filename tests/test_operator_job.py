"""Tests for the transport-neutral Operator job adapter."""

from unittest.mock import AsyncMock, patch

import pytest

from clearwing.agent.operator import OperatorResult
from clearwing.agent.operator_job import (
    OperatorJobRequest,
    OperatorJobValidationError,
    run_operator_job,
)


class TestOperatorJobRequest:
    def test_defaults_and_normalization(self):
        request = OperatorJobRequest.from_mapping(
            {"target": " 10.0.0.1 ", "goals": [" Scan ports "]}
        )

        assert request.target == "10.0.0.1"
        assert request.goals == ["Scan ports"]
        assert request.model == "claude-sonnet-4-6"
        assert request.operator_model == ""
        assert request.max_turns == 100
        assert request.timeout_minutes == 60
        assert request.cost_limit == 0.0
        assert request.auto_approve_scans is True
        assert request.auto_approve_exploits is False

    def test_allows_explicit_domain_options(self):
        request = OperatorJobRequest.from_mapping(
            {
                "target": "example.test",
                "goals": ["scan", "report"],
                "model": "test-model",
                "operator_model": "operator-model",
                "max_turns": 12,
                "timeout_minutes": 5,
                "cost_limit": 1,
                "auto_approve_scans": False,
                "auto_approve_exploits": True,
            }
        )

        config = request.to_config()
        assert config.target == "example.test"
        assert config.goals == ["scan", "report"]
        assert config.operator_model == "operator-model"
        assert config.max_turns == 12
        assert config.timeout_minutes == 5
        assert config.cost_limit == 1.0
        assert config.auto_approve_scans is False
        assert config.auto_approve_exploits is True

    @pytest.mark.parametrize(
        ("body", "message"),
        [
            ({"goals": ["scan"]}, "target"),
            ({"target": "host", "goals": []}, "goals"),
            ({"target": "host", "goals": [""]}, r"goals\[0\]"),
            ({"target": "host", "goals": ["scan"], "max_turns": True}, "max_turns"),
            ({"target": "host", "goals": ["scan"], "cost_limit": -1}, "cost_limit"),
            (
                {"target": "host", "goals": ["scan"], "auto_approve_exploits": 1},
                "auto_approve_exploits",
            ),
            ({"target": "host", "goals": ["scan"], "api_key": "secret"}, "api_key"),
            ({"target": "host", "goals": ["scan"], "input": "provider payload"}, "input"),
        ],
    )
    def test_rejects_invalid_or_transport_specific_input(self, body, message):
        with pytest.raises(OperatorJobValidationError, match=message):
            OperatorJobRequest.from_mapping(body)


@pytest.mark.asyncio
async def test_run_operator_job_passes_progress_and_serializes_result():
    progress = []
    result = OperatorResult(
        goals=["scan"],
        target="host",
        status="completed",
        turns=3,
        findings=[{"severity": "high"}],
        conversation_summary="done",
    )

    with patch("clearwing.agent.operator_job.OperatorAgent") as agent_class:
        agent_class.return_value.arun = AsyncMock(return_value=result)
        serialized = await run_operator_job(
            {"target": "host", "goals": ["scan"]},
            on_progress=lambda role, content: progress.append((role, content)),
        )

    config = agent_class.call_args.args[0]
    config.on_message("agent", "working")
    assert progress == [("agent", "working")]
    assert serialized == {
        "goals": ["scan"],
        "target": "host",
        "status": "completed",
        "turns": 3,
        "findings": [{"severity": "high"}],
        "flags_found": [],
        "cost_usd": 0.0,
        "tokens_used": 0,
        "duration_seconds": 0.0,
        "escalation_question": "",
        "error": "",
        "conversation_summary": "done",
    }
