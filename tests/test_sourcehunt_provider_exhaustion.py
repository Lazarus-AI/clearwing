from __future__ import annotations

import asyncio

import pytest

from clearwing.llm import (
    ProviderExhaustedError,
    ProviderExhaustionState,
    is_provider_exhausted_error,
)
from clearwing.llm.budget import SpendLedger
from clearwing.llm.native import AsyncLLMClient


class _ProviderResponse:
    status_code = 403


class _ProviderError(RuntimeError):
    def __init__(self, message):
        super().__init__(message)
        self.response = _ProviderResponse()


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        (
            "HTTP 403 type: access_terminated_error message: "
            "You've reached your usage limit for this billing cycle",
            True,
        ),
        ("HTTP 401 unauthorized", False),
        ("HTTP 403 forbidden", False),
        ("HTTP 429 rate limit", False),
    ],
)
def test_provider_exhaustion_classification_is_narrow(message, expected):
    assert is_provider_exhausted_error(RuntimeError(message)) is expected


def test_provider_exhaustion_uses_structured_http_status():
    error = _ProviderError(
        "type: access_terminated_error; usage limit reached for this billing cycle"
    )

    assert is_provider_exhausted_error(error) is True


def test_provider_exhaustion_is_not_caught_by_ordinary_fallbacks():
    caught = False
    try:
        raise ProviderExhaustedError("quota")
    except Exception:
        caught = True
    except ProviderExhaustedError:
        pass

    assert caught is False


def test_exhaustion_marks_shared_clients_and_stops_before_dispatch(tmp_path):
    ledger = SpendLedger(
        limit_usd=0,
        session_id="sh-provider",
        repo_url="repo",
        output_dir=tmp_path,
    )
    state = ProviderExhaustionState()
    client = AsyncLLMClient(model_name="test", provider_name="openai", api_key="test")
    first = client.with_spend_ledger(
        ledger,
        stage="hunt",
        provider_exhaustion_state=state,
    )
    second = client.with_spend_ledger(
        ledger,
        stage="verify",
        provider_exhaustion_state=state,
    )
    state.mark(RuntimeError("quota"))

    with pytest.raises(ProviderExhaustedError, match="quota"):
        second._reserve_spend_call(messages=[], system="", tools=None, max_tokens=None)
    assert first._provider_exhaustion_state is second._provider_exhaustion_state


def test_rate_limit_retry_behavior_remains_bounded(monkeypatch):
    client = AsyncLLMClient(
        model_name="test",
        provider_name="openai",
        api_key="test",
        rate_limit_max_retries=2,
        rate_limit_initial_backoff_seconds=0.1,
    )
    attempts = 0

    async def fail():
        nonlocal attempts
        attempts += 1
        raise RuntimeError("HTTP 429 rate limit")

    async def no_sleep(_delay):
        return None

    monkeypatch.setattr(asyncio, "sleep", no_sleep)
    with pytest.raises(RuntimeError, match="429"):
        asyncio.run(client._with_retries(fail))
    assert attempts == 3
