"""Hard-cap and persistence regressions for the run-scoped LLM ledger."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from genai_pyo3 import ChatMessage, ChatResponse, Usage

from clearwing.llm.budget import (
    BudgetConfigurationError,
    BudgetExceeded,
    SpendLedger,
)
from clearwing.llm.native import AsyncLLMClient
from clearwing.sourcehunt.pool import HunterPool, HuntPoolConfig
from clearwing.sourcehunt.runner import SourceHuntRunner


def _ledger(tmp_path, *, budget: float = 1.0) -> SpendLedger:
    return SpendLedger(
        limit_usd=budget,
        session_id="budget-test",
        repo_url="/tmp/repo",
        output_dir=tmp_path,
        input_price_per_million=0.0,
        # One generated token costs one dollar. This makes reservations and
        # assertions exact without enormous synthetic usage counts.
        output_price_per_million=1_000_000.0,
    )


def test_strict_budget_rejects_unknown_pricing_before_dispatch(tmp_path):
    ledger = SpendLedger(
        limit_usd=1.0,
        session_id="unknown-model",
        repo_url="/tmp/repo",
        output_dir=tmp_path,
    )

    with pytest.raises(BudgetConfigurationError, match="No verified pricing"):
        ledger.validate_model(
            model="private-model-with-unknown-price",
            provider="openai",
            supports_output_limit=True,
        )

    assert ledger.spent_usd == 0.0


def test_budget_rejects_provider_without_output_ceiling(tmp_path, monkeypatch):
    from clearwing.providers import openai_oauth

    def fail_refresh():
        raise RuntimeError("no stored test credentials")

    monkeypatch.setattr(
        openai_oauth,
        "ensure_fresh_openai_oauth_credentials",
        fail_refresh,
    )
    monkeypatch.setattr(openai_oauth, "extract_account_id", lambda _token: "test-account")
    ledger = _ledger(tmp_path)
    client = AsyncLLMClient(
        model_name="private-priced-model",
        provider_name="openai_codex",
        api_key="test",
    )

    with pytest.raises(BudgetConfigurationError, match="output-token ceiling"):
        client.with_spend_ledger(ledger, stage="rank")


def test_gateway_requires_gateway_specific_pricing_override(tmp_path):
    ledger = SpendLedger(
        limit_usd=1.0,
        session_id="gateway-pricing",
        repo_url="/tmp/repo",
        output_dir=tmp_path,
    )

    with pytest.raises(BudgetConfigurationError, match="through a gateway"):
        ledger.validate_model(
            model="anthropic/claude-sonnet-4-6",
            provider="openai",
            supports_output_limit=True,
        )


def test_reservations_are_atomic_across_concurrent_native_calls(tmp_path, monkeypatch):
    ledger = _ledger(tmp_path)
    client = AsyncLLMClient(
        model_name="private-priced-model",
        provider_name="anthropic",
        api_key="test",
        max_concurrency=8,
    ).with_spend_ledger(ledger, stage="hunt")
    observed_caps: list[int | None] = []

    async def fake_policy(self, client_obj, request, options):
        observed_caps.append(options.max_tokens)
        await asyncio.sleep(0.01)
        return ChatResponse(
            content=[{"text": "done"}],
            usage=Usage(prompt_tokens=0, completion_tokens=1, total_tokens=1),
        )

    monkeypatch.setattr(AsyncLLMClient, "_build_client", lambda self, cls: object())
    monkeypatch.setattr(AsyncLLMClient, "_achat_with_provider_policy", fake_policy)

    async def run_calls():
        return await asyncio.gather(
            *[
                client.achat(messages=[ChatMessage("user", f"call {idx}")])
                for idx in range(8)
            ],
            return_exceptions=True,
        )

    results = asyncio.run(run_calls())

    assert sum(isinstance(result, ChatResponse) for result in results) == 1
    assert sum(isinstance(result, BudgetExceeded) for result in results) == 7
    assert observed_caps == [1]
    assert ledger.spent_usd == pytest.approx(1.0)
    assert ledger.remaining_usd == pytest.approx(0.0)


def test_unlimited_ledger_tracks_usage_without_changing_output_limit(
    tmp_path, monkeypatch,
):
    ledger = _ledger(tmp_path, budget=0.0)
    client = AsyncLLMClient(
        model_name="private-priced-model",
        provider_name="anthropic",
        api_key="test",
    ).with_spend_ledger(ledger, stage="rank")
    observed_caps: list[int | None] = []

    async def fake_policy(self, client_obj, request, options):
        observed_caps.append(options.max_tokens)
        return ChatResponse(
            content=[{"text": "done"}],
            usage=Usage(prompt_tokens=0, completion_tokens=2, total_tokens=2),
        )

    monkeypatch.setattr(AsyncLLMClient, "_build_client", lambda self, cls: object())
    monkeypatch.setattr(AsyncLLMClient, "_achat_with_provider_policy", fake_policy)

    asyncio.run(client.achat(messages=[ChatMessage("user", "unlimited")]))

    assert observed_caps == [None]
    assert ledger.spent_usd == pytest.approx(2.0)
    assert ledger.remaining_usd is None


@dataclass
class _RunResult:
    findings: list
    cost_usd: float
    tokens_used: int
    stop_reason: str


def test_parallel_hunter_pool_cannot_overspend_global_ledger(tmp_path, monkeypatch):
    ledger = _ledger(tmp_path)
    client = AsyncLLMClient(
        model_name="private-priced-model",
        provider_name="anthropic",
        api_key="test",
        max_concurrency=8,
    ).with_spend_ledger(ledger, stage="hunt")

    async def fake_policy(self, client_obj, request, options):
        await asyncio.sleep(0.01)
        return ChatResponse(
            content=[{"text": "done"}],
            usage=Usage(prompt_tokens=0, completion_tokens=1, total_tokens=1),
        )

    monkeypatch.setattr(AsyncLLMClient, "_build_client", lambda self, cls: object())
    monkeypatch.setattr(AsyncLLMClient, "_achat_with_provider_policy", fake_policy)

    files = [
        {
            "path": f"file-{idx}.c",
            "absolute_path": f"/tmp/file-{idx}.c",
            "surface": 5,
            "influence": 5,
            "reachability": 5,
            "priority": 5.0,
            "tier": "A",
            "tags": [],
            "language": "c",
            "loc": 1,
        }
        for idx in range(8)
    ]

    def factory(file_target, sandbox, session_id):
        context = MagicMock(session_id=session_id, cleanup_variants=MagicMock())

        class Hunter:
            async def arun(self):
                await client.achat(messages=[ChatMessage("user", file_target["path"])])
                return _RunResult(
                    findings=[{"id": file_target["path"]}],
                    cost_usd=1.0,
                    tokens_used=1,
                    stop_reason="completed",
                )

        return Hunter(), context

    pool = HunterPool(
        HuntPoolConfig(
            files=files,
            repo_path="/tmp",
            hunter_factory=factory,
            max_parallel=8,
            budget_usd=1.0,
            starting_band="deep",
            max_band="deep",
            redundancy_override=1,
        )
    )

    asyncio.run(pool.arun())

    assert ledger.spent_usd == pytest.approx(1.0)
    assert ledger.spent_usd <= ledger.limit_usd
    assert ledger.spent_by("tier", stage="hunt") == {"A": pytest.approx(1.0)}
    assert pool.budget_exhausted is True
    assert pool.completed_target_count == 1


def test_streaming_calls_settle_against_the_same_ledger(tmp_path, monkeypatch):
    ledger = _ledger(tmp_path)
    client = AsyncLLMClient(
        model_name="private-priced-model",
        provider_name="anthropic",
        api_key="test",
    ).with_spend_ledger(ledger, stage="verify")
    observed_caps: list[int | None] = []

    class StreamingClient:
        async def astream_chat(self, model, request, options):
            observed_caps.append(options.max_tokens)

            async def events():
                yield SimpleNamespace(content="ok", end=object())

            return events()

    response = ChatResponse(
        content=[{"text": "ok"}],
        usage=Usage(prompt_tokens=0, completion_tokens=1, total_tokens=1),
    )
    monkeypatch.setattr(
        AsyncLLMClient, "_build_client", lambda self, cls: StreamingClient(),
    )
    monkeypatch.setattr(
        AsyncLLMClient,
        "_chat_response_from_stream_end",
        lambda self, end: response,
    )
    deltas: list[str] = []

    result = asyncio.run(
        client.achat_stream(
            messages=[ChatMessage("user", "stream")],
            on_text_delta=deltas.append,
        )
    )

    assert result is response
    assert deltas == ["ok"]
    assert observed_caps == [1]
    assert ledger.spent_usd == pytest.approx(1.0)


def test_ledger_persists_reservations_settlements_and_final_status(tmp_path):
    ledger = _ledger(tmp_path)
    reservation = ledger.reserve_call(
        model="private-priced-model",
        provider="anthropic",
        stage="verify",
        input_token_upper_bound=0,
        requested_max_output_tokens=None,
        supports_output_limit=True,
        metadata={"finding_id": "finding-1"},
    )
    assert reservation.max_output_tokens == 1
    ledger.settle_call(
        reservation,
        input_tokens=0,
        output_tokens=1,
    )
    summary = ledger.finalize("budget_exhausted")

    manifest = json.loads(ledger.manifest_path.read_text(encoding="utf-8"))
    events = [
        json.loads(line)
        for line in ledger.ledger_path.read_text(encoding="utf-8").splitlines()
    ]

    assert summary["status"] == "budget_exhausted"
    assert summary["complete"] is False
    assert manifest["total_spent"] == pytest.approx(1.0)
    assert [event["event"] for event in events] == [
        "run_started",
        "call_reserved",
        "call_settled",
        "run_finished",
    ]
    assert events[2]["metadata"] == {"finding_id": "finding-1"}


def test_ambiguous_failure_consumes_reservation(tmp_path):
    ledger = _ledger(tmp_path)
    reservation = ledger.reserve_call(
        model="private-priced-model",
        provider="anthropic",
        stage="rank",
        input_token_upper_bound=0,
        requested_max_output_tokens=None,
        supports_output_limit=True,
    )

    ledger.fail_call(reservation, error="connection lost after request upload")

    assert ledger.spent_usd == pytest.approx(1.0)
    with pytest.raises(BudgetExceeded):
        ledger.reserve_call(
            model="private-priced-model",
            provider="anthropic",
            stage="rank",
            input_token_upper_bound=0,
            requested_max_output_tokens=None,
            supports_output_limit=True,
        )


def test_cancellation_closes_an_inflight_reservation(tmp_path, monkeypatch):
    ledger = _ledger(tmp_path)
    client = AsyncLLMClient(
        model_name="private-priced-model",
        provider_name="anthropic",
        api_key="test",
    ).with_spend_ledger(ledger, stage="hunt")

    async def exercise():
        entered = asyncio.Event()

        async def wait_forever(self, client_obj, request, options):
            entered.set()
            await asyncio.Event().wait()
            return ChatResponse()

        monkeypatch.setattr(AsyncLLMClient, "_build_client", lambda self, cls: object())
        monkeypatch.setattr(
            AsyncLLMClient, "_achat_with_provider_policy", wait_forever,
        )
        task = asyncio.create_task(
            client.achat(messages=[ChatMessage("user", "cancel me")])
        )
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(exercise())

    snapshot = ledger.snapshot()
    assert snapshot["reserved_usd"] == 0.0
    assert snapshot["total_spent"] == pytest.approx(1.0)


def test_runner_manifest_uses_ranker_ledger_not_hunter_totals(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def main():\n    return 0\n", encoding="utf-8")
    output = tmp_path / "out"
    client = AsyncLLMClient(
        model_name="private-priced-model",
        provider_name="anthropic",
        api_key="test",
    )

    async def fake_policy(self, client_obj, request, options):
        payload = {
            "results": [
                {
                    "path": "app.py",
                    "surface": 2,
                    "influence": 1,
                    "surface_rationale": "small input surface",
                    "influence_rationale": "isolated helper",
                }
            ]
        }
        return ChatResponse(
            content=[{"text": json.dumps(payload)}],
            usage=Usage(prompt_tokens=0, completion_tokens=1, total_tokens=1),
        )

    monkeypatch.setattr(AsyncLLMClient, "_build_client", lambda self, cls: object())
    monkeypatch.setattr(AsyncLLMClient, "_achat_with_provider_policy", fake_policy)

    runner = SourceHuntRunner(
        repo_url=str(repo),
        local_path=str(repo),
        depth="quick",
        budget_usd=1.0,
        input_price_per_million=0.0,
        output_price_per_million=1_000_000.0,
        output_dir=str(output),
        ranker_llm=client,
        enable_knowledge_graph=False,
        enable_mechanism_memory=False,
    )
    result = runner.run()
    manifest = json.loads(
        (output / result.session_id / "manifest.json").read_text(encoding="utf-8")
    )

    assert result.status == "completed"
    assert result.cost_usd == pytest.approx(1.0)
    assert result.spent_per_tier == {"A": 0.0, "B": 0.0, "C": 0.0}
    assert manifest["total_spent"] == pytest.approx(1.0)
    assert manifest["status"] == "completed"
    assert manifest["outputs"]["ledger"].endswith("spend-ledger.jsonl")


def test_runner_returns_clean_partial_result_when_budget_cannot_fit_call(
    tmp_path, monkeypatch,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def main():\n    return 0\n", encoding="utf-8")
    client = AsyncLLMClient(
        model_name="private-priced-model",
        provider_name="anthropic",
        api_key="test",
    )
    dispatched = False

    async def should_not_dispatch(self, client_obj, request, options):
        nonlocal dispatched
        dispatched = True
        return ChatResponse()

    monkeypatch.setattr(AsyncLLMClient, "_build_client", lambda self, cls: object())
    monkeypatch.setattr(
        AsyncLLMClient, "_achat_with_provider_policy", should_not_dispatch,
    )

    runner = SourceHuntRunner(
        repo_url=str(repo),
        local_path=str(repo),
        depth="quick",
        budget_usd=0.5,
        input_price_per_million=0.0,
        output_price_per_million=1_000_000.0,
        output_dir=str(tmp_path / "out"),
        ranker_llm=client,
        enable_knowledge_graph=False,
        enable_mechanism_memory=False,
    )
    result = runner.run()
    manifest = json.loads(
        (tmp_path / "out" / result.session_id / "manifest.json").read_text(
            encoding="utf-8"
        )
    )

    assert dispatched is False
    assert result.status == "budget_exhausted"
    assert result.exit_code == 3
    assert result.cost_usd == 0.0
    assert manifest["status"] == "budget_exhausted"
    assert manifest["complete"] is False


def test_no_rank_skips_ranker_pricing_preflight_and_dispatch(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def main():\n    return 0\n", encoding="utf-8")
    client = AsyncLLMClient(
        model_name="private-model-with-unknown-price",
        provider_name="openai",
        api_key="test",
    )
    dispatched = False

    async def should_not_dispatch(self, client_obj, request, options):
        nonlocal dispatched
        dispatched = True
        return ChatResponse()

    monkeypatch.setattr(
        AsyncLLMClient,
        "_achat_with_provider_policy",
        should_not_dispatch,
    )

    runner = SourceHuntRunner(
        repo_url=str(repo),
        local_path=str(repo),
        depth="quick",
        budget_usd=1.0,
        output_dir=str(tmp_path / "out"),
        ranker_llm=client,
        no_rank=True,
        enable_knowledge_graph=False,
        enable_mechanism_memory=False,
    )

    result = runner.run()

    assert dispatched is False
    assert result.status == "completed"
    assert result.cost_usd == 0.0
