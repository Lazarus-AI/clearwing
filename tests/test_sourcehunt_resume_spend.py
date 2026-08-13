from __future__ import annotations

import json

import pytest

from clearwing.llm.budget import SpendLedger


def _ledger(tmp_path, session_id="sh-spend", *, limit=10, resume=False):
    return SpendLedger(
        limit_usd=limit,
        session_id=session_id,
        repo_url="repo",
        output_dir=tmp_path,
        input_price_per_million=0,
        output_price_per_million=1_000_000,
        resume=resume,
    )


def test_settled_spend_is_restored_once(tmp_path):
    ledger = _ledger(tmp_path)
    reservation = ledger.reserve_call(
        model="test",
        provider="test",
        stage="hunt",
        input_token_upper_bound=0,
        requested_max_output_tokens=1,
        supports_output_limit=True,
    )
    ledger.settle_call(reservation, input_tokens=0, output_tokens=1)

    resumed = _ledger(tmp_path, resume=True)
    resumed_again = _ledger(tmp_path, resume=True)

    assert resumed.spent_usd == pytest.approx(1)
    assert resumed_again.spent_usd == pytest.approx(1)


def test_orphan_reservation_uses_cap_active_when_reserved(tmp_path):
    uncapped = _ledger(tmp_path, "sh-uncapped", limit=0)
    uncapped.reserve_call(
        model="test",
        provider="test",
        stage="hunt",
        input_token_upper_bound=0,
        requested_max_output_tokens=1,
        supports_output_limit=True,
    )

    resumed = _ledger(tmp_path, "sh-uncapped", limit=1, resume=True)

    assert resumed.spent_usd == 0


def test_capped_orphan_is_charged_once_even_when_new_cap_is_higher(tmp_path):
    capped = _ledger(tmp_path, "sh-capped", limit=1)
    reservation = capped.reserve_call(
        model="test",
        provider="test",
        stage="hunt",
        input_token_upper_bound=0,
        requested_max_output_tokens=1,
        supports_output_limit=True,
    )

    resumed = _ledger(tmp_path, "sh-capped", limit=10, resume=True)
    resumed_again = _ledger(tmp_path, "sh-capped", limit=10, resume=True)
    events = [
        json.loads(line) for line in resumed.ledger_path.read_text(encoding="utf-8").splitlines()
    ]

    assert resumed.spent_usd == pytest.approx(1)
    assert resumed_again.spent_usd == pytest.approx(1)
    assert sum(
        event.get("event") == "call_settled" and event.get("call_id") == reservation.call_id
        for event in events
    ) == 1
