"""QuadB60 1,048,576-token envelope resolution."""

from __future__ import annotations

import json

from clearwing.llm.native import _configured_max_model_len
from clearwing.sourcehunt.config import parse_runtime_tuning_policy
from clearwing.sourcehunt.validator import _configured_validator_max_tokens


def test_missing_llm_block_defaults_to_quadb60_window():
    policy = parse_runtime_tuning_policy({"ok": True, "policy": {}})
    assert policy.llm.max_model_len == 1_048_576
    assert policy.llm.validator_max_tokens == 32_768
    assert policy.sourcehunt.ranker.enable_thinking is False


def test_explicit_llm_block_wins(monkeypatch):
    monkeypatch.setenv(
        "CLEARWING_RUNTIME_TUNING_JSON",
        json.dumps({"policy": {"llm": {"max_model_len": 524288, "validator_max_tokens": 4096}}}),
    )
    monkeypatch.setenv("CLEARWING_MAX_MODEL_LEN", "262144")
    monkeypatch.setenv("CLEARWING_VALIDATOR_MAX_TOKENS", "8192")
    assert _configured_max_model_len() == 524288
    assert _configured_validator_max_tokens() == 4096


def test_absent_json_uses_quadb60_default_not_stale_env_when_json_defaults(monkeypatch):
    monkeypatch.delenv("CLEARWING_RUNTIME_TUNING_JSON", raising=False)
    monkeypatch.setenv("CLEARWING_MAX_MODEL_LEN", "262144")
    # Empty JSON path still builds a default policy with the 1,048,576 window.
    assert _configured_max_model_len() == 1_048_576
