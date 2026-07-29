from __future__ import annotations

import base64
import json
import time
import urllib.parse

from clearwing.providers import openai_oauth as oauth
from clearwing.providers.openai_oauth import (
    OPENAI_AUTH_JWT_CLAIM_PATH,
    build_anthropic_authorize_url,
    build_authorize_url,
    credentials_from_value,
    extract_account_id,
    generate_pkce,
    parse_authorization_input,
)


def _b64url(obj) -> str:
    raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _fake_jwt(payload: dict) -> str:
    header = {"alg": "none", "typ": "JWT"}
    return f"{_b64url(header)}.{_b64url(payload)}.sig"


def test_generate_pkce_lengths():
    verifier, challenge = generate_pkce()
    assert 43 <= len(verifier) <= 128
    assert challenge


def test_build_authorize_url_contains_expected_params():
    url = build_authorize_url(challenge="CHALLENGE", state="STATE")
    assert "auth.openai.com/oauth/authorize" in url
    assert "code_challenge=CHALLENGE" in url
    assert "state=STATE" in url
    assert "codex_cli_simplified_flow=true" in url


def test_build_anthropic_authorize_url_uses_claude_subscription_callback():
    url = build_anthropic_authorize_url(challenge="CHALLENGE", state="STATE")
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    assert parsed.scheme == "https"
    assert parsed.netloc == "claude.ai"
    assert parsed.path == "/oauth/authorize"
    assert params["redirect_uri"] == ["https://console.anthropic.com/oauth/code/callback"]
    assert params["code_challenge"] == ["CHALLENGE"]
    assert params["state"] == ["STATE"]


def test_exchange_anthropic_authorization_code_posts_to_platform(monkeypatch):
    calls = []

    def fake_post_json(url, data, **kwargs):
        calls.append((url, data, kwargs))
        return {
            "access_token": "sk-ant-oat01-" + ("a" * 80),
            "refresh_token": "refresh",
            "expires_in": 3600,
        }

    monkeypatch.setattr(oauth, "_post_json", fake_post_json)
    monkeypatch.setattr(oauth, "anthropic_claude_code_user_agent", lambda: "ua")

    creds = oauth.exchange_anthropic_authorization_code(
        code="CODE",
        state="STATE",
        verifier="VERIFIER",
    )

    assert creds.token.startswith("sk-ant-oat01-")
    assert creds.refresh == "refresh"
    assert calls[0][0] == "https://platform.claude.com/v1/oauth/token"
    assert calls[0][1]["redirect_uri"] == "https://console.anthropic.com/oauth/code/callback"
    assert calls[0][1]["code"] == "CODE"
    assert calls[0][1]["code_verifier"] == "VERIFIER"
    assert calls[0][2]["headers"] == {"User-Agent": oauth.ANTHROPIC_OAUTH_TOKEN_USER_AGENT}


def test_load_anthropic_oauth_credentials_prefers_fresh_claude_code(monkeypatch, tmp_path):
    auth_file = tmp_path / "token.anthropic_setup_token.json"
    auth_file.write_text(
        json.dumps(
            {
                "token": "sk-ant-oat01-clearwing",
                "refresh": "clearwing-refresh",
                "expires_ms": int(time.time() * 1000) + 600_000,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(oauth, "_auth_file", lambda _key: auth_file)
    monkeypatch.setattr(oauth, "_read_claude_code_credentials_from_keychain", lambda: None)
    monkeypatch.setattr(
        oauth,
        "_read_claude_code_credentials_from_file",
        lambda: oauth.AnthropicOAuthCredentials(
            token="sk-ant-oat01-claude-code",
            refresh="claude-refresh",
            expires_ms=int(time.time() * 1000) + 600_000,
        ),
    )

    creds = oauth.load_anthropic_oauth_credentials()

    assert creds is not None
    assert creds.token == "sk-ant-oat01-claude-code"


def test_load_anthropic_oauth_credentials_uses_fresh_clearwing_over_stale_claude(
    monkeypatch, tmp_path
):
    auth_file = tmp_path / "token.anthropic_setup_token.json"
    auth_file.write_text(
        json.dumps(
            {
                "token": "sk-ant-oat01-clearwing",
                "refresh": "clearwing-refresh",
                "expires_ms": int(time.time() * 1000) + 600_000,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(oauth, "_auth_file", lambda _key: auth_file)
    monkeypatch.setattr(oauth, "_read_claude_code_credentials_from_keychain", lambda: None)
    monkeypatch.setattr(
        oauth,
        "_read_claude_code_credentials_from_file",
        lambda: oauth.AnthropicOAuthCredentials(
            token="sk-ant-oat01-stale-claude-code",
            refresh="stale-refresh",
            expires_ms=int(time.time() * 1000) - 600_000,
        ),
    )

    creds = oauth.load_anthropic_oauth_credentials()

    assert creds is not None
    assert creds.token == "sk-ant-oat01-clearwing"


def test_parse_authorization_input_url():
    code, state = parse_authorization_input("http://localhost:1455/auth/callback?code=abc&state=xyz")
    assert code == "abc"
    assert state == "xyz"


def test_parse_authorization_input_hash():
    code, state = parse_authorization_input("abc#xyz")
    assert code == "abc"
    assert state == "xyz"


def test_parse_authorization_input_querystring():
    code, state = parse_authorization_input("code=abc&state=xyz")
    assert code == "abc"
    assert state == "xyz"


def test_parse_authorization_input_raw_code():
    code, state = parse_authorization_input("abc")
    assert code == "abc"
    assert state is None


def test_extract_account_id_from_jwt():
    token = _fake_jwt({OPENAI_AUTH_JWT_CLAIM_PATH: {"chatgpt_account_id": "acct_123"}})
    assert extract_account_id(token) == "acct_123"


def test_credentials_from_legacy_shape_accepts_account_id():
    token = _fake_jwt({OPENAI_AUTH_JWT_CLAIM_PATH: {"chatgpt_account_id": "acct_123"}})
    creds = credentials_from_value(
        {
            "access": token,
            "refresh": "r",
            "expires": 123,
            "accountId": "acct_123",
        }
    )
    assert creds is not None
    assert creds.account_id == "acct_123"
