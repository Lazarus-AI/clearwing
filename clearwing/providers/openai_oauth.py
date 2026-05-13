"""OAuth support for OpenAI Codex and Anthropic Claude Code.

OpenAI Codex: mirrors the ChatGPT subscription OAuth flow used by the
Codex CLI — browser PKCE login on localhost, refresh-token persistence
under ``~/.clearwing/auth/``, and authenticated calls to the ChatGPT
backend API.

Anthropic Claude Code: PKCE browser login against ``claude.ai``, with
token exchange and refresh via ``console.anthropic.com``. Credentials
are stored alongside the OpenAI ones and auto-refreshed on demand.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import queue
import secrets
import socket
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from socketserver import TCPServer
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - non-Unix fallback
    fcntl = None  # type: ignore[assignment]


OPENAI_CODEX_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
OPENAI_CODEX_AUTHORIZE_URL = "https://auth.openai.com/oauth/authorize"
OPENAI_CODEX_TOKEN_URL = "https://auth.openai.com/oauth/token"  # noqa: S105
OPENAI_CODEX_REDIRECT_URI = "http://localhost:1455/auth/callback"
OPENAI_CODEX_CALLBACK_PORT = 1455
OPENAI_CODEX_CALLBACK_PATH = "/auth/callback"
OPENAI_CODEX_SCOPE = "openid profile email offline_access"
OPENAI_CODEX_ORIGINATOR = "pi"
OPENAI_CODEX_DEFAULT_BASE_URL = "https://chatgpt.com/backend-api"
OPENAI_CODEX_DEFAULT_MODEL = "gpt-5.2"
OPENAI_CODEX_OAUTH_CONFIG_KEY = "oauth.openai_codex"
OPENAI_AUTH_JWT_CLAIM_PATH = "https://api.openai.com/auth"

# --- Anthropic Claude Code OAuth constants ----------------------------------

ANTHROPIC_OAUTH_CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
ANTHROPIC_OAUTH_AUTHORIZE_URL = "https://claude.ai/oauth/authorize"
ANTHROPIC_OAUTH_TOKEN_URL = "https://console.anthropic.com/v1/oauth/token"  # noqa: S105
ANTHROPIC_OAUTH_REFRESH_TOKEN_URLS = (
    "https://platform.claude.com/v1/oauth/token",
    "https://console.anthropic.com/v1/oauth/token",
)
ANTHROPIC_OAUTH_MANUAL_REDIRECT_URI = "https://console.anthropic.com/oauth/code/callback"
ANTHROPIC_OAUTH_SCOPE = "org:create_api_key user:profile user:inference"
ANTHROPIC_SETUP_TOKEN_PREFIX = "sk-ant-oat01-"  # noqa: S105
ANTHROPIC_SETUP_TOKEN_MIN_LENGTH = 80
ANTHROPIC_SETUP_TOKEN_CONFIG_KEY = "token.anthropic_setup_token"  # noqa: S105
ANTHROPIC_CLAUDE_CODE_COMMON_BETAS = (
    "interleaved-thinking-2025-05-14",
    "fine-grained-tool-streaming-2025-05-14",
    "context-1m-2025-08-07",
)
ANTHROPIC_CLAUDE_CODE_OAUTH_BETAS = (
    "claude-code-20250219",
    "oauth-2025-04-20",
)
ANTHROPIC_CLAUDE_CODE_BETA = ",".join(
    (*ANTHROPIC_CLAUDE_CODE_COMMON_BETAS, *ANTHROPIC_CLAUDE_CODE_OAUTH_BETAS)
)
ANTHROPIC_CLAUDE_CODE_VERSION_FALLBACK = "2.1.74"
_anthropic_claude_code_version_cache: str | None = None

# --- Common infrastructure --------------------------------------------------

from clearwing.core.config import clearwing_home

AUTH_DIR = clearwing_home() / "auth"


@dataclass(frozen=True)
class OpenAIOAuthCredentials:
    access: str
    refresh: str
    expires_ms: int
    account_id: str


@dataclass(frozen=True)
class AnthropicOAuthCredentials:
    token: str
    refresh: str = ""
    expires_ms: int = 0


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(raw: str) -> bytes:
    s = (raw or "").strip()
    if not s:
        return b""
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode(s + pad)


def generate_pkce() -> tuple[str, str]:
    verifier = _b64url_encode(secrets.token_bytes(32))
    challenge = _b64url_encode(hashlib.sha256(verifier.encode("utf-8")).digest())
    return verifier, challenge


def create_state() -> str:
    return secrets.token_hex(16)


def build_authorize_url(
    *,
    challenge: str,
    state: str,
    redirect_uri: str = OPENAI_CODEX_REDIRECT_URI,
    originator: str = OPENAI_CODEX_ORIGINATOR,
) -> str:
    params = {
        "response_type": "code",
        "client_id": OPENAI_CODEX_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "scope": OPENAI_CODEX_SCOPE,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
        "originator": originator,
    }
    return f"{OPENAI_CODEX_AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"


def parse_authorization_input(value: str) -> tuple[str | None, str | None]:
    """Accept a full callback URL, ``code#state``, query string, or raw code."""
    v = (value or "").strip()
    if not v:
        return None, None

    parsed = urllib.parse.urlparse(v)
    if parsed.scheme and parsed.netloc:
        qs = urllib.parse.parse_qs(parsed.query)
        return (qs.get("code") or [None])[0], (qs.get("state") or [None])[0]

    if "#" in v:
        code, st = v.split("#", 1)
        return code or None, st or None

    if "code=" in v:
        qs = urllib.parse.parse_qs(v)
        return (qs.get("code") or [None])[0], (qs.get("state") or [None])[0]

    return v, None


def decode_jwt_payload(token: str) -> dict[str, Any] | None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        return json.loads(_b64url_decode(parts[1]).decode("utf-8"))
    except Exception:
        return None


def extract_account_id(access_token: str) -> str | None:
    payload = decode_jwt_payload(access_token)
    auth = payload.get(OPENAI_AUTH_JWT_CLAIM_PATH) if isinstance(payload, dict) else None
    account_id = auth.get("chatgpt_account_id") if isinstance(auth, dict) else None
    return account_id if isinstance(account_id, str) and account_id else None


def _post_form(
    url: str,
    data: dict[str, str],
    *,
    error_label: str = "OAuth token request",
    headers: dict[str, str] | None = None,
    timeout_seconds: int = 30,
) -> dict[str, Any]:
    body = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded", **(headers or {})},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{error_label} failed: HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"{error_label} failed: {exc}") from exc
    return json.loads(raw)


def _post_json(
    url: str,
    data: dict[str, Any],
    *,
    error_label: str = "OAuth token request",
    headers: dict[str, str] | None = None,
    timeout_seconds: int = 30,
) -> dict[str, Any]:
    body = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            **(headers or {}),
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{error_label} failed: HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"{error_label} failed: {exc}") from exc


def exchange_authorization_code(
    *,
    code: str,
    verifier: str,
    redirect_uri: str = OPENAI_CODEX_REDIRECT_URI,
) -> OpenAIOAuthCredentials:
    data = _post_form(
        OPENAI_CODEX_TOKEN_URL,
        {
            "grant_type": "authorization_code",
            "client_id": OPENAI_CODEX_CLIENT_ID,
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": redirect_uri,
        },
    )
    return _credentials_from_token_response(data, "exchange")


def refresh_openai_oauth_token(refresh_token: str) -> OpenAIOAuthCredentials:
    data = _post_form(
        OPENAI_CODEX_TOKEN_URL,
        {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": OPENAI_CODEX_CLIENT_ID,
        },
    )
    return _credentials_from_token_response(data, "refresh")


def _credentials_from_token_response(data: dict[str, Any], label: str) -> OpenAIOAuthCredentials:
    access = data.get("access_token")
    refresh = data.get("refresh_token")
    expires_in = data.get("expires_in")
    if not isinstance(access, str) or not isinstance(refresh, str):
        raise RuntimeError(f"OpenAI OAuth token {label} failed: missing access/refresh token.")
    if not isinstance(expires_in, int | float):
        raise RuntimeError(f"OpenAI OAuth token {label} failed: missing expires_in.")

    account_id = extract_account_id(access)
    if not account_id:
        raise RuntimeError(f"OpenAI OAuth token {label} failed: missing ChatGPT account id.")

    return OpenAIOAuthCredentials(
        access=access,
        refresh=refresh,
        expires_ms=int(time.time() * 1000) + int(expires_in * 1000),
        account_id=account_id,
    )


def credentials_to_dict(creds: OpenAIOAuthCredentials) -> dict[str, Any]:
    return {
        "access": creds.access,
        "refresh": creds.refresh,
        "expires_ms": int(creds.expires_ms),
        "account_id": creds.account_id,
    }


def credentials_from_value(value: Any) -> OpenAIOAuthCredentials | None:
    if value is None:
        return None
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except Exception:
            return None
    if not isinstance(value, dict):
        return None

    access = value.get("access")
    refresh = value.get("refresh")
    expires_ms = value.get("expires_ms") or value.get("expires")
    account_id = value.get("account_id") or value.get("accountId")
    if not isinstance(access, str) or not isinstance(refresh, str):
        return None
    if not isinstance(expires_ms, int | float):
        return None
    if not isinstance(account_id, str) or not account_id:
        account_id = extract_account_id(access) or ""
    if not account_id:
        return None
    return OpenAIOAuthCredentials(
        access=access,
        refresh=refresh,
        expires_ms=int(expires_ms),
        account_id=account_id,
    )


def _auth_file(key: str = OPENAI_CODEX_OAUTH_CONFIG_KEY) -> Path:
    return AUTH_DIR / f"{key}.json"


def _ensure_auth_dir() -> None:
    AUTH_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(AUTH_DIR, 0o700)
    except OSError:
        pass


def load_openai_oauth_credentials() -> OpenAIOAuthCredentials | None:
    path = _auth_file()
    try:
        return credentials_from_value(json.loads(path.read_text(encoding="utf-8")))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def save_openai_oauth_credentials(creds: OpenAIOAuthCredentials) -> None:
    _ensure_auth_dir()
    path = _auth_file()
    fd, tmp = tempfile.mkstemp(dir=AUTH_DIR, suffix=".tmp", prefix=f"{OPENAI_CODEX_OAUTH_CONFIG_KEY}.")
    try:
        os.write(fd, json.dumps(credentials_to_dict(creds), indent=2).encode("utf-8"))
        os.fsync(fd)
        os.close(fd)
        os.replace(tmp, path)
        os.chmod(path, 0o600)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def delete_openai_oauth_credentials() -> None:
    try:
        _auth_file().unlink()
    except FileNotFoundError:
        pass


@contextmanager
def _auth_lock(key: str = OPENAI_CODEX_OAUTH_CONFIG_KEY) -> Generator[None, None, None]:
    _ensure_auth_dir()
    lock_path = AUTH_DIR / f"{key}.lock"
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR)
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def ensure_fresh_openai_oauth_credentials(
    *,
    skew_seconds: int = 300,
) -> OpenAIOAuthCredentials:
    with _auth_lock():
        creds = load_openai_oauth_credentials()
        if not creds:
            raise RuntimeError("OpenAI OAuth is not configured. Run: `clearwing setup --provider openai-oauth`")

        now_ms = int(time.time() * 1000)
        if creds.expires_ms > now_ms + skew_seconds * 1000:
            return creds

        refreshed = refresh_openai_oauth_token(creds.refresh)
        save_openai_oauth_credentials(refreshed)
        return refreshed


def run_callback_server(
    *,
    port: int = OPENAI_CODEX_CALLBACK_PORT,
    callback_path: str = OPENAI_CODEX_CALLBACK_PATH,
    timeout_seconds: int = 60,
    expected_state: str | None = None,
) -> dict[str, str] | None:
    result_queue: queue.Queue[dict[str, str]] = queue.Queue(maxsize=1)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: Any, **_kwargs: Any) -> None:
            return

        def do_GET(self) -> None:  # noqa: N802
            parsed = urllib.parse.urlparse(self.path or "")
            if parsed.path != callback_path:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Not found")
                return

            qs = urllib.parse.parse_qs(parsed.query)
            code = (qs.get("code") or [""])[0]
            state = (qs.get("state") or [""])[0]
            if expected_state is not None and state != expected_state:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"State mismatch")
                return
            if not code:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Missing authorization code")
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                b"<!doctype html><html><body>"
                b"<p>Authentication successful. Return to your terminal.</p>"
                b"</body></html>"
            )
            try:
                result_queue.put_nowait({"code": code, "state": state})
            except Exception:
                pass

    server: TCPServer | None = None
    try:
        server = TCPServer(("127.0.0.1", port), Handler)
    except OSError:
        return None

    def _serve() -> None:
        assert server is not None
        with server:
            server.serve_forever(poll_interval=0.1)

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    try:
        return result_queue.get(timeout=max(5, timeout_seconds))
    except Exception:
        return None
    finally:
        try:
            server.shutdown()
        except Exception:
            pass
        thread.join(timeout=1.0)


def is_callback_port_available() -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", OPENAI_CODEX_CALLBACK_PORT))
        return True
    except OSError:
        return False


def login_openai_oauth(
    *,
    no_open: bool = False,
    timeout_seconds: int = 60,
    allow_manual_fallback: bool = True,
    input_fn=input,
    print_fn=print,
) -> OpenAIOAuthCredentials:
    """Run the browser OAuth flow and persist credentials."""
    if not is_callback_port_available():
        raise RuntimeError("Port 1455 is required for OpenAI OAuth but is already in use.")

    verifier, challenge = generate_pkce()
    state = create_state()
    auth_url = build_authorize_url(challenge=challenge, state=state)

    print_fn("OpenAI OAuth")
    print_fn("1. A browser window should open. Sign in to ChatGPT and approve.")
    print_fn("2. If the callback page fails to load, paste the browser URL here.")
    print_fn(auth_url)

    if not no_open:
        try:
            webbrowser.open(auth_url)
        except Exception:
            pass

    result = run_callback_server(timeout_seconds=timeout_seconds, expected_state=state)
    code: str | None = result.get("code") if result else None

    if not code and not allow_manual_fallback:
        raise RuntimeError("Authorization callback not received.")

    if not code:
        pasted = input_fn("Paste the authorization code (or full redirect URL): ").strip()
        parsed_code, parsed_state = parse_authorization_input(pasted)
        if parsed_state and parsed_state != state:
            raise RuntimeError("State mismatch. Paste the redirect URL from this login attempt.")
        code = parsed_code

    if not code:
        raise RuntimeError("Missing authorization code.")

    creds = exchange_authorization_code(code=code, verifier=verifier)
    save_openai_oauth_credentials(creds)
    return ensure_fresh_openai_oauth_credentials(skew_seconds=0)


# --- Anthropic Claude Code OAuth flow ---------------------------------------


def detect_anthropic_claude_code_version() -> str:
    import subprocess

    for cmd in ("claude", "claude-code"):
        try:
            result = subprocess.run(
                [cmd, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except Exception:
            continue
        version = (result.stdout or "").strip().split()
        if result.returncode == 0 and version and version[0][:1].isdigit():
            return version[0]
    return ANTHROPIC_CLAUDE_CODE_VERSION_FALLBACK


def anthropic_claude_code_user_agent() -> str:
    global _anthropic_claude_code_version_cache  # noqa: PLW0603
    if _anthropic_claude_code_version_cache is None:
        _anthropic_claude_code_version_cache = detect_anthropic_claude_code_version()
    return f"claude-cli/{_anthropic_claude_code_version_cache} (external, cli)"


def build_anthropic_authorize_url(
    *,
    challenge: str,
    state: str,
    redirect_uri: str = ANTHROPIC_OAUTH_MANUAL_REDIRECT_URI,
) -> str:
    params = {
        "code": "true",
        "client_id": ANTHROPIC_OAUTH_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": ANTHROPIC_OAUTH_SCOPE,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
    }
    return f"{ANTHROPIC_OAUTH_AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"


def exchange_anthropic_authorization_code(
    *,
    code: str,
    state: str,
    verifier: str,
    redirect_uri: str = ANTHROPIC_OAUTH_MANUAL_REDIRECT_URI,
) -> AnthropicOAuthCredentials:
    data = _post_json(
        ANTHROPIC_OAUTH_TOKEN_URL,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": ANTHROPIC_OAUTH_CLIENT_ID,
            "code_verifier": verifier,
            "state": state,
        },
        error_label="Anthropic OAuth token exchange",
        headers={"User-Agent": anthropic_claude_code_user_agent()},
    )
    access = data.get("access_token")
    if not isinstance(access, str) or not access:
        raise RuntimeError("Anthropic OAuth token exchange failed: missing access_token.")
    error = validate_anthropic_setup_token(access)
    if error:
        raise RuntimeError(f"Anthropic OAuth token exchange returned an invalid token: {error}")
    refresh = data.get("refresh_token")
    expires_in = data.get("expires_in")
    expires_ms = (
        int(time.time() * 1000) + int(float(expires_in) * 1000)
        if isinstance(expires_in, int | float)
        else 0
    )
    return AnthropicOAuthCredentials(
        token=access,
        refresh=refresh if isinstance(refresh, str) else "",
        expires_ms=expires_ms,
    )


def refresh_anthropic_token(refresh_token: str) -> AnthropicOAuthCredentials:
    if not refresh_token:
        raise RuntimeError("Anthropic OAuth token refresh failed: missing refresh token.")

    last_error: Exception | None = None
    for endpoint in ANTHROPIC_OAUTH_REFRESH_TOKEN_URLS:
        try:
            data = _post_form(
                endpoint,
                {
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": ANTHROPIC_OAUTH_CLIENT_ID,
                },
                error_label=f"Anthropic OAuth token refresh at {endpoint}",
                headers={"User-Agent": anthropic_claude_code_user_agent()},
                timeout_seconds=10,
            )
        except RuntimeError as exc:
            last_error = exc
            continue

        access = data.get("access_token")
        if not isinstance(access, str) or not access:
            raise RuntimeError("Anthropic OAuth token refresh failed: missing access_token.")
        error = validate_anthropic_setup_token(access)
        if error:
            raise RuntimeError(f"Anthropic OAuth token refresh returned an invalid token: {error}")
        next_refresh = data.get("refresh_token")
        expires_in = data.get("expires_in", 3600)
        return AnthropicOAuthCredentials(
            token=access,
            refresh=next_refresh if isinstance(next_refresh, str) and next_refresh else refresh_token,
            expires_ms=int(time.time() * 1000) + int(float(expires_in) * 1000),
        )

    if last_error is not None:
        raise RuntimeError(f"Anthropic OAuth token refresh failed: {last_error}") from last_error
    raise RuntimeError("Anthropic OAuth token refresh failed.")


def validate_anthropic_setup_token(token: str) -> str | None:
    if not token:
        return "Token is empty."
    if token.startswith("sk-ant-api"):
        return "Token is an Anthropic API key, not an OAuth/setup token."
    if token.startswith(ANTHROPIC_SETUP_TOKEN_PREFIX) and len(token) < ANTHROPIC_SETUP_TOKEN_MIN_LENGTH:
        return f"Token is too short (min {ANTHROPIC_SETUP_TOKEN_MIN_LENGTH} chars)."
    if token.startswith("sk-ant-") or token.startswith("eyJ") or token.startswith("cc-"):
        return None
    return "Token does not look like an Anthropic OAuth/setup token."


def anthropic_credentials_to_dict(creds: AnthropicOAuthCredentials) -> dict[str, Any]:
    data: dict[str, Any] = {"token": creds.token}
    if creds.refresh:
        data["refresh"] = creds.refresh
    if creds.expires_ms:
        data["expires_ms"] = int(creds.expires_ms)
    return data


def anthropic_credentials_from_value(value: Any) -> AnthropicOAuthCredentials | None:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except Exception:
            return None
    if not isinstance(value, dict):
        return None
    token = (
        value.get("token")
        or value.get("access")
        or value.get("accessToken")
        or value.get("access_token")
    )
    if not isinstance(token, str) or not token:
        return None
    refresh = value.get("refresh") or value.get("refreshToken") or value.get("refresh_token")
    expires_ms = (
        value.get("expires_ms")
        or value.get("expiresAt")
        or value.get("expires_at_ms")
        or value.get("expires")
        or 0
    )
    return AnthropicOAuthCredentials(
        token=token,
        refresh=refresh if isinstance(refresh, str) else "",
        expires_ms=int(expires_ms) if isinstance(expires_ms, int | float) else 0,
    )


_CLAUDE_CLI_CREDENTIAL_PATH = Path.home() / ".claude" / ".credentials.json"


def load_anthropic_oauth_credentials() -> AnthropicOAuthCredentials | None:
    path = _auth_file(ANTHROPIC_SETUP_TOKEN_CONFIG_KEY)
    try:
        creds = anthropic_credentials_from_value(
            json.loads(path.read_text(encoding="utf-8"))
        )
        if creds:
            return creds
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass
    if _CLAUDE_CLI_CREDENTIAL_PATH.exists():
        try:
            data = json.loads(_CLAUDE_CLI_CREDENTIAL_PATH.read_text(encoding="utf-8"))
            oauth = data.get("claudeAiOauth")
            if isinstance(oauth, dict):
                return anthropic_credentials_from_value(oauth)
        except Exception:
            pass
    return None


def save_anthropic_oauth_credentials(creds: AnthropicOAuthCredentials) -> None:
    _ensure_auth_dir()
    path = _auth_file(ANTHROPIC_SETUP_TOKEN_CONFIG_KEY)
    fd, tmp = tempfile.mkstemp(dir=AUTH_DIR, suffix=".tmp", prefix=f"{ANTHROPIC_SETUP_TOKEN_CONFIG_KEY}.")
    try:
        os.write(fd, json.dumps(anthropic_credentials_to_dict(creds), indent=2).encode("utf-8"))
        os.fsync(fd)
        os.close(fd)
        os.replace(tmp, path)
        os.chmod(path, 0o600)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def ensure_fresh_anthropic_oauth_credentials(
    *,
    skew_seconds: int = 300,
) -> AnthropicOAuthCredentials:
    with _auth_lock(ANTHROPIC_SETUP_TOKEN_CONFIG_KEY):
        creds = load_anthropic_oauth_credentials()
        if not creds:
            raise RuntimeError(
                "Anthropic OAuth is not configured. Run: `clearwing setup --provider anthropic-oauth`"
            )
        if not creds.refresh or not creds.expires_ms:
            return creds
        now_ms = int(time.time() * 1000)
        if creds.expires_ms > now_ms + skew_seconds * 1000:
            return creds
        refreshed = refresh_anthropic_token(creds.refresh)
        save_anthropic_oauth_credentials(refreshed)
        return refreshed


def anthropic_oauth_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "anthropic-beta": ANTHROPIC_CLAUDE_CODE_BETA,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
        "user-agent": anthropic_claude_code_user_agent(),
        "x-app": "cli",
    }


def login_anthropic_oauth(
    *,
    no_open: bool = False,
    timeout_seconds: int = 300,
    input_fn=input,
    print_fn=print,
) -> AnthropicOAuthCredentials:
    verifier, challenge = generate_pkce()
    state = verifier
    auth_url = build_anthropic_authorize_url(
        challenge=challenge,
        state=state,
        redirect_uri=ANTHROPIC_OAUTH_MANUAL_REDIRECT_URI,
    )

    print_fn("Anthropic OAuth / Claude Code")
    print_fn("Open this link, sign in to Claude, approve Clearwing, then paste the code shown:")
    print_fn(auth_url)
    if not no_open:
        try:
            webbrowser.open(auth_url)
        except Exception:
            pass

    pasted = input_fn("Paste the authorization code or full redirect URL: ").strip()
    code, parsed_state = parse_authorization_input(pasted)
    if parsed_state and parsed_state != state:
        raise RuntimeError("State mismatch. Paste the code from this login attempt.")
    if not code:
        raise RuntimeError("Missing Anthropic authorization code.")
    creds = exchange_anthropic_authorization_code(
        code=code,
        state=parsed_state or state,
        verifier=verifier,
        redirect_uri=ANTHROPIC_OAUTH_MANUAL_REDIRECT_URI,
    )
    save_anthropic_oauth_credentials(creds)
    return creds


__all__ = [
    "ANTHROPIC_CLAUDE_CODE_BETA",
    "ANTHROPIC_SETUP_TOKEN_CONFIG_KEY",
    "AnthropicOAuthCredentials",
    "OPENAI_AUTH_JWT_CLAIM_PATH",
    "OPENAI_CODEX_DEFAULT_BASE_URL",
    "OPENAI_CODEX_DEFAULT_MODEL",
    "OPENAI_CODEX_OAUTH_CONFIG_KEY",
    "OpenAIOAuthCredentials",
    "anthropic_claude_code_user_agent",
    "anthropic_oauth_headers",
    "build_anthropic_authorize_url",
    "build_authorize_url",
    "create_state",
    "credentials_from_value",
    "credentials_to_dict",
    "decode_jwt_payload",
    "delete_openai_oauth_credentials",
    "ensure_fresh_anthropic_oauth_credentials",
    "ensure_fresh_openai_oauth_credentials",
    "exchange_anthropic_authorization_code",
    "exchange_authorization_code",
    "extract_account_id",
    "generate_pkce",
    "load_anthropic_oauth_credentials",
    "load_openai_oauth_credentials",
    "login_anthropic_oauth",
    "login_openai_oauth",
    "parse_authorization_input",
    "refresh_anthropic_token",
    "refresh_openai_oauth_token",
    "save_anthropic_oauth_credentials",
    "save_openai_oauth_credentials",
    "validate_anthropic_setup_token",
]
