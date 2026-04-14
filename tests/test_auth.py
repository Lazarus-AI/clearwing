from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from vulnexploit.safety.auth import (
    AuthConfig,
    AuthConfigLoader,
    FormLogin,
    APIAuth,
    CookieAuth,
    OAuthConfig,
)


# ---------------------------------------------------------------------------
# Dataclass defaults
# ---------------------------------------------------------------------------

class TestFormLoginDefaults:
    def test_defaults(self):
        form = FormLogin(url="http://example.com/login")
        assert form.url == "http://example.com/login"
        assert form.username_field == "username"
        assert form.password_field == "password"
        assert form.submit_selector == "button[type=submit]"
        assert form.username == ""
        assert form.password == ""
        assert form.success_indicator == ""
        assert form.failure_indicator == ""


class TestAPIAuthDefaults:
    def test_defaults(self):
        api = APIAuth(auth_type="bearer")
        assert api.auth_type == "bearer"
        assert api.token == ""
        assert api.header_name == "Authorization"
        assert api.header_prefix == "Bearer"
        assert api.api_key_param == ""
        assert api.username == ""
        assert api.password == ""


class TestCookieAuthDefaults:
    def test_defaults(self):
        cookie = CookieAuth()
        assert cookie.cookies == {}


class TestOAuthConfigDefaults:
    def test_defaults(self):
        oauth = OAuthConfig()
        assert oauth.auth_url == ""
        assert oauth.token_url == ""
        assert oauth.client_id == ""
        assert oauth.client_secret == ""
        assert oauth.scope == ""
        assert oauth.redirect_uri == ""


# ---------------------------------------------------------------------------
# AuthConfig.has_credentials
# ---------------------------------------------------------------------------

class TestAuthConfigHasCredentials:
    def test_form_with_credentials(self):
        config = AuthConfig(
            target="http://10.0.0.1",
            auth_type="form",
            form=FormLogin(url="http://10.0.0.1/login", username="admin", password="secret"),
        )
        assert config.has_credentials() is True

    def test_form_without_credentials(self):
        config = AuthConfig(
            target="http://10.0.0.1",
            auth_type="form",
            form=FormLogin(url="http://10.0.0.1/login"),
        )
        assert config.has_credentials() is False

    def test_api_with_token(self):
        config = AuthConfig(
            target="http://api.example.com",
            auth_type="api",
            api=APIAuth(auth_type="bearer", token="tok_abc123"),
        )
        assert config.has_credentials() is True

    def test_api_with_basic_auth(self):
        config = AuthConfig(
            target="http://api.example.com",
            auth_type="api",
            api=APIAuth(auth_type="basic", username="user", password="pass"),
        )
        assert config.has_credentials() is True

    def test_api_without_credentials(self):
        config = AuthConfig(
            target="http://api.example.com",
            auth_type="api",
            api=APIAuth(auth_type="bearer"),
        )
        assert config.has_credentials() is False

    def test_cookie_with_cookies(self):
        config = AuthConfig(
            target="http://10.0.0.1",
            auth_type="cookie",
            cookie=CookieAuth(cookies={"session": "abc123"}),
        )
        assert config.has_credentials() is True

    def test_cookie_without_cookies(self):
        config = AuthConfig(
            target="http://10.0.0.1",
            auth_type="cookie",
            cookie=CookieAuth(),
        )
        assert config.has_credentials() is False

    def test_oauth_with_client_id(self):
        config = AuthConfig(
            target="http://10.0.0.1",
            auth_type="oauth",
            oauth=OAuthConfig(client_id="my-client"),
        )
        assert config.has_credentials() is True

    def test_oauth_without_client_id(self):
        config = AuthConfig(
            target="http://10.0.0.1",
            auth_type="oauth",
            oauth=OAuthConfig(),
        )
        assert config.has_credentials() is False

    def test_none_auth_type(self):
        config = AuthConfig(target="http://10.0.0.1", auth_type="none")
        assert config.has_credentials() is False


# ---------------------------------------------------------------------------
# AuthConfigLoader
# ---------------------------------------------------------------------------

FORM_YAML = """\
target: "http://10.0.0.1"
auth_type: form
form:
  url: "http://10.0.0.1/login"
  username: admin
  password: "${TARGET_PASSWORD}"
  success_indicator: "Dashboard"
"""

API_YAML = """\
target: "http://api.example.com"
auth_type: api
api:
  auth_type: bearer
  token: "tok_abc123"
"""

COOKIE_YAML = """\
target: "http://10.0.0.1"
auth_type: cookie
cookie:
  cookies:
    session: "abc123"
    csrf: "xyz789"
"""

OAUTH_YAML = """\
target: "http://10.0.0.1"
auth_type: oauth
oauth:
  auth_url: "https://auth.example.com/authorize"
  token_url: "https://auth.example.com/token"
  client_id: "my-client"
  client_secret: "${OAUTH_SECRET}"
  scope: "read write"
  redirect_uri: "http://localhost:8080/callback"
"""


@pytest.fixture
def loader(tmp_path, monkeypatch):
    """Create an AuthConfigLoader with a temp CONFIG_DIR."""
    monkeypatch.setattr(AuthConfigLoader, "CONFIG_DIR", tmp_path)
    return AuthConfigLoader()


class TestAuthConfigLoaderLoad:
    def test_load_from_yaml(self, tmp_path, loader, monkeypatch):
        monkeypatch.setenv("TARGET_PASSWORD", "s3cret")
        config_file = tmp_path / "target.yml"
        config_file.write_text(FORM_YAML, encoding="utf-8")

        config = loader.load(str(config_file))

        assert config.target == "http://10.0.0.1"
        assert config.auth_type == "form"
        assert config.form is not None
        assert config.form.url == "http://10.0.0.1/login"
        assert config.form.username == "admin"
        assert config.form.password == "s3cret"
        assert config.form.success_indicator == "Dashboard"

    def test_missing_file_raises(self, loader):
        with pytest.raises(FileNotFoundError, match="Auth config not found"):
            loader.load("/nonexistent/path/config.yml")


class TestAuthConfigLoaderSaveRoundTrip:
    def test_save_and_reload(self, tmp_path, loader):
        original = AuthConfig(
            target="http://10.0.0.1",
            auth_type="form",
            form=FormLogin(
                url="http://10.0.0.1/login",
                username="admin",
                password="secret",
                success_indicator="Dashboard",
            ),
        )
        save_path = str(tmp_path / "roundtrip.yml")
        loader.save(original, path=save_path)

        reloaded = loader.load(save_path)

        assert reloaded.target == original.target
        assert reloaded.auth_type == original.auth_type
        assert reloaded.form.url == original.form.url
        assert reloaded.form.username == original.form.username
        assert reloaded.form.password == original.form.password
        assert reloaded.form.success_indicator == original.form.success_indicator
        assert reloaded.session_persistence == original.session_persistence


class TestResolveEnv:
    def test_resolve_env_variable(self, monkeypatch):
        monkeypatch.setenv("MY_SECRET", "hunter2")
        result = AuthConfigLoader._resolve_env("${MY_SECRET}")
        assert result == "hunter2"

    def test_plain_string_no_resolution(self):
        result = AuthConfigLoader._resolve_env("plain_value")
        assert result == "plain_value"

    def test_missing_env_returns_empty(self, monkeypatch):
        monkeypatch.delenv("NONEXISTENT_VAR_12345", raising=False)
        result = AuthConfigLoader._resolve_env("${NONEXISTENT_VAR_12345}")
        assert result == ""

    def test_non_string_value(self):
        result = AuthConfigLoader._resolve_env(42)
        assert result == "42"


class TestLoadForTarget:
    def test_matching_target(self, tmp_path, loader):
        config_file = tmp_path / "myapp.yml"
        config_file.write_text(FORM_YAML.replace("${TARGET_PASSWORD}", "pass"), encoding="utf-8")

        config = loader.load_for_target("http://10.0.0.1")

        assert config is not None
        assert config.target == "http://10.0.0.1"
        assert config.auth_type == "form"

    def test_no_matching_target(self, loader):
        config = loader.load_for_target("http://unknown.host")
        assert config is None

    def test_matching_yaml_extension(self, tmp_path, loader):
        config_file = tmp_path / "myapp.yaml"
        config_file.write_text(API_YAML, encoding="utf-8")

        config = loader.load_for_target("http://api.example.com")

        assert config is not None
        assert config.auth_type == "api"


class TestParseFormAuth:
    def test_parse_form(self, loader):
        raw = yaml.safe_load(FORM_YAML.replace("${TARGET_PASSWORD}", "pass123"))
        config = loader._parse(raw)

        assert config.auth_type == "form"
        assert config.form is not None
        assert config.form.url == "http://10.0.0.1/login"
        assert config.form.username == "admin"
        assert config.form.password == "pass123"
        assert config.form.success_indicator == "Dashboard"
        assert config.form.username_field == "username"
        assert config.form.password_field == "password"
        assert config.form.submit_selector == "button[type=submit]"


class TestParseAPIAuth:
    def test_parse_api_bearer(self, loader):
        raw = yaml.safe_load(API_YAML)
        config = loader._parse(raw)

        assert config.auth_type == "api"
        assert config.api is not None
        assert config.api.auth_type == "bearer"
        assert config.api.token == "tok_abc123"
        assert config.api.header_name == "Authorization"
        assert config.api.header_prefix == "Bearer"


class TestParseCookieAuth:
    def test_parse_cookie(self, loader):
        raw = yaml.safe_load(COOKIE_YAML)
        config = loader._parse(raw)

        assert config.auth_type == "cookie"
        assert config.cookie is not None
        assert config.cookie.cookies == {"session": "abc123", "csrf": "xyz789"}


class TestParseOAuthConfig:
    def test_parse_oauth(self, loader, monkeypatch):
        monkeypatch.setenv("OAUTH_SECRET", "oauth_secret_val")
        raw = yaml.safe_load(OAUTH_YAML)
        config = loader._parse(raw)

        assert config.auth_type == "oauth"
        assert config.oauth is not None
        assert config.oauth.auth_url == "https://auth.example.com/authorize"
        assert config.oauth.token_url == "https://auth.example.com/token"
        assert config.oauth.client_id == "my-client"
        assert config.oauth.client_secret == "oauth_secret_val"
        assert config.oauth.scope == "read write"
        assert config.oauth.redirect_uri == "http://localhost:8080/callback"
