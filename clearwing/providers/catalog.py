"""Shared provider catalog for the setup wizard and doctor command.

One dataclass-backed table of known LLM providers — name, base URL
default, recommended model default, API key env var name, the
"getting started" URL, and a short human description. The `setup`
command iterates this to build its menu; the `doctor` command uses it
to format network-reachability checks and credentials help text.

Adding a new provider means adding one entry here.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ProviderPreset:
    """One known LLM backend, with enough metadata to configure it."""

    #: Short key used for CLI choice arguments and config lookups.
    #: Stable across versions — operators script against it.
    key: str

    #: Human-readable name shown in the setup menu.
    display_name: str

    #: One-line description shown under the name in the menu.
    description: str

    #: URL users visit to get an API key (or learn how to install).
    docs_url: str

    #: Default `base_url` for the OpenAI-compatible endpoint. None for
    #: Anthropic direct, which does not use a base_url override.
    default_base_url: str | None = None

    #: Default model identifier. Used both as the initial prompt
    #: default in the setup wizard and as a sanity check in doctor.
    default_model: str = ""

    #: Name of the env var conventionally used by this provider
    #: (e.g. OPENROUTER_API_KEY). When set, the setup wizard can
    #: offer to reference it via `${NAME}` instead of prompting for
    #: the literal secret. None for keyless backends (Ollama / LM
    #: Studio).
    api_key_env_var: str | None = None

    #: True if this backend runs locally (no network round-trip to
    #: a vendor). Used by doctor's reachability check.
    is_local: bool = False

    #: True if this provider's default endpoint is OpenAI-compatible.
    #: False for Anthropic direct (which uses a different transport).
    is_openai_compat: bool = True

    #: Optional list of extra models to show as alternatives in the
    #: setup wizard ("Common models: ..." hint).
    alt_models: tuple[str, ...] = field(default_factory=tuple)

    #: Required genai-pyo3 adapter name. Every preset in the catalog
    #: declares exactly one of: `anthropic`, `openai`, `openai_resp`,
    #: `openai_codex`, `ollama`, `gemini`. The wizard persists this as
    #: `adapter:` under `provider:` in `~/.clearwing/config.yaml` and
    #: the provider manager routes by it — no base-URL guessing on
    #: preset-driven configs.
    provider_adapter: str = ""

    #: Optional named auth flow. OAuth providers use this to skip API-key
    #: prompts and write an auth marker into config.yaml.
    auth_flow: str | None = None


# --- The catalog ----------------------------------------------------------


#: Ordered list — the order here is the order they appear in the setup menu.
#: OAuth providers first (no API key needed); then Anthropic direct, then
#: the rest in rough order of user familiarity.
PROVIDER_PRESETS: tuple[ProviderPreset, ...] = (
    ProviderPreset(
        key="anthropic-oauth",
        display_name="Anthropic OAuth (Claude Code)",
        description="Claude via browser OAuth, no API key. Uses your claude.ai account.",
        docs_url="https://claude.ai/",
        default_base_url=None,
        default_model="claude-sonnet-4-6",
        api_key_env_var=None,
        is_openai_compat=False,
        alt_models=("claude-opus-4-7", "claude-opus-4-6", "claude-haiku-4-5-20251001"),
        provider_adapter="anthropic",
        auth_flow="anthropic_oauth",
    ),
    ProviderPreset(
        key="openai-oauth",
        display_name="OpenAI OAuth (ChatGPT)",
        description="ChatGPT Plus/Pro browser OAuth, no Platform API key. Uses the Codex backend.",
        docs_url="https://chatgpt.com/",
        default_base_url="https://chatgpt.com/backend-api",
        default_model="gpt-5.2",
        api_key_env_var=None,
        is_openai_compat=False,
        alt_models=("gpt-5.4", "gpt-5.4-mini", "gpt-5.2"),
        provider_adapter="openai_codex",
        auth_flow="openai_codex",
    ),
    ProviderPreset(
        key="anthropic",
        display_name="Anthropic direct (API key)",
        description="Claude via API key from console.anthropic.com.",
        docs_url="https://console.anthropic.com/",
        default_base_url=None,
        default_model="claude-sonnet-4-6",
        api_key_env_var="ANTHROPIC_API_KEY",
        is_openai_compat=False,
        alt_models=("claude-opus-4-7", "claude-opus-4-6", "claude-haiku-4-5-20251001"),
        provider_adapter="anthropic",
    ),
    ProviderPreset(
        key="openrouter",
        display_name="OpenRouter",
        description="One key, 200+ models. Claude / GPT / Llama / Gemini / Qwen via "
        "`anthropic/...` / `openai/...` / `meta-llama/...` model names.",
        docs_url="https://openrouter.ai/keys",
        default_base_url="https://openrouter.ai/api/v1",
        default_model="anthropic/claude-opus-4",
        api_key_env_var="OPENROUTER_API_KEY",
        alt_models=(
            "anthropic/claude-opus-4.7",
            "anthropic/claude-sonnet-4",
            "anthropic/claude-haiku-4-5",
            "openai/gpt-4o",
            "meta-llama/llama-3.3-70b-instruct",
            "qwen/qwen-2.5-coder-32b-instruct",
            "google/gemini-2.0-flash",
        ),
        provider_adapter="openai",
    ),
    ProviderPreset(
        key="ollama",
        display_name="Ollama (local, native adapter)",
        description="Local models, free, no API key. Uses the native "
        "rust-genai Ollama adapter at http://localhost:11434.",
        docs_url="https://ollama.com/download",
        default_base_url="http://localhost:11434",
        default_model="qwen2.5-coder:32b",
        api_key_env_var=None,
        is_local=True,
        alt_models=("qwen2.5:72b", "llama3.3:70b", "mistral-small3:24b"),
        provider_adapter="ollama",
    ),
    ProviderPreset(
        key="lmstudio",
        display_name="LM Studio (local)",
        description="Local models with a GUI loader, free, no API key. "
        "OpenAI-compatible server at http://localhost:1234/v1.",
        docs_url="https://lmstudio.ai/",
        default_base_url="http://localhost:1234/v1",
        default_model="local-model",
        api_key_env_var=None,
        is_local=True,
        provider_adapter="openai",
    ),
    ProviderPreset(
        key="openai",
        display_name="OpenAI (Chat Completions API)",
        description="GPT-4o / GPT-4o-mini via `/v1/chat/completions` on "
        "api.openai.com. Use `openai-responses` for GPT-5.x and o-series "
        "reasoning models.",
        docs_url="https://platform.openai.com/api-keys",
        default_base_url="https://api.openai.com/v1",
        default_model="gpt-4o",
        api_key_env_var="OPENAI_API_KEY",
        alt_models=("gpt-4o-mini",),
        provider_adapter="openai",
    ),
    ProviderPreset(
        key="openai-responses",
        display_name="OpenAI (Responses API)",
        description="GPT-5.x / o-series / current reasoning models via "
        "`/v1/responses` on api.openai.com. Required for GPT-5.x and "
        "the o-series; works for GPT-4o too. Streams by default.",
        docs_url="https://platform.openai.com/api-keys",
        default_base_url="https://api.openai.com/v1",
        default_model="gpt-5.4",
        api_key_env_var="OPENAI_API_KEY",
        alt_models=("gpt-5.4-mini", "gpt-5.3-codex", "o3", "o3-mini", "gpt-4o"),
        provider_adapter="openai_resp",
    ),
    ProviderPreset(
        key="together",
        display_name="Together AI",
        description="Managed hosting for Llama / Qwen / DeepSeek / Mixtral.",
        docs_url="https://api.together.xyz/settings/api-keys",
        default_base_url="https://api.together.xyz/v1",
        default_model="meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
        api_key_env_var="TOGETHER_API_KEY",
        alt_models=(
            "Qwen/Qwen2.5-Coder-32B-Instruct",
            "deepseek-ai/DeepSeek-V3",
            "mistralai/Mixtral-8x22B-Instruct-v0.1",
        ),
        provider_adapter="openai",
    ),
    ProviderPreset(
        key="groq",
        display_name="Groq",
        description="Fast inference on Llama / Qwen / Mixtral via LPU hardware.",
        docs_url="https://console.groq.com/keys",
        default_base_url="https://api.groq.com/openai/v1",
        default_model="llama-3.3-70b-versatile",
        api_key_env_var="GROQ_API_KEY",
        alt_models=("qwen-2.5-coder-32b", "mixtral-8x7b-32768"),
        provider_adapter="openai",
    ),
    ProviderPreset(
        key="fireworks",
        display_name="Fireworks AI",
        description="Hosted Llama / Qwen / DeepSeek / Mixtral.",
        docs_url="https://fireworks.ai/account/api-keys",
        default_base_url="https://api.fireworks.ai/inference/v1",
        default_model="accounts/fireworks/models/qwen2p5-coder-32b-instruct",
        api_key_env_var="FIREWORKS_API_KEY",
        provider_adapter="openai",
    ),
    ProviderPreset(
        key="deepseek",
        display_name="DeepSeek",
        description="DeepSeek-Chat and DeepSeek-Coder via api.deepseek.com.",
        docs_url="https://platform.deepseek.com/api_keys",
        default_base_url="https://api.deepseek.com/v1",
        default_model="deepseek-chat",
        api_key_env_var="DEEPSEEK_API_KEY",
        alt_models=("deepseek-coder",),
        provider_adapter="openai",
    ),
    ProviderPreset(
        key="minimax",
        display_name="MiniMax",
        description="MiniMax M2.7 / M2.5 reasoning models via the Anthropic-compatible "
        "endpoint at api.minimax.io/anthropic. 200K context.",
        docs_url="https://platform.minimax.io/",
        default_base_url="https://api.minimax.io/anthropic",
        default_model="MiniMax-M2.7",
        api_key_env_var="MINIMAX_API_KEY",
        is_openai_compat=False,
        alt_models=(
            "MiniMax-M2.7-highspeed",
            "MiniMax-M2.5",
            "MiniMax-M2.5-highspeed",
            "MiniMax-M2.1",
        ),
        provider_adapter="anthropic",
    ),
    ProviderPreset(
        key="custom",
        display_name="Custom OpenAI-compatible endpoint (/v1/chat/completions)",
        description="Any service that speaks `/v1/chat/completions` — vLLM, "
        "SGLang, SiliconFlow, Anyscale, a reverse proxy, etc. Use "
        "`openai-responses` for `/v1/responses` endpoints instead.",
        docs_url="https://docs.anthropic.com/en/api/openai-sdk",  # generic reference
        default_base_url="",
        default_model="",
        api_key_env_var=None,
        provider_adapter="openai",
    ),
)


def preset_by_key(key: str) -> ProviderPreset | None:
    """Look up a provider preset by its short key. Case-insensitive."""
    key_lower = key.lower().strip()
    aliases = {
        "openai_oauth": "openai-oauth",
        "openai-codex": "openai-oauth",
        "openai_codex": "openai-oauth",
        "anthropic_oauth": "anthropic-oauth",
        "claude-code": "anthropic-oauth",
        "claude_code": "anthropic-oauth",
    }
    key_lower = aliases.get(key_lower, key_lower)
    for preset in PROVIDER_PRESETS:
        if preset.key == key_lower:
            return preset
    return None


__all__ = [
    "PROVIDER_PRESETS",
    "ProviderPreset",
    "preset_by_key",
]
