from __future__ import annotations

from clearwing.providers.catalog import (
    PROVIDER_PRESETS as KNOWN_PROVIDERS,
)
from clearwing.providers.catalog import (
    ProviderPreset,
    preset_by_key,
)
from clearwing.providers.env import (
    DEFAULT_ANTHROPIC_MODEL,
    ENV_ANTHROPIC_KEY,
    ENV_API_KEY,
    ENV_BASE_URL,
    ENV_MODEL,
    EndpointPricing,
    LLMEndpoint,
    resolve_llm_endpoint,
)
from clearwing.providers.manager import (
    DEFAULT_ROUTES,
    PROVIDER_PRESETS,
    ModelRoute,
    ProviderConfig,
    ProviderManager,
)

__all__ = [
    # Endpoint resolution
    "LLMEndpoint",
    "EndpointPricing",
    "resolve_llm_endpoint",
    "ENV_BASE_URL",
    "ENV_API_KEY",
    "ENV_MODEL",
    "ENV_ANTHROPIC_KEY",
    "DEFAULT_ANTHROPIC_MODEL",
    # Provider manager + routing
    "ProviderManager",
    "ProviderConfig",
    "ModelRoute",
    "PROVIDER_PRESETS",
    "DEFAULT_ROUTES",
    # Provider catalog (for the setup wizard + doctor command)
    "KNOWN_PROVIDERS",
    "ProviderPreset",
    "preset_by_key",
]
