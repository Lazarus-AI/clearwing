from __future__ import annotations

from clearwing.providers.binding import (
    AgentLimits,
    BindingValidationError,
    InferenceProfile,
    ModelCapabilities,
    ReasoningSupport,
    capabilities_for,
    model_family,
    validate_agent_limits,
    validate_inference,
)
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
from clearwing.providers.roles import (
    ROLES,
    TASK_ROLES,
    Role,
    RoleAssignment,
    Tier,
    recommend_roles,
    role_for_task,
)
from clearwing.providers.runtime import (
    install_runtime_routing,
    runtime_routing,
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
    # Model roles (vendor-neutral capability layer)
    "Tier",
    "Role",
    "ROLES",
    "TASK_ROLES",
    "RoleAssignment",
    "recommend_roles",
    "role_for_task",
    # Capabilities / inference bindings
    "InferenceProfile",
    "AgentLimits",
    "validate_agent_limits",
    "ModelCapabilities",
    "ReasoningSupport",
    "BindingValidationError",
    "capabilities_for",
    "model_family",
    "validate_inference",
    # One-run process provider routing
    "install_runtime_routing",
    "runtime_routing",
    # Provider catalog (for the setup wizard + doctor command)
    "KNOWN_PROVIDERS",
    "ProviderPreset",
    "preset_by_key",
]
