"""Model capabilities, inference profiles, and role bindings.

Three layers, each answering exactly one question (see docs/model-roles.md):

    Model         "what is technically possible?"   -> ModelCapabilities
    Role binding  "how much cognition do I buy?"     -> InferenceProfile
    (task route)  "how should this workflow run?"     -> agent limits (elsewhere)

**Capabilities are intrinsic facts** about an endpoint/model — context
window, output ceiling, tool support, which reasoning levels exist. They
do not depend on how Clearwing uses the model.

**An inference profile is a policy decision** — how hard to make this model
think and how much to let it write *for one role*. The same model serves
several roles at different profiles (DeepSeek Flash as a `low`-reasoning
coordinator and a `high`-reasoning researcher).

Binding a role to a model means picking a profile, and that pick is
validated against the model's capabilities at load time: asking for a
reasoning level a model doesn't have, or an output budget past its
ceiling, fails immediately instead of halfway through a scan.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace

from clearwing.llm.native import _model_supports_reasoning_effort

# ---------------------------------------------------------------------------
# Reasoning levels — a canonical order so validation can compare them.
# ---------------------------------------------------------------------------

#: Ascending deliberation. ``none`` and ``off`` are synonyms for "omit".
REASONING_ORDER: tuple[str, ...] = (
    "none",
    "minimal",
    "low",
    "medium",
    "high",
    "xhigh",
    "max",
)


def normalize_reasoning(value: str | None) -> str | None:
    """Canonicalize a reasoning token. ``off`` -> ``none``; None/auto pass."""
    if value is None:
        return None
    v = str(value).strip().lower()
    if v == "off":
        return "none"
    return v


# ---------------------------------------------------------------------------
# InferenceProfile — the policy knobs on a role binding.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InferenceProfile:
    """How to operate a model for one role. Every field optional.

    Fields left ``None`` inherit — from the role default, then the
    provider/model default, then Clearwing's built-in behavior. ``reasoning``
    uses the vocabulary in :data:`REASONING_ORDER`.
    """

    reasoning: str | None = None
    max_output_tokens: int | None = None
    temperature: float | None = None
    top_p: float | None = None
    # Staged (schema + validation only for now; not yet on the wire):
    context_budget_tokens: int | None = None
    tool_choice: str | None = None
    parallel_tool_calls: bool | None = None
    timeout_seconds: int | None = None

    def merged(self, override: InferenceProfile | None) -> InferenceProfile:
        """Return self with every set field of *override* applied on top."""
        if override is None:
            return self
        changes = {
            k: v for k, v in override.__dict__.items() if v is not None
        }
        return replace(self, **changes)

    @classmethod
    def from_dict(cls, d: Mapping | None) -> InferenceProfile:
        if not d:
            return cls()
        return cls(
            reasoning=normalize_reasoning(d.get("reasoning")),
            max_output_tokens=d.get("max_output_tokens"),
            temperature=d.get("temperature"),
            top_p=d.get("top_p"),
            context_budget_tokens=d.get("context_budget_tokens"),
            tool_choice=d.get("tool_choice"),
            parallel_tool_calls=d.get("parallel_tool_calls"),
            timeout_seconds=d.get("timeout_seconds"),
        )


# ---------------------------------------------------------------------------
# ModelCapabilities — intrinsic facts about a model.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AgentLimits:
    """Workflow bounds for an agentic loop — the task-route layer.

    Distinct from the inference profile: these bound *how the workflow runs*
    (how many assistant turns, how many tool calls) rather than a single
    model call. ``None`` fields are unbounded.
    """

    max_steps: int | None = None
    max_tool_calls: int | None = None
    max_retries: int | None = None

    @classmethod
    def from_dict(cls, d: Mapping | None) -> AgentLimits | None:
        if not d:
            return None
        return cls(
            max_steps=d.get("max_steps"),
            max_tool_calls=d.get("max_tool_calls"),
            max_retries=d.get("max_retries"),
        )

    @property
    def is_empty(self) -> bool:
        return (
            self.max_steps is None
            and self.max_tool_calls is None
            and self.max_retries is None
        )


def validate_agent_limits(route: str, d: Mapping | None) -> list[str]:
    """Return problems for an ``agent:`` block (positive integers only)."""
    if not d:
        return []
    problems: list[str] = []
    for name in ("max_steps", "max_tool_calls", "max_retries"):
        v = d.get(name)
        if v is None:
            continue
        if isinstance(v, bool) or not isinstance(v, int) or v <= 0:
            problems.append(f"route {route!r} {name}={v!r} must be a positive integer")
    return problems


@dataclass(frozen=True)
class ReasoningSupport:
    """What reasoning a model can do.

    ``levels`` empty means "supported but the exact set is unknown" — so
    validation won't reject a level, only the outright-unsupported case.
    """

    supported: bool = True
    levels: tuple[str, ...] = ()
    can_disable: bool = True


@dataclass(frozen=True)
class ModelCapabilities:
    """Intrinsic facts about an endpoint/model. ``None`` == unknown.

    Unknown fields are not validated against — Clearwing never fabricates a
    limit it doesn't actually know. Declare exact numbers in a
    ``model_roles.models:`` block when you want output/context validation.
    """

    context_window: int | None = None
    max_output_tokens: int | None = None
    tools: bool = True
    parallel_tools: bool = True
    structured_output: bool = True
    vision: bool = False
    streaming: bool = True
    reasoning: ReasoningSupport = field(default_factory=ReasoningSupport)

    @classmethod
    def from_dict(cls, d: Mapping | None) -> ModelCapabilities:
        if not d:
            return cls()
        r = d.get("reasoning")
        if isinstance(r, Mapping):
            reasoning = ReasoningSupport(
                supported=bool(r.get("supported", True)),
                levels=tuple(normalize_reasoning(x) for x in (r.get("levels") or ())),
                can_disable=bool(r.get("can_disable", True)),
            )
        elif isinstance(r, bool):
            reasoning = ReasoningSupport(supported=r)
        else:
            reasoning = ReasoningSupport()
        return cls(
            context_window=d.get("context_window"),
            max_output_tokens=d.get("max_output_tokens"),
            tools=bool(d.get("tools", True)),
            parallel_tools=bool(d.get("parallel_tools", True)),
            structured_output=bool(d.get("structured_output", True)),
            vision=bool(d.get("vision", False)),
            streaming=bool(d.get("streaming", True)),
            reasoning=reasoning,
        )


def capabilities_for(
    model: str, declared: ModelCapabilities | None = None
) -> ModelCapabilities:
    """Best-effort capabilities for *model*, merged over any *declared* facts.

    The only thing Clearwing infers on its own is reasoning support, which it
    grounds in the same denylist the client uses (Qwen2 / Gemma / Llama /
    Mistral reject the ``reasoning_effort`` parameter). Everything else stays
    unknown unless the operator declares it — so validation never invents a
    ceiling. A declared value always wins.
    """
    if declared is not None:
        return declared
    supported = _model_supports_reasoning_effort(model)
    return ModelCapabilities(reasoning=ReasoningSupport(supported=supported))


# ---------------------------------------------------------------------------
# Model family — for the reviewer independence constraint.
# ---------------------------------------------------------------------------

_FAMILY_PATTERNS: tuple[tuple[str, str], ...] = (
    ("claude", "claude"),
    ("gpt", "openai"),
    ("o1", "openai"),
    ("o3", "openai"),
    ("o4", "openai"),
    ("qwen", "qwen"),
    ("llama", "llama"),
    ("deepseek", "deepseek"),
    ("minimax", "minimax"),
    ("gemini", "gemini"),
    ("gemma", "gemma"),
    ("mistral", "mistral"),
    ("mixtral", "mistral"),
)


def model_family(model: str) -> str:
    """Coarse model-family label used to judge reviewer independence.

    A reviewer that shares a family with the model it reviews is not truly
    independent, so :func:`clearwing.providers.roles.recommend_roles` uses
    this to avoid handing a finding back to its own family.
    """
    lower = (model or "").lower()
    for needle, family in _FAMILY_PATTERNS:
        if needle in lower:
            return family
    return "unknown"


# ---------------------------------------------------------------------------
# Validation.
# ---------------------------------------------------------------------------


class BindingValidationError(ValueError):
    """Raised when one or more role bindings are incompatible with a model."""


def validate_inference(
    role: str,
    model: str,
    inference: InferenceProfile,
    capabilities: ModelCapabilities,
) -> list[str]:
    """Return a list of human-readable problems (empty when the binding is ok)."""
    problems: list[str] = []
    r = normalize_reasoning(inference.reasoning)

    if r is not None and r not in ("none", "auto"):
        if not capabilities.reasoning.supported:
            problems.append(
                f"role {role!r} requests reasoning={inference.reasoning!r}, but model "
                f"{model!r} does not support the reasoning_effort parameter"
            )
        elif capabilities.reasoning.levels and r not in capabilities.reasoning.levels:
            allowed = ", ".join(capabilities.reasoning.levels)
            problems.append(
                f"role {role!r} requests reasoning={inference.reasoning!r}, but model "
                f"{model!r} supports only: {allowed}"
            )
    if r == "none" and not capabilities.reasoning.can_disable:
        problems.append(
            f"role {role!r} disables reasoning, but model {model!r} cannot disable it"
        )

    if (
        inference.max_output_tokens is not None
        and capabilities.max_output_tokens is not None
        and inference.max_output_tokens > capabilities.max_output_tokens
    ):
        problems.append(
            f"role {role!r} sets max_output_tokens={inference.max_output_tokens}, "
            f"above model {model!r} ceiling of {capabilities.max_output_tokens}"
        )

    if (
        inference.context_budget_tokens is not None
        and capabilities.context_window is not None
        and inference.context_budget_tokens > capabilities.context_window
    ):
        problems.append(
            f"role {role!r} sets context_budget_tokens={inference.context_budget_tokens}, "
            f"above model {model!r} context window of {capabilities.context_window}"
        )

    return problems


__all__ = [
    "REASONING_ORDER",
    "normalize_reasoning",
    "InferenceProfile",
    "AgentLimits",
    "validate_agent_limits",
    "ReasoningSupport",
    "ModelCapabilities",
    "capabilities_for",
    "model_family",
    "BindingValidationError",
    "validate_inference",
]
