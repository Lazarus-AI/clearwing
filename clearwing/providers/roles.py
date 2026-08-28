"""Model roles — the vendor-neutral capability layer.

Clearwing has ~100 tools and a dozen LLM call sites, but only a handful
of *kinds* of cognition. A **role** names one kind ("investigate through
tools", "produce a testable artifact", "independently falsify a claim")
without naming a model. Each role decomposes into two things a provider
can actually be asked for:

    role -> (tier, reasoning_effort)

`tier` is a rung on a provider's capability ladder (small / mid / large);
`reasoning_effort` is the deliberation budget passed to the
model (the same vocabulary `AsyncLLMClient` accepts). Concrete model
identifiers never appear here — they come from whatever provider the
operator configured, via that provider's tier ladder in
:mod:`clearwing.providers.catalog`. That indirection is what lets
`hunter` mean "the mid-tier model, thinking hard" regardless of whether
the user is on Anthropic, OpenRouter, or a local Ollama box.

Three layers, resolved outward:

    task string  ->  role  ->  (tier, reasoning)  ->  concrete model
    (call site)     (here)      (here)                (provider ladder)

`TASK_ROLES` is the first arrow: it maps the task strings that call sites
already pass (``hunter``, ``ranker``, ``verifier``, ``sourcehunt_exploit``,
``operator`` …) onto roles, so nothing at the call sites has to change.
`recommend_roles` is the last arrow: given the providers the operator
configured, it fills every role with a concrete model — the "sensible
recommendation from the available providers".
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum

from clearwing.providers.binding import InferenceProfile, model_family
from clearwing.providers.catalog import ProviderPreset

# ---------------------------------------------------------------------------
# Tiers — the rungs a provider ladder must fill.
# ---------------------------------------------------------------------------


class Tier(str, Enum):
    """A rung on a provider's capability ladder.

    A provider only has to answer three questions ("what is your small /
    mid / large model?"), and every role resolves from those. Values are
    the keys used in :attr:`ProviderPreset.tier_models`.
    """

    SMALL = "small"  # cheap, bounded transforms and classification
    MID = "mid"  # the agentic workhorse (tool-use investigation, artifacts)
    LARGE = "large"  # frontier reasoning for hard / stuck / high-value work


# ---------------------------------------------------------------------------
# Roles — the stable vocabulary.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Role:
    """One kind of cognition Clearwing buys, independent of any vendor.

    Attributes:
        name: Stable identifier used in config (``roles:``) and routing.
        tier: Which rung of the provider ladder fills this role.
        inference: The role's *default* inference profile — reasoning
            budget plus output/temperature policy. Overridable per binding
            and per route.
        independent: When True, the resolver prefers a *different* model
            family than the primary one — the role is judging work the
            primary produced, so family diversity guards against a model
            rubber-stamping itself. Falls back to the primary's ladder when
            no independent family is configured (and says so).
        summary: One line shown by ``clearwing models``.
    """

    name: str
    tier: Tier
    inference: InferenceProfile = field(default_factory=InferenceProfile)
    independent: bool = False
    summary: str = ""

    @property
    def reasoning(self) -> str | None:
        """The role's default reasoning budget (from its inference profile)."""
        return self.inference.reasoning


#: The six runtime roles. ``coordinator`` / ``researcher`` / ``builder``
#: deliberately share the MID tier — they are the same physical model at
#: different inference profiles (and different names, so ``builder`` can later
#: be re-pointed at a coder model without touching ``researcher``). The
#: output budgets follow the "how much cognition do I buy" logic: bounded for
#: utility, generous for investigation/construction, largest for escalation.
ROLES: dict[str, Role] = {
    "utility": Role(
        "utility",
        Tier.SMALL,
        InferenceProfile(reasoning="none", max_output_tokens=8192),
        summary="Bounded transforms, ranking, classification, dedup",
    ),
    "coordinator": Role(
        "coordinator",
        Tier.MID,
        InferenceProfile(reasoning="low", max_output_tokens=8192, temperature=0.2),
        summary="Plan, delegate, track progress, decide next step",
    ),
    "researcher": Role(
        "researcher",
        Tier.MID,
        InferenceProfile(reasoning="high", max_output_tokens=32768, temperature=0.2),
        summary="Investigate through tools and evidence",
    ),
    "builder": Role(
        "builder",
        Tier.MID,
        InferenceProfile(reasoning="high", max_output_tokens=32768, temperature=0.1),
        summary="Produce executable artifacts the environment tests",
    ),
    "frontier": Role(
        "frontier",
        Tier.LARGE,
        InferenceProfile(reasoning="max", max_output_tokens=65536),
        summary="Resolve hard, stuck, or high-value problems",
    ),
    "reviewer": Role(
        "reviewer",
        Tier.LARGE,
        InferenceProfile(reasoning="xhigh", max_output_tokens=32768, temperature=0.1),
        independent=True,
        summary="Independent critical review / falsification",
    ),
}


#: The task-route layer: existing call-site task strings -> role. Adding a
#: new call site means adding one line here, not a new model knob. Any task
#: not listed resolves through ``default`` (researcher). ``mechanical`` is
#: intentionally absent — code with no LLM has no role.
TASK_ROLES: dict[str, str] = {
    # cheap cognition
    "ranker": "utility",
    "report": "utility",
    "context_summary": "utility",
    "nday_filter": "utility",
    "finding_dedup": "utility",
    "recmem_episode": "utility",
    "proof_local": "utility",
    # orchestration
    "operator": "coordinator",
    "planner": "coordinator",
    "planning": "coordinator",
    # investigation
    "default": "researcher",
    "hunter": "researcher",
    "recon": "researcher",
    "reveng_analysis": "researcher",
    "recmem_semantic": "researcher",
    "proof_exploration": "researcher",
    # artifact construction
    "harness": "builder",
    "patcher": "builder",
    "reveng_reconstructor": "builder",
    "poc_hardener": "builder",
    "exploit": "builder",
    # escalation
    "frontier": "frontier",
    "proof_frontier": "frontier",
    "sourcehunt_exploit": "frontier",
    # independent scrutiny
    "verifier": "reviewer",
    "proof_falsifier": "reviewer",
}


def role_for_task(task: str) -> Role:
    """Resolve a call-site task string to its :class:`Role`.

    Unknown tasks fall back to the ``researcher`` role (the ``default``
    task), matching the pre-roles behavior where every unrouted task hit
    the default route.
    """
    name = TASK_ROLES.get(task, "researcher")
    return ROLES[name]


# ---------------------------------------------------------------------------
# Resolution — role -> concrete model, from the configured providers.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RoleAssignment:
    """A role bound to a concrete model with an inference profile.

    ``provider`` is a provider *key* (``anthropic``, ``deepseek`` …),
    matching :attr:`ProviderPreset.key` — the caller turns that into a
    live endpoint. ``inference`` is the resolved profile for this binding;
    ``reasoning`` mirrors ``inference.reasoning`` for back-compat. ``reason``
    is a short human string for ``clearwing models`` and debug output.
    ``constraints`` carries policy flags such as ``independent_model_family``
    and, for the reviewer, whether that independence was actually satisfied.
    """

    role: str
    provider: str
    model: str
    inference: InferenceProfile = field(default_factory=InferenceProfile)
    constraints: dict = field(default_factory=dict)
    reason: str = ""

    @property
    def reasoning(self) -> str | None:
        return self.inference.reasoning


def _pick_reviewer_source(
    providers: list[ProviderPreset], primary: ProviderPreset, tier: str
) -> tuple[ProviderPreset, bool]:
    """Choose the reviewer's provider, preferring a different model family.

    Returns (source, independent_satisfied). Independence means the
    reviewer's model is a different family than the primary's — a reviewer
    that shares a family with the model it reviews isn't truly independent.
    Prefers the first configured provider whose tier model differs in family;
    falls back to the second provider, then the primary, flagging when
    independence could not be met rather than silently pretending.
    """
    primary_family = model_family(primary.model_for_tier(tier))
    for candidate in providers[1:]:
        if model_family(candidate.model_for_tier(tier)) != primary_family:
            return candidate, True
    if len(providers) > 1:
        return providers[1], False  # a second provider, but same family
    return primary, False  # only one provider — independence via tier, not family


def recommend_roles(
    providers: list[ProviderPreset],
    overrides: dict[str, dict] | None = None,
) -> dict[str, RoleAssignment]:
    """Fill every role from the configured providers' tier ladders.

    Args:
        providers: Configured provider presets in *preference order*.
            ``providers[0]`` is the primary and supplies most roles;
            ``independent`` roles (reviewer) prefer a different-family
            provider from the rest of the list.
        overrides: Optional per-role overrides, keyed by role name. Each may
            carry flat ``provider`` / ``model`` / ``reasoning`` and/or a
            nested ``inference:`` dict and ``constraints:`` — the ``roles:``
            config block. Overrides always win over the recommendation.

    Returns:
        A mapping of every role name in :data:`ROLES` to a
        :class:`RoleAssignment`, carrying the resolved inference profile.

    Raises:
        ValueError: if ``providers`` is empty.
    """
    if not providers:
        raise ValueError("recommend_roles needs at least one configured provider")

    primary = providers[0]

    out: dict[str, RoleAssignment] = {}
    for name, role in ROLES.items():
        constraints: dict = {}
        if role.independent:
            src, satisfied = _pick_reviewer_source(providers, primary, role.tier.value)
            constraints = {
                "independent_model_family": True,
                "independent_satisfied": satisfied,
            }
            if src is not primary and satisfied:
                reason = f"{role.tier.value} tier on {src.key} (independent of {primary.key})"
            elif src is not primary:
                reason = f"{role.tier.value} tier on {src.key} (same family as {primary.key})"
            else:
                reason = f"{role.tier.value} tier on {src.key} (no independent family configured)"
        else:
            src = primary
            reason = f"{role.tier.value} tier on {src.key}"
        model = src.model_for_tier(role.tier.value)
        out[name] = RoleAssignment(
            role=name,
            provider=src.key,
            model=model,
            inference=role.inference,
            constraints=constraints,
            reason=reason,
        )

    for name, ov in (overrides or {}).items():
        base = out.get(name)
        if base is None:
            # Override for a role we don't know — skip rather than invent a tier.
            continue
        inference = base.inference
        if "reasoning" in ov:
            inference = replace(inference, reasoning=ov["reasoning"])
        inference = inference.merged(InferenceProfile.from_dict(ov.get("inference")))
        constraints = {**base.constraints, **(ov.get("constraints") or {})}
        out[name] = replace(
            base,
            provider=ov.get("provider", base.provider),
            model=ov.get("model", base.model),
            inference=inference,
            constraints=constraints,
            reason="config roles: override",
        )

    # Independence is a fact about the FINAL model, so recompute it after
    # overrides: a binding that repoints the reviewer to a different-family
    # model satisfies the constraint even though the ladder pick did not.
    # "Generator" family is the primary's mid tier — the researcher/hunter
    # whose findings the reviewer judges.
    generator_family = model_family(primary.model_for_tier(Tier.MID.value))
    for name, a in list(out.items()):
        if a.constraints.get("independent_model_family"):
            satisfied = model_family(a.model) != generator_family
            if satisfied != a.constraints.get("independent_satisfied"):
                out[name] = replace(
                    a, constraints={**a.constraints, "independent_satisfied": satisfied}
                )
    return out


__all__ = [
    "Tier",
    "Role",
    "ROLES",
    "TASK_ROLES",
    "role_for_task",
    "RoleAssignment",
    "recommend_roles",
]
