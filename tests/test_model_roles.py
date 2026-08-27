from __future__ import annotations

import pytest

from clearwing.llm.native import effective_reasoning_effort
from clearwing.providers.catalog import preset_by_key
from clearwing.providers.manager import ProviderManager
from clearwing.providers.roles import (
    ROLES,
    TASK_ROLES,
    Tier,
    recommend_roles,
    role_for_task,
)

# --- Vocabulary integrity --------------------------------------------------


class TestRolesVocabulary:
    def test_every_task_maps_to_a_real_role(self):
        for task, role in TASK_ROLES.items():
            assert role in ROLES, f"task {task!r} maps to unknown role {role!r}"

    def test_every_role_tier_is_valid(self):
        for role in ROLES.values():
            assert isinstance(role.tier, Tier)

    def test_reasoning_uses_client_vocabulary(self):
        allowed = {"none", "minimal", "low", "medium", "high", "xhigh", "max"}
        for role in ROLES.values():
            assert role.reasoning in allowed

    def test_only_reviewer_is_independent(self):
        independent = {n for n, r in ROLES.items() if r.independent}
        assert independent == {"reviewer"}

    def test_coordinator_researcher_builder_share_mid_tier(self):
        assert ROLES["coordinator"].tier is Tier.MID
        assert ROLES["researcher"].tier is Tier.MID
        assert ROLES["builder"].tier is Tier.MID

    def test_unknown_task_falls_back_to_researcher(self):
        assert role_for_task("no-such-task").name == "researcher"

    def test_known_task_resolution(self):
        assert role_for_task("hunter").name == "researcher"
        assert role_for_task("verifier").name == "reviewer"
        assert role_for_task("ranker").name == "utility"
        assert role_for_task("operator").name == "coordinator"


# --- recommend_roles: the recommendation engine ----------------------------


class TestRecommendRoles:
    def test_single_provider_fills_every_role(self):
        anthropic = preset_by_key("anthropic")
        got = recommend_roles([anthropic])
        assert set(got) == set(ROLES)

    def test_single_provider_tier_ladder(self):
        anthropic = preset_by_key("anthropic")
        got = recommend_roles([anthropic])
        assert got["utility"].model == "claude-haiku-4-5-20251001"
        assert got["researcher"].model == "claude-sonnet-4-6"
        assert got["frontier"].model == "claude-opus-4-7"
        assert got["researcher"].reasoning == "high"
        assert got["frontier"].reasoning == "max"
        assert got["utility"].reasoning == "none"

    def test_reviewer_independence_falls_back_to_primary(self):
        anthropic = preset_by_key("anthropic")
        got = recommend_roles([anthropic])
        # Only one provider — reviewer stays on it (independence via tier).
        assert got["reviewer"].provider == "anthropic"
        assert got["reviewer"].model == "claude-opus-4-7"
        assert got["reviewer"].reasoning == "xhigh"

    def test_reviewer_moves_to_second_provider(self):
        primary = preset_by_key("deepseek")
        audit = preset_by_key("anthropic")
        got = recommend_roles([primary, audit])
        assert got["researcher"].provider == "deepseek"
        assert got["reviewer"].provider == "anthropic"
        assert got["reviewer"].model == "claude-opus-4-7"

    def test_overrides_win(self):
        anthropic = preset_by_key("anthropic")
        got = recommend_roles(
            [anthropic],
            overrides={"frontier": {"model": "claude-opus-4-6", "reasoning": "high"}},
        )
        assert got["frontier"].model == "claude-opus-4-6"
        assert got["frontier"].reasoning == "high"
        assert got["frontier"].reason == "config roles: override"

    def test_missing_tier_falls_back_to_default_model(self):
        lmstudio = preset_by_key("lmstudio")  # no tier_models declared
        got = recommend_roles([lmstudio])
        assert got["frontier"].model == lmstudio.default_model
        assert got["utility"].model == lmstudio.default_model

    def test_empty_providers_raises(self):
        with pytest.raises(ValueError):
            recommend_roles([])


# --- effective_reasoning_effort: the denylist guard ------------------------


class TestEffectiveReasoningEffort:
    def test_normal_model_honors_request(self):
        assert effective_reasoning_effort("claude-sonnet-4-6", "high") == "high"
        assert effective_reasoning_effort("claude-opus-4-7", "max") == "max"

    def test_denylisted_family_downgrades_to_none(self):
        # qwen2 / gemma / llama / mistral reject the reasoning_effort param.
        assert effective_reasoning_effort("qwen2.5-coder:32b", "high") is None
        assert effective_reasoning_effort("llama-3.3-70b-versatile", "max") is None

    def test_auto_and_none_pass_through(self):
        assert effective_reasoning_effort("qwen2.5-coder:32b", "auto") == "auto"
        assert effective_reasoning_effort("qwen2.5-coder:32b", None) is None

    def test_explicit_none_on_supported_model(self):
        assert effective_reasoning_effort("claude-sonnet-4-6", "none") == "none"


# --- ProviderManager.from_roles: the wiring --------------------------------


class TestProviderManagerFromRoles:
    def _manager(self, provider_keys):
        presets = [preset_by_key(k) for k in provider_keys]
        assignments = recommend_roles(presets)
        return ProviderManager.from_roles(assignments, {p.key: p for p in presets})

    def test_task_routes_carry_role_model_and_reasoning(self):
        mgr = self._manager(["anthropic"])
        hunter = mgr._route_for_task("hunter")
        assert hunter.model == "claude-sonnet-4-6"
        assert hunter.reasoning == "high"

        verifier = mgr._route_for_task("verifier")
        assert verifier.model == "claude-opus-4-7"
        assert verifier.reasoning == "xhigh"

        ranker = mgr._route_for_task("ranker")
        assert ranker.model == "claude-haiku-4-5-20251001"
        assert ranker.reasoning == "none"

    def test_role_named_routes_exist(self):
        mgr = self._manager(["anthropic"])
        assert mgr._route_for_task("researcher").model == "claude-sonnet-4-6"
        assert mgr._route_for_task("frontier").reasoning == "max"

    def test_unknown_task_routes_through_researcher_role(self):
        mgr = self._manager(["anthropic"])
        route = mgr._route_for_task("brand-new-call-site")
        # No such task/role route -> researcher role route (role fallback).
        assert route.model == "claude-sonnet-4-6"

    def test_synthesized_provider_config(self):
        mgr = self._manager(["anthropic"])
        assert "anthropic" in mgr.list_providers()

    def test_from_config_model_roles_block(self):
        mgr = ProviderManager.from_config(
            {"model_roles": {"providers": ["deepseek", "anthropic"]}}
        )
        # reviewer independence -> second provider
        assert mgr._route_for_task("verifier").provider == "anthropic"
        assert mgr._route_for_task("hunter").provider == "deepseek"

    def test_from_config_empty_model_roles_defaults_to_anthropic(self):
        mgr = ProviderManager.from_config({"model_roles": {}})
        assert mgr._route_for_task("hunter").provider == "anthropic"


# --- Backward compatibility ------------------------------------------------


class TestBackwardCompat:
    def test_default_routes_manager_unknown_task_hits_default(self):
        mgr = ProviderManager()  # DEFAULT_ROUTES, no role-named routes
        route = mgr._route_for_task("some-unrouted-task")
        assert route is mgr._route_for_task("default")

    def test_default_routes_have_no_reasoning(self):
        # Pre-roles routes leave reasoning None so the client auto-resolves.
        mgr = ProviderManager()
        assert mgr._route_for_task("hunter").reasoning is None
