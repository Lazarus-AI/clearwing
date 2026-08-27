from __future__ import annotations

import pytest

from clearwing.providers.binding import (
    AgentLimits,
    BindingValidationError,
    InferenceProfile,
    ModelCapabilities,
    ReasoningSupport,
    capabilities_for,
    model_family,
    normalize_reasoning,
    validate_inference,
)
from clearwing.providers.catalog import preset_by_key
from clearwing.providers.manager import ProviderManager
from clearwing.providers.roles import ROLES, recommend_roles

# --- InferenceProfile ------------------------------------------------------


class TestInferenceProfile:
    def test_from_dict_maps_off_to_none(self):
        p = InferenceProfile.from_dict({"reasoning": "off", "max_output_tokens": 8192})
        assert p.reasoning == "none"
        assert p.max_output_tokens == 8192

    def test_merged_override_wins_field_by_field(self):
        base = InferenceProfile(reasoning="high", max_output_tokens=32768, temperature=0.2)
        merged = base.merged(InferenceProfile(max_output_tokens=12000))
        assert merged.reasoning == "high"  # untouched
        assert merged.max_output_tokens == 12000  # overridden
        assert merged.temperature == 0.2

    def test_merged_none_is_identity(self):
        base = InferenceProfile(reasoning="low")
        assert base.merged(None) == base


# --- ModelCapabilities -----------------------------------------------------


class TestCapabilities:
    def test_from_dict_reasoning_levels(self):
        caps = ModelCapabilities.from_dict(
            {"context_window": 200000, "reasoning": {"levels": ["low", "High"]}}
        )
        assert caps.context_window == 200000
        assert caps.reasoning.levels == ("low", "high")  # normalized

    def test_from_dict_reasoning_bool(self):
        caps = ModelCapabilities.from_dict({"reasoning": False})
        assert caps.reasoning.supported is False

    def test_capabilities_for_grounds_reasoning_in_denylist(self):
        assert capabilities_for("qwen2.5-coder:32b").reasoning.supported is False
        assert capabilities_for("claude-sonnet-4-6").reasoning.supported is True

    def test_declared_wins(self):
        declared = ModelCapabilities(context_window=123)
        assert capabilities_for("claude-sonnet-4-6", declared) is declared


class TestModelFamily:
    @pytest.mark.parametrize(
        "model,family",
        [
            ("claude-opus-4-7", "claude"),
            ("anthropic/claude-sonnet-4", "claude"),
            ("gpt-5.4", "openai"),
            ("o3", "openai"),
            ("Qwen/Qwen3.8-27B", "qwen"),
            ("deepseek-reasoner", "deepseek"),
            ("MiniMax-M2.7", "minimax"),
            ("something-unknown", "unknown"),
        ],
    )
    def test_family(self, model, family):
        assert model_family(model) == family


# --- validate_inference ----------------------------------------------------


class TestValidateInference:
    def test_level_not_supported(self):
        caps = ModelCapabilities(reasoning=ReasoningSupport(levels=("low", "high")))
        problems = validate_inference("utility", "m", InferenceProfile(reasoning="xhigh"), caps)
        assert problems and "supports only" in problems[0]

    def test_reasoning_unsupported_entirely(self):
        caps = ModelCapabilities(reasoning=ReasoningSupport(supported=False))
        problems = validate_inference("r", "m", InferenceProfile(reasoning="high"), caps)
        assert problems and "does not support" in problems[0]

    def test_output_over_ceiling(self):
        caps = ModelCapabilities(max_output_tokens=16000)
        problems = validate_inference(
            "r", "m", InferenceProfile(max_output_tokens=32768), caps
        )
        assert problems and "max_output_tokens" in problems[0]

    def test_context_over_window(self):
        caps = ModelCapabilities(context_window=128000)
        problems = validate_inference(
            "r", "m", InferenceProfile(context_budget_tokens=500000), caps
        )
        assert problems and "context window" in problems[0]

    def test_cannot_disable(self):
        caps = ModelCapabilities(reasoning=ReasoningSupport(can_disable=False))
        problems = validate_inference("u", "m", InferenceProfile(reasoning="none"), caps)
        assert problems and "cannot disable" in problems[0]

    def test_valid_binding_no_problems(self):
        caps = ModelCapabilities(reasoning=ReasoningSupport(levels=("low", "high", "max")))
        assert validate_inference("r", "m", InferenceProfile(reasoning="high"), caps) == []

    def test_normalize_reasoning(self):
        assert normalize_reasoning("off") == "none"
        assert normalize_reasoning(None) is None


# --- Role default inference profiles ---------------------------------------


class TestRoleInference:
    def test_role_output_budgets(self):
        assert ROLES["utility"].inference.max_output_tokens == 8192
        assert ROLES["researcher"].inference.max_output_tokens == 32768
        assert ROLES["frontier"].inference.max_output_tokens == 65536

    def test_reasoning_property_still_works(self):
        assert ROLES["utility"].reasoning == "none"
        assert ROLES["frontier"].reasoning == "max"


# --- recommend_roles: independence constraint ------------------------------


class TestReviewerIndependence:
    def test_independent_when_family_differs(self):
        got = recommend_roles([preset_by_key("deepseek"), preset_by_key("anthropic")])
        rev = got["reviewer"]
        assert rev.provider == "anthropic"
        assert rev.constraints["independent_satisfied"] is True

    def test_not_independent_single_provider(self):
        got = recommend_roles([preset_by_key("anthropic")])
        assert got["reviewer"].constraints["independent_satisfied"] is False

    def test_not_independent_same_family_second_provider(self):
        # anthropic-oauth and anthropic both resolve to the claude family.
        got = recommend_roles([preset_by_key("anthropic"), preset_by_key("anthropic-oauth")])
        assert got["reviewer"].constraints["independent_satisfied"] is False

    def test_override_inference_merges(self):
        got = recommend_roles(
            [preset_by_key("anthropic")],
            overrides={"researcher": {"inference": {"max_output_tokens": 12000}}},
        )
        r = got["researcher"]
        assert r.inference.max_output_tokens == 12000
        assert r.inference.reasoning == "high"  # role default preserved

    def test_override_repoint_recomputes_independence(self):
        # Repointing the reviewer to a different-family model satisfies the
        # independence constraint even from a single-provider base.
        got = recommend_roles(
            [preset_by_key("deepseek")],
            overrides={"reviewer": {"provider": "openrouter", "model": "Qwen/Qwen3.8-A95B"}},
        )
        assert got["reviewer"].constraints["independent_satisfied"] is True


# --- Manager: config bindings + validation ---------------------------------


class TestManagerBindings:
    def test_binding_flows_to_route_inference(self):
        mgr = ProviderManager.from_config({"model_roles": {"providers": ["anthropic"]}})
        route = mgr._route_for_task("frontier")
        assert route.inference is not None
        assert route.inference.max_output_tokens == 65536
        assert route.effective_reasoning == "max"

    def test_named_model_binding_with_capabilities(self):
        cfg = {
            "model_roles": {
                "providers": ["anthropic"],
                "models": {
                    "qwen_big": {
                        "provider": "openrouter",
                        "model": "Qwen/Qwen3.8-A95B",
                        "capabilities": {"reasoning": {"levels": ["low", "high", "xhigh"]}},
                    }
                },
                "roles": {"reviewer": {"model": "qwen_big", "inference": {"reasoning": "xhigh"}}},
            }
        }
        mgr = ProviderManager.from_config(cfg)
        rev = mgr._route_for_task("verifier")  # verifier -> reviewer
        assert rev.provider == "openrouter"
        assert rev.model == "Qwen/Qwen3.8-A95B"
        assert rev.effective_reasoning == "xhigh"

    def test_invalid_binding_raises_at_load(self):
        cfg = {
            "model_roles": {
                "providers": ["anthropic"],
                "models": {
                    "qwen_small": {
                        "provider": "openrouter",
                        "model": "Qwen/Qwen3.8-27B",
                        "capabilities": {"reasoning": {"levels": ["low", "high"]}},
                    }
                },
                "roles": {"utility": {"model": "qwen_small", "inference": {"reasoning": "xhigh"}}},
            }
        }
        with pytest.raises(BindingValidationError) as exc:
            ProviderManager.from_config(cfg)
        assert "utility" in str(exc.value) and "supports only" in str(exc.value)

    def test_inference_reaches_created_client(self):
        # from_roles path builds a real client; assert the binding's output
        # budget and temperature land on the client as defaults.
        mgr = ProviderManager.from_config({"model_roles": {"providers": ["anthropic"]}})
        client = mgr.get_native_client("researcher")
        assert client.default_max_tokens == 32768
        assert client.default_temperature == 0.2

    def test_context_budget_reaches_client(self):
        cfg = {
            "model_roles": {
                "providers": ["anthropic"],
                "roles": {"researcher": {"inference": {"context_budget_tokens": 120000}}},
            }
        }
        mgr = ProviderManager.from_config(cfg)
        assert mgr.get_native_client("researcher").context_budget_tokens == 120000
        # A role without an explicit budget stays None (summarizer default).
        assert mgr.get_native_client("frontier").context_budget_tokens is None


class TestContextBudgetSummarization:
    """The seam context_budget_tokens drives: when the agent loop summarizes."""

    def _messages(self, approx_tokens: int):
        # ContextSummarizer estimates tokens as chars // 4.
        from clearwing.llm import ChatMessage

        return [ChatMessage("user", "x" * (approx_tokens * 4))]

    def test_smaller_budget_triggers_earlier(self):
        from clearwing.data.memory import ContextSummarizer

        cs = ContextSummarizer()
        msgs = self._messages(50_000)
        assert cs.should_summarize(msgs) is False  # under the 150K default (0.8*150K)
        assert cs.should_summarize(msgs, max_tokens=50_000) is True  # over 0.8*50K


class TestFallback:
    def _block(self, roles):
        return {
            "providers": ["anthropic"],
            "models": {
                "pro": {"provider": "anthropic", "model": "claude-opus-4-7"},
                "qwen": {
                    "provider": "openrouter",
                    "model": "Qwen/Qwen3.8-A95B",
                    "capabilities": {"reasoning": {"levels": ["low", "high", "max", "xhigh"]}},
                },
                "dpro": {"provider": "deepseek", "model": "deepseek-reasoner"},
            },
            "roles": roles,
        }

    def test_failover_when_primary_key_unset(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
        block = self._block(
            {"frontier": {"model": "pro", "fallback": [{"model": "qwen"}]}}
        )
        a = ProviderManager.resolve_role_assignments(block)[0]
        f = a["frontier"]
        assert f.provider == "openrouter" and f.model == "Qwen/Qwen3.8-A95B"
        assert f.constraints["fallback_used"] == "Qwen/Qwen3.8-A95B"

    def test_primary_used_when_available(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or")
        block = self._block(
            {"frontier": {"model": "pro", "fallback": [{"model": "qwen"}]}}
        )
        f = ProviderManager.resolve_role_assignments(block)[0]["frontier"]
        assert f.provider == "anthropic"
        assert "fallback_used" not in f.constraints

    def test_reviewer_never_silently_same_family(self, monkeypatch):
        # Generator = anthropic; the only reviewer candidate is also anthropic.
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
        block = self._block(
            {
                "reviewer": {
                    "model": "pro",
                    "constraints": {"independent_model_family": True},
                    "fallback": [{"model": "pro"}],
                }
            }
        )
        r = ProviderManager.resolve_role_assignments(block)[0]["reviewer"]
        assert r.constraints["independent_available"] is False
        assert r.constraints["independent_satisfied"] is False

    def test_reviewer_prefers_independent_fallback(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or")
        # Primary reviewer shares the generator (anthropic) family; the qwen
        # fallback is independent and available -> it wins.
        block = self._block(
            {
                "reviewer": {
                    "model": "pro",
                    "inference": {"reasoning": "xhigh"},
                    "constraints": {"independent_model_family": True},
                    "fallback": [{"model": "qwen"}],
                }
            }
        )
        r = ProviderManager.resolve_role_assignments(block)[0]["reviewer"]
        assert r.provider == "openrouter"
        assert r.constraints["independent_satisfied"] is True

    def test_broken_fallback_fails_at_load(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
        # qwen_small declares levels [low, high]; a fallback asking xhigh is invalid.
        block = {
            "providers": ["anthropic"],
            "models": {
                "qwen_small": {
                    "provider": "openrouter",
                    "model": "Qwen/Qwen3.8-27B",
                    "capabilities": {"reasoning": {"levels": ["low", "high"]}},
                }
            },
            "roles": {
                "frontier": {
                    "inference": {"reasoning": "max"},
                    "fallback": [{"model": "qwen_small", "inference": {"reasoning": "xhigh"}}],
                }
            },
        }
        with pytest.raises(BindingValidationError):
            ProviderManager.from_config({"model_roles": block})


class TestAgentLimits:
    def test_limits_resolved_from_routes(self):
        cfg = {
            "model_roles": {
                "providers": ["anthropic"],
                "routes": {"hunter": {"agent": {"max_steps": 30, "max_tool_calls": 80}}},
            }
        }
        mgr = ProviderManager.from_config(cfg)
        limits = mgr.get_agent_limits("hunter")
        assert limits.max_steps == 30 and limits.max_tool_calls == 80

    def test_no_limits_returns_none(self):
        mgr = ProviderManager.from_config({"model_roles": {"providers": ["anthropic"]}})
        assert mgr.get_agent_limits("hunter") is None

    def test_route_inference_override_applies(self):
        cfg = {
            "model_roles": {
                "providers": ["anthropic"],
                "routes": {"default": {"inference": {"max_output_tokens": 12000}}},
            }
        }
        mgr = ProviderManager.from_config(cfg)
        assert mgr._route_for_task("default").inference.max_output_tokens == 12000

    def test_named_route_with_explicit_role(self):
        cfg = {
            "model_roles": {
                "providers": ["anthropic"],
                "routes": {
                    "network.investigate": {
                        "role": "researcher",
                        "agent": {"max_steps": 20},
                        "inference": {"max_output_tokens": 8000},
                    }
                },
            }
        }
        mgr = ProviderManager.from_config(cfg)
        assert mgr.get_agent_limits("network.investigate").max_steps == 20
        r = mgr._route_for_task("network.investigate")
        assert r.model == "claude-sonnet-4-6"  # researcher tier
        assert r.inference.max_output_tokens == 8000

    def test_bad_limit_raises_at_load(self):
        cfg = {
            "model_roles": {
                "providers": ["anthropic"],
                "routes": {"hunter": {"agent": {"max_steps": 0}}},
            }
        }
        with pytest.raises(BindingValidationError):
            ProviderManager.from_config(cfg)


class TestAgentLoopEnforcement:
    def _graph(self, agent_limits):
        from clearwing.agent.runtime import NativeAgentGraph

        return NativeAgentGraph(
            llm=object(),
            native_tools=[],
            tools=[],
            system_prompt_fn=lambda s: "sys",
            model_name="m",
            session_id=None,
            state_updater_fn=lambda *a, **k: {},
            knowledge_graph_populator_fn=None,
            input_guardrail_tool_names=frozenset(),
            output_guardrail_tool_names=frozenset(),
            enable_cost_tracker=False,
            enable_episodic_memory=False,
            enable_audit=False,
            enable_knowledge_graph=False,
            enable_input_guardrail=False,
            enable_output_guardrail=False,
            enable_event_bus=False,
            enable_context_summarizer=False,
            agent_limits=agent_limits,
        )

    def _drive(self, agent_limits):
        import asyncio

        graph = self._graph(agent_limits)
        graph._get_or_create_state("t")
        steps = {"assistant": 0, "tools": 0}

        class _Msg:
            content = ""
            tool_calls = [{"id": "1", "name": "x", "args": {}}]  # always wants a tool

        async def fake_step(st):
            steps["assistant"] += 1
            st["messages"].append(_Msg())
            return {}

        async def fake_tools(st, tcs, resume_decision=None):
            steps["tools"] += 1
            return ([], False)

        graph._aassistant_step = fake_step
        graph._arun_tool_calls = fake_tools

        async def run():
            async for _ in graph._arun_loop("t"):
                pass

        asyncio.run(run())
        return steps

    def test_max_steps_bounds_the_loop(self):
        steps = self._drive(AgentLimits(max_steps=3))
        assert steps["assistant"] == 3

    def test_max_tool_calls_bounds_the_loop(self):
        steps = self._drive(AgentLimits(max_tool_calls=2))
        assert steps["tools"] == 2

    def test_unbounded_by_default_uses_natural_stop(self):
        # No limits + an assistant that stops emitting tool calls -> 1 step.
        import asyncio

        graph = self._graph(None)

        class _NoCalls:
            content = "done"
            tool_calls = []

        async def fake_step(st):
            st["messages"].append(_NoCalls())
            return {}

        graph._aassistant_step = fake_step
        graph._get_or_create_state("t")

        async def run():
            async for _ in graph._arun_loop("t"):
                pass

        asyncio.run(run())  # terminates naturally (no tool calls)


class TestInferenceWiring:
    def test_top_p_and_timeout_reach_client(self):
        cfg = {
            "model_roles": {
                "providers": ["anthropic"],
                "roles": {
                    "researcher": {"inference": {"top_p": 0.9, "timeout_seconds": 120}}
                },
            }
        }
        client = ProviderManager.from_config(cfg).get_native_client("researcher")
        assert client.default_top_p == 0.9
        assert client.timeout_seconds == 120

    def test_timeout_wrapper_raises_on_slow_dispatch(self):
        import asyncio

        from clearwing.llm.native import AsyncLLMClient

        client = AsyncLLMClient(
            model_name="claude-sonnet-4-6", provider_name="anthropic", api_key="k"
        )
        client.timeout_seconds = 0.05

        async def slow(_client, _request, _options):
            await asyncio.sleep(0.5)
            return "unreached"

        client._achat_provider_dispatch = slow
        with pytest.raises(asyncio.TimeoutError):
            asyncio.run(client._achat_with_provider_policy(None, None, None))

    def test_no_timeout_when_unset(self):
        import asyncio

        from clearwing.llm.native import AsyncLLMClient

        client = AsyncLLMClient(
            model_name="claude-sonnet-4-6", provider_name="anthropic", api_key="k"
        )
        assert client.timeout_seconds is None

        async def fast(_client, _request, _options):
            return "ok"

        client._achat_provider_dispatch = fast
        assert asyncio.run(client._achat_with_provider_policy(None, None, None)) == "ok"

    def test_rebuild_options_preserve_top_p(self):
        from genai_pyo3 import ChatOptions

        from clearwing.llm.native import AsyncLLMClient

        opts = ChatOptions(top_p=0.8, reasoning_effort="high", max_tokens=1000)
        assert AsyncLLMClient._rebuild_options_without_reasoning(opts).top_p == 0.8
        assert AsyncLLMClient._rebuild_options_without_max_tokens(opts).top_p == 0.8
