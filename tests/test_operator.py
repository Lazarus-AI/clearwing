"""Tests for the Operator agent."""

from unittest.mock import MagicMock, patch

from clearwing.agent.operator import (
    _OPERATOR_SYSTEM_PROMPT,
    OperatorAgent,
    OperatorConfig,
    OperatorResult,
)


class TestOperatorConfig:
    def test_defaults(self):
        cfg = OperatorConfig(goals=["scan ports"], target="10.0.0.1")
        assert cfg.model == "claude-sonnet-4-6"
        assert cfg.max_turns == 100
        assert cfg.timeout_minutes == 60
        assert cfg.auto_approve_scans is True
        assert cfg.auto_approve_exploits is False
        assert cfg.cost_limit == 0.0

    def test_custom_values(self):
        cfg = OperatorConfig(
            goals=["a", "b"],
            target="192.168.1.1",
            model="gpt-4o",
            max_turns=50,
            timeout_minutes=30,
            cost_limit=5.0,
            auto_approve_exploits=True,
            base_url="http://localhost:8000/v1",
            api_key="test-key",
        )
        assert cfg.goals == ["a", "b"]
        assert cfg.model == "gpt-4o"
        assert cfg.cost_limit == 5.0
        assert cfg.base_url == "http://localhost:8000/v1"

    def test_operator_model_defaults_empty(self):
        cfg = OperatorConfig(goals=["scan"], target="10.0.0.1")
        assert cfg.operator_model == ""


class TestOperatorResult:
    def test_fields(self):
        r = OperatorResult(
            goals=["scan ports"],
            target="10.0.0.1",
            status="completed",
            turns=5,
            cost_usd=0.05,
        )
        assert r.status == "completed"
        assert r.turns == 5
        assert r.findings == []
        assert r.flags_found == []
        assert r.escalation_question == ""

    def test_escalated_result(self):
        r = OperatorResult(
            goals=["scan"],
            target="10.0.0.1",
            status="escalated",
            escalation_question="What credentials to use?",
        )
        assert r.status == "escalated"
        assert "credentials" in r.escalation_question


class TestOperatorAgentInit:
    def test_init(self):
        cfg = OperatorConfig(goals=["scan"], target="10.0.0.1")
        op = OperatorAgent(cfg)
        assert op._turns == 0
        assert op._progress == []
        assert op._escalated is False


class TestFormatGoals:
    def test_single_goal(self):
        cfg = OperatorConfig(goals=["Scan for open ports"], target="10.0.0.1")
        op = OperatorAgent(cfg)
        text = op._format_goals()
        assert "10.0.0.1" in text
        assert "Scan for open ports" in text
        assert "1." in text

    def test_multiple_goals(self):
        cfg = OperatorConfig(
            goals=["Scan ports", "Find vulnerabilities", "Generate report"],
            target="192.168.1.1",
        )
        op = OperatorAgent(cfg)
        text = op._format_goals()
        assert "1." in text
        assert "2." in text
        assert "3." in text
        assert "192.168.1.1" in text


class TestOperatorSystemPrompt:
    def test_prompt_contains_placeholders(self):
        assert "{goals}" in _OPERATOR_SYSTEM_PROMPT
        assert "{target}" in _OPERATOR_SYSTEM_PROMPT
        assert "{progress}" in _OPERATOR_SYSTEM_PROMPT

    def test_prompt_formatting(self):
        result = _OPERATOR_SYSTEM_PROMPT.format(
            goals="1. Scan ports",
            target="10.0.0.1",
            progress="No progress yet.",
        )
        assert "10.0.0.1" in result
        assert "Scan ports" in result
        assert "ESCALATE" in result
        assert "GOALS_COMPLETE" in result


class TestRunInnerTurn:
    def test_extracts_ai_content(self):
        cfg = OperatorConfig(goals=["scan"], target="10.0.0.1")
        op = OperatorAgent(cfg)

        mock_ai = MagicMock()
        mock_ai.type = "ai"
        mock_ai.content = "I found port 22 open."

        mock_graph = MagicMock()
        mock_graph.stream.return_value = [{"messages": [mock_ai]}]

        result = op._run_inner_turn(mock_graph, {}, {"messages": []})
        assert "port 22" in result

    def test_handles_list_content(self):
        cfg = OperatorConfig(goals=["scan"], target="10.0.0.1")
        op = OperatorAgent(cfg)

        mock_ai = MagicMock()
        mock_ai.type = "ai"
        mock_ai.content = [{"type": "text", "text": "Found SSH"}]

        mock_graph = MagicMock()
        mock_graph.stream.return_value = [{"messages": [mock_ai]}]

        result = op._run_inner_turn(mock_graph, {}, {"messages": []})
        assert "SSH" in result

    def test_handles_exception(self):
        cfg = OperatorConfig(goals=["scan"], target="10.0.0.1")
        op = OperatorAgent(cfg)

        mock_graph = MagicMock()
        mock_graph.stream.side_effect = RuntimeError("connection lost")

        result = op._run_inner_turn(mock_graph, {}, {"messages": []})
        assert "error" in result.lower()


class TestDecideNext:
    def test_goals_complete(self):
        cfg = OperatorConfig(goals=["scan ports"], target="10.0.0.1")
        op = OperatorAgent(cfg)

        mock_llm = MagicMock()
        mock_response = MagicMock()
        mock_response.content = "GOALS_COMPLETE"
        mock_llm.invoke.return_value = mock_response

        decision = op._decide_next(mock_llm, "All ports scanned, report generated.")
        assert decision.startswith("GOALS_COMPLETE")

    def test_escalate(self):
        cfg = OperatorConfig(goals=["scan"], target="10.0.0.1")
        op = OperatorAgent(cfg)

        mock_llm = MagicMock()
        mock_response = MagicMock()
        mock_response.content = "ESCALATE: What are the login credentials?"
        mock_llm.invoke.return_value = mock_response

        decision = op._decide_next(mock_llm, "I need credentials to log in.")
        assert decision.startswith("ESCALATE:")
        assert "credentials" in decision

    def test_next_instruction(self):
        cfg = OperatorConfig(goals=["scan", "exploit"], target="10.0.0.1")
        op = OperatorAgent(cfg)

        mock_llm = MagicMock()
        mock_response = MagicMock()
        mock_response.content = "Now scan for vulnerabilities on the open ports."
        mock_llm.invoke.return_value = mock_response

        decision = op._decide_next(mock_llm, "Found ports 22, 80, 443 open.")
        assert "scan" in decision.lower() or "vulnerabilities" in decision.lower()

    def test_handles_llm_error(self):
        cfg = OperatorConfig(goals=["scan"], target="10.0.0.1")
        op = OperatorAgent(cfg)

        mock_llm = MagicMock()
        mock_llm.invoke.side_effect = RuntimeError("API error")

        decision = op._decide_next(mock_llm, "Agent output")
        assert "Continue" in decision


class TestBuildResult:
    def test_completed_result(self):
        import time

        cfg = OperatorConfig(goals=["scan"], target="10.0.0.1")
        op = OperatorAgent(cfg)
        op._turns = 5

        mock_state = MagicMock()
        mock_state.values = {
            "vulnerabilities": [{"cve": "CVE-2024-1234", "severity": "high"}],
            "exploit_results": [],
            "flags_found": [{"flag": "flag{test}", "pattern": "flag\\{.*\\}"}],
            "total_cost_usd": 0.12,
            "total_tokens": 5000,
        }
        mock_graph = MagicMock()
        mock_graph.get_state.return_value = mock_state

        result = op._build_result(mock_graph, {}, time.time() - 10, "completed")
        assert result.status == "completed"
        assert result.turns == 5
        assert len(result.findings) == 1
        assert len(result.flags_found) == 1
        assert result.cost_usd == 0.12

    def test_escalated_result(self):
        import time

        cfg = OperatorConfig(goals=["scan"], target="10.0.0.1")
        op = OperatorAgent(cfg)

        mock_state = MagicMock()
        mock_state.values = {}
        mock_graph = MagicMock()
        mock_graph.get_state.return_value = mock_state

        result = op._build_result(
            mock_graph,
            {},
            time.time(),
            "escalated",
            escalation_question="Need credentials",
        )
        assert result.status == "escalated"
        assert result.escalation_question == "Need credentials"

    def test_exploit_results_added_to_findings(self):
        import time

        cfg = OperatorConfig(goals=["exploit"], target="10.0.0.1")
        op = OperatorAgent(cfg)

        mock_state = MagicMock()
        mock_state.values = {
            "vulnerabilities": [],
            "exploit_results": [
                {"success": True, "vulnerability": "RCE"},
                {"success": False, "vulnerability": "SQLi"},
            ],
            "flags_found": [],
            "total_cost_usd": 0.0,
            "total_tokens": 0,
        }
        mock_graph = MagicMock()
        mock_graph.get_state.return_value = mock_state

        result = op._build_result(mock_graph, {}, time.time(), "completed")
        # Only successful exploits become findings
        assert len(result.findings) == 1
        assert "RCE" in result.findings[0]["description"]


class TestEmit:
    def test_calls_callback(self):
        calls = []
        cfg = OperatorConfig(
            goals=["scan"],
            target="10.0.0.1",
            on_message=lambda role, content: calls.append((role, content)),
        )
        op = OperatorAgent(cfg)
        op._emit("agent", "hello")
        assert len(calls) == 1
        assert calls[0] == ("agent", "hello")

    def test_no_callback(self):
        cfg = OperatorConfig(goals=["scan"], target="10.0.0.1")
        op = OperatorAgent(cfg)
        op._emit("agent", "hello")  # Should not raise

    def test_callback_exception_ignored(self):
        def bad_callback(role, content):
            raise ValueError("boom")

        cfg = OperatorConfig(
            goals=["scan"],
            target="10.0.0.1",
            on_message=bad_callback,
        )
        op = OperatorAgent(cfg)
        op._emit("agent", "hello")  # Should not raise


class TestHandleInterrupt:
    def test_auto_approve_scan(self):
        cfg = OperatorConfig(
            goals=["scan"],
            target="10.0.0.1",
            auto_approve_scans=True,
        )
        op = OperatorAgent(cfg)

        mock_interrupt = MagicMock()
        mock_interrupt.value = "Approve scan of port 80?"
        mock_task = MagicMock()
        mock_task.interrupts = [mock_interrupt]

        mock_state = MagicMock()
        mock_state.tasks = [mock_task]

        mock_graph = MagicMock()

        result = op._handle_interrupt(mock_state, mock_graph, {})
        assert result is True

    def test_exploit_not_auto_approved(self):
        cfg = OperatorConfig(
            goals=["exploit"],
            target="10.0.0.1",
            auto_approve_scans=True,
            auto_approve_exploits=False,
        )
        op = OperatorAgent(cfg)

        mock_interrupt = MagicMock()
        mock_interrupt.value = "Approve RCE exploit?"
        mock_task = MagicMock()
        mock_task.interrupts = [mock_interrupt]

        mock_state = MagicMock()
        mock_state.tasks = [mock_task]

        mock_graph = MagicMock()

        result = op._handle_interrupt(mock_state, mock_graph, {})
        assert result is False

    def test_exploit_auto_approved_when_enabled(self):
        cfg = OperatorConfig(
            goals=["exploit"],
            target="10.0.0.1",
            auto_approve_exploits=True,
        )
        op = OperatorAgent(cfg)

        mock_interrupt = MagicMock()
        mock_interrupt.value = "Approve RCE exploit?"
        mock_task = MagicMock()
        mock_task.interrupts = [mock_interrupt]

        mock_state = MagicMock()
        mock_state.tasks = [mock_task]

        mock_graph = MagicMock()

        result = op._handle_interrupt(mock_state, mock_graph, {})
        assert result is True

    def test_no_tasks(self):
        cfg = OperatorConfig(goals=["scan"], target="10.0.0.1")
        op = OperatorAgent(cfg)

        mock_state = MagicMock()
        mock_state.tasks = None

        result = op._handle_interrupt(mock_state, MagicMock(), {})
        assert result is True


class TestOperatorRun:
    """Integration-level tests for the full run() loop using mocks."""

    @staticmethod
    def _make_mock_graph(responses: list[str], state_values: dict = None):
        """Create a mock graph that returns the given responses in sequence."""
        mock_graph = MagicMock()

        # Each call to stream yields one AI message
        def make_stream(resp_text):
            mock_ai = MagicMock()
            mock_ai.type = "ai"
            mock_ai.content = resp_text
            return [{"messages": [mock_ai]}]

        side = [make_stream(r) for r in responses]
        # After exhausting responses, return empty (no AI content)
        empty = [{"messages": []}]
        mock_graph.stream.side_effect = side + [empty] * 200

        # get_state returns consistent values
        sv = state_values or {
            "vulnerabilities": [],
            "exploit_results": [],
            "flags_found": [],
            "total_cost_usd": 0.01,
            "total_tokens": 100,
        }
        mock_state = MagicMock()
        mock_state.values = sv
        mock_state.next = None  # no interrupts
        mock_state.tasks = []
        mock_graph.get_state.return_value = mock_state

        return mock_graph

    @patch("clearwing.agent.operator.OperatorAgent._decide_next")
    @patch("clearwing.agent.graph._create_llm")
    @patch("clearwing.agent.create_agent")
    def test_completes_when_goals_met(self, mock_create, mock_create_llm, mock_decide):
        mock_graph = self._make_mock_graph(["Scanning ports...", "All done."])
        mock_create.return_value = mock_graph
        mock_create_llm.return_value = MagicMock()

        # First call: continue, second call: goals complete
        mock_decide.side_effect = ["Now find vulnerabilities.", "GOALS_COMPLETE"]

        cfg = OperatorConfig(goals=["scan ports"], target="10.0.0.1")
        op = OperatorAgent(cfg)
        result = op.run()

        assert result.status == "completed"
        assert result.turns == 2

    @patch("clearwing.agent.operator.OperatorAgent._decide_next")
    @patch("clearwing.agent.graph._create_llm")
    @patch("clearwing.agent.create_agent")
    def test_escalates_on_unknown_question(self, mock_create, mock_create_llm, mock_decide):
        mock_graph = self._make_mock_graph(["What credentials should I use?"])
        mock_create.return_value = mock_graph
        mock_create_llm.return_value = MagicMock()

        mock_decide.return_value = "ESCALATE: What are the SSH credentials?"

        cfg = OperatorConfig(goals=["scan"], target="10.0.0.1")
        op = OperatorAgent(cfg)
        result = op.run()

        assert result.status == "escalated"
        assert "SSH credentials" in result.escalation_question

    @patch("clearwing.agent.operator.OperatorAgent._decide_next")
    @patch("clearwing.agent.graph._create_llm")
    @patch("clearwing.agent.create_agent")
    def test_escalate_with_callback(self, mock_create, mock_create_llm, mock_decide):
        mock_graph = self._make_mock_graph(
            [
                "What credentials?",
                "Logged in successfully.",
            ]
        )
        mock_create.return_value = mock_graph
        mock_create_llm.return_value = MagicMock()

        mock_decide.side_effect = [
            "ESCALATE: What is the SSH password?",
            "GOALS_COMPLETE",
        ]

        cfg = OperatorConfig(
            goals=["scan"],
            target="10.0.0.1",
            on_escalate=lambda q: "password123",
        )
        op = OperatorAgent(cfg)
        result = op.run()

        assert result.status == "completed"

    @patch("clearwing.agent.operator.OperatorAgent._decide_next")
    @patch("clearwing.agent.graph._create_llm")
    @patch("clearwing.agent.create_agent")
    def test_max_turns_stops(self, mock_create, mock_create_llm, mock_decide):
        mock_graph = self._make_mock_graph(["still scanning..."] * 5)
        mock_create.return_value = mock_graph
        mock_create_llm.return_value = MagicMock()
        mock_decide.return_value = "Continue scanning."

        cfg = OperatorConfig(goals=["scan"], target="10.0.0.1", max_turns=3)
        op = OperatorAgent(cfg)
        result = op.run()

        assert result.turns == 3
        assert "max turns" in result.error.lower()

    @patch("clearwing.agent.operator.OperatorAgent._decide_next")
    @patch("clearwing.agent.graph._create_llm")
    @patch("clearwing.agent.create_agent")
    def test_on_complete_callback(self, mock_create, mock_create_llm, mock_decide):
        mock_graph = self._make_mock_graph(["done"])
        mock_create.return_value = mock_graph
        mock_create_llm.return_value = MagicMock()
        mock_decide.return_value = "GOALS_COMPLETE"

        results = []
        cfg = OperatorConfig(
            goals=["scan"],
            target="10.0.0.1",
            on_complete=lambda r: results.append(r),
        )
        op = OperatorAgent(cfg)
        op.run()

        assert len(results) == 1
        assert results[0].status == "completed"

    @patch("clearwing.agent.operator.OperatorAgent._decide_next")
    @patch("clearwing.agent.graph._create_llm")
    @patch("clearwing.agent.create_agent")
    def test_on_message_callback(self, mock_create, mock_create_llm, mock_decide):
        mock_graph = self._make_mock_graph(["scanning..."])
        mock_create.return_value = mock_graph
        mock_create_llm.return_value = MagicMock()
        mock_decide.return_value = "GOALS_COMPLETE"

        messages = []
        cfg = OperatorConfig(
            goals=["scan"],
            target="10.0.0.1",
            on_message=lambda role, content: messages.append((role, content)),
        )
        op = OperatorAgent(cfg)
        op.run()

        # Should have at least the agent message
        agent_msgs = [m for m in messages if m[0] == "agent"]
        assert len(agent_msgs) >= 1

    @patch("clearwing.agent.graph._create_llm")
    @patch("clearwing.agent.create_agent")
    def test_empty_response_ends_loop(self, mock_create, mock_create_llm):
        mock_graph = self._make_mock_graph([])  # no real responses
        mock_create.return_value = mock_graph
        mock_create_llm.return_value = MagicMock()

        cfg = OperatorConfig(goals=["scan"], target="10.0.0.1")
        op = OperatorAgent(cfg)
        result = op.run()

        # Should exit cleanly after first turn yields empty
        assert result.turns <= 1
