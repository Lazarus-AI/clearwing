"""Tests for the specialist agent modules (planner, recon, exploit, reporter)."""

import json

from clearwing.agent.specialists import ExploitAgent, ReconAgent, ReporterAgent
from clearwing.agent.specialists.planner_agent import Plan, PlannerAgent, Subtask

# --- Subtask ---


class TestSubtask:
    def test_defaults(self):
        st = Subtask(id=1, description="Scan ports", agent="recon")
        assert st.status == "pending"
        assert st.result is None

    def test_fields(self):
        st = Subtask(
            id=2,
            description="Exploit RCE",
            agent="exploit",
            status="completed",
            result="Shell obtained",
        )
        assert st.id == 2
        assert st.agent == "exploit"
        assert st.status == "completed"


# --- Plan ---


class TestPlan:
    def _make_plan(self):
        return Plan(
            goal="Pentest 10.0.0.1",
            subtasks=[
                Subtask(id=1, description="Scan ports", agent="recon"),
                Subtask(id=2, description="Detect services", agent="recon"),
                Subtask(id=3, description="Exploit vuln", agent="exploit"),
                Subtask(id=4, description="Write report", agent="reporter"),
            ],
        )

    def test_next_task(self):
        plan = self._make_plan()
        task = plan.next_task()
        assert task.id == 1

    def test_next_task_skips_completed(self):
        plan = self._make_plan()
        plan.mark_complete(1, "Done")
        task = plan.next_task()
        assert task.id == 2

    def test_next_task_none_when_all_done(self):
        plan = self._make_plan()
        for st in plan.subtasks:
            plan.mark_complete(st.id)
        assert plan.next_task() is None

    def test_mark_complete(self):
        plan = self._make_plan()
        plan.mark_complete(1, "Ports: 22, 80, 443")
        assert plan.subtasks[0].status == "completed"
        assert plan.subtasks[0].result == "Ports: 22, 80, 443"

    def test_is_complete(self):
        plan = self._make_plan()
        assert not plan.is_complete()
        for st in plan.subtasks:
            plan.mark_complete(st.id)
        assert plan.is_complete()

    def test_is_complete_with_skipped(self):
        plan = self._make_plan()
        for st in plan.subtasks:
            st.status = "skipped"
        assert plan.is_complete()

    def test_summary(self):
        plan = self._make_plan()
        plan.mark_complete(1, "Done")
        summary = plan.summary()
        assert "Pentest 10.0.0.1" in summary
        assert "recon" in summary
        assert "exploit" in summary
        assert "reporter" in summary


# --- PlannerAgent._parse_subtasks ---


class TestParseSubtasks:
    def test_valid_json(self):
        content = '[{"description": "Scan ports", "agent": "recon"}, {"description": "Write report", "agent": "reporter"}]'
        subtasks = PlannerAgent._parse_subtasks(content)
        assert len(subtasks) == 2
        assert subtasks[0].description == "Scan ports"
        assert subtasks[0].agent == "recon"
        assert subtasks[0].id == 1
        assert subtasks[1].id == 2

    def test_json_with_surrounding_text(self):
        content = 'Here is the plan:\n[{"description": "Scan", "agent": "recon"}]\nEnd.'
        subtasks = PlannerAgent._parse_subtasks(content)
        assert len(subtasks) == 1

    def test_max_15_subtasks(self):
        items = [{"description": f"Task {i}", "agent": "recon"} for i in range(20)]

        content = json.dumps(items)
        subtasks = PlannerAgent._parse_subtasks(content)
        assert len(subtasks) == 15

    def test_invalid_json_fallback(self):
        content = "Just do a port scan and find vulnerabilities"
        subtasks = PlannerAgent._parse_subtasks(content)
        assert len(subtasks) == 1
        assert subtasks[0].agent == "recon"

    def test_no_brackets_fallback(self):
        content = "No JSON here at all"
        subtasks = PlannerAgent._parse_subtasks(content)
        assert len(subtasks) == 1
        assert "No JSON" in subtasks[0].description

    def test_ids_are_sequential(self):
        content = '[{"description": "A", "agent": "recon"}, {"description": "B", "agent": "exploit"}, {"description": "C", "agent": "reporter"}]'
        subtasks = PlannerAgent._parse_subtasks(content)
        assert [st.id for st in subtasks] == [1, 2, 3]


# --- Agent classes exist and have expected interface ---


class TestAgentInterfaces:
    def test_planner_agent_init(self):
        agent = PlannerAgent(model_name="claude-sonnet-4-6")
        assert agent.llm is not None

    def test_recon_agent_init(self):
        agent = ReconAgent(model_name="claude-sonnet-4-6")
        assert agent.model_name == "claude-sonnet-4-6"

    def test_exploit_agent_init(self):
        agent = ExploitAgent(model_name="claude-sonnet-4-6")
        assert agent.model_name == "claude-sonnet-4-6"

    def test_reporter_agent_init(self):
        agent = ReporterAgent(model_name="claude-sonnet-4-6")
        assert agent.model_name == "claude-sonnet-4-6"
