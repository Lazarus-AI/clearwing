from __future__ import annotations

import json
from dataclasses import dataclass, field

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage


@dataclass
class Subtask:
    id: int
    description: str
    agent: str  # "recon", "exploit", "reporter"
    status: str = "pending"  # pending, in_progress, completed, skipped
    result: str | None = None


@dataclass
class Plan:
    goal: str
    subtasks: list[Subtask] = field(default_factory=list)
    current_index: int = 0

    def next_task(self) -> Subtask | None:
        for st in self.subtasks:
            if st.status == "pending":
                return st
        return None

    def mark_complete(self, task_id: int, result: str = ""):
        for st in self.subtasks:
            if st.id == task_id:
                st.status = "completed"
                st.result = result
                break

    def is_complete(self) -> bool:
        return all(st.status in ("completed", "skipped") for st in self.subtasks)

    def summary(self) -> str:
        lines = [f"Plan: {self.goal}"]
        for st in self.subtasks:
            marker = (
                "\u2713"
                if st.status == "completed"
                else "\u25cb"
                if st.status == "pending"
                else "\u2192"
                if st.status == "in_progress"
                else "\u2717"
            )
            lines.append(f"  {marker} [{st.agent}] {st.description} ({st.status})")
        return "\n".join(lines)


PLANNER_PROMPT = """You are a penetration testing planner. Given a high-level goal and target information, decompose the task into an ordered list of subtasks.

Each subtask must specify:
- description: what to do
- agent: which specialist handles it ("recon", "exploit", or "reporter")

Rules:
- Maximum 15 subtasks
- Start with reconnaissance before exploitation
- Always end with reporting
- Order tasks logically (scan before enumerate, enumerate before exploit)
- Each subtask should be specific and actionable

Return a JSON array of objects with "description" and "agent" keys.
Example: [{"description": "Scan target for open ports", "agent": "recon"}, ...]
"""


class PlannerAgent:
    """Decomposes a high-level pentest goal into ordered subtasks."""

    def __init__(self, model_name: str = "claude-sonnet-4-6"):
        self.llm = ChatAnthropic(model=model_name)

    def create_plan(self, goal: str, context: str = "") -> Plan:
        """Create a plan from a high-level goal."""
        messages = [
            SystemMessage(content=PLANNER_PROMPT),
            HumanMessage(content=f"Goal: {goal}\n\nContext:\n{context}"),
        ]
        response = self.llm.invoke(messages)
        content = response.content if isinstance(response.content, str) else str(response.content)

        # Parse JSON from response
        subtasks = self._parse_subtasks(content)
        return Plan(goal=goal, subtasks=subtasks)

    def refine_plan(self, plan: Plan, feedback: str) -> Plan:
        """Refine an existing plan based on results so far."""
        messages = [
            SystemMessage(content=PLANNER_PROMPT),
            HumanMessage(
                content=(
                    f"Original goal: {plan.goal}\n\n"
                    f"Current plan status:\n{plan.summary()}\n\n"
                    f"Feedback/new findings: {feedback}\n\n"
                    "Revise the remaining subtasks (keep completed ones as-is). "
                    "Return the full updated subtask list as JSON."
                )
            ),
        ]
        response = self.llm.invoke(messages)
        content = response.content if isinstance(response.content, str) else str(response.content)
        new_subtasks = self._parse_subtasks(content)

        # Preserve completed tasks, replace pending ones
        completed = [st for st in plan.subtasks if st.status == "completed"]
        # Re-number new tasks starting after completed
        start_id = max((st.id for st in completed), default=0) + 1
        for i, st in enumerate(new_subtasks):
            st.id = start_id + i

        plan.subtasks = completed + new_subtasks
        return plan

    @staticmethod
    def _parse_subtasks(content: str) -> list[Subtask]:
        """Extract JSON subtask array from LLM response."""
        # Find JSON array in response
        start = content.find("[")
        end = content.rfind("]") + 1
        if start == -1 or end == 0:
            return [Subtask(id=1, description=content.strip(), agent="recon")]

        try:
            raw = json.loads(content[start:end])
        except json.JSONDecodeError:
            return [Subtask(id=1, description=content.strip(), agent="recon")]

        subtasks = []
        for i, item in enumerate(raw[:15]):  # Max 15 subtasks
            subtasks.append(
                Subtask(
                    id=i + 1,
                    description=item.get("description", str(item)),
                    agent=item.get("agent", "recon"),
                )
            )
        return subtasks
