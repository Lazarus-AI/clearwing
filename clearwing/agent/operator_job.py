"""Transport-neutral job adapter for the autonomous Operator agent.

This module gives embedders a small, stable boundary around :class:`OperatorAgent`
without imposing an HTTP protocol or an LLM-provider response schema.  Transports
remain responsible for authentication, job lifecycle, cancellation, and provider
configuration.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from typing import Any

from clearwing.agent.operator import OperatorAgent, OperatorConfig

OperatorProgressCallback = Callable[[str, str], None]


class OperatorJobValidationError(ValueError):
    """Raised when an Operator job request is malformed."""


@dataclass(frozen=True)
class OperatorJobRequest:
    """Validated, transport-independent input for an Operator job."""

    target: str
    goals: list[str]
    model: str = "claude-sonnet-4-6"
    operator_model: str = ""
    max_turns: int = 100
    timeout_minutes: int = 60
    cost_limit: float = 0.0
    auto_approve_scans: bool = True
    auto_approve_exploits: bool = False

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> OperatorJobRequest:
        """Parse and strictly validate a request mapping.

        Unknown fields are rejected so transport-specific or provider-specific
        options cannot silently leak through this boundary.
        """
        if not isinstance(value, Mapping):
            raise OperatorJobValidationError("request must be an object")

        allowed = {
            "target",
            "goals",
            "model",
            "operator_model",
            "max_turns",
            "timeout_minutes",
            "cost_limit",
            "auto_approve_scans",
            "auto_approve_exploits",
        }
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise OperatorJobValidationError(f"unknown field(s): {', '.join(unknown)}")

        target = _nonempty_string(value.get("target"), "target")

        goals_value = value.get("goals")
        if not isinstance(goals_value, list) or not goals_value:
            raise OperatorJobValidationError("goals must be a non-empty list of strings")
        goals = [
            _nonempty_string(goal, f"goals[{index}]") for index, goal in enumerate(goals_value)
        ]

        model = _nonempty_string(value.get("model", cls.model), "model")
        operator_model = value.get("operator_model", cls.operator_model)
        if not isinstance(operator_model, str):
            raise OperatorJobValidationError("operator_model must be a string")
        operator_model = operator_model.strip()

        max_turns = _positive_integer(value.get("max_turns", cls.max_turns), "max_turns")
        timeout_minutes = _positive_integer(
            value.get("timeout_minutes", cls.timeout_minutes), "timeout_minutes"
        )
        cost_limit = _nonnegative_number(value.get("cost_limit", cls.cost_limit), "cost_limit")
        auto_approve_scans = _boolean(
            value.get("auto_approve_scans", cls.auto_approve_scans), "auto_approve_scans"
        )
        auto_approve_exploits = _boolean(
            value.get("auto_approve_exploits", cls.auto_approve_exploits),
            "auto_approve_exploits",
        )

        return cls(
            target=target,
            goals=goals,
            model=model,
            operator_model=operator_model,
            max_turns=max_turns,
            timeout_minutes=timeout_minutes,
            cost_limit=cost_limit,
            auto_approve_scans=auto_approve_scans,
            auto_approve_exploits=auto_approve_exploits,
        )

    def to_config(self, *, on_progress: OperatorProgressCallback | None = None) -> OperatorConfig:
        """Build the core Operator configuration for this job."""
        return OperatorConfig(
            target=self.target,
            goals=list(self.goals),
            model=self.model,
            operator_model=self.operator_model,
            max_turns=self.max_turns,
            timeout_minutes=self.timeout_minutes,
            cost_limit=self.cost_limit,
            auto_approve_scans=self.auto_approve_scans,
            auto_approve_exploits=self.auto_approve_exploits,
            on_message=on_progress,
        )


async def run_operator_job(
    request: Mapping[str, Any] | OperatorJobRequest,
    *,
    on_progress: OperatorProgressCallback | None = None,
) -> dict[str, Any]:
    """Run an Operator job and serialize its domain result.

    Provider credentials and endpoint overrides intentionally do not appear in
    the request.  An embedding transport should configure those through its own
    trusted runtime boundary.
    """
    parsed = (
        request
        if isinstance(request, OperatorJobRequest)
        else OperatorJobRequest.from_mapping(request)
    )
    result = await OperatorAgent(parsed.to_config(on_progress=on_progress)).arun()
    return asdict(result)


def _nonempty_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise OperatorJobValidationError(f"{name} must be a non-empty string")
    return value.strip()


def _positive_integer(value: Any, name: str) -> int:
    if type(value) is not int or value <= 0:
        raise OperatorJobValidationError(f"{name} must be a positive integer")
    return value


def _nonnegative_number(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise OperatorJobValidationError(f"{name} must be a non-negative number")
    return float(value)


def _boolean(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise OperatorJobValidationError(f"{name} must be a boolean")
    return value
