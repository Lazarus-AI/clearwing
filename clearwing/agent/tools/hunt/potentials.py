"""Investigation queue tool: flag_potential.

Lets the hunter bookmark suspicious lines without committing to a finding.
The queue accumulates across file reads so cross-file asymmetries stay visible.
"""

from __future__ import annotations

import logging
import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from clearwing.llm import NativeToolSpec, ToolInputModel

from .sandbox import HunterContext

logger = logging.getLogger(__name__)


PotentialPriority = Literal["high", "medium", "low"]
EvidenceStatus = Literal["unknown", "supported", "disproven"]


class PotentialVerification(BaseModel):
    """Neutral evidence gaps that must be resolved before promotion."""

    model_config = ConfigDict(extra="forbid")

    attacker_control: EvidenceStatus = "unknown"
    reachability: EvidenceStatus = "unknown"
    guard_behavior: EvidenceStatus = "unknown"
    impact: EvidenceStatus = "unknown"


class Potential(BaseModel):
    """Durable investigation state, independent of conversation history."""

    model_config = ConfigDict(extra="forbid")

    id: str
    file: str
    line: int
    note: str
    hypothesis: str
    security_invariant: str
    priority: PotentialPriority
    status: Literal["unresolved"] = "unresolved"
    verification: PotentialVerification = Field(default_factory=PotentialVerification)
    observations: list[str] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)
    disproof_conditions: list[str] = Field(default_factory=list)
    deferred_reason: str = ""
    missing_evidence: list[str] = Field(default_factory=list)


class FlagPotentialInput(ToolInputModel):
    file: str = Field(description="Existing repository-relative source path.")
    line: int = Field(description="Line number of the suspicious call or expression.")
    note: str = Field(default="", description="Optional concrete source fact observed here.")
    hypothesis: str = Field(
        description="Security property that may be violated and the resulting impact."
    )
    security_invariant: str = Field(
        default="", description="Safety or authorization rule that must hold if the code is secure."
    )
    open_questions: list[str] = Field(
        default_factory=list,
        max_length=4,
        description="Neutral unanswered questions needed to assess the hypothesis.",
    )
    disproof_conditions: list[str] = Field(
        default_factory=list,
        max_length=3,
        description="Concrete source facts that would rule out the hypothesis.",
    )
    priority: PotentialPriority = Field(
        default="medium",
        description=(
            "high — directly violates a security invariant; investigate next. "
            "medium — suspicious asymmetry; investigate after high items. "
            "low — minor code smell; investigate only if time permits."
        ),
    )


class UpdatePotentialInput(ToolInputModel):
    potential_id: str = Field(description="ID returned by flag_potential.")
    observation: str | None = Field(
        default=None,
        description="One new source-backed fact learned during verification.",
    )
    security_invariant: str | None = Field(default=None)
    open_questions: list[str] | None = Field(default=None, max_length=4)
    disproof_conditions: list[str] | None = Field(default=None, max_length=3)


class DismissPotentialInput(ToolInputModel):
    potential_id: str = Field(description="ID returned by flag_potential.")
    resolution: str = Field(
        description="One sentence explaining the source evidence that ruled out the lead."
    )
    disproof_condition: str = Field(
        description="Exact previously recorded disproof condition satisfied by the evidence."
    )
    evidence: list[str] = Field(
        min_length=1,
        max_length=4,
        description="Source citations such as path:line plus the fact established there.",
    )


class DeferPotentialInput(ToolInputModel):
    potential_id: str = Field(description="ID returned by flag_potential.")
    reason: str = Field(description="Why the lead remains unresolved after bounded verification.")
    missing_evidence: list[str] = Field(
        default_factory=list,
        max_length=4,
        description="Specific evidence a later verifier must obtain.",
    )


def _dismissal_validation_error(
    potential: dict, disproof_condition: str, evidence: list[str]
) -> str | None:
    if disproof_condition not in (potential.get("disproof_conditions") or []):
        return (
            "disproof_condition must exactly match one recorded on the potential. "
            "Defer it if evidence is inconclusive."
        )
    if not evidence or not all(":" in item for item in evidence):
        return "cite at least one repository path and line as path:line."
    return None


def build_potential_tools(ctx: HunterContext) -> list[NativeToolSpec]:  # noqa: C901

    def flag_potential(
        file: str,
        line: int,
        hypothesis: str,
        note: str = "",
        security_invariant: str = "",
        open_questions: list[str] | None = None,
        disproof_conditions: list[str] | None = None,
        priority: PotentialPriority = "medium",
        **_: object,
    ) -> str:
        entry = Potential(
            id=uuid.uuid4().hex[:8],
            file=file,
            line=line,
            note=note or hypothesis,
            hypothesis=hypothesis,
            security_invariant=security_invariant,
            priority=priority,
            open_questions=open_questions or [],
            disproof_conditions=disproof_conditions or [],
        )
        ctx.potentials.append(entry.model_dump(mode="json"))
        logger.info("FLAGGED %s:%d [%s] %s", file, line, priority, hypothesis[:120])
        return f"Flagged {file}:{line} as potential [{entry.id}] ({priority}). Queue: {len(ctx.potentials)} unresolved."

    def update_potential(
        potential_id: str,
        observation: str | None = None,
        security_invariant: str | None = None,
        open_questions: list[str] | None = None,
        disproof_conditions: list[str] | None = None,
        **_: object,
    ) -> str:
        for potential in ctx.potentials:
            if potential.get("id") != potential_id:
                continue
            if observation:
                potential.setdefault("observations", []).append(observation)
            if security_invariant is not None:
                potential["security_invariant"] = security_invariant
            if open_questions is not None:
                potential["open_questions"] = open_questions
            if disproof_conditions is not None:
                potential["disproof_conditions"] = disproof_conditions
            return f"Updated potential [{potential_id}]."
        return f"No potential found with id={potential_id}"

    def dismiss_potential(
        potential_id: str,
        resolution: str,
        disproof_condition: str,
        evidence: list[str],
        **_: object,
    ) -> str:
        for index, potential in enumerate(ctx.potentials):
            if potential.get("id") == potential_id:
                if error := _dismissal_validation_error(
                    potential, disproof_condition, evidence
                ):
                    return f"Potential [{potential_id}] not dismissed: {error}"
                resolved = ctx.potentials.pop(index)
                resolved.update(
                    {
                        "status": "dismissed",
                        "resolution": resolution,
                        "satisfied_disproof_condition": disproof_condition,
                        "resolution_evidence": evidence,
                    }
                )
                ctx.potential_history.append(resolved)
                return f"Potential [{potential_id}] ruled out: {resolution}"
        return f"No potential found with id={potential_id}"

    def defer_potential(
        potential_id: str,
        reason: str,
        missing_evidence: list[str] | None = None,
        **_: object,
    ) -> str:
        for potential in ctx.potentials:
            if potential.get("id") != potential_id:
                continue
            potential["deferred_reason"] = reason
            potential["missing_evidence"] = missing_evidence or []
            return f"Deferred potential [{potential_id}] as unresolved: {reason}"
        return f"No potential found with id={potential_id}"

    return [
        NativeToolSpec(
            name="flag_potential",
            description=(
                "Bookmark a concrete security hypothesis immediately, before extended "
                "verification. Requires only file, line, and hypothesis. Flagging is not "
                "a claim that the issue is confirmed."
            ),
            schema=FlagPotentialInput.model_json_schema(),
            handler=flag_potential,
        ),
        NativeToolSpec(
            name="update_potential",
            description=(
                "Add source-backed evidence or neutral verification criteria to an existing "
                "potential as the investigation progresses."
            ),
            schema=UpdatePotentialInput.model_json_schema(),
            handler=update_potential,
        ),
        NativeToolSpec(
            name="defer_potential",
            description=(
                "Stop active verification while preserving an unresolved potential. "
                "Use when the bounded sourcehunt budget is exhausted and later verification "
                "must obtain specific missing evidence."
            ),
            schema=DeferPotentialInput.model_json_schema(),
            handler=defer_potential,
        ),
        NativeToolSpec(
            name="dismiss_potential",
            description=(
                "Resolve a flagged potential as dismissed only after source evidence satisfies "
                "one of its recorded disproof conditions. The dismissed lead remains in the "
                "audit history. Do not dismiss an inconclusive lead; defer it instead."
            ),
            schema=DismissPotentialInput.model_json_schema(),
            handler=dismiss_potential,
        ),
    ]
