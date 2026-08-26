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


class DeferPotentialInput(ToolInputModel):
    potential_id: str = Field(description="ID returned by flag_potential.")
    reason: str = Field(description="Why the lead remains unresolved after bounded verification.")
    missing_evidence: list[str] = Field(
        default_factory=list,
        max_length=4,
        description="Specific evidence a later verifier must obtain.",
    )


def build_potential_tools(ctx: HunterContext) -> list[NativeToolSpec]:

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
        **_: object,
    ) -> str:
        for index, potential in enumerate(ctx.potentials):
            if potential.get("id") == potential_id:
                ctx.potentials.pop(index)
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
                "Remove a flagged potential only after source evidence affirmatively rules it out. "
                "Do not dismiss an inconclusive lead; unresolved leads are preserved in the SITREP."
            ),
            schema=DismissPotentialInput.model_json_schema(),
            handler=dismiss_potential,
        ),
    ]
