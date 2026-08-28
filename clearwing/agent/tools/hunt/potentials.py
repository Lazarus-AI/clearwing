"""Investigation queue tool: flag_potential.

Lets the hunter bookmark suspicious lines without committing to a finding.
The queue accumulates across file reads so cross-file asymmetries stay visible.
"""

from __future__ import annotations

import logging
import re
import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from clearwing.llm import NativeToolSpec, ToolInputModel

from .sandbox import HunterContext

logger = logging.getLogger(__name__)


PotentialPriority = Literal["high", "medium", "low"]
EvidenceStatus = Literal["unknown", "supported", "disproven"]
PotentialImpact = Literal[
    "memory_corruption",
    "authorization_bypass",
    "integrity_or_confidentiality",
    "code_execution",
    "resource_exhaustion",
    "other",
    "unknown",
]
PotentialNovelty = Literal["distinct", "related", "duplicate", "unknown"]
PotentialAction = Literal["update", "reopen", "close"]

_IMPACT_SCORES: dict[str, int] = {
    "code_execution": 55,
    "memory_corruption": 50,
    "authorization_bypass": 50,
    "integrity_or_confidentiality": 40,
    "resource_exhaustion": 5,
    "other": 10,
    "unknown": 0,
}
_EVIDENCE_SCORES: dict[str, int] = {"supported": 8, "unknown": 0, "disproven": -20}
_NOVELTY_SCORES: dict[str, int] = {"distinct": 8, "related": 2, "unknown": 0, "duplicate": -40}


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
    security_boundary: str = ""
    security_invariant: str
    priority: PotentialPriority
    priority_score: int = 0
    priority_reasons: list[str] = Field(default_factory=list)
    impact_class: PotentialImpact = "unknown"
    novelty: PotentialNovelty = "unknown"
    status: Literal["open", "examined", "safe", "unresolved", "confirmed"] = "open"
    attacker_inputs: list[str] = Field(default_factory=list)
    required_relationships: list[str] = Field(default_factory=list)
    observed_checks: list[str] = Field(default_factory=list)
    missing_checks: list[str] = Field(default_factory=list)
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
    security_boundary: str = Field(
        default="",
        description="Public entry point, parser, verifier, state transition, or authorization decision.",
    )
    attacker_inputs: list[str] = Field(default_factory=list, max_length=6)
    required_relationships: list[str] = Field(default_factory=list, max_length=6)
    observed_checks: list[str] = Field(default_factory=list, max_length=6)
    missing_checks: list[str] = Field(default_factory=list, max_length=6)
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
    impact_class: PotentialImpact = Field(
        default="unknown",
        description=(
            "Most plausible direct security impact. Classify recoverable allocation or "
            "CPU pressure as resource_exhaustion, not memory_corruption."
        ),
    )
    novelty: PotentialNovelty = Field(
        default="unknown",
        description="Whether this is distinct from, related to, or duplicates an existing lead.",
    )
    priority: PotentialPriority = Field(
        default="medium",
        description=(
            "Initial hint retained for compatibility. The queue recomputes priority from "
            "typed impact, verification evidence, invariant completeness, and novelty."
        ),
    )


class UpdatePotentialInput(ToolInputModel):
    potential_id: str = Field(description="ID returned by flag_potential.")
    action: PotentialAction = Field(
        default="update",
        description=(
            "update an active lead, reopen a previously unresolved lead, or close an "
            "active lead as unresolved. Use dismiss_potential for evidence-backed safe closure."
        ),
    )
    reason: str | None = Field(
        default=None,
        description="Required for reopen and close; explain the investigation-state transition.",
    )
    missing_evidence: list[str] | None = Field(default=None, max_length=4)
    observation: str | None = Field(
        default=None,
        description="One new source-backed fact learned during verification.",
    )
    security_invariant: str | None = Field(default=None)
    security_boundary: str | None = Field(default=None)
    attacker_inputs: list[str] | None = Field(default=None, max_length=6)
    required_relationships: list[str] | None = Field(default=None, max_length=6)
    observed_checks: list[str] | None = Field(default=None, max_length=6)
    missing_checks: list[str] | None = Field(default=None, max_length=6)
    open_questions: list[str] | None = Field(default=None, max_length=4)
    disproof_conditions: list[str] | None = Field(default=None, max_length=3)
    impact_class: PotentialImpact | None = None
    novelty: PotentialNovelty | None = None
    attacker_control: EvidenceStatus | None = None
    reachability: EvidenceStatus | None = None
    guard_behavior: EvidenceStatus | None = Field(
        default=None,
        description="supported means source evidence supports the suspected missing/ineffective guard.",
    )
    impact: EvidenceStatus | None = None


def _score_potential(potential: dict) -> tuple[int, list[str]]:
    """Derive lead priority from impact, evidence, invariant strength, and novelty."""

    impact_class = str(potential.get("impact_class", "unknown"))
    score = _IMPACT_SCORES.get(impact_class, 0)
    reasons = [f"impact={impact_class}:{score:+d}"]

    verification = potential.get("verification") or {}
    for field in ("attacker_control", "reachability", "guard_behavior", "impact"):
        status = str(verification.get(field, "unknown"))
        points = _EVIDENCE_SCORES.get(status, 0)
        score += points
        if points:
            reasons.append(f"{field}={status}:{points:+d}")

    map_points = 0
    if potential.get("security_invariant"):
        map_points += 4
    if potential.get("required_relationships"):
        map_points += 4
    if potential.get("missing_checks"):
        map_points += 4
    score += map_points
    if map_points:
        reasons.append(f"invariant_map:{map_points:+d}")

    novelty = str(potential.get("novelty", "unknown"))
    novelty_points = _NOVELTY_SCORES.get(novelty, 0)
    score += novelty_points
    if novelty_points:
        reasons.append(f"novelty={novelty}:{novelty_points:+d}")
    return score, reasons


def _refresh_priority(potential: dict) -> None:
    score, reasons = _score_potential(potential)
    potential["priority_score"] = score
    potential["priority_reasons"] = reasons
    potential["priority"] = "high" if score >= 55 else ("medium" if score >= 30 else "low")


def _sort_potentials(potentials: list[dict]) -> None:
    potentials.sort(key=lambda item: int(item.get("priority_score", 0)), reverse=True)


def _normalized_words(value: object) -> set[str]:
    return set(re.findall(r"[a-z0-9_]+", str(value).lower()))


def _same_potential(existing: dict, candidate: dict) -> bool:
    existing_file = str(existing.get("file", "")).removeprefix("/workspace/")
    candidate_file = str(candidate.get("file", "")).removeprefix("/workspace/")
    if existing_file != candidate_file:
        return False
    same_contract = bool(candidate.get("security_boundary")) and (
        _normalized_words(existing.get("security_boundary"))
        == _normalized_words(candidate.get("security_boundary"))
        and _normalized_words(existing.get("security_invariant"))
        == _normalized_words(candidate.get("security_invariant"))
    )
    if same_contract:
        return True
    if existing.get("line") != candidate.get("line"):
        return False
    return existing.get("impact_class") == candidate.get("impact_class")


def _find_duplicate(ctx: HunterContext, candidate: dict) -> dict | None:
    return next(
        (
            existing
            for existing in [*ctx.potentials, *ctx.potential_history]
            if _same_potential(existing, candidate)
        ),
        None,
    )


def _potential_error(code: str, message: str, **details: object) -> dict[str, object]:
    return {"ok": False, "error": {"code": code, "message": message, **details}}


def _resolve_update_target(
    ctx: HunterContext,
    potential_id: str,
    action: PotentialAction,
    reason: str | None,
) -> tuple[dict | None, str | dict[str, object] | None, bool]:
    active = next((item for item in ctx.potentials if item.get("id") == potential_id), None)
    if action != "reopen":
        if active is not None:
            if action == "close" and not reason:
                return None, _potential_error(
                    "MISSING_TRANSITION_REASON",
                    "Closing a potential requires a reason.",
                    potential_id=potential_id,
                    status=active.get("status", "open"),
                ), False
            return active, None, False
        historical = next(
            (item for item in ctx.potential_history if item.get("id") == potential_id),
            None,
        )
        if historical is not None:
            return None, _potential_error(
                "POTENTIAL_NOT_ACTIVE",
                "The potential is closed; reopen it before updating it.",
                potential_id=potential_id,
                status=historical.get("status", "unknown"),
            ), False
        return None, f"No potential found with id={potential_id}", False

    if active is not None:
        return None, _potential_error(
            "INVALID_POTENTIAL_TRANSITION",
            f"Potential [{potential_id}] is already active; update or close it.",
            potential_id=potential_id,
            status=active.get("status", "open"),
        ), False
    history_index = next(
        (
            index
            for index, item in enumerate(ctx.potential_history)
            if item.get("id") == potential_id
        ),
        None,
    )
    if history_index is None:
        return None, f"No potential found with id={potential_id}", False
    historical = ctx.potential_history[history_index]
    if historical.get("status") != "unresolved":
        return None, _potential_error(
            "INVALID_POTENTIAL_TRANSITION",
            "Only an unresolved potential may be reopened.",
            potential_id=potential_id,
            status=historical.get("status", "unknown"),
        ), False
    if not reason:
        return None, _potential_error(
            "MISSING_TRANSITION_REASON",
            "Reopening a potential requires a reason.",
            potential_id=potential_id,
            status="unresolved",
        ), False
    potential = ctx.potential_history.pop(history_index)
    potential.setdefault("reopen_events", []).append(
        {
            "reason": reason,
            "previous_deferred_reason": potential.get("deferred_reason", ""),
            "previous_missing_evidence": potential.get("missing_evidence", []),
        }
    )
    potential["status"] = "examined"
    potential["deferred_reason"] = ""
    potential["missing_evidence"] = []
    ctx.potentials.append(potential)
    return potential, None, True


def _apply_potential_updates(potential: dict, updates: dict[str, object]) -> None:
    observation = updates.pop("observation", None)
    if observation:
        potential.setdefault("observations", []).append(observation)
        potential["status"] = "examined"
    for field, value in updates.items():
        if value is not None:
            potential[field] = value


def _update_verification(
    potential: dict,
    *,
    attacker_control: EvidenceStatus | None,
    reachability: EvidenceStatus | None,
    guard_behavior: EvidenceStatus | None,
    impact: EvidenceStatus | None,
) -> None:
    verification = potential.setdefault("verification", {})
    for field, value in (
        ("attacker_control", attacker_control),
        ("reachability", reachability),
        ("guard_behavior", guard_behavior),
        ("impact", impact),
    ):
        if value is not None:
            verification[field] = value


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
        security_boundary: str = "",
        security_invariant: str = "",
        attacker_inputs: list[str] | None = None,
        required_relationships: list[str] | None = None,
        observed_checks: list[str] | None = None,
        missing_checks: list[str] | None = None,
        open_questions: list[str] | None = None,
        disproof_conditions: list[str] | None = None,
        priority: PotentialPriority = "medium",
        impact_class: PotentialImpact = "unknown",
        novelty: PotentialNovelty = "unknown",
        **_: object,
    ) -> str | dict[str, object]:
        entry = Potential(
            id=uuid.uuid4().hex[:8],
            file=file,
            line=line,
            note=note or hypothesis,
            hypothesis=hypothesis,
            security_boundary=security_boundary,
            security_invariant=security_invariant,
            priority=priority,
            impact_class=impact_class,
            novelty=novelty,
            attacker_inputs=attacker_inputs or [],
            required_relationships=required_relationships or [],
            observed_checks=observed_checks or [],
            missing_checks=missing_checks or [],
            open_questions=open_questions or [],
            disproof_conditions=disproof_conditions or [],
        )
        potential = entry.model_dump(mode="json")
        _refresh_priority(potential)
        if duplicate := _find_duplicate(ctx, potential):
            duplicate_id = str(duplicate.get("id", ""))
            duplicate_status = str(duplicate.get("status", "open"))
            return _potential_error(
                "POTENTIAL_ALREADY_EXISTS",
                (
                    "A semantically equivalent potential already exists. Decide whether to "
                    "update it, reopen it if unresolved, close it, or abandon this lead."
                ),
                potential_id=duplicate_id,
                status=duplicate_status,
                priority_score=duplicate.get("priority_score", 0),
            )
        ctx.potentials.append(potential)
        _sort_potentials(ctx.potentials)
        logger.info(
            "FLAGGED %s:%d [%s score=%d] %s",
            file,
            line,
            potential["priority"],
            potential["priority_score"],
            hypothesis[:120],
        )
        return (
            f"Flagged {file}:{line} as potential [{entry.id}] "
            f"({potential['priority']}, score={potential['priority_score']}). "
            f"Queue: {len(ctx.potentials)} unresolved."
        )

    def update_potential(
        potential_id: str,
        action: PotentialAction = "update",
        reason: str | None = None,
        missing_evidence: list[str] | None = None,
        observation: str | None = None,
        security_boundary: str | None = None,
        security_invariant: str | None = None,
        attacker_inputs: list[str] | None = None,
        required_relationships: list[str] | None = None,
        observed_checks: list[str] | None = None,
        missing_checks: list[str] | None = None,
        open_questions: list[str] | None = None,
        disproof_conditions: list[str] | None = None,
        impact_class: PotentialImpact | None = None,
        novelty: PotentialNovelty | None = None,
        attacker_control: EvidenceStatus | None = None,
        reachability: EvidenceStatus | None = None,
        guard_behavior: EvidenceStatus | None = None,
        impact: EvidenceStatus | None = None,
        **_: object,
    ) -> str | dict[str, object]:
        potential, error, reopened = _resolve_update_target(
            ctx, potential_id, action, reason
        )
        if error is not None:
            return error
        assert potential is not None
        _apply_potential_updates(
            potential,
            {
                "observation": observation,
                "security_boundary": security_boundary,
                "security_invariant": security_invariant,
                "attacker_inputs": attacker_inputs,
                "required_relationships": required_relationships,
                "observed_checks": observed_checks,
                "missing_checks": missing_checks,
                "open_questions": open_questions,
                "disproof_conditions": disproof_conditions,
                "impact_class": impact_class,
                "novelty": novelty,
            },
        )
        _update_verification(
            potential,
            attacker_control=attacker_control,
            reachability=reachability,
            guard_behavior=guard_behavior,
            impact=impact,
        )
        _refresh_priority(potential)
        if action == "close":
            ctx.potentials.remove(potential)
            potential["status"] = "unresolved"
            potential["deferred_reason"] = reason
            potential["missing_evidence"] = missing_evidence or []
            ctx.potential_history.append(potential)
            return f"Closed potential [{potential_id}] as unresolved: {reason}"
        _sort_potentials(ctx.potentials)
        transition = "Reopened" if reopened else "Updated"
        return (
            f"{transition} potential [{potential_id}] "
            f"({potential['priority']}, score={potential['priority_score']})."
        )

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
                        "status": "safe",
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
        for index, potential in enumerate(ctx.potentials):
            if potential.get("id") != potential_id:
                continue
            resolved = ctx.potentials.pop(index)
            resolved["status"] = "unresolved"
            resolved["deferred_reason"] = reason
            resolved["missing_evidence"] = missing_evidence or []
            ctx.potential_history.append(resolved)
            return f"Deferred potential [{potential_id}] as unresolved: {reason}"
        return f"No potential found with id={potential_id}"

    return [
        NativeToolSpec(
            name="flag_potential",
            description=(
                "Bookmark a concrete security hypothesis immediately, before extended "
                "verification. Requires only file, line, and hypothesis. Flagging is not "
                "a claim that the issue is confirmed. Add the invariant map when known: "
                "boundary, attacker inputs, required relationships, observed checks, and "
                "checks that appear missing. Classify the direct impact and novelty so the "
                "queue can prioritize the lead without benchmark-specific knowledge."
            ),
            schema=FlagPotentialInput.model_json_schema(),
            handler=flag_potential,
        ),
        NativeToolSpec(
            name="update_potential",
            description=(
                "Update an active potential, reopen an unresolved historical potential, or "
                "close an active potential as unresolved. Complete its invariant map before "
                "promotion. Reopening and closing require a reason. Use dismiss_potential—not "
                "close—for a source-proven safe lead. Typed verification evidence recomputes "
                "priority from impact, attacker control, reachability, guard behavior, impact "
                "evidence, invariant completeness, and novelty."
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
                "audit history. A validation check is sufficient disproof only when it dominates "
                "every subsequent attacker-controlled mutation and every security-sensitive use "
                "across all reachable states. Do not dismiss an inconclusive lead; defer it instead."
            ),
            schema=DismissPotentialInput.model_json_schema(),
            handler=dismiss_potential,
        ),
    ]
