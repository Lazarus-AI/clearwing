"""Investigation queue tool: flag_potential.

Lets the hunter bookmark suspicious lines without committing to a finding.
The queue accumulates across file reads so cross-file asymmetries stay visible.
"""

from __future__ import annotations

import logging
import uuid
from typing import Literal, NotRequired, TypedDict

from pydantic import Field

from clearwing.llm import NativeToolSpec, ToolInputModel

from .sandbox import HunterContext

logger = logging.getLogger(__name__)


PotentialPriority = Literal["high", "medium", "low"]
PotentialStatus = Literal["open", "unknown", "clear"]
ResolvedPotentialStatus = Literal["unknown", "clear"]


class Potential(TypedDict):
    id: str
    file: str
    line: int
    note: str
    hypothesis: str
    priority: PotentialPriority
    status: PotentialStatus
    resolution: NotRequired[str]


class FlagPotentialInput(ToolInputModel):
    file: str = Field(description="Repo-relative file path, e.g. 'src/parser/decode.c'.")
    line: int = Field(description="Line number of the suspicious call or expression.")
    note: str = Field(
        description=(
            "What you observed at this line — one concrete sentence. "
            "Example: 'calls memcpy with user-supplied length without bounds check, "
            "unlike parse_header which validates len < buf_size at line 233.'"
        )
    )
    hypothesis: str = Field(
        description=(
            "The vulnerability class this might indicate. "
            "Example: 'CWE-120: stack buffer overflow — attacker-controlled length "
            "passed directly to memcpy without validation.'"
        )
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
    status: ResolvedPotentialStatus = Field(
        description=(
            "unknown — investigated but evidence remains inconclusive. "
            "clear — investigated and ruled out."
        )
    )
    resolution: str = Field(description="One sentence explaining the resulting state.")
def build_potential_tools(ctx: HunterContext) -> list[NativeToolSpec]:

    def flag_potential(
        file: str,
        line: int,
        note: str,
        hypothesis: str,
        priority: PotentialPriority = "medium",
        **_: object,
    ) -> str:
        entry: Potential = {
            "id": uuid.uuid4().hex[:8],
            "file": file,
            "line": line,
            "note": note,
            "hypothesis": hypothesis,
            "priority": priority,
            "status": "open",
        }
        ctx.potentials.append(entry)
        open_count = sum(1 for p in ctx.potentials if p["status"] == "open")
        logger.info("FLAGGED %s:%d [%s/open] %s", file, line, priority, note[:120])
        return (
            f"Flagged {file}:{line} as potential [{entry['id']}] "
            f"({priority}/open). Queue: {open_count} open."
        )

    def update_potential(
        potential_id: str,
        status: ResolvedPotentialStatus,
        resolution: str,
        **_: object,
    ) -> str:
        for potential in ctx.potentials:
            if potential.get("id") == potential_id:
                if potential.get("status") != "open":
                    return f"Potential [{potential_id}] is already {potential['status']}."
                potential["status"] = status
                potential["resolution"] = resolution
                return f"Potential [{potential_id}] marked {status}: {resolution}"
        return f"No potential found with id={potential_id}"

    return [
        NativeToolSpec(
            name="flag_potential",
            description=(
                "Call this the moment you see something suspicious while reading code — "
                "before moving on to the next file or function. "
                "Adds the line to an investigation queue so cross-file asymmetries stay "
                "visible even after you've read many more files. "
                "Do NOT defer flagging until you have a complete trace — flag early, "
                "then keep reading. A potential is not a finding: you are saying "
                "'this is worth coming back to', not 'this is definitely a bug'. "
                "Example trigger: you see a function call a core operation (encrypt, free, write) "
                "without the setup call (set_iv, null-check, bounds-check) that peer callers use."
            ),
            schema=FlagPotentialInput.model_json_schema(),
            handler=flag_potential,
        ),
        NativeToolSpec(
            name="update_potential",
            description=(
                "Resolve a previously flagged potential after investigating it. "
                "Use status='clear' when it is ruled out or status='unknown' when "
                "the available evidence is still inconclusive."
            ),
            schema=UpdatePotentialInput.model_json_schema(),
            handler=update_potential,
        ),
    ]
