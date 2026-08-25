"""Investigation queue tool: flag_potential.

Lets the hunter bookmark suspicious lines without committing to a finding.
The queue accumulates across file reads so cross-file asymmetries stay visible.
"""

from __future__ import annotations

import logging
import uuid
from typing import Literal, TypedDict

from pydantic import Field

from clearwing.llm import NativeToolSpec, ToolInputModel

from .sandbox import HunterContext

logger = logging.getLogger(__name__)


PotentialPriority = Literal["high", "medium", "low"]


class Potential(TypedDict):
    id: str
    file: str
    line: int
    note: str
    hypothesis: str
    priority: PotentialPriority


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


class DismissPotentialInput(ToolInputModel):
    potential_id: str = Field(description="ID returned by flag_potential.")
    resolution: str = Field(
        description="One sentence explaining the source evidence that ruled out the lead."
    )


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
        }
        ctx.potentials.append(entry)
        logger.info("FLAGGED %s:%d [%s] %s", file, line, priority, note[:120])
        return (
            f"Flagged {file}:{line} as potential [{entry['id']}] "
            f"({priority}). Queue: {len(ctx.potentials)} unresolved."
        )

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
            name="dismiss_potential",
            description=(
                "Remove a flagged potential only after source evidence affirmatively rules it out. "
                "Do not dismiss an inconclusive lead; unresolved leads are preserved in the SITREP."
            ),
            schema=DismissPotentialInput.model_json_schema(),
            handler=dismiss_potential,
        ),
    ]
