"""Investigation queue tools: flag_potential, get_potentials, dismiss_potential.

Lets the hunter bookmark suspicious lines without committing to a finding.
The queue accumulates across file reads so cross-file asymmetries stay visible.
"""

from __future__ import annotations

import logging
import uuid

logger = logging.getLogger(__name__)

from pydantic import Field

from clearwing.llm import NativeToolSpec, ToolInputModel

from .sandbox import HunterContext


class FlagPotentialInput(ToolInputModel):
    file: str = Field(description="Repo-relative file path, e.g. 'src/cipher_aes_ocb.c'.")
    line: int = Field(description="Line number of the suspicious call or expression.")
    note: str = Field(
        description=(
            "What you observed at this line — one concrete sentence. "
            "Example: 'calls aes_generic_ocb_cipher without calling update_iv first, "
            "unlike aes_ocb_block_update which calls update_iv at line 233.'"
        )
    )
    hypothesis: str = Field(
        description=(
            "The vulnerability class this might indicate. "
            "Example: 'CWE-325: missing required crypto step — IV never applied on one-shot path, "
            "enabling nonce reuse.'"
        )
    )
    priority: str = Field(
        default="medium",
        description=(
            "high — directly violates a security invariant; investigate next. "
            "medium — suspicious asymmetry; investigate after high items. "
            "low — minor code smell; investigate only if time permits."
        ),
    )


class DismissPotentialInput(ToolInputModel):
    potential_id: str = Field(description="ID returned by flag_potential.")
    reason: str = Field(
        description=(
            "Why this was ruled out — one sentence. "
            "Example: 'update_iv is called two lines earlier at line 499, inside the same if-block.'"
        )
    )


def build_potential_tools(ctx: HunterContext) -> list[NativeToolSpec]:

    def flag_potential(
        file: str,
        line: int,
        note: str,
        hypothesis: str,
        priority: str = "medium",
        **_: object,
    ) -> str:
        entry = {
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
        logger.info("FLAGGED %s:%d [%s] %s", file, line, priority, note[:120])
        return f"Flagged {file}:{line} as potential [{entry['id']}]. Queue: {open_count} open."

    def get_potentials(**_: object) -> list[dict]:
        return [p for p in ctx.potentials if p["status"] == "open"]

    def dismiss_potential(potential_id: str, reason: str, **_: object) -> str:
        for p in ctx.potentials:
            if p["id"] == potential_id:
                p["status"] = "dismissed"
                p["dismiss_reason"] = reason
                return f"Dismissed [{potential_id}]: {reason}"
        return f"No open potential with id={potential_id}"

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
            name="get_potentials",
            description=(
                "Return all open potentials in the investigation queue. "
                "Call this: (1) before deciding what file to read next — the queue "
                "may already point at the right place; (2) after reading several files "
                "to compare leads side by side for asymmetries; (3) before concluding "
                "the hunt to make sure no flagged lead was left uninvestigated."
            ),
            schema={
                "type": "object",
                "properties": {},
                "required": [],
                "title": "GetPotentialsInput",
            },
            handler=get_potentials,
        ),
        NativeToolSpec(
            name="dismiss_potential",
            description=(
                "Remove a potential from the queue after ruling it out. "
                "Call this when you have read enough context to confirm the suspicion "
                "was a false positive. Requires a one-sentence reason so the decision "
                "is traceable."
            ),
            schema=DismissPotentialInput.model_json_schema(),
            handler=dismiss_potential,
        ),
    ]
