"""Semgrep triage — LLM-ranked top finding per vulnerability category."""

from __future__ import annotations

import json
import logging

logger = logging.getLogger(__name__)

_TRIAGE_SYSTEM = """\
You are a security triage analyst. Given static analysis findings for a target, \
pick the single most important finding from each vulnerability category \
(injection, memory safety, auth/authz, crypto, path traversal, XSS, \
deserialization, DoS, information leak, race condition, etc).

Return ONLY a JSON array. Each element:
{"file": str, "line": int, "cwe": str, "category": str, "rationale": str}

rationale = one sentence explaining why this is the most interesting finding in its category.
If a category has no findings, omit it. Maximum one pick per category."""


async def triage_semgrep_findings(
    findings: list[dict],
    target_context: str,
    llm: object | None,
) -> list[dict]:
    """Pick the top finding per vulnerability category via a single LLM call.

    Returns enriched finding dicts (original fields + rationale).
    Falls back to raw findings on any failure or if llm is None.
    """
    if not findings:
        return []

    if llm is None:
        return findings

    # Build compact representation for the prompt
    compact = [
        {
            "file": f.get("file", ""),
            "line": f.get("line", 0),
            "severity": f.get("severity", ""),
            "cwe": f.get("cwe", ""),
            "message": f.get("message", "")[:200],
        }
        for f in findings
    ]

    user_msg = (
        f"## Target\n{target_context}\n\n"
        f"## Static Analysis Findings ({len(compact)} total)\n"
        f"```json\n{json.dumps(compact, separators=(',', ':'))}\n```\n\n"
        "Pick the single most important finding from each vulnerability category."
    )

    try:
        from clearwing.llm.native import ChatMessage

        response = await llm.achat(
            messages=[ChatMessage("user", user_msg)],
            system=_TRIAGE_SYSTEM,
            max_tokens=4000,
        )

        text = response.text.strip()
        # Extract JSON array from response (handle markdown fences)
        if text.startswith("```"):
            lines = text.splitlines()
            if len(lines) > 1:
                if lines[-1].strip() == "```":
                    lines = lines[1:-1]
                else:
                    lines = lines[1:]
                text = "\n".join(lines).strip()

        picks = json.loads(text)
        if not isinstance(picks, list):
            logger.warning("Triage LLM returned non-list, falling back to raw findings")
            return findings

        # Build lookup for enrichment
        pick_keys = {(p["file"], p["line"]) for p in picks if "file" in p and "line" in p}
        pick_rationales = {
            (p["file"], p["line"]): p.get("rationale", "")
            for p in picks
            if "file" in p and "line" in p
        }

        # Return only the picked findings, enriched with rationale
        result = []
        for f in findings:
            key = (f.get("file", ""), f.get("line", 0))
            if key in pick_keys:
                enriched = {**f, "rationale": pick_rationales.get(key, "")}
                result.append(enriched)

        if not result:
            # LLM picks didn't match any findings (bad file/line) — fall back
            logger.warning(
                "Triage picks matched no findings (%d picks, sample: %s), returning raw",
                len(picks), picks[:2],
            )
            return findings

        logger.info("Semgrep triage: %d categories from %d raw findings", len(result), len(findings))
        return result

    except Exception:
        logger.warning("Semgrep triage failed, returning raw findings", exc_info=True)
        return findings
