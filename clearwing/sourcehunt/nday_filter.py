"""N-day exploitability filter — cheap LLM triage for CVE candidates (spec 015).

Rates each CVE as LIKELY_EXPLOITABLE / POSSIBLY_EXPLOITABLE / UNLIKELY_EXPLOITABLE
based on the patch diff. Batches up to 10 CVEs per LLM call to keep costs
~$1-5 for 100 CVEs.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

FILTER_BATCH_SIZE = 10

FILTER_SYSTEM_PROMPT = """\
You are triaging CVE patches for exploitability. For each CVE below, assess
whether the vulnerability is likely exploitable for privilege escalation,
code execution, or significant information disclosure.

Consider:
- Memory corruption bugs (heap/stack overflow, use-after-free) → LIKELY
- Integer overflows leading to memory corruption → LIKELY
- Race conditions with security impact → POSSIBLY
- Null pointer dereferences, assertion failures → UNLIKELY
- Documentation/test-only changes → UNLIKELY
- Logic bugs with unclear security impact → POSSIBLY

Return a JSON array with one object per CVE:
[
  {
    "cve_id": "CVE-YYYY-NNNNN",
    "exploitability": "LIKELY_EXPLOITABLE" | "POSSIBLY_EXPLOITABLE" | "UNLIKELY_EXPLOITABLE",
    "reasoning": "one sentence"
  }
]

Return ONLY the JSON array."""


@dataclass
class NdayCandidate:
    cve_id: str
    patch_source: str = ""
    diff_text: str = ""
    description: str = ""
    exploitability: str = ""
    filter_reasoning: str = ""
    project: str = ""


def parse_cve_list(path: str) -> list[NdayCandidate]:
    """Parse a text file with one CVE per line.

    Format: CVE-YYYY-NNNNN [commit_sha] [description...]
    """
    candidates: list[NdayCandidate] = []
    text = Path(path).read_text(encoding="utf-8")
    for line in text.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        cve_id = parts[0]
        patch_source = parts[1] if len(parts) > 1 else ""
        description = parts[2] if len(parts) > 2 else ""
        candidates.append(NdayCandidate(
            cve_id=cve_id,
            patch_source=patch_source,
            description=description,
        ))
    return candidates


def fetch_recent_cves(repo_path: str, days: int = 90) -> list[NdayCandidate]:
    """Search git log for recent CVE-mentioning commits."""
    if not os.path.isdir(repo_path):
        return []
    try:
        proc = subprocess.run(
            [
                "git", "-C", repo_path, "log",
                f"--since={days} days ago",
                "--all", "--oneline", "--grep=CVE-",
                "--format=%H %s",
            ],
            capture_output=True, text=True, check=False, timeout=30,
        )
        if proc.returncode != 0:
            return []
    except Exception:
        return []

    cve_pattern = re.compile(r"(CVE-\d{4}-\d{4,})")
    candidates: list[NdayCandidate] = []
    seen: set[str] = set()

    for line in proc.stdout.strip().splitlines():
        if not line.strip():
            continue
        parts = line.split(None, 1)
        commit_sha = parts[0]
        message = parts[1] if len(parts) > 1 else ""
        for match in cve_pattern.finditer(message):
            cve_id = match.group(1)
            if cve_id in seen:
                continue
            seen.add(cve_id)
            candidates.append(NdayCandidate(
                cve_id=cve_id,
                patch_source=commit_sha,
                description=message,
            ))
    return candidates


class NdayFilter:
    """Cheap LLM-based triage to filter CVEs for exploitability."""

    def __init__(self, llm):
        self._llm = llm

    async def afilter(self, candidates: list[NdayCandidate]) -> list[NdayCandidate]:
        if not candidates:
            return []

        for i in range(0, len(candidates), FILTER_BATCH_SIZE):
            batch = candidates[i:i + FILTER_BATCH_SIZE]
            await self._filter_batch(batch)

        return [
            c for c in candidates
            if c.exploitability in ("LIKELY_EXPLOITABLE", "POSSIBLY_EXPLOITABLE")
        ]

    async def _filter_batch(self, batch: list[NdayCandidate]) -> None:
        prompt_parts = []
        for c in batch:
            diff_preview = c.diff_text[:2000] if c.diff_text else "(no diff available)"
            prompt_parts.append(
                f"CVE: {c.cve_id}\n"
                f"Description: {c.description or '(none)'}\n"
                f"Patch diff (truncated):\n```\n{diff_preview}\n```\n"
            )
        user_msg = "\n---\n".join(prompt_parts)

        try:
            response = await self._llm.aask(
                user_msg, system=FILTER_SYSTEM_PROMPT,
            )
            text = response.first_text() if hasattr(response, "first_text") else str(response)
            results = self._parse_response(text)
            by_cve = {r["cve_id"]: r for r in results}
            for c in batch:
                if c.cve_id in by_cve:
                    c.exploitability = by_cve[c.cve_id].get("exploitability", "")
                    c.filter_reasoning = by_cve[c.cve_id].get("reasoning", "")
                else:
                    c.exploitability = "POSSIBLY_EXPLOITABLE"
        except Exception:
            logger.warning("N-day filter LLM call failed", exc_info=True)
            for c in batch:
                c.exploitability = "POSSIBLY_EXPLOITABLE"

    def _parse_response(self, text: str) -> list[dict]:
        text = text.strip()
        json_match = re.search(r"\[.*\]", text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass
        return []
