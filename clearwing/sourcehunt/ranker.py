"""Three-axis file ranker for the sourcehunt pipeline.

The ranker scores each file on three independent axes:
    surface     (1-5) — direct vulnerability likelihood
    influence   (1-5) — downstream danger if this file has a bug
    reachability (1-5) — attacker-reachability through callgraph (v0.2 fills)

It computes a composite priority and (via pool._assign_tier) the tier (A/B/C).

Two-axis ranking exists from v0.1 (surface + influence). Reachability
defaults to 3 in v0.1 — v0.2's tree-sitter callgraph fills it in for real.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass
from typing import Any

from clearwing.llm import AsyncLLMClient, extract_json_array

from .state import FileTarget

logger = logging.getLogger(__name__)


RANKER_SYSTEM_PROMPT = """You are a security researcher triaging files in a project for vulnerability hunting. For each file listed below, return TWO independent scores from 1 to 5:

1. SURFACE — how likely this file *itself* contains an exploitable vulnerability:
   1 = Constants, type definitions, pure data, no logic
   2 = Internal utility code, no external input
   3 = Handles internal data with some complexity
   4 = Processes external data with validation
   5 = Parses raw untrusted input, handles auth, manages memory, or implements crypto

2. INFLUENCE — how dangerous this file is DOWNSTREAM if it contains a bug:
   1 = Isolated, only called in one place
   2 = Used by a handful of files in the same module
   3 = Used across the codebase but only in non-critical paths
   4 = Defines behavior used in security-critical paths (e.g. a hash comparison helper, a buffer size constant used in memcpy calls)
   5 = Defines a type, constant, macro, or default that is used EVERYWHERE and whose correctness is load-bearing — a bug here propagates to many callers. (A constants.h with MAX_AUTH_BYTES used in 50 memcpys is a 5, even though the file itself has no vulnerability.)

A file can score HIGH on influence and LOW on surface. That combination is what you're looking for — bugs in boring files that propagate widely.

Return ONLY a JSON array, no other text:
[
  {"path": "...", "surface": N, "influence": N, "surface_rationale": "one short sentence", "influence_rationale": "one short sentence"}
]
"""


# --- Config ------------------------------------------------------------------


@dataclass
class RankerConfig:
    chunk_size: int = 150  # files per LLM call
    max_inflight_chunks: int = 4
    llm_timeout_seconds: int | None = None
    large_repo_file_threshold: int = 2000
    include_static_hints: bool = True
    include_imports_by: bool = True
    static_hint_surface_floor: int = 3  # files with static_hint > 0 → min surface 3
    imports_by_threshold_floor: int = 10  # imports_by > N → min influence 3
    constants_influence_floor: int = 3  # defines_constants → min influence 3
    # v0.4 fuzz-harness rank boost: files tagged parser or fuzzable with
    # surface >= 4 get a priority boost because the HarnessGenerator will
    # seed them with crashes that make hunter runs dramatically cheaper.
    fuzzable_priority_boost: float = 0.5
    fuzzable_boost_min_surface: int = 4
    fuzzable_boost_tags: tuple = ("parser", "fuzzable")


# --- Ranker ------------------------------------------------------------------


class Ranker:
    """Rank a list of FileTarget entries on surface + influence + reachability.

    The ranker:
      1. Chunks files into groups of `chunk_size`.
      2. For each chunk, makes one LLM call with the RANKER_SYSTEM_PROMPT and
         a JSON list of file paths + cheap static hints (static_hint, imports_by,
         defines_constants, tags, language, loc).
      3. Parses the JSON response and applies floors:
         - static_hint > 0 → surface = max(surface, static_hint_surface_floor)
         - imports_by > threshold → influence = max(influence, floor)
         - defines_constants → influence = max(influence, floor)
      4. Computes priority = surface*0.5 + influence*0.2 + reachability*0.3.
      5. Returns the same FileTarget list with surface/influence/priority/
         rationales filled in (in-place modification + return for convenience).
    """

    def __init__(
        self,
        llm: AsyncLLMClient,
        config: RankerConfig | None = None,
    ):
        self.llm = llm
        self.config = config or RankerConfig()

    def rank(self, files: list[FileTarget]) -> list[FileTarget]:
        return asyncio.run(self.arank(files))

    async def arank(self, files: list[FileTarget]) -> list[FileTarget]:
        if not files:
            return files

        # Seed the whole corpus with cheap heuristic scores first so large
        # repositories can skip an all-files LLM pass and still produce
        # actionable tiers quickly.
        self._apply_heuristic_baseline(files)

        if len(files) > self.config.large_repo_file_threshold:
            logger.info(
                "Large repo detected for ranker; heuristics applied to %d files, "
                "LLM reranking all %d files",
                len(files),
                len(files),
            )

        chunks = self._chunk(files, self.config.chunk_size)
        total_chunks = len(chunks)
        scores_by_chunk = await self._rank_chunks_bounded(chunks)
        for chunk, scores in zip(chunks, scores_by_chunk, strict=False):
            self._apply_scores(chunk, scores)

        # Apply floors and compute priority for every file
        for ft in files:
            self._apply_floors(ft)
            ft["priority"] = self._compute_priority(ft)
            # v0.4 fuzz-harness rank boost: back-propagate the harness
            # generator's selection criteria into the priority score so
            # fuzzable parsers outrank non-fuzzable code at the same
            # surface+influence+reachability level.
            self._apply_fuzzable_boost(ft)

        return files

    async def _rank_chunks_bounded(
        self,
        chunks: list[list[FileTarget]],
    ) -> list[dict[str, dict[str, Any]]]:
        total_chunks = len(chunks)
        max_inflight = max(1, min(self.config.max_inflight_chunks, total_chunks))
        semaphore = asyncio.Semaphore(max_inflight)
        scores_by_chunk: list[dict[str, dict[str, Any]]] = [{} for _ in chunks]
        completed = 0

        async def run_one(index: int, chunk: list[FileTarget]) -> tuple[int, dict[str, dict[str, Any]]]:
            async with semaphore:
                return index, await self._rank_chunk(
                    chunk,
                    idx=index + 1,
                    total_chunks=total_chunks,
                )

        tasks = [asyncio.create_task(run_one(index, chunk)) for index, chunk in enumerate(chunks)]
        for future in asyncio.as_completed(tasks):
            index, scores = await future
            scores_by_chunk[index] = scores
            completed += 1
            logger.info(
                "Ranker progress %d/%d chunks completed",
                completed,
                total_chunks,
            )
        return scores_by_chunk

    def _apply_heuristic_baseline(self, files: list[FileTarget]) -> None:
        """Populate cheap baseline scores before any LLM reranking."""
        for ft in files:
            ft["surface"] = self._fallback_surface(ft)
            ft["influence"] = self._fallback_influence(ft)
            self._apply_floors(ft)
            ft["priority"] = self._compute_priority(ft)
            self._apply_fuzzable_boost(ft)

    # --- Chunking -----------------------------------------------------------

    @staticmethod
    def _chunk(files: list[FileTarget], chunk_size: int) -> list[list[FileTarget]]:
        return [files[i : i + chunk_size] for i in range(0, len(files), chunk_size)]

    # --- LLM call -----------------------------------------------------------

    async def _rank_chunk(
        self,
        chunk: list[FileTarget],
        *,
        idx: int,
        total_chunks: int,
    ) -> dict[str, dict[str, Any]]:
        """Return {path: {surface, influence, surface_rationale, influence_rationale}}."""
        user_msg = self._build_user_message(chunk)
        started_at = asyncio.get_running_loop().time()
        try:
            logger.info(
                "Ranker chunk %d/%d starting (%d files)",
                idx,
                total_chunks,
                len(chunk),
            )
            if self.config.llm_timeout_seconds and self.config.llm_timeout_seconds > 0:
                response = await asyncio.wait_for(
                    self.llm.aask_text(
                        system=RANKER_SYSTEM_PROMPT,
                        user=user_msg,
                    ),
                    timeout=self.config.llm_timeout_seconds,
                )
            else:
                response = await self.llm.aask_text(
                    system=RANKER_SYSTEM_PROMPT,
                    user=user_msg,
                )
        except TimeoutError:
            logger.warning(
                "Ranker LLM call timed out after %ss for %d files; falling back to heuristics",
                self.config.llm_timeout_seconds,
                len(chunk),
            )
            return {}
        except Exception:
            logger.warning("Ranker LLM call failed", exc_info=True)
            return {}
        elapsed = asyncio.get_running_loop().time() - started_at
        logger.info(
            "Ranker chunk %d/%d completed in %.1fs",
            idx,
            total_chunks,
            elapsed,
        )
        return self._parse_response(response.text)

    def _build_user_message(self, chunk: list[FileTarget]) -> str:
        """Build the user message — a JSON list of files with cheap static hints."""
        items = []
        for ft in chunk:
            item = {
                "path": ft.get("path", ""),
                "language": ft.get("language", "unknown"),
                "loc": ft.get("loc", 0),
                "tags": ft.get("tags", []),
            }
            if self.config.include_static_hints:
                item["static_hint_count"] = ft.get("static_hint", 0)
            if self.config.include_imports_by:
                # Prefer the tree-sitter callgraph count when available;
                # fall back to the cheap imports_by heuristic.
                transitive = ft.get("transitive_callers", 0)
                if transitive > 0:
                    item["transitive_callers_count"] = transitive
                else:
                    item["imports_by_count"] = ft.get("imports_by", 0)
                item["defines_constants"] = ft.get("defines_constants", False)
            items.append(item)
        return (
            "Score the following files. Use the static_hint_count and "
            "imports_by_count as guidance — they're cheap heuristic signals.\n\n"
            f"{json.dumps(items, indent=2)}"
        )

    def _parse_response(self, content: str) -> dict[str, dict[str, Any]]:
        """Extract the JSON array from the model response, robustly."""
        try:
            parsed = extract_json_array(content)
        except Exception:
            logger.warning("Ranker response had no JSON array; got: %s", content[:300])
            return {}
        out: dict[str, dict[str, Any]] = {}
        for entry in parsed:
            if not isinstance(entry, dict):
                continue
            path = entry.get("path")
            if not path:
                continue
            out[path] = {
                "surface": int(entry.get("surface", 0)),
                "influence": int(entry.get("influence", 0)),
                "surface_rationale": str(entry.get("surface_rationale", "")),
                "influence_rationale": str(entry.get("influence_rationale", "")),
            }
        return out

    # --- Score application --------------------------------------------------

    def _apply_scores(
        self,
        chunk: list[FileTarget],
        scores: dict[str, dict[str, Any]],
    ) -> None:
        """Write the LLM scores back into the FileTarget entries."""
        for ft in chunk:
            path = ft.get("path", "")
            entry = scores.get(path)
            if entry is None:
                # The LLM didn't return a score for this file — fall back to
                # cheap heuristics (mid-range, with a floor based on static_hint).
                ft["surface"] = self._fallback_surface(ft)
                ft["influence"] = self._fallback_influence(ft)
                ft["surface_rationale"] = "fallback (LLM did not score)"
                ft["influence_rationale"] = "fallback (LLM did not score)"
                continue
            ft["surface"] = self._clamp(entry["surface"], 1, 5)
            ft["influence"] = self._clamp(entry["influence"], 1, 5)
            ft["surface_rationale"] = entry["surface_rationale"]
            ft["influence_rationale"] = entry["influence_rationale"]

    def _apply_floors(self, ft: FileTarget) -> None:
        """Apply the static-hint, semgrep-hint, taint-hit, and imports-by floors."""
        # Static / Semgrep floor — pattern-level signals
        if ft.get("static_hint", 0) > 0 or ft.get("semgrep_hint", 0) > 0:
            ft["surface"] = max(
                ft.get("surface", 1),
                self.config.static_hint_surface_floor,
            )
        # v0.4 taint floor — a real source→sink path is stronger evidence
        # than a regex hit, so we push the floor one level higher (4).
        if ft.get("taint_hits", 0) > 0:
            ft["surface"] = max(
                ft.get("surface", 1),
                4,
            )
        # Influence floor: prefer transitive_callers (v0.2 callgraph) when
        # available; fall back to imports_by (v0.1 grep heuristic).
        influence_signal = ft.get("transitive_callers", 0) or ft.get("imports_by", 0)
        if influence_signal > self.config.imports_by_threshold_floor:
            ft["influence"] = max(
                ft.get("influence", 1),
                self.config.constants_influence_floor,
            )
        # defines_constants floor on influence
        if ft.get("defines_constants", False):
            ft["influence"] = max(
                ft.get("influence", 1),
                self.config.constants_influence_floor,
            )
        # Reachability defaults to 3 in v0.1 — only set if absent
        if not ft.get("reachability"):
            ft["reachability"] = 3

    @staticmethod
    def _compute_priority(ft: FileTarget) -> float:
        """priority = surface*0.5 + influence*0.2 + reachability*0.3"""
        s = ft.get("surface", 0)
        i = ft.get("influence", 0)
        r = ft.get("reachability", 3)
        return s * 0.5 + i * 0.2 + r * 0.3

    def _apply_fuzzable_boost(self, ft: FileTarget) -> None:
        """Apply the v0.4 fuzz-harness priority boost.

        Rationale: the HarnessGenerator picks files tagged parser/fuzzable
        with surface >= 4 and seeds their hunters with crash evidence.
        Those hunters are dramatically more productive per dollar, so the
        plan calls for these files to outrank peers at the same base score.

        This helper also records the boost on the FileTarget (via the
        `priority_boost_reason` key in `surface_rationale`) so a human can
        audit why the tier assignment happened.
        """
        tags = set(ft.get("tags", []))
        if not (tags & set(self.config.fuzzable_boost_tags)):
            return
        if ft.get("surface", 0) < self.config.fuzzable_boost_min_surface:
            return
        ft["priority"] = ft.get("priority", 0.0) + self.config.fuzzable_priority_boost
        # Audit trail: note the boost in the rationale so the tier
        # assignment is explainable.
        existing = ft.get("surface_rationale", "") or ""
        boost_note = f" [+{self.config.fuzzable_priority_boost} fuzzable boost]"
        if boost_note not in existing:
            ft["surface_rationale"] = (existing + boost_note).strip()

    @staticmethod
    def _clamp(v: Any, lo: int, hi: int) -> int:
        try:
            x = int(v)
        except (TypeError, ValueError):
            x = lo
        return max(lo, min(hi, x))

    def _fallback_surface(self, ft: FileTarget) -> int:
        """Heuristic surface score when the LLM didn't return one."""
        if ft.get("static_hint", 0) > 0:
            return self.config.static_hint_surface_floor
        if "parser" in ft.get("tags", []) or "fuzzable" in ft.get("tags", []):
            return 4
        if "auth_boundary" in ft.get("tags", []) or "crypto" in ft.get("tags", []):
            return 4
        if "memory_unsafe" in ft.get("tags", []):
            return 3
        return 2

    def _fallback_influence(self, ft: FileTarget) -> int:
        """Heuristic influence score when the LLM didn't return one."""
        imports_by = ft.get("imports_by", 0)
        if imports_by > 20:
            return 5
        if imports_by > 5:
            return 4
        if ft.get("defines_constants", False) and imports_by > 0:
            return 4
        if imports_by > 0:
            return 2
        return 1
