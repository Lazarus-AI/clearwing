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
import os
from dataclasses import dataclass
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from clearwing.core.event_payloads import SourcehuntStagePayload
from clearwing.core.events import EventBus
from clearwing.llm import AsyncLLMClient, BudgetExceeded
from clearwing.llm.native import extract_json_array, extract_json_object

from .state import FileTarget

logger = logging.getLogger(__name__)


# A 1..5 score. Expressed as a Literal (not Field(ge=1, le=5)) so the generated
# JSON schema is `{"type": "integer", "enum": [1,2,3,4,5]}` rather than
# minimum/maximum bounds — Anthropic's structured-output validator uses
# constrained decoding and rejects numeric-range keywords, but supports (and
# enforces) enums. Pydantic still validates the range on parse.
Score = Annotated[
    Literal[1, 2, 3, 4, 5],
    Field(description="Integer score from 1 (lowest) to 5 (highest)."),
]


class RankedFileScore(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    surface: Score
    influence: Score
    surface_rationale: str
    influence_rationale: str


class RankedFileScoreResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    results: list[RankedFileScore]


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

Return ONLY a JSON object with this shape, no other text:
{
  "results": [
    {"path": "...", "surface": N, "influence": N, "surface_rationale": "one short sentence", "influence_rationale": "one short sentence"}
  ]
}
"""


# --- Config ------------------------------------------------------------------


@dataclass
class RankerConfig:
    chunk_size: int = 150  # files per LLM call
    max_inflight_chunks: int = 4
    llm_timeout_seconds: int | None = None
    large_repo_file_threshold: int = 2000
    large_repo_llm_file_limit: int = 600
    large_repo_band_min: int = 0
    large_repo_bands: int = 4
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
    # Retries are scoped to malformed/empty structured-output responses from
    # the ranker LLM. Generic provider failures and timeouts fall back
    # immediately; AsyncLLMClient already handles provider rate-limit retries.
    chunk_max_retries: int = 2
    chunk_retry_backoff_seconds: float = 3.0
    # Circuit breaker: if this many consecutive chunks return empty (all
    # retries exhausted), cancel remaining chunks and fall back to heuristics.
    # Prevents burning tokens when the backend is persistently broken.
    circuit_breaker_threshold: int = 3


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

        llm_candidates = self._select_llm_candidates(files)
        if llm_candidates:
            chunks = self._chunk(llm_candidates, self.config.chunk_size)
            scores_by_chunk = await self._rank_chunks_bounded(chunks)
            for chunk, scores in zip(chunks, scores_by_chunk, strict=False):
                self._apply_scores(chunk, scores)
            # Opt-in determinism self-check (B1 verification): re-run the same
            # LLM scoring a second time on the identical chunks and log how much
            # the two passes agree. Inert unless the env flag OR the sentinel
            # file is present, so it never costs anything in normal operation.
            # The sentinel lets an operator toggle the check on a running
            # container (touch/rm) without an env change or recreate. With the
            # utility role pinned to temperature 0, agreement should be ~100%.
            if os.environ.get("CLEARWING_RANKER_DETERMINISM_CHECK") or os.path.exists(
                "/opt/clearwing/.ranker-determinism-check"
            ):
                print("RANKER_DET_CHECK: enabled — running second scoring pass", flush=True)
                await self._log_determinism_selfcheck(chunks, scores_by_chunk)

        # Apply floors and compute priority for every file
        for ft in files:
            self._apply_floors(ft)
            ft["priority"] = self._compute_priority(ft)
            # v0.4 fuzz-harness rank boost: back-propagate the harness
            # generator's selection criteria into the priority score so
            # fuzzable parsers outrank non-fuzzable code at the same
            # surface+influence+reachability level.
            self._apply_fuzzable_boost(ft)
            # Recursive SourceHunt: semantic sink-class tags lift surface to a
            # class floor and add a continuous tie-breaker. No-op when the file
            # carries no sink_classes (legacy/staged), so ranking is unchanged
            # there. See tag_ranker / sink_class_detectors (design v1 §5).
            self._apply_sink_class_boost(ft)

        return files

    def _apply_sink_class_boost(self, ft: FileTarget) -> None:
        """Lift surface to the sink-class floor and add a continuous term.

        Fires only for files that semantic detectors tagged (recursive mode):
        such a match is a stronger surface signal than a filename 'parser' tag,
        so it should outrank parser decoys and break the median tie.
        """
        sinks = ft.get("sink_classes") or []
        if not sinks:
            return
        floor = 4
        if "live_identifier_aliases_reserved_sentinel" in sinks:
            floor = 5
        if ft.get("surface", 0) < floor:
            ft["surface"] = floor
            ft["priority"] = self._compute_priority(ft)
        # Continuous tie-breaker from semantic evidence (breaks the integer-axis
        # ties): base for having a sink class + normalized taint/imports_by.
        micro = 0.2
        micro += min(0.1, ft.get("taint_hits", 0) * 0.05)
        micro += min(0.1, ft.get("imports_by", 0) / 500.0)
        ft["priority"] = ft.get("priority", 0.0) + micro
        existing = ft.get("surface_rationale", "") or ""
        note = f" [sink-class: {','.join(sorted(set(sinks)))}]"
        if note not in existing:
            ft["surface_rationale"] = (existing + note).strip()

    @staticmethod
    def _score_map(
        chunks: list[list[FileTarget]],
        scores_by_chunk: list[dict[str, dict[str, Any]]],
    ) -> dict[str, tuple[Any, Any]]:
        """Flatten per-chunk LLM scores into {path: (surface, influence)}."""
        out: dict[str, tuple[Any, Any]] = {}
        for chunk, scores in zip(chunks, scores_by_chunk, strict=False):
            for ft in chunk:
                path = ft.get("path", "")
                entry = scores.get(path)
                if entry and "surface" in entry and "influence" in entry:
                    out[path] = (entry["surface"], entry["influence"])
        return out

    async def _log_determinism_selfcheck(
        self,
        chunks: list[list[FileTarget]],
        scores_by_chunk_1: list[dict[str, dict[str, Any]]],
    ) -> None:
        """Re-rank the identical chunks and log pass-to-pass agreement.

        Direct empirical measure of ranker determinism: if the utility role is
        pinned to temperature 0 (greedy), the model should assign the same
        (surface, influence) scores on both passes → ~100% agreement. Any
        divergence localizes exactly which files the ranker is unstable on.

        Only the first N chunks are re-ranked (N from
        CLEARWING_RANKER_DETERMINISM_CHECK_CHUNKS, default 5), so the extra cost
        is bounded regardless of corpus size — a sample is enough to measure
        whether the model decodes deterministically.
        """
        try:
            max_chunks = int(os.environ.get("CLEARWING_RANKER_DETERMINISM_CHECK_CHUNKS", "5"))
        except ValueError:
            max_chunks = 5
        max_chunks = max(1, min(max_chunks, len(chunks)))
        sample_chunks = chunks[:max_chunks]
        sample_scores_1 = scores_by_chunk_1[:max_chunks]
        try:
            scores_by_chunk_2 = await self._rank_chunks_bounded(sample_chunks)
        except Exception:  # noqa: BLE001 — a diagnostic must never break a run
            print("RANKER_DET_CHECK: second pass FAILED", flush=True)
            logger.warning("Ranker determinism self-check second pass failed", exc_info=True)
            return

        pass1 = self._score_map(sample_chunks, sample_scores_1)
        pass2 = self._score_map(sample_chunks, scores_by_chunk_2)
        common = sorted(set(pass1) & set(pass2))
        if not common:
            print("RANKER_DET_CHECK: no overlapping scored files", flush=True)
            logger.warning("Ranker determinism self-check: no overlapping scored files")
            return

        exact = sum(1 for p in common if pass1[p] == pass2[p])
        mismatches = [(p, pass1[p], pass2[p]) for p in common if pass1[p] != pass2[p]]
        agreement = exact / len(common) * 100.0

        # Budget-relevant view: does the top-N (by the score the budget cut
        # would use) stay identical across passes? Rank each pass's files by
        # (surface+influence) desc and compare the top-40 sets.
        def _top_n(scores: dict[str, tuple[Any, Any]], n: int) -> set[str]:
            ordered = sorted(scores, key=lambda p: (-(scores[p][0] + scores[p][1]), p))
            return set(ordered[:n])

        top_n = 40
        top1, top2 = _top_n(pass1, top_n), _top_n(pass2, top_n)
        top_overlap = len(top1 & top2)

        summary = (
            f"RANKER_DET_CHECK RESULT | temp={getattr(self.llm, 'default_temperature', '?')} | "
            f"sampled {len(sample_chunks)}/{len(chunks)} chunks | files={len(common)} | "
            f"score-agreement={agreement:.1f}% ({exact}/{len(common)} exact) | "
            f"top-{top_n} overlap={top_overlap}/{top_n} | mismatches={len(mismatches)}"
        )
        print(summary, flush=True)
        logger.warning(summary)
        for path, s1, s2 in mismatches[:15]:
            line = f"RANKER_DET_CHECK MISMATCH | {path} | pass1={s1} pass2={s2}"
            print(line, flush=True)
            logger.warning(line)

    async def _rank_chunks_bounded(
        self,
        chunks: list[list[FileTarget]],
    ) -> list[dict[str, dict[str, Any]]]:
        total_chunks = len(chunks)
        max_inflight = max(1, min(self.config.max_inflight_chunks, total_chunks))
        semaphore = asyncio.Semaphore(max_inflight)
        scores_by_chunk: list[dict[str, dict[str, Any]]] = [{} for _ in chunks]
        consecutive_failures = 0

        async def run_one(
            index: int, chunk: list[FileTarget]
        ) -> tuple[int, dict[str, dict[str, Any]]]:
            async with semaphore:
                return index, await self._rank_chunk(
                    chunk,
                    idx=index + 1,
                    total_chunks=total_chunks,
                )

        # Launch all tasks but process results as they come in.
        # If the circuit breaker trips, cancel remaining tasks.
        tasks = [asyncio.create_task(run_one(index, chunk)) for index, chunk in enumerate(chunks)]
        completed = 0
        try:
            for future in asyncio.as_completed(tasks):
                index, scores = await future
                scores_by_chunk[index] = scores
                completed += 1

                # Circuit breaker: track consecutive empty results
                if scores:
                    consecutive_failures = 0
                else:
                    consecutive_failures += 1
                    if consecutive_failures >= self.config.circuit_breaker_threshold:
                        remaining = sum(1 for t in tasks if not t.done())
                        logger.warning(
                            "Ranker circuit breaker tripped after %d consecutive "
                            "empty chunks (%d/%d completed, %d cancelled); "
                            "remaining files will use heuristic fallback",
                            consecutive_failures,
                            completed,
                            total_chunks,
                            remaining,
                        )
                        for task in tasks:
                            if not task.done():
                                task.cancel()
                        await asyncio.gather(*tasks, return_exceptions=True)
                        break

                logger.info(
                    "Ranker progress %d/%d chunks completed",
                    completed,
                    total_chunks,
                )
                EventBus().emit_message(
                    f"ranking progress  {completed}/{total_chunks} chunks ranked",
                    "info",
                )
                EventBus().emit_sourcehunt_stage(
                    SourcehuntStagePayload(
                        session_id="",
                        repo="",
                        stage="rank",
                        status="progress",
                        findings_so_far=0,
                        cost_usd=0.0,
                        detail=f"{completed}/{total_chunks} chunks",
                        progress=completed / total_chunks,
                    )
                )
        except BudgetExceeded:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise
        return scores_by_chunk

    def _apply_heuristic_baseline(self, files: list[FileTarget]) -> None:
        """Populate cheap baseline scores before any LLM reranking."""
        for ft in files:
            ft["surface"] = self._fallback_surface(ft)
            ft["influence"] = self._fallback_influence(ft)
            ft["surface_rationale"] = "heuristic baseline"
            ft["influence_rationale"] = "heuristic baseline"
            self._apply_floors(ft)
            ft["priority"] = self._compute_priority(ft)
            self._apply_fuzzable_boost(ft)

    def _select_llm_candidates(self, files: list[FileTarget]) -> list[FileTarget]:
        if len(files) <= self.config.large_repo_file_threshold:
            return files

        limit = max(0, self.config.large_repo_llm_file_limit)
        if limit == 0:
            logger.info(
                "Large repo detected for ranker; heuristics applied to %d files, "
                "LLM reranking disabled",
                len(files),
            )
            return []

        ordered = [
            ft
            for _, ft in sorted(
                enumerate(files),
                key=lambda item: self._candidate_sort_key(item[0], item[1]),
                reverse=True,
            )
        ]
        candidates = self._reserve_band_minimum(ordered, limit)
        logger.info(
            "Large repo detected for ranker; heuristics applied to %d files, "
            "LLM reranking top %d files",
            len(files),
            len(candidates),
        )
        return candidates

    def _reserve_band_minimum(self, ordered: list[FileTarget], limit: int) -> list[FileTarget]:
        """Take ``limit`` files from ``ordered`` (already sorted best-first),
        but reserve ``large_repo_band_min`` slots for each priority band first.

        A plain head cut keeps only the front of a single global ordering, so a
        file whose heuristic ``priority`` sits in a lower band never reaches the
        LLM reranker even when it is the only file in its band. Reserving a
        per-band minimum keeps at least one representative of each populated
        band; the remaining slots are filled globally, so the head of the
        ordering is unchanged apart from the reserved lower-band files. The
        reservation never exceeds ``limit``: when the requested minimum across
        all configured bands exceeds it, log a warning and use a plain head cut.
        """
        if not ordered:
            return []
        band_min = max(0, self.config.large_repo_band_min)
        bands = max(1, self.config.large_repo_bands)
        if band_min == 0 or bands == 1:
            return ordered[:limit]
        if band_min * bands > limit:
            logger.warning(
                "band-reservation exceeds candidate limit; falling back to head cut "
                "(band_min=%d, bands=%d, limit=%d)",
                band_min,
                bands,
                limit,
            )
            return ordered[:limit]

        hi = ordered[0].get("priority", 0.0)
        lo = ordered[-1].get("priority", 0.0)
        span = hi - lo
        if span <= 0:
            # Every file shares one priority (e.g. --no-rank): no bands to
            # protect, so the plain head cut is already correct.
            return ordered[:limit]

        def band_of(ft: FileTarget) -> int:
            # Higher priority → lower band index. Clamp the bottom edge: a
            # file at exactly ``lo`` gives frac=1 → int(1*bands)=bands, which
            # is one past the last valid index, so cap it at ``bands-1``.
            frac = (hi - ft.get("priority", 0.0)) / span
            return min(bands - 1, int(frac * bands))

        by_band: dict[int, list[int]] = {}
        for idx, ft in enumerate(ordered):
            by_band.setdefault(band_of(ft), []).append(idx)

        reserved: set[int] = set()
        # Round-robin the reservation: the r-th file of each populated band in
        # ascending band order (strongest band first).
        for rank in range(band_min):
            if len(reserved) >= limit:
                break
            for band in sorted(by_band):
                if len(reserved) >= limit:
                    break
                members = by_band[band]
                if rank < len(members):
                    reserved.add(members[rank])
        # Fill any remaining slots globally in best-first order.
        for idx in range(len(ordered)):
            if len(reserved) >= limit:
                break
            reserved.add(idx)
        # Preserve the global ordering of the final set.
        return [ft for idx, ft in enumerate(ordered) if idx in reserved][:limit]

    @staticmethod
    def _candidate_sort_key(index: int, ft: FileTarget) -> tuple:
        influence_signal = ft.get("transitive_callers", 0) or ft.get("imports_by", 0)
        static_signals = (
            ft.get("static_hint", 0) + ft.get("semgrep_hint", 0) + ft.get("taint_hits", 0)
        )
        return (
            ft.get("priority", 0.0),
            ft.get("surface", 0),
            ft.get("influence", 0),
            static_signals,
            influence_signal,
            ft.get("loc", 0),
            -index,
        )

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
        max_attempts = 1 + max(0, self.config.chunk_max_retries)
        started_at = asyncio.get_running_loop().time()
        logger.info(
            "Ranker chunk %d/%d starting (%d files)",
            idx,
            total_chunks,
            len(chunk),
        )

        last_exc: Exception | None = None
        for attempt in range(max_attempts):
            try:
                if self.config.llm_timeout_seconds and self.config.llm_timeout_seconds > 0:
                    scores, response = await asyncio.wait_for(
                        self.llm.aask_json(
                            system=RANKER_SYSTEM_PROMPT,
                            user=user_msg,
                            schema_model=RankedFileScoreResponse,
                            schema_name="ranked_file_score_response",
                        ),
                        timeout=self.config.llm_timeout_seconds,
                    )
                else:
                    scores, response = await self.llm.aask_json(
                        system=RANKER_SYSTEM_PROMPT,
                        user=user_msg,
                        schema_model=RankedFileScoreResponse,
                        schema_name="ranked_file_score_response",
                    )
                elapsed = asyncio.get_running_loop().time() - started_at
                logger.info(
                    "Ranker chunk %d/%d completed in %.1fs",
                    idx,
                    total_chunks,
                    elapsed,
                )
                return self._parse_response(scores)
            except BudgetExceeded:
                raise
            except TimeoutError:
                logger.warning(
                    "Ranker LLM call timed out after %ss for %d files; falling back to heuristics",
                    self.config.llm_timeout_seconds,
                    len(chunk),
                )
                return {}
            except Exception as exc:
                if not self._is_retryable_structured_output_error(exc):
                    logger.warning(
                        "Ranker LLM call failed; falling back to heuristics",
                        exc_info=True,
                    )
                    return {}
                last_exc = exc
                if attempt < max_attempts - 1:
                    delay = max(0.0, self.config.chunk_retry_backoff_seconds) * (2**attempt)
                    logger.debug(
                        "Ranker chunk %d/%d attempt %d failed (%s); retrying in %.1fs",
                        idx,
                        total_chunks,
                        attempt + 1,
                        exc,
                        delay,
                    )
                    await asyncio.sleep(delay)

        logger.warning(
            "Ranker chunk %d/%d failed after %d attempts (%s); falling back to heuristics",
            idx,
            total_chunks,
            max_attempts,
            last_exc,
        )
        return {}

    @staticmethod
    def _is_retryable_structured_output_error(exc: Exception) -> bool:
        if isinstance(exc, (json.JSONDecodeError, ValidationError)):
            return True
        return isinstance(exc, ValueError) and str(exc).startswith(
            "LLM returned empty response; expected JSON matching"
        )

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

    def _parse_response(self, parsed: Any) -> dict[str, dict[str, Any]]:
        if isinstance(parsed, str):
            try:
                parsed_obj = extract_json_object(parsed)
            except ValueError:
                parsed_obj = None
            if isinstance(parsed_obj, dict) and "results" in parsed_obj:
                parsed = parsed_obj
            elif isinstance(parsed_obj, dict) and "path" in parsed_obj:
                parsed = [parsed_obj]
            else:
                try:
                    parsed = extract_json_array(parsed)
                except ValueError:
                    return {}

        items = parsed.get("results", []) if isinstance(parsed, dict) else parsed
        if not isinstance(items, list):
            return {}
        out: dict[str, dict[str, Any]] = {}
        for entry in items:
            if isinstance(entry, RankedFileScore):
                item = entry.model_dump()
            elif isinstance(entry, dict):
                item = entry
            else:
                continue
            path = item.get("path")
            if not path:
                continue
            out[path] = {
                "surface": int(item.get("surface", 0)),
                "influence": int(item.get("influence", 0)),
                "surface_rationale": str(item.get("surface_rationale", "")),
                "influence_rationale": str(item.get("influence_rationale", "")),
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
