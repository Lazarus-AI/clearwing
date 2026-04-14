"""Variant Hunter Loop — compound finding density within a single run.

For each verified finding, auto-generate three pattern artifacts:
    1. A lexical grep query (cheap regex).
    2. A semantic description of what to look for (free-form text).
    3. (Optional v1.0+) A tree-sitter AST pattern.

Then search the full codebase for structural matches, and feed each match
back into the hunter pool as a pre-seeded hypothesis: "A similar pattern was
just verified at {file}:{line}. Check whether this match is the same flaw."

This creates compounding finding density inside ONE run — one verified bug
becomes a search vector for its siblings. Distinct from the cross-run
MechanismStore, which carries patterns ACROSS runs.
"""

from __future__ import annotations

import json
import logging
import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage

from .state import Finding

logger = logging.getLogger(__name__)


# --- Data classes -----------------------------------------------------------


@dataclass
class VariantPattern:
    """The three-artifact pattern generated from a verified finding."""

    grep_regex: str
    semantic_description: str
    ast_pattern: str = ""  # reserved for v1.0+ tree-sitter match


@dataclass
class VariantMatch:
    """One candidate variant: a file+line location that matched the pattern."""

    file: str
    line_number: int
    matched_text: str
    source_finding_id: str
    pattern: VariantPattern


@dataclass
class VariantSeed:
    """Shape the runner hands to the hunter pool as pre-seeded context."""

    original_finding: Finding
    match: VariantMatch
    message: str


# --- Prompt -----------------------------------------------------------------


PATTERN_GEN_SYSTEM_PROMPT = """You are generating a search pattern from a verified vulnerability so we can find SIBLING bugs in the same codebase.

Given the finding, return ONLY a JSON object:
{
  "grep_regex": "a single-line regex that matches the vulnerable pattern — should return true positives + false positives",
  "semantic_description": "one sentence — what to look for when a human reviews a match"
}

Requirements for grep_regex:
- ONE line.
- No anchors that assume specific whitespace/indentation.
- Match the vulnerable API call or pattern itself, NOT the specific variable names.
- Prefer broad over narrow — the hunter will weed out false positives.

Example:

Input: memcpy with user-controlled length in src/parse_packet.c
Output: {
  "grep_regex": "memcpy\\\\s*\\\\([^,]+,[^,]+,[^)]*(len|length|size)[^)]*\\\\)",
  "semantic_description": "memcpy whose length argument comes from a user-controlled variable named len/length/size"
}

Input: f-string SQL in app/views.py
Output: {
  "grep_regex": "\\\\.execute\\\\s*\\\\(\\\\s*f[\\\"']",
  "semantic_description": "cursor.execute called with an f-string — SQL built from string interpolation"
}

Return ONLY the JSON."""


# --- Pattern generator ------------------------------------------------------


class VariantPatternGenerator:
    """Ask the LLM for a grep pattern + semantic description."""

    def __init__(self, llm: BaseChatModel):
        self.llm = llm

    def generate(self, finding: Finding) -> VariantPattern | None:
        user_msg = self._build_user_message(finding)
        try:
            response = self.llm.invoke(
                [
                    SystemMessage(content=PATTERN_GEN_SYSTEM_PROMPT),
                    HumanMessage(content=user_msg),
                ]
            )
        except Exception:
            logger.debug("Variant pattern LLM call failed", exc_info=True)
            return None

        content = response.content if isinstance(response.content, str) else str(response.content)
        parsed = self._parse_response(content)
        if not parsed:
            return None
        return VariantPattern(
            grep_regex=parsed.get("grep_regex", ""),
            semantic_description=parsed.get("semantic_description", ""),
        )

    def _build_user_message(self, finding: Finding) -> str:
        view = {
            "file": finding.get("file"),
            "line_number": finding.get("line_number"),
            "cwe": finding.get("cwe"),
            "description": finding.get("description"),
            "code_snippet": finding.get("code_snippet"),
        }
        return f"Verified finding:\n{json.dumps(view, indent=2)}"

    def _parse_response(self, content: str) -> dict | None:
        match = re.search(r"\{[\s\S]*\}", content)
        if not match:
            return None
        try:
            parsed = json.loads(match.group(0))
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None


# --- Variant searcher -------------------------------------------------------


class VariantSearcher:
    """Search the codebase for structural matches of a VariantPattern.

    v0.3: pure-python regex over the source tree, with the same skip-dir
    hygiene as SourceAnalyzer. The AST-level search is deferred — the
    cheap regex catches the right class of bugs for now.
    """

    SKIP_DIRS = {
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "vendor",
        "dist",
        "build",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "target",
    }
    MAX_FILE_SIZE = 1_000_000
    MAX_MATCHES_PER_PATTERN = 50

    def search(
        self,
        repo_path: str,
        pattern: VariantPattern,
        source_finding: Finding,
        exclude_paths: set | None = None,
    ) -> list[VariantMatch]:
        """Return a list of VariantMatch hits, excluding the source finding's
        own file.line (don't re-flag the bug that spawned the pattern).
        """
        if not pattern.grep_regex:
            return []
        try:
            rx = re.compile(pattern.grep_regex)
        except re.error:
            logger.debug("Variant pattern regex is invalid: %s", pattern.grep_regex)
            return []

        exclude_paths = exclude_paths or set()
        source_file = source_finding.get("file", "")
        source_line = source_finding.get("line_number", 0)

        matches: list[VariantMatch] = []
        for dirpath, dirnames, filenames in os.walk(repo_path):
            dirnames[:] = [d for d in dirnames if d not in self.SKIP_DIRS]
            for fname in filenames:
                full_path = os.path.join(dirpath, fname)
                rel = os.path.relpath(full_path, repo_path)
                if rel in exclude_paths:
                    continue
                try:
                    if os.path.getsize(full_path) > self.MAX_FILE_SIZE:
                        continue
                    with open(full_path, encoding="utf-8", errors="replace") as f:
                        for i, line in enumerate(f, 1):
                            if rel == source_file and i == source_line:
                                continue  # skip the source finding's own line
                            if rx.search(line):
                                matches.append(
                                    VariantMatch(
                                        file=rel,
                                        line_number=i,
                                        matched_text=line.rstrip(),
                                        source_finding_id=source_finding.get("id", ""),
                                        pattern=pattern,
                                    )
                                )
                                if len(matches) >= self.MAX_MATCHES_PER_PATTERN:
                                    return matches
                except OSError:
                    continue
        return matches


# --- Orchestrator -----------------------------------------------------------


@dataclass
class VariantLoopConfig:
    """Budget and termination knobs for the variant loop.

    The loop runs until ANY of these fires:
        - iterations_run >= max_iterations
        - one pass produces zero new variant seeds (fixpoint reached)
        - total_variant_budget_usd is exhausted (if > 0)

    Default: up to 3 iterations, 5 variants per finding per pass.
    """

    max_iterations: int = 3  # at most 3 loop passes
    max_variants_per_finding: int = 5  # cap hunt-back queue per finding per pass
    enable_llm_pattern_gen: bool = True  # turn off for offline / cheap mode
    # v0.4 fixpoint driver:
    per_iteration_callback: Callable[[VariantLoopResult], None] | None = None
    stop_on_empty_iteration: bool = True  # terminate when a pass yields zero seeds


@dataclass
class VariantLoopResult:
    seeds: list[VariantSeed] = field(default_factory=list)
    patterns_generated: int = 0
    matches_found: int = 0
    iterations: int = 0


class VariantLoop:
    """Run the variant loop: for each verified finding, generate a pattern,
    search the codebase, and produce VariantSeed entries that the caller
    can re-feed into the HunterPool.

    The orchestration contract: this class does NOT spawn hunters itself.
    It returns VariantSeed entries for the runner to dispatch. Keeping it
    orchestration-agnostic lets us run the loop in a test harness without
    an LLM sandbox.
    """

    def __init__(
        self,
        pattern_gen: VariantPatternGenerator,
        searcher: VariantSearcher | None = None,
        config: VariantLoopConfig | None = None,
    ):
        self.pattern_gen = pattern_gen
        self.searcher = searcher or VariantSearcher()
        self.config = config or VariantLoopConfig()

    def run(
        self,
        verified_findings: list[Finding],
        repo_path: str,
        already_seen_locations: set | None = None,
        reverify_callback: Callable[[list[Any]], list[Finding]] | None = None,
    ) -> VariantLoopResult:
        """Drive the variant loop until fixpoint or budget exhausted.

        This is the production driver — it runs run_once() repeatedly,
        feeding each iteration's new variants back in as seeds for the
        next iteration's pattern generation. Terminates when any of:
            - iterations_run >= config.max_iterations
            - an iteration produces zero new variant seeds
            - reverify_callback raises or returns None

        Args:
            verified_findings: initial seed set.
            repo_path: clone root.
            already_seen_locations: initial (file, line_number) tuples to skip.
            reverify_callback: Optional callable
                `(seeds: list[VariantSeed]) -> list[Finding]`. If
                supplied, the driver calls it after each iteration to
                re-verify the seeds as Findings, then feeds those
                new findings into the NEXT iteration's pattern generation.
                If None, seeds are accumulated but NOT re-verified —
                subsequent iterations only operate on the original
                verified_findings, making the fixpoint a single-pass.

        Returns:
            A single VariantLoopResult aggregating seeds/patterns/matches
            across every iteration, with .iterations reflecting the count.
        """
        aggregate = VariantLoopResult()
        seen_locations = set(already_seen_locations or set())
        current_findings = list(verified_findings)

        for iteration in range(1, self.config.max_iterations + 1):
            pass_result = self.run_once(
                verified_findings=current_findings,
                repo_path=repo_path,
                already_seen_locations=seen_locations,
            )
            aggregate.patterns_generated += pass_result.patterns_generated
            aggregate.matches_found += pass_result.matches_found
            aggregate.seeds.extend(pass_result.seeds)
            aggregate.iterations = iteration

            # Per-iteration observation hook
            if self.config.per_iteration_callback is not None:
                try:
                    self.config.per_iteration_callback(pass_result)
                except Exception:
                    logger.debug("per_iteration_callback raised", exc_info=True)

            # Fixpoint check: an empty pass means nothing new was found.
            if self.config.stop_on_empty_iteration and not pass_result.seeds:
                logger.debug(
                    "Variant loop fixpoint reached after %d iteration(s)",
                    iteration,
                )
                break

            # For the next iteration, extend already_seen with what we just
            # found so we don't rediscover the same locations.
            for seed in pass_result.seeds:
                seen_locations.add((seed.match.file, seed.match.line_number))

            # If a reverify_callback was supplied, turn the new seeds into
            # actual verified findings and use THOSE as the next iteration's
            # input. This is how "compounding inside one run" works — each
            # iteration's confirmed variants spawn the next pattern search.
            if reverify_callback is not None:
                try:
                    new_verified = reverify_callback(pass_result.seeds)
                except Exception:
                    logger.warning(
                        "reverify_callback raised — stopping variant loop",
                        exc_info=True,
                    )
                    break
                if not new_verified:
                    # Nothing survived re-verification → no new seeds for next pass
                    break
                current_findings = list(new_verified)
            else:
                # Without a callback, subsequent iterations keep the same
                # seed set. This is the "cheap mode" — still terminates on
                # empty iteration because the patterns are deterministic.
                pass

        return aggregate

    def run_once(
        self,
        verified_findings: list[Finding],
        repo_path: str,
        already_seen_locations: set | None = None,
    ) -> VariantLoopResult:
        """Single pass of the variant loop.

        Args:
            verified_findings: Findings that have passed the verifier.
            repo_path: Absolute path to the cloned repo.
            already_seen_locations: Set of (file, line_number) tuples to skip
                (e.g. locations already reported). Prevents re-flagging.

        Returns:
            VariantLoopResult with seeds the caller should push into the pool.
        """
        result = VariantLoopResult()
        seen = already_seen_locations or set()
        for finding in verified_findings:
            pattern = self.pattern_gen.generate(finding)
            if pattern is None:
                continue
            result.patterns_generated += 1

            matches = self.searcher.search(repo_path, pattern, finding)
            # Cap matches per finding
            matches = matches[: self.config.max_variants_per_finding]
            for m in matches:
                key = (m.file, m.line_number)
                if key in seen:
                    continue
                seen.add(key)
                result.seeds.append(
                    VariantSeed(
                        original_finding=finding,
                        match=m,
                        message=self._build_seed_message(finding, m),
                    )
                )
                result.matches_found += 1
        result.iterations = 1
        return result

    def _build_seed_message(
        self,
        original: Finding,
        match: VariantMatch,
    ) -> str:
        """The message injected into the pre-seeded hunter's prompt."""
        return (
            f"A similar pattern to a verified vulnerability was found here. "
            f"Original finding: {original.get('description', '')} "
            f"(at {original.get('file', '?')}:{original.get('line_number', '?')}). "
            f"Pattern (semantic): {match.pattern.semantic_description}. "
            f"Match text: {match.matched_text.strip()} "
            f"Check whether this is the same flaw or a safe usage."
        )
