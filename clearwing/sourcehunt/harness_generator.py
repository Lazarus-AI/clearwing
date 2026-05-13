"""Crash-first Harness Generator node.

For each rank-4+ file tagged as a parser / decoder / fuzzable, the generator:

    1. Asks an LLM to produce a libFuzzer-style harness that calls the
       file's main entry point with a (data, size) buffer.
    2. Compiles the harness inside the HunterSandbox with ASan + libFuzzer.
    3. Runs the harness in the background with a time budget.
    4. On crash, captures the sanitizer report + minimized input.
    5. Returns a SeededCrash record for each file that crashed.

The Hunter agents for those files get a different system prompt that
asks them to explain the crash and assess exploitability — a much easier
task than cold-reading the file.

v0.2 integration: run BEFORE HunterPool fan-out. Crashes flow downstream
as `seeded_crash` parameters to build_hunter_agent().

v0.2 safety: if no LLM is available, no sandbox is available, or compiling
fails, the generator logs and moves on. It never blocks the pipeline —
cold-start hunters remain the fallback.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any

from clearwing.llm import AsyncLLMClient
from clearwing.sandbox.hunter_sandbox import HunterSandbox

from .state import FileTarget

logger = logging.getLogger(__name__)


# --- Config & results -------------------------------------------------------


@dataclass
class HarnessGeneratorConfig:
    """Budget and selection knobs for the harness generator."""

    total_time_budget_seconds: int = 7200  # 2 hours across all harnesses
    per_harness_duration_seconds: int = 30  # per libFuzzer run
    max_harnesses: int = 10  # cap — don't fuzz everything
    min_surface: int = 4  # only fuzz surface>=4 files
    required_tags: tuple = ("parser", "fuzzable")  # match ANY
    max_parallel: int = 2
    compile_timeout_seconds: int = 120


@dataclass
class SeededCrash:
    """One crash produced by a harness. Flows into the hunter as seeded context."""

    file: str  # repo-relative path of the file being fuzzed
    target_function: str
    report: str  # parsed ASan/UBSan report
    minimized_input: bytes = b""
    harness_source: str = ""
    crashed: bool = True
    duration_seconds: float = 0.0


@dataclass
class HarnessGeneratorResult:
    seeded_crashes: list[SeededCrash] = field(default_factory=list)
    harnesses_generated: int = 0
    harnesses_crashed: int = 0
    total_duration_seconds: float = 0.0
    cost_usd: float = 0.0


# --- Harness-generator LLM prompt ------------------------------------------


HARNESS_GEN_SYSTEM_PROMPT = """You are a security researcher writing a libFuzzer harness for a single C/C++ function so a fuzzer can find crashes.

Given the file's source code and the target function signature, produce ONLY a complete C file that:

1. Includes <stdint.h> and whatever headers the target function needs from the project.
2. Defines `int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)`.
3. Calls the target function with buffer data derived from Data/Size, handling any input-shape parsing (length prefixes, minimum sizes, pointer wrapping).
4. Returns 0 on a successful non-crashing run.

Requirements:
- No `main()`. libFuzzer provides its own.
- No network, no filesystem outside /tmp.
- No infinite loops.
- Under 80 lines.

Return ONLY the C source code, no markdown fences, no prose."""


# --- Generator --------------------------------------------------------------


class HarnessGenerator:
    """Orchestrates harness generation + background fuzzing for a set of files.

    Usage:
        gen = HarnessGenerator(llm, sandbox_factory)
        result = gen.run(file_targets, repo_path)
        for crash in result.seeded_crashes:
            # crash.file is a repo-relative path
            # crash.report is the parsed sanitizer report
            ...
    """

    def __init__(
        self,
        llm: AsyncLLMClient,
        sandbox_factory: Any = None,  # Callable[[], SandboxContainer] | HunterSandbox
        config: HarnessGeneratorConfig | None = None,
    ) -> None:
        self.llm = llm
        self.sandbox_factory = sandbox_factory
        self.config = config or HarnessGeneratorConfig()

    def run(
        self,
        file_targets: list[FileTarget],
        repo_path: str,
    ) -> HarnessGeneratorResult:
        """Select eligible files, generate harnesses, compile, run.

        Never raises on per-file failure — logs and moves on. The pipeline
        can proceed with zero seeded crashes if nothing fuzzes cleanly.
        """
        start = time.monotonic()
        result = HarnessGeneratorResult()

        eligible = self._select_eligible(file_targets)
        if not eligible:
            logger.info("HarnessGenerator: no eligible files")
            return result

        logger.info(
            "HarnessGenerator: fuzzing %d files (max=%d)", len(eligible), self.config.max_harnesses
        )

        # Cap at max_harnesses, preferring highest priority first
        eligible.sort(key=lambda f: -f.get("priority", 0.0))
        eligible = eligible[: self.config.max_harnesses]

        # Run in parallel, respecting total time budget
        with ThreadPoolExecutor(max_workers=self.config.max_parallel) as pool:
            futures = {pool.submit(self._fuzz_one, ft, repo_path): ft for ft in eligible}
            deadline = start + self.config.total_time_budget_seconds
            for future in as_completed(futures):
                if time.monotonic() > deadline:
                    logger.info("HarnessGenerator: total time budget exceeded")
                    break
                ft = futures[future]
                try:
                    crash = future.result(
                        timeout=self.config.compile_timeout_seconds
                        + self.config.per_harness_duration_seconds
                        + 10
                    )
                except Exception as e:
                    logger.debug("Harness for %s failed: %s", ft.get("path"), e)
                    continue
                if crash is None:
                    continue
                result.harnesses_generated += 1
                if crash.crashed:
                    result.harnesses_crashed += 1
                    result.seeded_crashes.append(crash)

        result.total_duration_seconds = time.monotonic() - start
        logger.info(
            "HarnessGenerator: %d harnesses generated, %d crashed",
            result.harnesses_generated,
            result.harnesses_crashed,
        )
        return result

    # --- Eligibility --------------------------------------------------------

    def _select_eligible(self, file_targets: list[FileTarget]) -> list[FileTarget]:
        """Pick files worth fuzzing: high surface + parser/fuzzable tag."""
        out = []
        required = set(self.config.required_tags)
        for ft in file_targets:
            if ft.get("surface", 0) < self.config.min_surface:
                continue
            if not (set(ft.get("tags", [])) & required):
                continue
            # Only C/C++ in v0.2 — Rust/Go/Python fuzzing is more involved
            if ft.get("language") not in ("c", "cpp"):
                continue
            out.append(ft)
        return out

    # --- Per-file fuzz loop -------------------------------------------------

    def _fuzz_one(
        self,
        file_target: FileTarget,
        repo_path: str,
    ) -> SeededCrash | None:
        """Generate + compile + run a harness for one file."""
        sandbox = self._spawn_sandbox()
        if sandbox is None:
            logger.debug("No sandbox for %s; skipping", file_target.get("path"))
            return None

        try:
            # 1. Read the file contents
            abs_path = file_target.get("absolute_path", "")
            if not abs_path or not os.path.exists(abs_path):
                return None
            with open(abs_path, encoding="utf-8", errors="replace") as f:
                file_source = f.read()[:8000]

            # 2. Pick a target function — the last non-static function def
            target_function = _guess_target_function(file_source)
            if not target_function:
                logger.debug("No target function in %s", file_target.get("path"))
                return None

            # 3. Ask the LLM for a harness
            harness_source = self._generate_harness(
                file_path=file_target.get("path", ""),
                file_source=file_source,
                target_function=target_function,
            )
            if not harness_source:
                return None

            # 4. Write the harness into /scratch and compile it with libFuzzer
            harness_filename = f"harness_{uuid.uuid4().hex[:6]}.c"
            sandbox.write_file(f"/scratch/{harness_filename}", harness_source.encode("utf-8"))

            binary_path = f"/scratch/fuzz_{uuid.uuid4().hex[:6]}"
            compile_cmd = (
                f"gcc -fsanitize=address,undefined,fuzzer -g -O1 "
                f"-I /workspace -I /workspace/include "
                f"/scratch/{harness_filename} "
                f"-o {binary_path} 2>&1"
            )
            compile_result = sandbox.exec(
                ["sh", "-c", compile_cmd],
                timeout=self.config.compile_timeout_seconds,
            )
            if compile_result.exit_code != 0:
                logger.debug(
                    "Compile failed for %s: %s",
                    file_target.get("path"),
                    compile_result.stdout[:500],
                )
                return None

            # 5. Run libFuzzer for the per-harness duration
            run_result = sandbox.exec(
                [
                    "sh",
                    "-c",
                    f"{binary_path} -max_total_time={self.config.per_harness_duration_seconds} 2>&1",
                ],
                timeout=self.config.per_harness_duration_seconds + 10,
            )

            crashed = run_result.exit_code not in (0, 124)
            report = ""
            if crashed:
                report = _parse_sanitizer_report(run_result.stdout or run_result.stderr)

            return SeededCrash(
                file=file_target.get("path", ""),
                target_function=target_function,
                report=report,
                harness_source=harness_source,
                crashed=crashed,
                duration_seconds=run_result.duration_seconds,
            )
        finally:
            try:
                sandbox.stop()
            except Exception:
                pass

    def _spawn_sandbox(self) -> Any:
        """Spawn a fresh sandbox container for this fuzz run."""
        if self.sandbox_factory is None:
            return None
        if isinstance(self.sandbox_factory, HunterSandbox):
            return self.sandbox_factory.spawn()
        try:
            return self.sandbox_factory()
        except Exception:
            logger.debug("sandbox_factory failed", exc_info=True)
            return None

    def _generate_harness(
        self,
        file_path: str,
        file_source: str,
        target_function: str,
    ) -> str | None:
        """Ask the LLM for a harness C source."""
        user_msg = (
            f"Target file: {file_path}\n"
            f"Target function: {target_function}\n\n"
            f"File source (may be truncated):\n\n{file_source}\n"
        )
        try:
            response = asyncio.run(
                self.llm.aask_text(
                    system=HARNESS_GEN_SYSTEM_PROMPT,
                    user=user_msg,
                )
            )
            response_text = response.first_text or ""
        except Exception:
            logger.debug("Harness-gen LLM call failed", exc_info=True)
            return None
        return _strip_markdown_fences(response_text)


# --- Helpers ----------------------------------------------------------------


_C_FUNCTION_DEF = re.compile(
    r"^\s*(?:static\s+)?(?:inline\s+)?[\w\s\*]+\s+(\w+)\s*\([^;{]*\)\s*\{",
    re.MULTILINE,
)


def _guess_target_function(source: str) -> str | None:
    """Pick the last non-static function defined in a C source file.

    Heuristic — in practice the LLM will also pick a function in its harness.
    We mostly need a hint to pass to the LLM prompt.
    """
    candidates = _C_FUNCTION_DEF.findall(source)
    # Filter out main() — we want a library function
    candidates = [c for c in candidates if c != "main"]
    return candidates[-1] if candidates else None


def _strip_markdown_fences(content: str) -> str:
    """Remove ```c ... ``` fences if the model added them."""
    content = content.strip()
    m = re.match(r"^```(?:c|cpp)?\s*\n([\s\S]*?)\n```\s*$", content)
    if m:
        return m.group(1)
    return content


_SANITIZER_HEADER = re.compile(
    r"==\d+==\s*ERROR:\s*(AddressSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer|libFuzzer)",
    re.IGNORECASE,
)


def _parse_sanitizer_report(raw: str) -> str:
    """Extract a concise crash summary from the sanitizer output."""
    if not raw:
        return ""
    lines = raw.splitlines()
    start = 0
    for i, line in enumerate(lines):
        if _SANITIZER_HEADER.search(line):
            start = i
            break
    snippet = "\n".join(lines[start : start + 60])
    return snippet[:6000]
