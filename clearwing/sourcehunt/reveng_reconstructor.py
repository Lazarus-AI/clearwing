"""Reverse engineering source reconstructor — LLM-driven recovery (spec 016).

Takes raw Ghidra decompilation output with auto-generated names and produces
readable C source with meaningful function/variable names, fixed types, and
confidence ratings.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from .reveng_decompiler import DecompilationResult, StaticAnalysisResult

logger = logging.getLogger(__name__)

RECONSTRUCTION_BATCH_SIZE = 8

RECONSTRUCTION_SYSTEM_PROMPT = """\
You are reconstructing source code from Ghidra decompilation output. The
decompiled code has auto-generated names (FUN_00401234, DAT_00601000, etc.)
and may have incorrect types.

For each function:
1. Infer a meaningful function name from its behavior and context
2. Infer meaningful variable names from usage patterns
3. Fix type annotations where Ghidra likely got them wrong
4. Rate your confidence (0.0 to 1.0) in the reconstruction accuracy

Return ONLY a JSON array:
[
  {
    "original_name": "FUN_00401234",
    "reconstructed_name": "parse_config_file",
    "source_code": "int parse_config_file(const char *path) { ... }",
    "confidence": 0.85,
    "notes": "Reads file line by line, splits on '=', stores in global config struct"
  }
]"""


@dataclass
class ReconstructedSource:
    original_name: str = ""
    reconstructed_name: str = ""
    source_code: str = ""
    confidence: float = 0.0
    notes: str = ""


@dataclass
class ReconstructionValidation:
    compiles: bool = False
    compile_errors: list[str] = field(default_factory=list)
    function_coverage: float = 0.0


@dataclass
class ReconstructionResult:
    sources: list[ReconstructedSource] = field(default_factory=list)
    total_functions: int = 0
    reconstructed_count: int = 0
    combined_source: str = ""
    validation: ReconstructionValidation = field(
        default_factory=ReconstructionValidation,
    )


class RevengReconstructor:
    """LLM-driven source reconstruction from Ghidra decompilation output."""

    BATCH_SIZE = RECONSTRUCTION_BATCH_SIZE

    def __init__(self, llm: Any):
        self._llm = llm

    async def areconstruct(
        self,
        decompilation: DecompilationResult,
        static_info: StaticAnalysisResult,
    ) -> ReconstructionResult:
        """Reconstruct source from decompiled functions."""
        result = ReconstructionResult(total_functions=decompilation.total_functions)

        if not decompilation.functions:
            return result

        # Sort functions by priority: larger functions with more calls first
        prioritized = sorted(
            decompilation.functions,
            key=lambda f: (len(f.calls), f.size),
            reverse=True,
        )

        # Build shared context from static analysis
        context = self._build_context(static_info)

        for i in range(0, len(prioritized), self.BATCH_SIZE):
            batch = prioritized[i:i + self.BATCH_SIZE]
            reconstructed = await self._reconstruct_batch(batch, context)
            result.sources.extend(reconstructed)

        result.reconstructed_count = len(result.sources)
        result.combined_source = self._assemble_source(result.sources)
        return result

    async def _reconstruct_batch(
        self,
        batch: list,
        context: str,
    ) -> list[ReconstructedSource]:
        """Reconstruct a batch of decompiled functions via LLM."""
        prompt_parts = [f"Context:\n{context}\n\nFunctions to reconstruct:\n"]
        for func in batch:
            decompiled = func.decompiled_c[:3000] if func.decompiled_c else "(empty)"
            calls_str = ", ".join(func.calls[:20]) if func.calls else "(none)"
            prompt_parts.append(
                f"--- {func.name} (addr=0x{func.address:x}, size={func.size}) ---\n"
                f"Calls: {calls_str}\n"
                f"```c\n{decompiled}\n```\n"
            )
        user_msg = "\n".join(prompt_parts)

        try:
            response = await self._llm.aask(
                user_msg, system=RECONSTRUCTION_SYSTEM_PROMPT,
            )
            text = response.first_text if hasattr(response, "first_text") else str(response)
            return self._parse_response(text, batch)
        except Exception:
            logger.warning("Reconstruction LLM call failed", exc_info=True)
            return self._fallback_reconstruction(batch)

    def _parse_response(
        self,
        text: str,
        batch: list,
    ) -> list[ReconstructedSource]:
        """Parse LLM JSON response into ReconstructedSource objects."""
        text = text.strip()
        json_match = re.search(r"\[.*\]", text, re.DOTALL)
        if not json_match:
            return self._fallback_reconstruction(batch)

        try:
            items = json.loads(json_match.group())
        except json.JSONDecodeError:
            return self._fallback_reconstruction(batch)

        results = []
        for item in items:
            results.append(ReconstructedSource(
                original_name=item.get("original_name", ""),
                reconstructed_name=item.get("reconstructed_name", ""),
                source_code=item.get("source_code", ""),
                confidence=float(item.get("confidence", 0.0)),
                notes=item.get("notes", ""),
            ))
        return results

    def _fallback_reconstruction(
        self,
        batch: list,
    ) -> list[ReconstructedSource]:
        """Use raw decompilation as fallback when LLM fails."""
        return [
            ReconstructedSource(
                original_name=func.name,
                reconstructed_name=func.name,
                source_code=func.decompiled_c,
                confidence=0.0,
                notes="LLM reconstruction failed; raw Ghidra output",
            )
            for func in batch
            if func.decompiled_c
        ]

    def _build_context(self, static_info: StaticAnalysisResult) -> str:
        """Build shared context string from static analysis."""
        parts = []
        if static_info.file_type:
            parts.append(f"Binary type: {static_info.file_type}")
        if static_info.imports:
            parts.append(f"Imported functions: {', '.join(static_info.imports[:50])}")
        if static_info.strings_sample:
            interesting = [
                s for s in static_info.strings_sample.splitlines()[:100]
                if len(s) > 4
            ]
            if interesting:
                parts.append(f"Notable strings:\n" + "\n".join(interesting[:30]))
        return "\n".join(parts) if parts else "(no static analysis context)"

    def _assemble_source(self, sources: list[ReconstructedSource]) -> str:
        """Combine all reconstructed functions into a single source file."""
        if not sources:
            return ""

        parts = [
            "/* Reconstructed source — LLM-generated from Ghidra decompilation */",
            "#include <stdio.h>",
            "#include <stdlib.h>",
            "#include <string.h>",
            "#include <stdint.h>",
            "",
        ]
        for src in sources:
            if src.source_code:
                parts.append(f"/* {src.original_name} -> {src.reconstructed_name} */")
                parts.append(src.source_code)
                parts.append("")

        return "\n".join(parts)


async def validate_reconstruction(
    container: Any,
    combined_source: str,
    total_functions: int,
    reconstructed_count: int,
) -> ReconstructionValidation:
    """Validate reconstructed source by attempting compilation."""
    validation = ReconstructionValidation()

    if not combined_source:
        return validation

    validation.function_coverage = (
        reconstructed_count / total_functions if total_functions > 0 else 0.0
    )

    try:
        container.write_file(
            "/workspace/source/reconstructed.c",
            combined_source.encode("utf-8"),
        )
        r = container.exec(
            "gcc -fsyntax-only -w /workspace/source/reconstructed.c 2>&1",
            timeout=30,
        )
        validation.compiles = r.exit_code == 0
        if r.exit_code != 0 and r.stdout:
            validation.compile_errors = r.stdout.strip().splitlines()[:20]
    except Exception:
        logger.debug("Reconstruction validation failed", exc_info=True)

    return validation
