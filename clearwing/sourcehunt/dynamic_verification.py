"""Shared tool loop for independent finding verification."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from clearwing.llm import (
    AsyncLLMClient,
    ChatMessage,
    ChatResponse,
    NativeToolSpec,
    ToolCall,
)
from clearwing.llm.native import response_text
from clearwing.reporting.safety import redact_tree

from .state import EVIDENCE_LEVELS, EvidenceLevel

logger = logging.getLogger(__name__)

_MAX_TOOL_OUTPUT_CHARS = 16_000
_DYNAMIC_EVIDENCE_TOOLS = {"execute"}
_CRASH_SIGNATURE_RE = re.compile(
    r"(?:"
    r"AddressSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer|ThreadSanitizer|"
    r"heap-buffer-overflow|stack-buffer-overflow|use-after-free|double[- ]free|"
    r"runtime error:|SEGV|SIGSEGV|segmentation fault|core dumped|"
    r"assertion .* failed|abort trap"
    r")",
    re.IGNORECASE,
)
_NON_REPRO_RE = re.compile(
    r"(?:out of memory|oom killed|cannot allocate memory|timed out|timeout expired)",
    re.IGNORECASE,
)

VERIFICATION_TOOL_INSTRUCTIONS = """The target repository is available in a
fresh sandbox at /workspace. Use execute for normal project builds, tests,
debuggers, sanitizer runs, and reproducer commands; use write_file for a focused
harness when needed. If a PoC is provided, attempt it before returning the
verdict. Distinguish a genuine product failure from a broken harness, build
error, invocation error, timeout, or OOM, and cite the exact command/result in
your rationale. Keep source
changes limited to test instrumentation or harnesses and account for them when
judging the unmodified code."""

_TOOL_REQUIRED_REMINDER = """You returned a verdict without running a dynamic
verification tool. Do not claim that a crash or behavior was reproduced from
static reasoning. Call execute now to build or run a focused reproducer. If
dynamic verification is genuinely impossible, return a
conservative verdict and explicitly say why it could not be completed."""


@dataclass(frozen=True)
class ToolAssistedVerificationResult:
    """Final model response plus auditable dynamic-tool usage."""

    response: ChatResponse
    attempted_dynamic_calls: int
    completed_dynamic_calls: int
    qualifying_crash_calls: int = 0
    evidence: tuple[dict[str, Any], ...] = ()


def _clip(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[:limit].rstrip() + f"\n... truncated {len(value) - limit} chars ..."


async def _invoke_tool(
    tools_by_name: dict[str, NativeToolSpec],
    tool_call: ToolCall,
) -> tuple[Any, bool]:
    tool = tools_by_name.get(tool_call.fn_name)
    if tool is None:
        return {"error": f"unknown verification tool: {tool_call.fn_name}"}, False
    arguments = tool_call.fn_arguments
    if not isinstance(arguments, dict):
        arguments = {}
    try:
        return await tool.ainvoke(arguments), True
    except Exception as exc:
        logger.warning("Verification tool %s failed", tool_call.fn_name, exc_info=True)
        return {"error": f"{type(exc).__name__}: {exc}"}, False


def _completed_tool_output(output: Any, invoked: bool) -> bool:
    if not invoked:
        return False
    if isinstance(output, dict):
        if output.get("error") or output.get("timed_out"):
            return False
        exit_code = output.get("exit_code")
        if isinstance(exit_code, int) and exit_code < 0:
            return False
    return True


def _qualifies_as_product_crash(
    *,
    tool_name: str,
    arguments: dict[str, Any],
    output: Any,
    product_file: str | None,
    written_crash_markers: bool = False,
) -> bool:
    """Recognize concrete product crash output without trusting model prose."""
    if tool_name != "execute" or not isinstance(output, dict):
        return False
    if output.get("error") or output.get("timed_out"):
        return False
    exit_code = output.get("exit_code")
    if not isinstance(exit_code, int) or exit_code in {124, 137} or exit_code < 0:
        return False
    combined = f"{output.get('stdout', '')}\n{output.get('stderr', '')}"
    if _NON_REPRO_RE.search(combined) or not _CRASH_SIGNATURE_RE.search(combined):
        return False
    if exit_code == 0 and not re.search(r"runtime error:", combined, re.IGNORECASE):
        return False
    if written_crash_markers:
        return False
    command = str(arguments.get("command") or "")
    if _CRASH_SIGNATURE_RE.search(command):
        # Do not accept `echo AddressSanitizer` (or equivalent) as evidence.
        return False
    if product_file:
        normalized = product_file.removeprefix("./")
        if normalized not in combined and normalized.rsplit("/", 1)[-1] not in combined:
            return False
        integrity = output.get("workspace_integrity")
        if isinstance(integrity, dict) and integrity.get("available"):
            if not integrity.get("valid"):
                return False
            if any(normalized in str(change) for change in integrity.get("workspace_changes", [])):
                return False
    return True


def _stored_arguments(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Persist bounded, redacted tool inputs, including generated harnesses."""
    safe = redact_tree(arguments)
    if tool_name != "write_file":
        return safe
    contents = str(safe.get("contents") or "")
    encoded = contents.encode("utf-8")
    return {
        **safe,
        "contents": _clip(contents, _MAX_TOOL_OUTPUT_CHARS),
        "contents_size_bytes": len(encoded),
        "contents_sha256": hashlib.sha256(encoded).hexdigest(),
    }


def clamp_dynamic_evidence_level(
    level: EvidenceLevel,
    *,
    qualifying_crash_calls: int,
) -> EvidenceLevel:
    """Cap model-selected evidence at the strongest host-observed level."""
    maximum: EvidenceLevel = (
        "crash_reproduced" if qualifying_crash_calls > 0 else "static_corroboration"
    )
    if EVIDENCE_LEVELS.index(level) > EVIDENCE_LEVELS.index(maximum):
        return maximum
    return level


_C_LIKE_EXTS = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".c++"}

# Deterministic C/C++ dynamic probe. Runs from /workspace inside the no-network
# verification sandbox. Best-effort: (1) build + run any project fuzz harness on
# its sample inputs under ASan/UBSan (the strongest crash oracle), then (2) a
# sanitizer build-smoke of the non-test core sources. A runtime sanitizer report is a
# host-observed product crash; a clean build+run is a completed dynamic call.
_MECHANICAL_C_PROBE = r"""
cd /workspace 2>/dev/null || { echo '===NO_WORKSPACE==='; exit 3; }
SAN='-fsanitize=address,undefined -g -fno-omit-frame-pointer -O1'
CC=$(command -v gcc || command -v clang || echo gcc)
ran=0
: > /tmp/cw_b.err; : > /tmp/cw_r.err
CORE=$(ls *.c 2>/dev/null | grep -viE 'test|fuzz|example|main' | tr '\n' ' ')
HARN=$(ls fuzz*/*fuzz*.c fuzz*/**/*fuzz*.c *fuzz*.c 2>/dev/null | head -1)
DRV=$(ls fuzz*/*main*.c fuzz*/**/*main*.c 2>/dev/null | head -1)
if [ -n "$HARN" ] && [ -n "$CORE" ]; then
  if $CC $SAN -I. $CORE "$HARN" $DRV -o /tmp/cw_fz 2>>/tmp/cw_b.err; then
    INS=$(ls fuzz*/inputs/* fuzz*/**/inputs/* fuzz*/corpus/* 2>/dev/null | head -60)
    for f in $INS; do timeout 20 /tmp/cw_fz "$f" >/dev/null 2>>/tmp/cw_r.err || true; ran=1; done
  fi
fi
if [ -n "$CORE" ]; then
  $CC $SAN -I. -c $CORE -o /dev/null 2>>/tmp/cw_b.err && ran=1
fi
echo '===RUN_ERR==='; head -c 12000 /tmp/cw_r.err 2>/dev/null
echo; echo '===BUILD_ERR==='; head -c 6000 /tmp/cw_b.err 2>/dev/null
echo; echo "===RAN=$ran==="
"""


class _PocRepro(BaseModel):
    """Single-shot repro spec: the model drafts, the harness executes it."""

    language: str = ""
    driver_filename: str = "cw_poc_driver.c"
    driver_source: str = ""
    build_command: str = ""
    run_command: str = ""
    applicable: bool = True
    notes: str = ""


_POC_SYSTEM_PROMPT = """You write ONE minimal, self-contained dynamic reproducer
for a single reported vulnerability in a C/C++ project. The target repository is
already checked out at /workspace (read-only sources you may compile). Produce a
JSON object with: driver_filename (e.g. cw_poc_driver.c), driver_source (a
COMPLETE C/C++ file with main() that #includes the relevant target header(s) from
/workspace and exercises the exact code path so the described bug triggers a
sanitizer report), build_command, and run_command.

Hard requirements:
- build_command MUST compile the driver together with every target source it
  needs, from /workspace, with `-fsanitize=address,undefined -g -I/workspace`,
  producing the binary at exactly /tmp/cw_poc. No network, no cmake fetch.
- run_command MUST execute /tmp/cw_poc (with any argv/stdin needed) so the bug
  fires. Keep total runtime under ~15s.
- Prefer the smallest input that triggers it (from the finding's own PoC if it
  states one). Do NOT fabricate a crash with abort()/raise — the crash must come
  from the target code itself.
- If a dynamic reproducer is genuinely not applicable to this finding, set
  applicable=false and leave the commands empty.
Return only the JSON object."""


async def run_poc_driven_probe(
    llm: AsyncLLMClient,
    tools: Sequence[NativeToolSpec] | None,
    finding: Any,
    *,
    product_file: str | None = None,
) -> dict[str, Any] | None:
    """Model drafts a PoC once; the harness builds+runs it deterministically.

    This supports models that reliably draft a reproducer in a single structured
    call but do not reliably orchestrate multi-turn ``execute`` tool loops. The
    single-shot generation is delegated to the model; write/build/run/observe is
    performed mechanically here.
    A host-observed sanitizer crash referencing the product file is objective
    confirmation (``crash_reproduced``). Returns an evidence dict or ``None``.
    """

    if not tools:
        return None
    by_name = {t.name: t for t in tools}
    execute = by_name.get("execute")
    write_file = by_name.get("write_file")
    if execute is None or write_file is None:
        return None
    fpath = str((finding.get("file") if hasattr(finding, "get") else "") or "")
    ext = ("." + fpath.rsplit(".", 1)[-1].lower()) if "." in fpath else ""
    if ext not in _C_LIKE_EXTS:
        return None

    def _fv(key: str, default: str = "") -> str:
        try:
            return str(finding.get(key) or default)
        except Exception:
            return default

    user = json.dumps(
        {
            "file": fpath,
            "line": _fv("line_number"),
            "finding_type": _fv("finding_type"),
            "severity": _fv("severity"),
            "description": _fv("description")[:4000],
            "recommendation": _fv("recommendation")[:1000],
            "code_snippet": _fv("code_snippet")[:2000],
        },
        default=str,
    )
    try:
        response = await llm.aask_text(
            system=_POC_SYSTEM_PROMPT,
            user=user,
            response_schema=_PocRepro,
            response_schema_name="PocRepro",
        )
        spec = _PocRepro.model_validate_json(response_text(response))
    except Exception:
        logger.warning("PoC-driven probe: generation failed", exc_info=True)
        return None
    if not spec.applicable or not spec.driver_source or not spec.build_command:
        return None

    # 1) write the driver into the sandbox
    driver_path = spec.driver_filename or "cw_poc_driver.c"
    if "/" in driver_path:
        driver_path = driver_path.rsplit("/", 1)[-1]
    try:
        await write_file.ainvoke(
            {"path": f"/workspace/{driver_path}", "contents": spec.driver_source}
        )
    except Exception:
        logger.warning("PoC-driven probe: write_file failed", exc_info=True)
        return None

    # 2) build then run, deterministically, capturing each result
    build_cmd = spec.build_command
    run_cmd = spec.run_command or "/tmp/cw_poc"
    combined = f"cd /workspace 2>/dev/null; ( {build_cmd} ) 2>/tmp/cw_poc_build.err && echo ===POC_BUILT=== && ( {run_cmd} ) 2>&1; echo ===POC_DONE rc=$?==="
    try:
        output = await execute.ainvoke({"command": combined, "timeout": 300})
        invoked = True
    except Exception:
        logger.warning("PoC-driven probe: execute failed", exc_info=True)
        output, invoked = {"error": "poc execute raised"}, False

    completed = _completed_tool_output(output, invoked)
    run_section = ""
    built = False
    if isinstance(output, dict):
        combined_out = f"{output.get('stdout', '')}\n{output.get('stderr', '')}"
        built = "===POC_BUILT===" in combined_out
        run_section = combined_out.split("===POC_BUILT===", 1)[-1] if built else ""
    crash_view = {
        "exit_code": 1
        if _CRASH_SIGNATURE_RE.search(run_section)
        else (output.get("exit_code") if isinstance(output, dict) else None),
        "stdout": "",
        "stderr": run_section,
        "workspace_integrity": output.get("workspace_integrity")
        if isinstance(output, dict)
        else None,
    }
    qualifying_crash = _qualifies_as_product_crash(
        tool_name="execute",
        arguments={"command": "poc-driven-probe"},
        output=crash_view,
        product_file=product_file,
    )
    stored_output = redact_tree(output)
    if isinstance(stored_output, dict):
        stored_output = {
            k: _clip(v, _MAX_TOOL_OUTPUT_CHARS) if isinstance(v, str) else v
            for k, v in stored_output.items()
        }
    return {
        "tool": "execute",
        "call_id": "poc-driven-probe",
        "arguments": {"poc_driven": True, "built": built, "driver": driver_path},
        "output": stored_output,
        "completed": completed and built,
        "qualifying_crash": qualifying_crash,
    }


async def run_mechanical_dynamic_probe(
    tools: Sequence[NativeToolSpec] | None,
    finding: Any,
    *,
    product_file: str | None = None,
) -> dict[str, Any] | None:
    """Drive one deterministic build/run in the sandbox, model-independently.

    The adversarial verifier requires at least one completed dynamic tool call,
    but some models will not reliably emit an ``execute`` call. This performs that dynamic step
    mechanically: it invokes the same ``execute`` tool the model would, with a
    fixed build+repro command, so the dynamic gate reflects a real host
    observation rather than the model's tool-use behavior. Returns an evidence
    dict (with ``completed`` / ``qualifying_crash``) or ``None`` when no probe is
    applicable (unsupported language, or no execute tool).
    """

    if not tools:
        return None
    execute = next((t for t in tools if t.name == "execute"), None)
    if execute is None:
        return None
    fpath = str((finding.get("file") if hasattr(finding, "get") else "") or "")
    ext = ("." + fpath.rsplit(".", 1)[-1].lower()) if "." in fpath else ""
    if ext not in _C_LIKE_EXTS:
        return None  # C/C++ MVP; other languages fall through to the caller

    command = _MECHANICAL_C_PROBE
    try:
        output = await execute.ainvoke({"command": command, "timeout": 600})
        invoked = True
    except Exception:
        logger.warning("mechanical dynamic probe failed to execute", exc_info=True)
        output, invoked = {"error": "mechanical probe raised"}, False

    # Only the RUN_ERR section counts as a product crash — build errors do not.
    run_section = ""
    combined = ""
    if isinstance(output, dict):
        combined = f"{output.get('stdout', '')}\n{output.get('stderr', '')}"
        run_section = combined.split("===BUILD_ERR===", 1)[0]
    # The shell wrapper itself ends successfully after printing diagnostics.
    # Require its explicit marker so a failed build or absent harness cannot be
    # mistaken for a completed dynamic run.
    completed = _completed_tool_output(output, invoked) and "===RAN=1===" in combined
    crash_view = {
        "exit_code": 1
        if _CRASH_SIGNATURE_RE.search(run_section)
        else (output.get("exit_code") if isinstance(output, dict) else None),
        "stdout": "",
        "stderr": run_section,
        "workspace_integrity": output.get("workspace_integrity")
        if isinstance(output, dict)
        else None,
    }
    qualifying_crash = _qualifies_as_product_crash(
        tool_name="execute",
        arguments={"command": "mechanical-dynamic-probe"},
        output=crash_view,
        product_file=product_file,
    )
    stored_output = redact_tree(output)
    if isinstance(stored_output, dict):
        stored_output = {
            k: _clip(v, _MAX_TOOL_OUTPUT_CHARS) if isinstance(v, str) else v
            for k, v in stored_output.items()
        }
    return {
        "tool": "execute",
        "call_id": "mechanical-dynamic-probe",
        "arguments": {"mechanical": True},
        "output": stored_output,
        "completed": completed,
        "qualifying_crash": qualifying_crash,
    }


async def run_tool_assisted_verification(
    llm: AsyncLLMClient,
    *,
    system_prompt: str,
    user_message: str,
    tools: Sequence[NativeToolSpec] | None,
    response_schema: type[BaseModel] | None = None,
    response_schema_name: str | None = None,
    max_tool_rounds: int = 8,
    max_tool_calls: int = 32,
    max_wall_seconds: float = 1800.0,
    product_file: str | None = None,
) -> ToolAssistedVerificationResult:
    """Run tools in the verifier's own context, then return its final verdict."""
    active_tools = list(tools or [])
    combined_prompt = system_prompt + "\n\n" + VERIFICATION_TOOL_INSTRUCTIONS
    messages = [ChatMessage("user", user_message)]
    tools_by_name = {tool.name: tool for tool in active_tools}
    attempted_dynamic_calls = 0
    completed_dynamic_calls = 0
    qualifying_crash_calls = 0
    evidence: list[dict[str, Any]] = []
    sent_tool_required_reminder = False
    total_tool_calls = 0
    written_crash_markers = False
    started_at = time.monotonic()

    for _round in range(max_tool_rounds):
        if time.monotonic() - started_at >= max_wall_seconds:
            break
        response = await llm.achat(
            messages=messages,
            system=combined_prompt,
            tools=active_tools,
            response_schema=response_schema,
            response_schema_name=response_schema_name,
        )
        tool_calls = response.tool_calls or []
        if not tool_calls:
            if completed_dynamic_calls == 0 and not sent_tool_required_reminder:
                messages.append(ChatMessage("assistant", response.first_text or ""))
                messages.append(ChatMessage("user", _TOOL_REQUIRED_REMINDER))
                sent_tool_required_reminder = True
                continue
            return ToolAssistedVerificationResult(
                response=response,
                attempted_dynamic_calls=attempted_dynamic_calls,
                completed_dynamic_calls=completed_dynamic_calls,
                qualifying_crash_calls=qualifying_crash_calls,
                evidence=tuple(evidence),
            )

        messages.append(
            ChatMessage(
                "assistant",
                response.first_text or "",
                tool_calls=tool_calls,
            )
        )
        for tool_call in tool_calls:
            total_tool_calls += 1
            is_dynamic = tool_call.fn_name in _DYNAMIC_EVIDENCE_TOOLS
            arguments = tool_call.fn_arguments if isinstance(tool_call.fn_arguments, dict) else {}
            if is_dynamic:
                attempted_dynamic_calls += 1
            if total_tool_calls > max_tool_calls:
                output, invoked = {"error": "verification tool-call limit exceeded"}, False
            elif time.monotonic() - started_at >= max_wall_seconds:
                output, invoked = {"error": "verification wall-clock limit exceeded"}, False
            else:
                output, invoked = await _invoke_tool(tools_by_name, tool_call)
            completed = _completed_tool_output(output, invoked)
            qualifying_crash = _qualifies_as_product_crash(
                tool_name=tool_call.fn_name,
                arguments=arguments,
                output=output,
                product_file=product_file,
                written_crash_markers=written_crash_markers,
            )
            if is_dynamic and completed:
                completed_dynamic_calls += 1
            if is_dynamic and qualifying_crash:
                qualifying_crash_calls += 1
            stored_output = redact_tree(output)
            if isinstance(stored_output, dict):
                stored_output = {
                    key: _clip(value, _MAX_TOOL_OUTPUT_CHARS) if isinstance(value, str) else value
                    for key, value in stored_output.items()
                }
            stored_arguments = _stored_arguments(tool_call.fn_name, arguments)
            evidence.append(
                {
                    "tool": tool_call.fn_name,
                    "call_id": tool_call.call_id,
                    "arguments": stored_arguments,
                    "output": stored_output,
                    "completed": completed,
                    "qualifying_crash": qualifying_crash,
                }
            )
            if tool_call.fn_name == "write_file":
                written = str(arguments.get("contents") or "")
                written_crash_markers = written_crash_markers or bool(
                    _CRASH_SIGNATURE_RE.search(written)
                )
            output_text = _clip(
                json.dumps(redact_tree(output), default=str),
                _MAX_TOOL_OUTPUT_CHARS,
            )
            messages.append(
                ChatMessage(
                    "tool",
                    output_text,
                    tool_response_call_id=tool_call.call_id,
                )
            )

    # The model used every tool round. Remove tools for one final synthesis so
    # the verifier cannot end with an unpaired call or no verdict.
    response = await llm.achat(
        messages=messages,
        system=combined_prompt,
        tools=None,
        response_schema=response_schema,
        response_schema_name=response_schema_name,
    )
    return ToolAssistedVerificationResult(
        response=response,
        attempted_dynamic_calls=attempted_dynamic_calls,
        completed_dynamic_calls=completed_dynamic_calls,
        qualifying_crash_calls=qualifying_crash_calls,
        evidence=tuple(evidence),
    )
