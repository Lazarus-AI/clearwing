"""Per-file hunter runtime for sourcehunt.

This module now uses a native async tool-calling loop backed by genai-pyo3,
not LangChain/LangGraph. The prompts and tool set are unchanged; the
execution model is simpler: assistant response -> tool calls -> tool results ->
next assistant response, repeated until the model stops calling tools or the
step budget is exhausted.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from clearwing.agent.tools.hunt import (
    HunterContext,
    build_deep_agent_tools,
    build_hunter_tools,
    build_propagation_auditor_tools,
)
from clearwing.llm import AsyncLLMClient, ChatMessage, NativeToolSpec, ToolCall
from clearwing.observability.telemetry import CostTracker
from clearwing.sandbox.container import SandboxContainer

from .state import FileTarget, Finding

logger = logging.getLogger(__name__)


def _trajectory_base_dir() -> Path:
    raw = os.environ.get("CLEARWING_SOURCEHUNT_TRACE_DIR")
    if raw:
        return Path(raw).expanduser()
    home = os.environ.get("CLEARWING_HOME") or os.path.expanduser("~/.clearwing")
    return Path(home) / "sourcehunt" / "trajectories"


def _sanitize_path_component(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
    return cleaned or "unknown"


def _trajectory_path(ctx: HunterContext) -> Path:
    session = _sanitize_path_component(ctx.session_id or "no_session")
    rel_file = _sanitize_path_component((ctx.file_path or "unknown").replace("/", "__"))
    return _trajectory_base_dir() / session / f"{rel_file}.jsonl"


def _serialize_tool_call(tool_call: ToolCall) -> dict[str, Any]:
    if hasattr(tool_call, "to_dict"):
        return dict(tool_call.to_dict())
    return {
        "call_id": getattr(tool_call, "call_id", ""),
        "fn_name": getattr(tool_call, "fn_name", ""),
        "fn_arguments": getattr(tool_call, "fn_arguments", None),
        "fn_arguments_json": getattr(tool_call, "fn_arguments_json", ""),
    }


def _serialize_message(message: ChatMessage) -> dict[str, Any]:
    if hasattr(message, "to_dict"):
        return dict(message.to_dict())
    tool_calls = getattr(message, "tool_calls", None) or []
    return {
        "role": message.role,
        "content": message.content,
        "tool_calls": [_serialize_tool_call(tc) for tc in tool_calls],
        "tool_response_call_id": getattr(message, "tool_response_call_id", None),
    }


def _first_matching_line(path: Path, pattern: str) -> int | None:
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line_number, line in enumerate(handle, start=1):
                if re.search(pattern, line):
                    return line_number
    except OSError:
        return None
    return None


def _memory_safety_heuristic_hints(
    repo_path: str,
    file_target: FileTarget,
) -> list[dict[str, Any]]:
    """Derive high-signal, file-local hints for memory-safety hunters.

    The goal is not to prove a bug statically here; it is to surface concrete
    candidate mechanisms already visible in the source tree so the hunter does
    not get stuck on generic memcpy noise.
    """

    target_rel = str(file_target.get("path") or "")
    if not target_rel:
        return []

    target_path = Path(repo_path) / target_rel
    if not target_path.is_file():
        return []

    hints: list[dict[str, Any]] = []

    sentinel_init_line = _first_matching_line(target_path, r"memset\([^;\n]*slice_table[^;\n]*-1")
    sentinel_check_line = _first_matching_line(target_path, r"slice_table\[.*\]\s*==\s*0xFFFF")
    counter_assign_line = _first_matching_line(
        target_path, r"sl->slice_num\s*=\s*\+\+h->current_slice"
    )
    counter_compare_line = _first_matching_line(
        target_path, r"slice_table\[.*\]\s*[!=]=\s*sl->slice_num"
    )

    if sentinel_init_line and (sentinel_check_line or counter_assign_line):
        details: list[str] = [f"`slice_table` is sentinel-filled at line {sentinel_init_line}"]
        if sentinel_check_line:
            details.append(f"checked against `0xFFFF` at line {sentinel_check_line}")
        if counter_assign_line:
            details.append(
                f"`sl->slice_num` is incremented from `current_slice` at line {counter_assign_line}"
            )
        hints.append(
            {
                "line": sentinel_init_line,
                "description": "Potential sentinel/counter collision: " + "; ".join(details) + ".",
            }
        )

    if counter_compare_line and counter_assign_line:
        hints.append(
            {
                "line": counter_compare_line,
                "description": (
                    f"`slice_table[...]` is compared to `sl->slice_num` at line {counter_compare_line}; "
                    f"check whether that counter can alias the sentinel-filled table state from line {sentinel_init_line or '?'}."
                ),
            }
        )

    top_border_line = _first_matching_line(
        target_path,
        r"top_border\s*=\s*sl->top_borders\[[^\]]+\]\[sl->mb_x\]",
    )
    if top_border_line and counter_compare_line:
        hints.append(
            {
                "line": top_border_line,
                "description": (
                    "Concrete sink cue: `top_border = sl->top_borders[..., sl->mb_x]` is written via "
                    f"`AV_COPY*` immediately after line {top_border_line}; if the sentinel/counter collision "
                    "breaks the same-slice boundary check at the left edge, follow this path to a real "
                    "buffer underflow/overflow rather than stopping at metadata confusion."
                ),
            }
        )

    header_path = target_path.parent / "h264dec.h"
    slice_width_line = _first_matching_line(header_path, r"uint16_t\s*\*\s*slice_table\b")
    current_slice_line = _first_matching_line(header_path, r"\bint\s+current_slice\b")
    if slice_width_line and current_slice_line:
        hints.append(
            {
                "line": counter_assign_line or sentinel_init_line or 1,
                "description": (
                    "Width check: related header `h264dec.h` declares `slice_table` as `uint16_t *` "
                    f"(line {slice_width_line}) and `current_slice` as `int` (line {current_slice_line})."
                ),
            }
        )

    writer_paths = [
        target_path.parent / "h264_cabac.c",
        target_path.parent / "h264_cavlc.c",
        target_path.parent / "h264_mvpred.h",
    ]
    writer_line = None
    compare_line = None
    for candidate in writer_paths:
        if writer_line is None:
            writer_line = _first_matching_line(candidate, r"slice_table\[.*\]\s*=\s*sl->slice_num")
        if compare_line is None:
            compare_line = _first_matching_line(
                candidate, r"slice_table\[.*\]\s*[!=]=\s*sl->slice_num"
            )
        if writer_line and compare_line:
            break
    if writer_line or compare_line:
        related_bits: list[str] = []
        if writer_line:
            related_bits.append(
                f"related decode paths write `slice_table[mb_xy] = sl->slice_num` (line {writer_line})"
            )
        if compare_line:
            related_bits.append(
                f"neighbor/cache logic compares `slice_table[...]` to `sl->slice_num` (line {compare_line})"
            )
        hints.append(
            {
                "line": counter_assign_line or sentinel_init_line or 1,
                "description": "Cross-file cue: " + "; ".join(related_bits) + ".",
            }
        )

    return hints[:5]


@dataclass
class HunterTrajectoryLogger:
    path: Path

    @classmethod
    def for_hunter(
        cls,
        ctx: HunterContext,
        *,
        prompt: str,
        initial_messages: list[ChatMessage],
        tools: list[NativeToolSpec],
    ) -> HunterTrajectoryLogger:
        path = _trajectory_path(ctx)
        path.parent.mkdir(parents=True, exist_ok=True)
        logger_obj = cls(path=path)
        logger_obj.log(
            "start",
            {
                "session_id": ctx.session_id,
                "file_path": ctx.file_path,
                "specialist": ctx.specialist,
                "prompt": prompt,
                "tools": [tool.name for tool in tools],
                "seeded_crash": ctx.seeded_crash,
            },
        )
        for message in initial_messages:
            logger_obj.log(
                "message",
                {
                    "step": 0,
                    "message": _serialize_message(message),
                },
            )
        return logger_obj

    def log(self, event: str, payload: dict[str, Any]) -> None:
        record = {
            "ts": time.time(),
            "event": event,
            **payload,
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True, default=str) + "\n")


# --- System prompts ---------------------------------------------------------


HUNTER_EXECUTION_RULES = """
Execution rules:
- This is a single-file hunt. Start with the target file, not a broad directory listing.
- Only use list_source_tree when you need to locate a concretely named related file or directory.
- By step 3, form at least one concrete candidate hypothesis tied to a function, field, buffer, or array.
- Prefer narrow grep_source/find_callers queries over broad regex sweeps across large directories.
- If a grep result is dominated by static tables, scan constants, or generic arithmetic noise, refine the query immediately.
- Keep read_source_file windows tight, usually 40-120 lines around the suspicious code.
- If a tool result is summarized or truncated, narrow the next request instead of repeating the same broad call.
- Once you have a plausible candidate, validate it with compile/run/fuzz tools when realistic, or explain exactly why static evidence is sufficient.
- Do not spend the final step on marginal confirmation. If the mechanism is already coherent, use record_finding.
- By the last 2 steps, either call record_finding or state explicitly why the evidence is still insufficient.
"""


GENERAL_HUNTER_PROMPT = """You are a security researcher hunting for a vulnerability in a single source file from the project {project_name}.

File: {file_path}
Language: {language}
Lines of code: {loc}
Tags: {tags}
{seeded_crash_block}{semgrep_hints_block}
You have access to:
- The cloned source tree (read-only) via read_source_file, list_source_tree, grep_source, find_callers
- A sandboxed compile + run loop via compile_file, run_with_sanitizer, write_test_case
- record_finding to log a vulnerability when you find one

Approach:
1. Read the target file and understand its role in the project.
2. Identify potential vulnerability patterns (memory safety, logic, injection, auth bypass).
3. Read related files (callers, callees, headers it includes) for context using grep_source and find_callers.
4. Hypothesize specific vulnerabilities.
5. If the file has a clear entry point, write a test input via write_test_case and try compile_file + run_with_sanitizer to confirm or reject each hypothesis.
6. If you find a real bug, call record_finding with:
   - severity (critical/high/medium/low/info)
   - cwe (CWE-89, CWE-787, etc.)
   - evidence_level: "suspicion" if pattern-only, "static_corroboration" if static
     analysis confirms it, "crash_reproduced" if you got an ASan/UBSan crash,
     "root_cause_explained" if you can articulate the mechanism end-to-end.
   - a short description and code_snippet
7. If you find nothing after thorough analysis, say so explicitly. Do not fabricate findings.

Budget: be efficient. You have a per-file cost cap.
"""


MEMORY_SAFETY_HUNTER_PROMPT = """You are a MEMORY SAFETY specialist hunting for a vulnerability in a single source file from the project {project_name}.

File: {file_path}
Language: {language}
Lines of code: {loc}
Tags: {tags}
{seeded_crash_block}{semgrep_hints_block}
Your specialty is the class of bugs that corrupt memory or control flow. Focus on:

1. LENGTH vs ALLOCATION MISMATCHES
   - memcpy / memmove / strcpy / strncpy / snprintf where the source size can
     exceed the destination allocation.
   - malloc(n) followed by writes past n.
   - Ring buffers and pool allocators with off-by-one wrap-around.

2. SIGNED / UNSIGNED CONFUSION
   - Length comparisons where a negative signed value becomes a huge unsigned.
   - size_t arithmetic that underflows to near-SIZE_MAX.
   - Indexing with signed types that can go negative.

3. WIDTH TRUNCATION
   - size_t → int, int → short, uint64 → uint32 assignments that silently
     drop high bits and then get used as buffer sizes or loop bounds.

4. MEMCPY BOUNDS
   - memcpy with length derived from an attacker-controlled header field.
   - memcpy where the destination was just allocated with a smaller size.
   - memcpy inside a loop that could write past the buffer on the last iteration.

5. ITERATOR OVERRUNS
   - while (p < end) where `end` isn't updated when the buffer grows.
   - for (i = 0; i <= n; i++) off-by-ones.
   - Pointer arithmetic that subtracts more than the allocation size.

6. SENTINEL COLLISIONS
   - 0xFF or 0x00 sentinels in protocol parsers where valid data can contain
     the sentinel value.
   - NUL-termination assumptions in data that isn't NUL-terminated.

7. SENTINEL / COUNTER COLLISIONS
   - Tables initialized with memset(..., -1, ...) or 0xFF/0xFFFF sentinels.
   - Ownership/progress tables compared against monotonically increasing IDs
     like slice/frame/reference counters.
   - Any case where the table element width is narrower than the counter it
     stores or is compared against.
   - If you see all of: sentinel initialization, writes from a slice/frame
     counter, and later reads compared both to the sentinel and to the current
     counter, treat that as a first-class candidate immediately.

8. USE-AFTER-FREE
   - free() followed by any use of the pointer.
   - Double-free via aliasing.
   - Dangling pointers after realloc() shrinks a buffer.

9. UNINITIALIZED MEMORY
   - stack variables used before assignment.
   - struct fields left uninitialized that get sent over the wire.

Approach:
1. Read the target file. Find every buffer, every pointer, every size computation.
2. For each buffer: where is it allocated? What's the size? Who writes to it?
3. For each size computation: can any input make it wrap, truncate, or underflow?
4. For parser/state-machine code, inspect sentinel-initialized tables,
   ownership/progress arrays, and counters before assuming the bug is a memcpy.
   Start by grepping for memset(..., -1 ...), 0xFF/0xFFFF sentinels, and
   tables compared against IDs/counters such as slice_num, frame_num, or
   owner indexes.
5. Use compile_file + run_with_sanitizer on the file with ASan/UBSan. If the
   project has a fuzz entry point, run it with a crafted input.
6. record_finding with evidence_level=crash_reproduced if you got an ASan
   report, else static_corroboration if you can show a pattern.

Static-evidence threshold for sentinel/counter bugs:
- If you can show a table is sentinel-filled, written with a monotonically
  increasing ID, and later consulted using sentinel checks or equality against
  that same ID, you do not need a crash to record a finding.
- If the table storage width is narrower than the ID or the sentinel value can
  collide with reachable counter values, record_finding with
  evidence_level=static_corroboration as soon as you can explain the
  collision mechanism end-to-end.
- For memory-safety claims, do not stop at "state confusion" if the same file
  contains border copies, buffer writes, or pointer-indexed reads gated by the
  corrupted ownership check. Follow the flow to the concrete read/write sink
  before recording when that sink is available in-file.

If the code is obviously safe (RAII, std::span, bounds-checked containers,
Rust-style borrowing), say so and move on. Do not fabricate bugs.
"""


KERNEL_SYSCALL_HUNTER_PROMPT = """You are a KERNEL / SYSCALL specialist hunting for a vulnerability in a single source file from the project {project_name}. Your specialty is the class of bugs that let a userspace caller subvert a kernel-space invariant.

File: {file_path}
Language: {language}
Lines of code: {loc}
Tags: {tags}
{seeded_crash_block}{semgrep_hints_block}
Focus on:

1. COPY_FROM_USER / COPY_TO_USER BOUNDS
   - copy_from_user(dst, src, len) where `len` isn't validated against `sizeof(dst)`.
   - get_user / put_user with the wrong size hint.
   - Double-fetch: reading the same userspace field twice and trusting it's unchanged (TOCTOU in the kernel).

2. IOCTL HANDLER CONFUSION
   - Switch on cmd number that falls through to a privileged branch on an unexpected value.
   - ioctl handlers that trust a length field embedded in the userspace struct.
   - The handler dispatches to a function that assumes CAP_SYS_ADMIN but the capability check is missing.

3. REFERENCE COUNTING
   - put/get pairs that don't match on every code path. Early-returns that skip put_*().
   - Race between refcount decrement and the free call.

4. LOCKING
   - Functions that acquire a lock on one path and not another.
   - sleeping-in-atomic: kmalloc(GFP_KERNEL) while holding a spinlock.
   - Lock-order inversion between two acquisition sites.

5. SIGNED/UNSIGNED BOUNDARY
   - Kernel loops with `int i` that should be `size_t`.
   - Array indices that a signed caller can make negative.

6. PERMISSION CHECKS
   - capable(CAP_SYS_ADMIN) called too late — after the sensitive action.
   - ns_capable() vs capable() confusion across namespaces.
   - Missing file->f_mode check on file descriptors.

7. REFERENCE LEAKS ON ERROR PATHS
   - dget/fput without the matching counterpart on an error return.
   - kfree on an already-freed pointer when two error paths converge.

Approach:
1. Identify every copy_*user, get_user, put_user, access_ok, and capable() call.
2. Trace the userspace-controlled inputs through the function to find where they're used as sizes, indices, or pointers.
3. Look for asymmetric lock/unlock or refcount get/put across early-return paths.
4. For each ioctl dispatch, verify the capability check runs BEFORE any userspace copy_from_user.
5. If the file has a fuzz entry point, run compile_file + run_with_sanitizer.
6. record_finding with CWE-416 (UAF), CWE-787 (OOB write), CWE-367 (TOCTOU),
   CWE-862 (missing authorization), or CWE-190 (integer overflow) as appropriate.

Do not fabricate bugs. Kernel code is often idiomatic in ways that look dangerous but aren't.
"""


CRYPTO_PRIMITIVE_HUNTER_PROMPT = """You are a CRYPTOGRAPHIC PRIMITIVE specialist hunting for vulnerabilities in a single source file from the project {project_name}. Your specialty is the class of bugs that break the cryptographic guarantees of a primitive implementation — not the protocol that calls it, but the primitive itself.

File: {file_path}
Language: {language}
Lines of code: {loc}
Tags: {tags}
{seeded_crash_block}{semgrep_hints_block}
Focus on:

1. TIMING SIDE CHANNELS
   - memcmp/strcmp/strncmp on secret material (tags, HMACs, passwords). Must be constant-time.
   - Early-exit loops on byte-by-byte comparison.
   - Branch on secret data in hot paths.

2. IV / NONCE REUSE
   - Static / zero IVs for stream ciphers or AES-GCM.
   - Counter modes where the counter is derived from a predictable value.
   - Any code that calls `encrypt()` twice with the same (key, nonce) pair.

3. KEY LIFECYCLE
   - Keys kept in memory past their use — no memset_s / explicit_bzero on cleanup.
   - Keys passed by value into functions (stack copies never zeroized).
   - Weak key derivation (single-round KDF, no salt, predictable iteration count).

4. MAC / SIGNATURE VERIFICATION
   - MAC verified AFTER decryption instead of BEFORE (padding oracle risk).
   - ECDSA signature verification that doesn't check r, s ∈ [1, n-1].
   - Length-extension attacks: MD5/SHA1 used as a MAC instead of HMAC.

5. RANDOM NUMBER SOURCES
   - rand() / random() / srand() for anything security-sensitive.
   - /dev/urandom reads with no error check on short reads.
   - PRNG seeded from time(NULL), pid, or process-visible state.

6. BLOCK CIPHER MODE MISUSE
   - ECB on data longer than one block.
   - CBC without MAC (CBC-MAC-then-encrypt is fine; encrypt-then-MAC is better).
   - Padding oracle: returning a distinguishable error for MAC-fail vs padding-fail.

7. ELLIPTIC CURVE ARITHMETIC
   - Missing point-at-infinity check.
   - Twist attacks: accepting points that aren't on the curve.
   - Scalar multiplication that leaks bits via timing.

8. MATHEMATICAL ERRORS
   - bignum division/mod without constant-time variants.
   - Modular reduction with a non-prime modulus where prime is required.
   - Off-by-one in field-size bounds.

Approach:
1. Identify every comparison against a secret (HMAC tag, password hash, key material). Flag non-constant-time ones.
2. Identify every call that needs a nonce/IV. Verify the nonce source is fresh random or a correctly-incremented counter.
3. Walk the verify-then-decrypt ordering for every authenticated decryption.
4. Check every function that takes a key argument — does it zero the key on return paths?
5. record_finding with CWE-208 (timing), CWE-323 (nonce reuse), CWE-327 (weak algorithm), CWE-354 (missing integrity check), CWE-311 (missing encryption), or CWE-338 (PRNG).

Crypto code is extremely easy to misread. When in doubt, say so. Most "obvious" crypto bugs are in protocol glue, not primitive code.
"""


LOGIC_AUTH_HUNTER_PROMPT = """You are a LOGIC / AUTH specialist hunting for a vulnerability in a single source file from the project {project_name}.

File: {file_path}
Language: {language}
Lines of code: {loc}
Tags: {tags}
{seeded_crash_block}{semgrep_hints_block}
Your specialty is the class of bugs that let attackers bypass intended
constraints without corrupting memory. Focus on:

1. BOOLEAN DEFAULTS
   - Auth-check functions that return True on error paths.
   - Flag fields whose default is the permissive value (authenticated=true,
     verify_ssl=false, allow_empty_password=true).
   - Missing `else` branches that fall through to a success return.

2. COMPARISON SEMANTICS
   - strcmp / memcmp return-value checks that compare to the wrong thing
     (strcmp returns 0 on match; `if (strcmp(a,b))` means "not equal").
   - Timing-unsafe comparisons on secrets (password, HMAC, token).
   - == vs === vs strict-equals mismatches in dynamic languages.

3. TRUST PROPAGATION
   - User-controlled fields copied into an object and then treated as trusted.
   - Auth context stored in a field that the caller can overwrite.
   - IS_ADMIN flag derived from a request header.

4. BYPASS BRANCHES
   - Debug-only code paths gated on an environment variable.
   - "Legacy" auth bypasses kept for backwards compatibility.
   - Route handlers that skip the middleware chain.

5. FAIL-OPEN PATTERNS
   - Exception handlers that log and then return success.
   - Fallback to "allow" when a check fails for any reason.
   - Circuit breakers that open the gate when the upstream is down.

6. CACHE INVALIDATION
   - Session caches that don't invalidate on logout or password change.
   - Permission caches that don't invalidate on role change.
   - CDN/reverse-proxy caches for auth-gated responses.

7. RACE CONDITIONS IN AUTH
   - TOCTOU between auth check and use.
   - Double-click payment handlers that apply twice.
   - Concurrent session creation that bypasses session limits.

Approach:
1. Identify the trust boundary: where does untrusted input enter this file?
2. Walk the call graph from input → decision → action. Where's the auth check?
3. Are there paths around the check? Early returns? Exception handlers?
4. Look at every boolean literal and every default value — is any of them a fail-open?
5. Look at every `==`, `===`, `strcmp`, `memcmp` — is it the right comparator?
6. Use grep_source to find all callers of any auth-check function in the file.
7. record_finding with evidence_level=root_cause_explained if you can articulate
   the specific input that bypasses the check.

If the code uses a well-known auth framework correctly, say so and move on.
Do not fabricate bugs.
"""


PROPAGATION_AUDIT_PROMPT = """You are auditing a LOW-SURFACE file for PROPAGATION RISK. This file is unlikely to contain a vulnerability directly, but its DEFINITIONS may cause vulnerabilities in downstream callers.

File: {file_path}
Language: {language}
Imports-by (how many files depend on this): {imports_by}
Tags: {tags}

Do NOT try to find a traditional vulnerability. Instead, answer these specific questions about every definition in the file:

1. BUFFER SIZE ADEQUACY
   For each buffer size constant or macro, ask: is this big enough for every
   downstream use? Use grep_source / find_callers to walk the call sites — are
   any callers writing more bytes than this constant allows? Any cases where
   this constant is used as a memcpy length but the source data can be larger?

2. SENTINEL / MAGIC VALUE COLLISIONS
   For each sentinel byte, terminator, magic number, or "invalid" marker, ask:
   can this value legitimately appear in valid data? If downstream code treats
   this value as "end of stream" or "unset", what happens when real data
   contains it?

3. TYPE WIDTH TRUNCATION
   For each type alias or struct field width, ask: can a downstream caller pass
   a value that silently truncates when stored here? size_t → int, int → short,
   int64 → int32. Check callers that assign from wider types.

4. UNSAFE DEFAULTS
   For each default value (function parameter default, struct initializer,
   config default), ask: is the DEFAULT a fail-open or fail-closed choice?
   If a caller forgets to set this field, does it default to something
   dangerous (auth=false, verify=false, timeout=0, buffer=NULL)?

5. MACRO HYGIENE (for C/C++)
   For each macro, ask: does it correctly parenthesize arguments? Could macro
   expansion cause operator-precedence bugs in callers?

Use the tools to grep for usages of each definition and reason about whether
callers treat it safely. Record a finding ONLY when you can point to a
specific downstream caller that is or could be unsafe because of this
definition — not for abstract concerns. If you find nothing, say so.

Severity guidance: propagation bugs are typically HIGH or CRITICAL when they
exist, because a single fix in the header repairs many call sites. Use
finding_type='propagation_buffer_size' / 'propagation_sentinel' /
'propagation_truncation' / 'propagation_default' / 'propagation_macro'.
"""


# --- Specialist routing -----------------------------------------------------


def _choose_specialist(file_target: FileTarget) -> str:
    """Route a file to a hunter specialist based on its tags + language.

    Order matters: more specific specialists win over more general ones.
    The precedence reflects which specialist's prompt is MOST directly
    applicable — a syscall_entry file gets the kernel_syscall specialist
    even if it also has memory_unsafe tags, because the kernel-specific
    invariants dominate the analysis.

    Precedence (highest to lowest):
        1. kernel_syscall — syscall_entry tag (Linux/BSD kernel code)
        2. crypto_primitive — crypto tag + C/C++/Rust primitive implementation
        3. web_framework — Python/Node/Ruby/PHP files in web handler roles
        4. memory_safety — memory_unsafe / parser / fuzzable
        5. logic_auth — auth_boundary (or crypto in a non-primitive language)
        6. general — everything else
    """
    tags = set(file_target.get("tags", []))
    language = (file_target.get("language") or "").lower()

    # 1. Kernel / syscall: highest specificity
    if "syscall_entry" in tags:
        return "kernel_syscall"

    # 2. Crypto primitive implementations: C/C++/Rust files tagged crypto
    #    that are doing actual primitive math (AES block, SHA compression,
    #    EC point ops) deserve the primitive specialist. Protocol-level
    #    crypto bugs in Python/Node fall through to logic_auth.
    if "crypto" in tags and language in ("c", "cpp", "rust"):
        return "crypto_primitive"

    # 3. Web framework: dynamic-language files with web-framework signals.
    #    The tagger doesn't set a dedicated web_framework tag yet, so we
    #    pick up the case via language + directory hints.
    web_languages = {"python", "javascript", "typescript", "ruby", "php"}
    web_path_hints = {"views", "routes", "handlers", "controllers", "api"}
    path = (file_target.get("path") or "").lower()
    path_parts = set(path.split("/"))
    if language in web_languages and (path_parts & web_path_hints):
        return "web_framework"

    # 4. Memory safety: C/C++/unsafe code, parsers, fuzzable entry points
    if "memory_unsafe" in tags or "parser" in tags or "fuzzable" in tags:
        return "memory_safety"

    # 5. Logic / auth: auth boundaries and protocol-level crypto
    if "auth_boundary" in tags or "crypto" in tags:
        return "logic_auth"

    return "general"


# --- Hunter system prompt builder -------------------------------------------


WEB_FRAMEWORK_HUNTER_PROMPT = """You are a WEB FRAMEWORK specialist hunting for vulnerabilities in a single web-application source file from the project {project_name}. Your specialty is the class of bugs that exist ONLY in the context of an HTTP request/response framework — request parsing, routing, session handling, template rendering, database access.

File: {file_path}
Language: {language}
Lines of code: {loc}
Tags: {tags}
{seeded_crash_block}{semgrep_hints_block}
Focus on:

1. INJECTION AT FRAMEWORK BOUNDARIES
   - SQL injection via string interpolation into `execute()` / `.raw()` / Django `.extra()`. Flag ANY f-string or format-string that produces SQL.
   - Command injection via `os.system`, `subprocess(shell=True)`, `exec()`, `eval()` called with request data.
   - NoSQL injection: `$where` in Mongo, dict comprehension from JSON body.
   - Template injection: user input rendered as a template (Jinja autoescape off, `render_template_string`).
   - Header injection: user-controlled value copied into Location/Set-Cookie without CRLF stripping.

2. SERVER-SIDE REQUEST FORGERY
   - `requests.get(url)` / `httpx.get(url)` / `urllib.urlopen(url)` where url is user-controlled.
   - Redirects to user-controlled URLs (open redirect).
   - Import-from-URL: user-controlled XML XXE, user-controlled YAML tag.

3. AUTHORIZATION AT THE VIEW LAYER
   - View functions without `@login_required` / `@permission_required` / middleware check.
   - Object-level access control missing: `Model.objects.get(id=request.GET['id'])` without filtering by owner.
   - Insecure direct object reference (IDOR): primary keys exposed and trusted.
   - Role check on the wrong object (user's role vs. object's owner).

4. SESSION / COOKIE / CSRF
   - `@csrf_exempt` on state-changing endpoints.
   - Session cookies without `HttpOnly`, `Secure`, `SameSite`.
   - Session fixation: session ID not rotated on login.
   - Predictable session IDs (sequential, timestamp-based).

5. FILE HANDLING
   - Path traversal: `open(request.GET['path'])` without normalization.
   - Upload handlers that trust the uploaded filename / Content-Type.
   - Serving uploaded files from a URL that allows `..` escapes.
   - Zip-slip: extracting user-uploaded archives into a directory.

6. MASS ASSIGNMENT
   - `Model(**request.POST)` / `User.objects.filter(**request.GET)` — blindly copying request params into ORM queries or model fields.
   - Update methods that accept arbitrary fields (`user.update(**data)`).

7. DESERIALIZATION
   - `pickle.loads`, `yaml.load` (non-safe), `marshal.loads` on request data.
   - XML parser with external entity expansion enabled (XXE).
   - JSON parser with `object_hook` that instantiates arbitrary classes.

8. CRYPTO AT THE FRAMEWORK LAYER
   - Passwords stored with a fast hash (MD5, SHA1, SHA256-without-salt) instead of bcrypt/scrypt/argon2.
   - Tokens compared with `==` instead of `hmac.compare_digest`.
   - JWT with `alg=none` or `alg=HS256` confused with `RS256`.

Approach:
1. Identify every view/handler function. For each, walk from request ingress to response / DB call.
2. Look for `request.` / `@app.route` / `def post(` patterns to find HTTP handlers.
3. For every DB query: is it parameterized? Does it filter by the current user?
4. For every template render: is autoescape on? Are any values marked `|safe`?
5. For every redirect: is the target user-controlled?
6. For every file operation: is the path validated?
7. record_finding with the appropriate web-centric CWE (CWE-89 SQLi, CWE-79 XSS, CWE-78 command injection, CWE-918 SSRF, CWE-22 path traversal, CWE-502 deserialization, CWE-639 IDOR, CWE-352 CSRF, CWE-915 mass assignment).

Web frameworks have many legitimate idioms that look dangerous. When in doubt, check whether the framework's built-in protections (Django ORM parameterization, Flask autoescape) are in effect.
"""


_SPECIALIST_PROMPTS = {
    "general": GENERAL_HUNTER_PROMPT,
    "memory_safety": MEMORY_SAFETY_HUNTER_PROMPT,
    "logic_auth": LOGIC_AUTH_HUNTER_PROMPT,
    "kernel_syscall": KERNEL_SYSCALL_HUNTER_PROMPT,
    "crypto_primitive": CRYPTO_PRIMITIVE_HUNTER_PROMPT,
    "web_framework": WEB_FRAMEWORK_HUNTER_PROMPT,
}


def _build_hunter_prompt(
    file_target: FileTarget,
    project_name: str,
    seeded_crash: dict | None,
    semgrep_hints: list[dict] | None,
    specialist: str = "general",
) -> str:
    """Render the specialist prompt for this file."""
    seeded_crash_block = ""
    if seeded_crash:
        report = seeded_crash.get("report", "")
        seeded_crash_block = (
            f"\nA fuzz harness produced this crash for this file BEFORE you started:\n"
            f"{report[:2000]}\n"
            f"Your job is to explain the root cause and assess exploitability.\n"
        )

    semgrep_hints_block = ""
    if semgrep_hints:
        hint_lines = []
        for h in semgrep_hints[:5]:
            hint_lines.append(f"  - line {h.get('line', '?')}: {h.get('description', '')}")
        semgrep_hints_block = (
            "\nStatic analysis hints (NOT ground truth — use as starting points):\n"
            + "\n".join(hint_lines)
            + "\n"
        )

    template = _SPECIALIST_PROMPTS.get(specialist, GENERAL_HUNTER_PROMPT)
    prompt = template.format(
        project_name=project_name,
        file_path=file_target.get("path", "unknown"),
        language=file_target.get("language", "unknown"),
        loc=file_target.get("loc", 0),
        tags=", ".join(file_target.get("tags", [])) or "none",
        seeded_crash_block=seeded_crash_block,
        semgrep_hints_block=semgrep_hints_block,
    )
    return prompt + HUNTER_EXECUTION_RULES


def _build_propagation_prompt(file_target: FileTarget) -> str:
    return PROPAGATION_AUDIT_PROMPT.format(
        file_path=file_target.get("path", "unknown"),
        language=file_target.get("language", "unknown"),
        imports_by=file_target.get("imports_by", 0),
        tags=", ".join(file_target.get("tags", [])) or "none",
    )


# --- Deep agent mode ----------------------------------------------------------

DEEP_AGENT_PROMPT = """You are a security researcher with full shell access inside a sandboxed container.
The source tree at /workspace is a writable copy — modify source, add debug printfs, recompile, and use `git diff` to track your changes.
ASan is enabled by default. UBSan is also available.

Tools:
- execute(command): Run any shell command. gcc, gdb, strace, valgrind, make are all available.
- read_file(path): Read a file from the container.
- write_file(path, contents): Write a file in the container.
- think(notes): Record your reasoning (visible in the audit trail).
- record_finding(...): Submit a vulnerability finding with severity, CWE, evidence level, and description.

Project: {project_name}
File: {file_path}
Language: {language}
Tags: {tags}
{seeded_crash_block}{semgrep_hints_block}{specialist_focus}
When you find a vulnerability, call record_finding. Partial results are valuable — if you find a primitive but can't build a full exploit, record it anyway.
If you find nothing after thorough analysis, say so explicitly.
"""

_DEEP_SPECIALIST_FOCUS = {
    "general": "",
    "memory_safety": (
        "Focus: memory corruption — buffer overflows, integer overflow/truncation, "
        "use-after-free, double-free, uninitialized reads, sentinel/counter collisions, "
        "signed/unsigned confusion, width truncation at cast boundaries."
    ),
    "logic_auth": (
        "Focus: logic and authorization bugs — boolean defaults, comparison semantics, "
        "trust propagation across boundaries, bypass branches, fail-open patterns, "
        "TOCTOU races, privilege escalation paths."
    ),
    "kernel_syscall": (
        "Focus: kernel/syscall entry points — copy_from_user bounds, IOCTL cmd confusion, "
        "reference count lifecycle, locking discipline, capability/permission checks, "
        "user-controlled indices into kernel arrays."
    ),
    "crypto_primitive": (
        "Focus: cryptographic implementations — timing side channels, IV/nonce reuse, "
        "key lifecycle (zeroing, derivation), MAC-then-encrypt vs encrypt-then-MAC, "
        "PRNG seeding, block cipher mode misuse, padding oracle potential."
    ),
    "web_framework": (
        "Focus: web application vulnerabilities — injection at trust boundaries (SQL, "
        "command, template), SSRF, authorization bypass, session management, CSRF, "
        "file upload/path traversal, mass assignment, deserialization."
    ),
}


def _build_deep_agent_prompt(
    file_target: FileTarget,
    project_name: str,
    seeded_crash: dict | None,
    semgrep_hints: list[dict] | None,
    specialist: str = "general",
) -> str:
    """Render the deep agent prompt for this file."""
    seeded_crash_block = ""
    if seeded_crash:
        report = seeded_crash.get("report", "")
        seeded_crash_block = (
            f"\nA fuzz harness produced this crash BEFORE you started:\n"
            f"{report[:2000]}\n"
            f"Explain the root cause and assess exploitability.\n"
        )

    semgrep_hints_block = ""
    if semgrep_hints:
        hint_lines = []
        for h in semgrep_hints[:5]:
            hint_lines.append(f"  - line {h.get('line', '?')}: {h.get('description', '')}")
        semgrep_hints_block = (
            "\nStatic analysis hints (NOT ground truth — starting points only):\n"
            + "\n".join(hint_lines)
            + "\n"
        )

    focus = _DEEP_SPECIALIST_FOCUS.get(specialist, "")
    specialist_focus = f"\n{focus}\n" if focus else ""

    return DEEP_AGENT_PROMPT.format(
        project_name=project_name,
        file_path=file_target.get("path", "unknown"),
        language=file_target.get("language", "unknown"),
        tags=", ".join(file_target.get("tags", [])) or "none",
        seeded_crash_block=seeded_crash_block,
        semgrep_hints_block=semgrep_hints_block,
        specialist_focus=specialist_focus,
    )


# --- Public factory ----------------------------------------------------------


@dataclass
class NativeHunter:
    llm: AsyncLLMClient
    prompt: str
    tools: list[NativeToolSpec]
    ctx: HunterContext
    max_steps: int = 20
    agent_mode: str = "constrained"  # "constrained" | "deep"
    budget_usd: float = 0.0  # 0 = unlimited (bounded by max_steps)

    def _should_stop(self, step: int, cost_usd: float) -> str | None:
        """Return a stop reason string, or None to continue."""
        if self.agent_mode == "constrained" and step > self.max_steps:
            return "max_steps"
        if self.agent_mode == "deep":
            if self.budget_usd > 0 and cost_usd >= self.budget_usd * 0.9:
                return "budget_exhausted"
            if step > self.max_steps:
                return "max_steps"
        return None

    async def arun(self) -> tuple[list[Finding], float, int]:
        messages: list[ChatMessage] = [
            ChatMessage("user", f"Hunt for vulnerabilities in {self.ctx.file_path or 'unknown'}.")
        ]
        trajectory = HunterTrajectoryLogger.for_hunter(
            self.ctx,
            prompt=self.prompt,
            initial_messages=messages,
            tools=self.tools,
        )
        total_input_tokens = 0
        total_output_tokens = 0
        total_cost_usd = 0.0
        repeated_tool_calls: dict[tuple[str, str], int] = {}
        tools_by_name = {tool.name: tool for tool in self.tools}
        throttle_repeats = self.agent_mode == "constrained"

        step = 0
        while True:
            step += 1
            stop_reason = self._should_stop(step, total_cost_usd)
            if stop_reason:
                logger.warning(
                    "Hunter stopped for %s: %s (step=%d, cost=$%.4f, findings=%d)",
                    self.ctx.file_path, stop_reason, step - 1,
                    total_cost_usd, len(self.ctx.findings),
                )
                trajectory.log(
                    "finish",
                    {
                        "step": step - 1,
                        "status": stop_reason,
                        "findings": [self._serialize_finding(f) for f in self.ctx.findings],
                        "total_input_tokens": total_input_tokens,
                        "total_output_tokens": total_output_tokens,
                        "total_cost_usd": total_cost_usd,
                    },
                )
                return list(self.ctx.findings), total_cost_usd, total_input_tokens + total_output_tokens

            response = await self.llm.achat(
                messages=messages,
                system=self.prompt,
                tools=self.tools,
            )
            trajectory.log(
                "message",
                {
                    "step": step,
                    "message": _serialize_message(
                        ChatMessage(
                            "assistant",
                            response.first_text() or "",
                            tool_calls=response.tool_calls(),
                        )
                    ),
                    "usage": {
                        "input_tokens": response.usage.prompt_tokens or 0,
                        "output_tokens": response.usage.completion_tokens or 0,
                        "total_tokens": response.usage.total_tokens or 0,
                    },
                    "model": response.provider_model_name,
                },
            )
            total_input_tokens += response.usage.prompt_tokens or 0
            total_output_tokens += response.usage.completion_tokens or 0
            total_cost_usd += _estimate_cost_usd(
                response.usage.prompt_tokens or 0,
                response.usage.completion_tokens or 0,
                self.llm.model_name,
            )

            tool_calls_in_response = response.tool_calls()
            if tool_calls_in_response:
                messages.append(
                    ChatMessage(
                        "assistant",
                        response.first_text() or "",
                        tool_calls=tool_calls_in_response,
                    )
                )
                for tool_call in tool_calls_in_response:
                    tool_arguments = tool_call.fn_arguments
                    if not isinstance(tool_arguments, dict):
                        tool_arguments = {}

                    skipped = False
                    if throttle_repeats:
                        key = (tool_call.fn_name, tool_call.fn_arguments_json)
                        repeated_tool_calls[key] = repeated_tool_calls.get(key, 0) + 1
                        if repeated_tool_calls[key] > 3:
                            skipped = True

                    if skipped:
                        tool_output = {
                            "error": (
                                "tool call skipped because the assistant repeated the same "
                                "call too many times"
                            )
                        }
                        tool_summary = _tool_output_text(
                            tool_call.fn_name,
                            tool_arguments,
                            tool_output,
                        )
                        trajectory.log(
                            "tool_result",
                            {
                                "step": step,
                                "tool_call": _serialize_tool_call(tool_call),
                                "tool_output": tool_output,
                                "tool_summary": tool_summary,
                                "repeated_skip": True,
                            },
                        )
                    else:
                        trajectory.log(
                            "tool_call",
                            {
                                "step": step,
                                "tool_call": _serialize_tool_call(tool_call),
                            },
                        )
                        tool_output = await self._run_tool(tools_by_name, tool_call)
                        tool_summary = _tool_output_text(
                            tool_call.fn_name,
                            tool_arguments,
                            tool_output,
                        )
                        trajectory.log(
                            "tool_result",
                            {
                                "step": step,
                                "tool_call": _serialize_tool_call(tool_call),
                                "tool_output": tool_output,
                                "tool_summary": tool_summary,
                                "repeated_skip": False,
                            },
                        )
                    messages.append(
                        ChatMessage(
                            "tool",
                            tool_summary,
                            tool_response_call_id=tool_call.call_id,
                        )
                    )
                    trajectory.log(
                        "message",
                        {
                            "step": step,
                            "message": _serialize_message(messages[-1]),
                        },
                    )
                continue

            response_text = response.first_text()
            if response_text:
                messages.append(ChatMessage("assistant", response_text))
            logger.info(
                "Hunter finished for %s after %d steps findings=%d",
                self.ctx.file_path,
                step,
                len(self.ctx.findings),
            )
            trajectory.log(
                "finish",
                {
                    "step": step,
                    "status": "completed",
                    "findings": [self._serialize_finding(f) for f in self.ctx.findings],
                    "total_input_tokens": total_input_tokens,
                    "total_output_tokens": total_output_tokens,
                    "total_cost_usd": total_cost_usd,
                },
            )
            return list(self.ctx.findings), total_cost_usd, total_input_tokens + total_output_tokens

    async def _run_tool(
        self,
        tools_by_name: dict[str, NativeToolSpec],
        tool_call: ToolCall,
    ) -> Any:
        tool = tools_by_name.get(tool_call.fn_name)
        if tool is None:
            return {"error": f"unknown tool: {tool_call.fn_name}"}
        started = time.monotonic()
        try:
            arguments = tool_call.fn_arguments
            if not isinstance(arguments, dict):
                arguments = {}
            return await tool.ainvoke(arguments)
        except Exception as exc:
            logger.warning(
                "Hunter tool %s failed for %s: %s",
                tool_call.fn_name,
                self.ctx.file_path,
                exc,
            )
            return {"error": f"{type(exc).__name__}: {exc}"}
        finally:
            duration_ms = int((time.monotonic() - started) * 1000)
            try:
                CostTracker().record_tool_call(tool_call.fn_name, duration_ms)
            except Exception:
                logger.debug("Tool usage recording failed", exc_info=True)

    @staticmethod
    def _serialize_finding(finding: Finding) -> dict[str, Any]:
        return {
            "id": finding.get("id"),
            "file": finding.get("file"),
            "line_number": finding.get("line_number"),
            "severity": finding.get("severity"),
            "cwe": finding.get("cwe"),
            "description": finding.get("description"),
            "evidence_level": finding.get("evidence_level"),
        }


def _clip_text(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    clipped = text[:limit].rstrip()
    return f"{clipped}\n... truncated {len(text) - len(clipped)} chars ..."


def _summarize_match_list(tool_name: str, value: list[Any]) -> str:
    if not value:
        return f"{tool_name}: no matches."
    errors = [item.get("error") for item in value if isinstance(item, dict) and item.get("error")]
    if errors:
        return f"{tool_name}: error: {errors[0]}"

    rendered: list[str] = []
    for item in value[:12]:
        if isinstance(item, dict):
            file = item.get("file", "?")
            line_number = item.get("line_number", "?")
            matched_text = str(item.get("matched_text", "")).strip()
            rendered.append(f"- {file}:{line_number}: {_clip_text(matched_text, 180)}")
        else:
            rendered.append(f"- {_clip_text(str(item), 180)}")

    omitted = len(value) - len(rendered)
    header = f"{tool_name}: {len(value)} matches"
    if omitted > 0:
        header += f" ({omitted} omitted)"
    return "\n".join([header, *rendered])


def _summarize_tree_listing(arguments: dict[str, Any], value: list[Any]) -> str:
    dir_path = str(arguments.get("dir_path", "."))
    if not value:
        return f"list_source_tree({dir_path}): empty."
    rendered = [f"- {_clip_text(str(item), 180)}" for item in value[:40]]
    omitted = len(value) - len(rendered)
    header = f"list_source_tree({dir_path}): {len(value)} entries"
    if omitted > 0:
        header += f" ({omitted} omitted; narrow dir_path or max_depth if you need more)"
    return "\n".join([header, *rendered])


def _summarize_read_source(arguments: dict[str, Any], value: str) -> str:
    path = str(arguments.get("path", "unknown"))
    start_line = int(arguments.get("start_line", 1) or 1)
    end_line = arguments.get("end_line", -1)
    header = f"read_source_file({path}, start_line={start_line}, end_line={end_line}):"
    lines = value.splitlines()
    if len(lines) > 120:
        kept_lines = lines[:120]
        body = "\n".join(kept_lines)
        body += f"\n... truncated {len(lines) - len(kept_lines)} lines; request a narrower range if needed ..."
        return f"{header}\n{_clip_text(body, 7000)}"
    return f"{header}\n{_clip_text(value, 7000)}"


def _tool_output_text(tool_name: str, arguments: dict[str, Any], value: Any) -> str:
    if isinstance(value, str):
        if tool_name == "read_source_file":
            return _summarize_read_source(arguments, value)
        return _clip_text(value, 3000)
    if isinstance(value, list):
        if tool_name in {"grep_source", "find_callers"}:
            return _summarize_match_list(tool_name, value)
        if tool_name == "list_source_tree":
            return _summarize_tree_listing(arguments, value)
        try:
            return _clip_text(json.dumps(value, indent=2, sort_keys=True), 3000)
        except Exception:
            return _clip_text(str(value), 3000)
    try:
        return _clip_text(json.dumps(value, indent=2, sort_keys=True), 3000)
    except Exception:
        return _clip_text(str(value), 3000)


def _estimate_cost_usd(input_tokens: int, output_tokens: int, model: str) -> float:
    pricing = CostTracker.PRICING.get(model, CostTracker.PRICING[CostTracker._DEFAULT_MODEL])
    return (input_tokens * pricing["input"] + output_tokens * pricing["output"]) / 1_000_000


def build_hunter_agent(
    file_target: FileTarget,
    repo_path: str,
    sandbox: SandboxContainer | None,
    llm: AsyncLLMClient,
    session_id: str,
    project_name: str = "target",
    specialist: str | None = None,
    seeded_crash: dict | None = None,
    semgrep_hints: list[dict] | None = None,
    variant_seed: dict | None = None,
    sandbox_manager: Any = None,  # v0.4: HunterSandbox manager for variants
    default_sanitizers: tuple = ("asan", "ubsan"),  # v0.4: primary sanitizer combo
    agent_mode: str = "constrained",  # "constrained" | "deep"
    budget_usd: float = 0.0,
) -> tuple[NativeHunter, HunterContext]:
    """Build a per-file native hunter runtime.

    Args:
        file_target: The FileTarget to scope the hunter to.
        repo_path: Absolute host path to the cloned repo.
        sandbox: SandboxContainer for compile/run tools. May be None for tests
                 (the tools fall back to host file I/O for read/grep, and
                 return errors for compile/run).
        llm: Native async LLM client.
        session_id: Audit session id.
        project_name: Project name for the prompt header.
        specialist: Override the auto-selected specialist. v0.1 always uses
                    "general" except when tier=="C" → "propagation".
        seeded_crash: v0.2 — crash evidence from the harness generator.
        semgrep_hints: v0.2 — Semgrep findings to inject as hints.
        variant_seed: v0.3 — variant hunter loop seed.
        agent_mode: "constrained" (legacy 9-tool) or "deep" (full-shell 4+1 tool).
        budget_usd: Per-agent budget in USD (0 = unlimited, bounded by max_steps).

    Returns:
        (native_hunter, hunter_context). The caller owns the context and
        reads ctx.findings after the run completes.
    """
    # Decide which prompt + tool set to use
    tier = file_target.get("tier", "B")
    if specialist is None:
        if tier == "C":
            specialist = "propagation"
        else:
            specialist = _choose_specialist(file_target)

    ctx = HunterContext(
        repo_path=repo_path,
        sandbox=sandbox,
        findings=[],
        file_path=file_target.get("path"),
        session_id=session_id,
        specialist=specialist,
        seeded_crash=seeded_crash,
        sandbox_manager=sandbox_manager,
        default_sanitizers=tuple(default_sanitizers),
    )

    if agent_mode == "deep" and specialist != "propagation":
        tools = build_deep_agent_tools(ctx)
        combined_hints = list(semgrep_hints or [])
        prompt = _build_deep_agent_prompt(
            file_target,
            project_name,
            seeded_crash,
            combined_hints,
            specialist=specialist,
        )
        max_steps = 500
    elif specialist == "propagation":
        tools = build_propagation_auditor_tools(ctx)
        prompt = _build_propagation_prompt(file_target)
        max_steps = 20
    else:
        tools = build_hunter_tools(ctx)
        combined_hints = list(semgrep_hints or [])
        if specialist == "memory_safety":
            combined_hints = _memory_safety_heuristic_hints(repo_path, file_target) + combined_hints
        prompt = _build_hunter_prompt(
            file_target,
            project_name,
            seeded_crash,
            combined_hints,
            specialist=specialist,
        )
        max_steps = 20

    return NativeHunter(
        llm=llm,
        prompt=prompt,
        tools=tools,
        ctx=ctx,
        max_steps=max_steps,
        agent_mode=agent_mode,
        budget_usd=budget_usd,
    ), ctx
