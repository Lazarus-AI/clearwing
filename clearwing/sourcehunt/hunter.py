"""Per-file hunter ReAct agent.

build_hunter_agent() wraps build_react_graph() (R1) with the sourcehunt-specific
tool set, system prompt, and SourceHuntState schema. v0.1 ships with a single
GeneralHunter; v0.2 adds memory_safety and logic_auth specialists with
different prompts but the same graph structure.
"""

from __future__ import annotations

import logging
from typing import Any

from langchain_core.language_models import BaseChatModel
from langgraph.graph.state import CompiledStateGraph

from clearwing.agent.graph import build_react_graph
from clearwing.agent.tools.hunt import (
    HunterContext,
    build_hunter_tools,
    build_propagation_auditor_tools,
)
from clearwing.sandbox.container import SandboxContainer

from .state import FileTarget, SourceHuntState

logger = logging.getLogger(__name__)


# --- System prompts ---------------------------------------------------------


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

7. USE-AFTER-FREE
   - free() followed by any use of the pointer.
   - Double-free via aliasing.
   - Dangling pointers after realloc() shrinks a buffer.

8. UNINITIALIZED MEMORY
   - stack variables used before assignment.
   - struct fields left uninitialized that get sent over the wire.

Approach:
1. Read the target file. Find every buffer, every pointer, every size computation.
2. For each buffer: where is it allocated? What's the size? Who writes to it?
3. For each size computation: can any input make it wrap, truncate, or underflow?
4. Use compile_file + run_with_sanitizer on the file with ASan/UBSan. If the
   project has a fuzz entry point, run it with a crafted input.
5. record_finding with evidence_level=crash_reproduced if you got an ASan
   report, else static_corroboration if you can show a pattern.

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


def _no_op_state_updater(tool_name: str, data: Any, state: dict) -> dict:
    """Hunter agents update SourceHuntState via record_finding directly,
    so no implicit tool-result→state mapping is needed."""
    return {}


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
    return template.format(
        project_name=project_name,
        file_path=file_target.get("path", "unknown"),
        language=file_target.get("language", "unknown"),
        loc=file_target.get("loc", 0),
        tags=", ".join(file_target.get("tags", [])) or "none",
        seeded_crash_block=seeded_crash_block,
        semgrep_hints_block=semgrep_hints_block,
    )


def _build_propagation_prompt(file_target: FileTarget) -> str:
    return PROPAGATION_AUDIT_PROMPT.format(
        file_path=file_target.get("path", "unknown"),
        language=file_target.get("language", "unknown"),
        imports_by=file_target.get("imports_by", 0),
        tags=", ".join(file_target.get("tags", [])) or "none",
    )


# --- Public factory ----------------------------------------------------------


def build_hunter_agent(
    file_target: FileTarget,
    repo_path: str,
    sandbox: SandboxContainer | None,
    llm: BaseChatModel,
    session_id: str,
    project_name: str = "target",
    specialist: str | None = None,
    seeded_crash: dict | None = None,
    semgrep_hints: list[dict] | None = None,
    variant_seed: dict | None = None,
    sandbox_manager: Any = None,  # v0.4: HunterSandbox manager for variants
    default_sanitizers: tuple = ("asan", "ubsan"),  # v0.4: primary sanitizer combo
) -> tuple[CompiledStateGraph, HunterContext]:
    """Build a per-file ReAct hunter agent.

    Args:
        file_target: The FileTarget to scope the hunter to.
        repo_path: Absolute host path to the cloned repo.
        sandbox: SandboxContainer for compile/run tools. May be None for tests
                 (the tools fall back to host file I/O for read/grep, and
                 return errors for compile/run).
        llm: Pre-bound LLM (.bind_tools should NOT be called yet — we do it).
        session_id: Audit session id.
        project_name: Project name for the prompt header.
        specialist: Override the auto-selected specialist. v0.1 always uses
                    "general" except when tier=="C" → "propagation".
        seeded_crash: v0.2 — crash evidence from the harness generator.
        semgrep_hints: v0.2 — Semgrep findings to inject as hints.
        variant_seed: v0.3 — variant hunter loop seed.

    Returns:
        (compiled_graph, hunter_context). The caller owns the context and
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

    if specialist == "propagation":
        tools = build_propagation_auditor_tools(ctx)
        prompt = _build_propagation_prompt(file_target)
    else:
        tools = build_hunter_tools(ctx)
        prompt = _build_hunter_prompt(
            file_target,
            project_name,
            seeded_crash,
            semgrep_hints,
            specialist=specialist,
        )

    # Bind tools to the LLM
    llm_with_tools = llm.bind_tools(tools)

    def system_prompt_fn(state: dict) -> str:
        # The prompt is fixed per-hunter (the file is the context). We don't
        # need to re-render from state — return the captured prompt string.
        return prompt

    graph = build_react_graph(
        llm_with_tools=llm_with_tools,
        tools=tools,
        system_prompt_fn=system_prompt_fn,
        state_schema=SourceHuntState,
        model_name="hunter",
        session_id=session_id,
        state_updater_fn=_no_op_state_updater,
        # Disable network-pentest knowledge graph and input-guardrail tool list
        knowledge_graph_populator_fn=lambda *a, **k: {},
        input_guardrail_tool_names=frozenset(),
        output_guardrail_tool_names=frozenset(),
        enable_knowledge_graph=False,
        enable_episodic_memory=False,
    )

    return graph, ctx
