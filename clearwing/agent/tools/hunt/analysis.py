"""Sandboxed build + execute tools for the source-hunt hunter.

Four tools: `compile_file`, `run_with_sanitizer`, `write_test_case`,
`fuzz_harness`. All four route through the sandbox (via
`HunterContext.get_sandbox_for_variant`) so that compile artifacts
and runtime side effects stay confined to a throwaway container.

`_default_libfuzzer_template` lives here because it's only used by
`fuzz_harness`. `_parse_sanitizer_report` lives here because it's
used by both `run_with_sanitizer` and `fuzz_harness` to extract a
concise ASan/UBSan/MSan summary from sanitizer stderr.
"""

from __future__ import annotations

import logging
import os
import re
import uuid

from langchain_core.tools import tool

from .discovery import _container_path, _normalize_path
from .sandbox import HunterContext, _parse_variant_arg

logger = logging.getLogger(__name__)


# --- Sanitizer parsing + libFuzzer template helpers ------------------------


_SANITIZER_HEADER = re.compile(
    r"==\d+==\s*ERROR:\s*(AddressSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer)",
    re.IGNORECASE,
)
_GENERIC_CRASH_KIND = re.compile(
    r"(heap-buffer-overflow|stack-buffer-overflow|use-after-free|"
    r"global-buffer-overflow|stack-overflow|double-free|invalid-free|"
    r"alloc-dealloc-mismatch|null deref|signed-integer-overflow|"
    r"runtime error)",
    re.IGNORECASE,
)


def _parse_sanitizer_report(stderr: str) -> str:
    """Extract a concise crash summary from sanitizer stderr.

    Returns the first 60 lines starting from the sanitizer header, or
    the whole stderr (capped) if no header is found.
    """
    if not stderr:
        return ""
    lines = stderr.splitlines()
    # Find the first sanitizer header
    start = 0
    for i, line in enumerate(lines):
        if _SANITIZER_HEADER.search(line):
            start = i
            break
    snippet = "\n".join(lines[start : start + 60])
    # If we never found a header, just return the first 60 lines
    if "ERROR" not in snippet:
        snippet = "\n".join(lines[:60])
    return snippet[:6000]


def _default_libfuzzer_template(
    target_function: str,
    signature: str = "",
) -> str:
    """Build a minimal libFuzzer harness that forwards the fuzzer buffer
    into the target function.

    Heuristic: inspect the signature for common libFuzzer-compatible shapes:
      1. `fn(const uint8_t*, size_t)` — forward Data/Size directly
      2. `fn(const char*, size_t)` — cast Data to char*, forward
      3. `fn(const char*)` — NUL-terminate Data into a scratch buffer, forward
      4. anything else — write the buffer to an in-memory temp file whose
         path is passed as a const char* argument
    The template always includes `#include "common.h"` candidates via a
    #pragma comment so the compile step has a chance of finding project
    headers under /workspace/include.

    The template is deliberately simple — a hunter that wants something
    fancier should call fuzz_harness with a hunter-supplied harness_source.
    """
    sig = signature.strip()
    safe_fn = re.sub(r"[^a-zA-Z0-9_]", "_", target_function)

    # Mode 1: libFuzzer-native signature — direct forward
    native_sig = re.compile(
        r"const\s+(uint8_t|unsigned\s+char|u_char)\s*\*.*size_t",
        re.IGNORECASE,
    )
    if native_sig.search(sig) or not sig:
        return f"""#include <stddef.h>
#include <stdint.h>

/* Template libFuzzer harness (auto-generated — native buffer passthrough).
 * Target: {target_function}
 */
extern int {target_function}(const unsigned char *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {{
    if (Size == 0) return 0;
    {target_function}(Data, Size);
    return 0;
}}
"""

    # Mode 2: const char* + size_t
    char_sig = re.compile(r"const\s+char\s*\*.*size_t", re.IGNORECASE)
    if char_sig.search(sig):
        return f"""#include <stddef.h>
#include <stdint.h>

extern int {target_function}(const char *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {{
    if (Size == 0) return 0;
    {target_function}((const char *)Data, Size);
    return 0;
}}
"""

    # Mode 3: NUL-terminated const char*
    cstr_sig = re.compile(r"const\s+char\s*\*(?!.*size_t)", re.IGNORECASE)
    if cstr_sig.search(sig):
        return f"""#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern int {target_function}(const char *s);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {{
    if (Size == 0 || Size > 65536) return 0;
    char *buf = (char *)malloc(Size + 1);
    if (!buf) return 0;
    memcpy(buf, Data, Size);
    buf[Size] = 0;
    {target_function}(buf);
    free(buf);
    return 0;
}}
"""

    # Mode 4: fallback — write to an in-memory temp file and pass the path
    return f"""#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern int {target_function}(const char *path);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {{
    if (Size == 0) return 0;
    char path[64];
    snprintf(path, sizeof(path), "/tmp/fuzz_{safe_fn}_XXXXXX");
    int fd = mkstemp(path);
    if (fd < 0) return 0;
    write(fd, Data, Size);
    close(fd);
    {target_function}(path);
    unlink(path);
    return 0;
}}
"""


# --- Tool builder -----------------------------------------------------------


def build_analysis_tools(ctx: HunterContext) -> list:
    """Build the four sandboxed build/execute tools for a hunter session."""

    @tool
    def compile_file(
        file_path: str,
        sanitizers: list[str] | None = None,
        extra_flags: str = "",
        sanitizer_variant: str = "",
    ) -> dict:
        """Compile a file inside the sandbox with sanitizers.

        Args:
            file_path: repo-relative path to the file.
            sanitizers: Override the compile-time -fsanitize list. Normally
                you should leave this None and use sanitizer_variant instead
                (the variant picks a pre-built sanitizer-specific image).
            extra_flags: Extra gcc/clang flags appended to the compile command.
            sanitizer_variant: Named variant to compile against. Common values:
                "" (default — ASan+UBSan image), "msan" (MSan image).
                MSan cannot coexist with ASan; passing "msan" spawns a fresh
                container from the MSan variant image instead of the primary.

        Returns:
            Dict with keys: success, binary_path, stdout, stderr, exit_code, variant.
        """
        # Pick the sandbox for the requested variant
        variant_list = _parse_variant_arg(sanitizer_variant)
        target_sandbox = ctx.get_sandbox_for_variant(variant_list)
        if target_sandbox is None:
            return {"success": False, "error": "no sandbox attached"}

        try:
            rel = _normalize_path(ctx.repo_path, file_path)
        except ValueError as e:
            return {"success": False, "error": str(e)}

        # Determine the sanitizer flags to compile with
        effective_sanitizers = variant_list or sanitizers or list(ctx.default_sanitizers)
        san_flags = ",".join(effective_sanitizers)

        basename = os.path.splitext(os.path.basename(rel))[0]
        out_path = f"/scratch/{basename}-{uuid.uuid4().hex[:6]}.bin"
        cmd = [
            "sh",
            "-c",
            f"gcc -fsanitize={san_flags} -g -O0 -fno-omit-frame-pointer "
            f"{extra_flags} -o {out_path} {_container_path(rel)} 2>&1",
        ]
        result = target_sandbox.exec(cmd, timeout=120)
        return {
            "success": result.exit_code == 0,
            "binary_path": out_path if result.exit_code == 0 else None,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.exit_code,
            "variant": san_flags,
        }

    @tool
    def run_with_sanitizer(
        binary: str,
        argv: list[str] | None = None,
        stdin: str = "",
        timeout: int = 30,
        sanitizer_variant: str = "",
    ) -> dict:
        """Run a binary inside the sandbox with sanitizer env vars set.

        Args:
            binary: Path to the binary inside the sandbox (e.g. /scratch/foo.bin).
            argv: Extra command-line arguments to pass after the binary.
            stdin: Optional stdin content to pipe to the binary.
            timeout: Per-run timeout in seconds.
            sanitizer_variant: Named variant to run in. Default is the primary
                ASan+UBSan container. Use "msan" to run the binary in the
                MSan variant image instead (binaries compiled for ASan CANNOT
                be run in the MSan container and vice versa — compile with
                the matching sanitizer_variant first).

        Returns:
            Dict with keys: exit_code, stdout, stderr, crashed, crash_evidence, variant.
            crash_evidence is the parsed ASan/UBSan/MSan report, if any.
        """
        variant_list = _parse_variant_arg(sanitizer_variant)
        target_sandbox = ctx.get_sandbox_for_variant(variant_list)
        if target_sandbox is None:
            return {"crashed": False, "error": "no sandbox attached"}

        argv_list = [binary] + (argv or [])
        if stdin:
            # Pipe stdin via shell
            quoted = stdin.replace("'", "'\\''")
            cmd = ["sh", "-c", f"echo '{quoted}' | {' '.join(argv_list)}"]
        else:
            cmd = argv_list

        result = target_sandbox.exec(cmd, timeout=timeout)
        crashed = result.exit_code not in (0, 124)
        crash_evidence = ""
        if crashed:
            crash_evidence = _parse_sanitizer_report(result.stderr or result.stdout)
        return {
            "exit_code": result.exit_code,
            "stdout": result.stdout[:4000],
            "stderr": result.stderr[:4000],
            "crashed": crashed,
            "timed_out": result.timed_out,
            "crash_evidence": crash_evidence,
            "variant": ",".join(variant_list) if variant_list else "default",
        }

    @tool
    def write_test_case(filename: str, content: str) -> str:
        """Write a test input / PoC into /scratch inside the sandbox.

        Args:
            filename: Filename only — written into /scratch (no path traversal).
            content: File content as a string.
        """
        # Filename must be a basename (no slashes) — validate before sandbox check
        if "/" in filename or filename.startswith("."):
            return "Error: filename must be a basename, no path components"
        if ctx.sandbox is None:
            return "Error: no sandbox attached"
        scratch_path = f"/scratch/{filename}"
        try:
            ctx.sandbox.write_file(scratch_path, content.encode("utf-8"))
        except Exception as e:
            return f"Error writing test case: {e}"
        return f"Wrote {len(content)} bytes to {scratch_path}"

    @tool
    def fuzz_harness(
        target_function: str,
        signature: str = "",
        harness_source: str = "",
        duration_seconds: int = 30,
        sanitizer_variant: str = "",
    ) -> dict:
        """Generate and run a libFuzzer harness for a C/C++ function.

        Two modes:
            1. Hunter-supplied: pass `harness_source` with a complete C file
               defining `int LLVMFuzzerTestOneInput(const uint8_t*, size_t)`.
            2. Template: pass `target_function` (and optionally `signature`)
               and the tool generates a default harness that forwards the
               fuzzer buffer into the function.

        The harness is written into /scratch, compiled in the sandbox with
        ASan + libFuzzer, and run for `duration_seconds`. Crashes are parsed
        from libFuzzer output and returned as crash_evidence.

        Args:
            target_function: Name of the function to fuzz (used to build the
                default template when harness_source is empty).
            signature: Optional signature hint (e.g. "int fn(const char*, size_t)").
                Currently used only to decide whether the function takes the
                raw byte buffer directly.
            harness_source: Pre-written libFuzzer C source. Overrides the
                template when non-empty.
            duration_seconds: Max fuzz duration (default 30s).
            sanitizer_variant: Which sanitizer sandbox to use (default primary).

        Returns:
            Dict with keys: status, crashes_found, crash_evidence,
                harness_path, binary_path, stdout, stderr.
        """
        variant_list = _parse_variant_arg(sanitizer_variant)
        target_sandbox = ctx.get_sandbox_for_variant(variant_list)
        if target_sandbox is None:
            return {
                "status": "no_sandbox",
                "message": "fuzz_harness requires an attached sandbox container",
                "target_function": target_function,
            }

        # Pick harness source — hunter-supplied wins over the template
        if harness_source.strip():
            source_to_use = harness_source
            source_kind = "hunter_supplied"
        else:
            if not target_function.strip():
                return {
                    "status": "error",
                    "message": "either harness_source or target_function must be provided",
                }
            source_to_use = _default_libfuzzer_template(target_function, signature)
            source_kind = "template"

        # Write the harness into /scratch
        harness_filename = f"fuzz_{uuid.uuid4().hex[:8]}.c"
        harness_path = f"/scratch/{harness_filename}"
        try:
            target_sandbox.write_file(harness_path, source_to_use.encode("utf-8"))
        except Exception as e:
            return {
                "status": "write_failed",
                "message": f"could not write harness: {e}",
            }

        # Compile with ASan + libFuzzer. The workspace is read-only; we
        # point `-I /workspace` so the harness can #include project headers.
        binary_path = f"/scratch/fuzz_{uuid.uuid4().hex[:6]}.bin"
        compile_cmd = [
            "sh",
            "-c",
            (
                "gcc -fsanitize=address,undefined,fuzzer "
                "-g -O1 -fno-omit-frame-pointer "
                "-I /workspace -I /workspace/include "
                f"-o {binary_path} {harness_path} 2>&1"
            ),
        ]
        compile_result = target_sandbox.exec(compile_cmd, timeout=120)
        if compile_result.exit_code != 0:
            return {
                "status": "compile_failed",
                "harness_path": harness_path,
                "harness_source_kind": source_kind,
                "stdout": compile_result.stdout[:4000],
                "stderr": compile_result.stderr[:4000],
            }

        # Run libFuzzer for the configured duration. -max_total_time caps
        # wall-clock; -error_exitcode=77 + -timeout=25 give libFuzzer a
        # chance to gracefully report before we kill it.
        run_cmd = [
            "sh",
            "-c",
            (
                f"{binary_path} "
                f"-max_total_time={duration_seconds} "
                f"-timeout={max(10, duration_seconds // 2)} "
                f"-error_exitcode=77 "
                f"-print_final_stats=1 2>&1"
            ),
        ]
        run_result = target_sandbox.exec(
            run_cmd,
            timeout=duration_seconds + 30,
        )
        output = run_result.stdout + run_result.stderr
        crash_evidence = _parse_sanitizer_report(output) if run_result.exit_code != 0 else ""
        crashes_found = 1 if run_result.exit_code not in (0, 124) else 0

        return {
            "status": "completed",
            "crashes_found": crashes_found,
            "crash_evidence": crash_evidence,
            "harness_path": harness_path,
            "harness_source_kind": source_kind,
            "binary_path": binary_path,
            "exit_code": run_result.exit_code,
            "duration_seconds": run_result.duration_seconds,
            "stdout": run_result.stdout[:4000],
            "stderr": run_result.stderr[:4000],
            "variant": ",".join(variant_list) if variant_list else "default",
        }

    return [compile_file, run_with_sanitizer, write_test_case, fuzz_harness]
