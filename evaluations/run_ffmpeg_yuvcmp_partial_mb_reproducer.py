"""Build and record the yuvcmp partial-macroblock overflow reproducer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.yuvcmp-partial-mb-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_yuvcmp_partial_mb_reproducer.c"),
    )
    parser.add_argument("--binary-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    source = checkout / "tools/yuvcmp.c"
    config = checkout / "config.h"
    if not harness.is_file() or not source.is_file() or not config.is_file():
        raise ValueError("harness and configured FFmpeg checkout must exist")

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    compile_command = [
        "clang",
        "-I.",
        "-include",
        "config.h",
        "-fsanitize=address,undefined",
        "-fno-omit-frame-pointer",
        "-g",
        "-O1",
        "-std=c17",
        "-o",
        str(binary),
        str(harness),
    ]
    compile_result = subprocess.run(
        compile_command,
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )

    width = 17
    height = 16
    luma_size = width * height
    chroma_size = width * height // 4
    frame_size = luma_size + 2 * chroma_size
    differing_offset = 16
    first_bytes = bytearray(frame_size)
    second_bytes = bytearray(frame_size)
    second_bytes[differing_offset] = 1
    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0"

    with tempfile.TemporaryDirectory(prefix="ffmpeg-yuvcmp-") as temporary:
        first = Path(temporary) / "first.yuv"
        second = Path(temporary) / "second.yuv"
        first.write_bytes(first_bytes)
        second.write_bytes(second_bytes)
        run_command = [str(binary), str(first), str(second)]
        if compile_result.returncode == 0:
            run_result = subprocess.run(
                run_command,
                cwd=checkout,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
        else:
            run_result = subprocess.CompletedProcess(
                run_command, 127, "", "compile failed"
            )

    combined = run_result.stdout + run_result.stderr
    indicators = {
        "asan_heap_buffer_overflow": (
            "AddressSanitizer: heap-buffer-overflow" in combined
        ),
        "one_byte_out_of_bounds_access": (
            "READ of size 1" in combined or "WRITE of size 1" in combined
        ),
        "production_function_in_trace": "ffmpeg_yuvcmp_main" in combined,
        "partial_macroblock_pixel_reported": "pixel (  16,0" in combined,
    }
    expected_observed = compile_result.returncode == 0 and all(indicators.values())
    commit_result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
    )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(UTC).isoformat(),
        "checkout": str(checkout),
        "checkout_commit": commit_result.stdout.strip() or None,
        "source": str(source),
        "source_sha256": _sha256(source),
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "binary": str(binary),
        "binary_sha256": _sha256(binary) if binary.is_file() else None,
        "width": width,
        "height": height,
        "luma_size": luma_size,
        "chroma_size": chroma_size,
        "frame_size": frame_size,
        "floor_macroblock_columns": width // 16,
        "floor_macroblock_rows": height // 16,
        "mberrors_allocation_bytes": (width // 16) * (height // 16),
        "differing_luma_offset": differing_offset,
        "differing_pixel": [16, 0],
        "computed_macroblock_index": 1,
        "compile_command": compile_command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "run_command": run_command,
        "asan_options": environment["ASAN_OPTIONS"],
        "returncode": run_result.returncode,
        "indicators": indicators,
        "expected_observed": expected_observed,
        "scope": (
            "For dimensions not divisible by 16, yuvcmp floor-divides the "
            "mberrors allocation dimensions but compares every luma pixel. "
            "Pixel (16,0) of a 17x16 frame therefore selects index one in a "
            "one-byte allocation. The later blockdump loop cannot reach a "
            "partial macroblock because it iterates only the floor-sized array."
        ),
        "stdout": run_result.stdout,
        "stderr": run_result.stderr,
    }
    temporary_output = output.with_suffix(output.suffix + ".tmp")
    temporary_output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary_output.replace(output)
    print(output)
    if not expected_observed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
