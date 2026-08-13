"""Build and record the DNN output-shape postprocessing diagnostic."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.dnn-output-shape-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_dnn_output_shape_reproducer.c"),
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


def _compile_commands(
    checkout: Path, harness: Path, binary: Path
) -> list[list[str]]:
    source_object = binary.with_name(binary.name + ".dnn_io_proc.o")
    common = [
        "clang",
        "-I.",
        "-D_ISOC11_SOURCE",
        "-D_FILE_OFFSET_BITS=64",
        "-D_LARGEFILE_SOURCE",
        "-I./compat/dispatch_semaphore",
        "-DPIC",
        "-I./compat/stdbit",
        "-DHAVE_AV_CONFIG_H",
        "-O1",
        "-std=c17",
        "-fPIC",
    ]
    source_command = [
        *common,
        "-c",
        str(checkout / "libavfilter/dnn/dnn_io_proc.c"),
        "-o",
        str(source_object),
    ]
    link_command = [
        *common,
        "-fsanitize=address,undefined",
        "-fno-omit-frame-pointer",
        "-g",
        "-o",
        str(binary),
        str(harness),
        str(source_object),
        "-Llibavfilter",
        "-Llibswscale",
        "-Llibavutil",
        "-lavfilter",
        "-lswscale",
        "-lavutil",
        "-lm",
        "-lbz2",
        "-lz",
    ]
    if platform.system() == "Darwin":
        link_command.extend(
            [
                "-framework",
                "Foundation",
                "-framework",
                "AudioToolbox",
                "-framework",
                "CoreAudio",
                "-framework",
                "AVFoundation",
                "-framework",
                "CoreGraphics",
                "-framework",
                "OpenGL",
                "-framework",
                "Metal",
                "-framework",
                "VideoToolbox",
                "-framework",
                "CoreImage",
                "-framework",
                "AppKit",
                "-framework",
                "CoreFoundation",
                "-framework",
                "CoreMedia",
                "-framework",
                "CoreVideo",
                "-framework",
                "CoreServices",
                "-framework",
                "Security",
                "-liconv",
            ]
        )
    link_command.append("-pthread")
    return [source_command, link_command]


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    source = checkout / "libavfilter/dnn/dnn_io_proc.c"
    if not harness.is_file() or not source.is_file():
        raise ValueError("harness and DNN postprocessor source must exist")

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    compile_commands = _compile_commands(checkout, harness, binary)
    compile_results = [
        subprocess.run(
            command, cwd=checkout, check=False, capture_output=True, text=True
        )
        for command in compile_commands
    ]
    compile_returncode = next(
        (result.returncode for result in compile_results if result.returncode), 0
    )
    environment: dict[str, str] | None = None
    if compile_returncode == 0:
        environment = os.environ.copy()
        environment["ASAN_OPTIONS"] = (
            "halt_on_error=1:abort_on_error=1:detect_leaks=0"
        )
        run_result = subprocess.run(
            [str(binary)],
            cwd=checkout,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
    else:
        run_result = subprocess.CompletedProcess(
            [str(binary)], 127, "", "compile failed"
        )

    combined = run_result.stdout + run_result.stderr
    indicators = {
        "one_channel_nchw_tensor": "tensor_channels=1" in combined,
        "rgb24_output_contract": "output_format=rgb24" in combined,
        "asan_heap_buffer_overflow": (
            "AddressSanitizer: heap-buffer-overflow" in combined
        ),
        "postprocessing_aborted": run_result.returncode != 0,
    }
    expected_observed = compile_returncode == 0 and all(indicators.values())
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
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "source": str(source),
        "source_sha256": _sha256(source),
        "binary": str(binary),
        "binary_sha256": _sha256(binary) if binary.is_file() else None,
        "compile_commands": compile_commands,
        "compile_returncode": compile_returncode,
        "compile_stdout": "".join(result.stdout for result in compile_results),
        "compile_stderr": "".join(result.stderr for result in compile_results),
        "run_command": [str(binary)],
        "asan_options": environment["ASAN_OPTIONS"] if environment else None,
        "returncode": run_result.returncode,
        "indicators": indicators,
        "expected_observed": expected_observed,
        "scope": (
            "Production postprocessor contract. dnn_io_proc.c is deliberately "
            "compiled without ASan to pass its independent one-pointer source "
            "plane-array read; the linked production libraries and harness "
            "remain instrumented. The sealed build does not include an "
            "optional DNN backend for end-to-end model loading."
        ),
        "stdout": run_result.stdout,
        "stderr": run_result.stderr,
    }
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    temporary.replace(output)
    print(output)
    if not expected_observed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
