"""Build, run, and record the RTP/QDM2 small-block ASan reproducer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "cw.ffmpeg.qdm2-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument(
        "--harness",
        type=Path,
        default=Path(__file__).with_name("ffmpeg_qdm2_reproducer.c"),
    )
    parser.add_argument("--binary-output", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--expect",
        choices=("vulnerable", "fixed"),
        default="vulnerable",
    )
    parser.add_argument(
        "--rtpdec-source",
        type=Path,
        help="Optional offline replacement rtpdec_qdm2.c to link before libavformat",
    )
    return parser.parse_args()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _run(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )


def _commit(checkout: Path) -> str | None:
    result = _run(["git", "rev-parse", "HEAD"], cwd=checkout)
    return result.stdout.strip() or None


def _compile_flags() -> list[str]:
    return [
        "clang",
        "-I.",
        "-I./",
        "-D_ISOC11_SOURCE",
        "-D_FILE_OFFSET_BITS=64",
        "-D_LARGEFILE_SOURCE",
        "-I./compat/dispatch_semaphore",
        "-DPIC",
        "-I./compat/stdbit",
        "-DZLIB_CONST",
        "-DHAVE_AV_CONFIG_H",
        "-DBUILDING_avformat",
        "-fsanitize=address,undefined",
        "-fno-omit-frame-pointer",
        "-g",
        "-O1",
        "-std=c17",
        "-fPIC",
        "-pthread",
    ]


def _link_flags() -> list[str]:
    flags = [
        "-Llibavcodec",
        "-Llibavdevice",
        "-Llibavfilter",
        "-Llibavformat",
        "-Llibavutil",
        "-Llibswscale",
        "-Llibswresample",
        "-lavformat",
        "-lavcodec",
        "-lswresample",
        "-lswscale",
        "-lavutil",
        "-lm",
        "-lbz2",
        "-lz",
    ]
    if platform.system() == "Darwin":
        flags[7:7] = [
            "-Wl,-dynamic,-search_paths_first",
            "-Wl,-no_warn_duplicate_libraries",
        ]
        flags.extend(
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
    flags.append("-pthread")
    return flags


def _write_json(path: Path, payload: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    harness = args.harness.expanduser().resolve()
    binary = args.binary_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    replacement = args.rtpdec_source.expanduser().resolve() if args.rtpdec_source else None
    required = [
        checkout / "config.h",
        checkout / "libavformat/libavformat.a",
        checkout / "libavcodec/libavcodec.a",
        checkout / "libswresample/libswresample.a",
        checkout / "libswscale/libswscale.a",
        checkout / "libavutil/libavutil.a",
        harness,
    ]
    if any(not path.is_file() for path in required):
        raise ValueError("checkout must contain the configured FFmpeg static libraries")
    if replacement is not None and not replacement.is_file():
        raise ValueError("rtpdec replacement source does not exist")

    binary.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    compile_steps: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="ffmpeg-qdm2-build-") as temporary:
        replacement_object: Path | None = None
        if replacement is not None:
            replacement_object = Path(temporary) / "rtpdec_qdm2.o"
            object_command = _compile_flags() + [
                "-Ilibavformat",
                "-c",
                str(replacement),
                "-o",
                str(replacement_object),
            ]
            object_result = _run(object_command, cwd=checkout)
            compile_steps.append(
                {
                    "command": object_command,
                    "returncode": object_result.returncode,
                    "stdout": object_result.stdout,
                    "stderr": object_result.stderr,
                }
            )
            if object_result.returncode != 0:
                _write_json(
                    output,
                    {
                        "schema_version": SCHEMA_VERSION,
                        "completed_at": datetime.now(UTC).isoformat(),
                        "compile_steps": compile_steps,
                    },
                )
                raise SystemExit(1)

        link_command = _compile_flags() + ["-o", str(binary), str(harness)]
        if replacement_object is not None:
            link_command.append(str(replacement_object))
        link_command.extend(_link_flags())
        link_result = _run(link_command, cwd=checkout)
        compile_steps.append(
            {
                "command": link_command,
                "returncode": link_result.returncode,
                "stdout": link_result.stdout,
                "stderr": link_result.stderr,
            }
        )

    if compile_steps[-1]["returncode"] == 0:
        environment = os.environ.copy()
        environment["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0"
        run_result = _run([str(binary)], cwd=checkout, env=environment)
    else:
        run_result = subprocess.CompletedProcess([str(binary)], 127, "", "compile failed")
    combined = run_result.stdout + run_result.stderr
    indicators = {
        "asan_negative_size_param": "AddressSanitizer: negative-size-param" in combined,
        "negative_size_is_minus_one": "size=-1" in combined,
        "qdm2_parse_packet_in_trace": "qdm2_parse_packet" in combined,
        "sanitizer_error": "ERROR: AddressSanitizer" in combined,
        "clean_invalid_data_rejection": run_result.returncode == 1
        and "AddressSanitizer" not in combined,
    }
    expected_observed = (
        all(
            indicators[key]
            for key in (
                "asan_negative_size_param",
                "negative_size_is_minus_one",
                "qdm2_parse_packet_in_trace",
            )
        )
        if args.expect == "vulnerable"
        else indicators["clean_invalid_data_rejection"]
    )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(UTC).isoformat(),
        "checkout": str(checkout),
        "checkout_commit": _commit(checkout),
        "harness": str(harness),
        "harness_sha256": _sha256(harness),
        "binary": str(binary),
        "binary_sha256": _sha256(binary) if binary.is_file() else None,
        "expect": args.expect,
        "replacement_source": str(replacement) if replacement else None,
        "replacement_source_sha256": _sha256(replacement) if replacement else None,
        "compile_steps": compile_steps,
        "run_command": [str(binary)],
        "asan_options": "halt_on_error=1:abort_on_error=1:detect_leaks=0",
        "returncode": run_result.returncode,
        "indicators": indicators,
        "expected_observed": expected_observed,
        "stdout": run_result.stdout,
        "stderr": run_result.stderr,
    }
    _write_json(output, payload)
    print(output)
    if not expected_observed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
