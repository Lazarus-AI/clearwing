"""Record the vf_mestimate INT_MAX mb_size signed-shift undefined behavior."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.mestimate-mb-size-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    output = args.output.expanduser().resolve()
    ffmpeg = checkout / "ffmpeg"
    source = checkout / "libavfilter/vf_mestimate.c"
    if not ffmpeg.is_file() or not source.is_file():
        raise ValueError("configured FFmpeg executable and vf_mestimate.c must exist")

    command = [
        str(ffmpeg),
        "-hide_banner",
        "-loglevel",
        "error",
        "-f",
        "lavfi",
        "-i",
        "testsrc2=s=64x64:r=1",
        "-vf",
        "mestimate=mb_size=2147483647",
        "-frames:v",
        "3",
        "-f",
        "null",
        "-",
    ]
    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0"
    environment["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    result = subprocess.run(
        command, check=False, capture_output=True, text=True, env=environment
    )
    combined = result.stdout + result.stderr
    indicators = {
        "public_int_max_option": "mestimate=mb_size=2147483647" in " ".join(command),
        "signed_shift_ub": (
            "left shift of 1 by 31 places cannot be represented" in combined
        ),
        "production_source_line": "libavfilter/vf_mestimate.c:86" in combined,
        "ubsan_aborted": result.returncode != 0,
    }
    expected_observed = all(indicators.values())
    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "checkout": str(checkout),
        "checkout_commit": subprocess.run(
            ["git", "-C", str(checkout), "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
        ).stdout.strip(),
        "source": str(source),
        "source_sha256": _sha256(source),
        "command": command,
        "asan_options": environment["ASAN_OPTIONS"],
        "ubsan_options": environment["UBSAN_OPTIONS"],
        "returncode": result.returncode,
        "indicators": indicators,
        "expected_observed": expected_observed,
        "scope": (
            "The public mb_size option accepts INT_MAX. av_ceil_log2_c returns "
            "31, after which config_input evaluates signed 1 << 31 before its "
            "zero-block validation can reject the configuration."
        ),
        "stdout": result.stdout,
        "stderr": result.stderr,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    temporary.replace(output)
    print(output)
    if not expected_observed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
