"""Run and record the pan named-channel out-of-bounds reproducer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.pan-named-channel-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ffmpeg", type=Path, required=True)
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
    ffmpeg = args.ffmpeg.expanduser().resolve()
    output = args.output.expanduser().resolve()
    if not ffmpeg.is_file():
        raise ValueError("ffmpeg binary must exist")

    command = [
        str(ffmpeg),
        "-hide_banner",
        "-loglevel",
        "error",
        "-f",
        "lavfi",
        "-i",
        "anullsrc=r=48000:cl=stereo",
        "-af",
        "pan=stereo|FL=AMBI0",
        "-frames:a",
        "1",
        "-f",
        "null",
        "-",
    ]
    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = (
        "halt_on_error=1:abort_on_error=1:detect_leaks=0"
    )
    environment["UBSAN_OPTIONS"] = "halt_on_error=0:print_stacktrace=0"
    result = subprocess.run(
        command,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    combined = result.stdout + result.stderr
    indicators = {
        "named_channel_index_1024": (
            "index 1024 out of bounds for type 'int[64]'" in combined
        ),
        "ubsan_out_of_bounds": (
            "UndefinedBehaviorSanitizer: undefined-behavior" in combined
        ),
        "pan_source_boundary": "libavfilter/af_pan.c" in combined,
        "first_operation_is_read": "READ of size 4" in combined,
        "asan_stack_violation": "AddressSanitizer: stack-" in combined,
        "filter_aborted": result.returncode != 0,
    }
    expected_observed = all(indicators.values())
    checkout = ffmpeg.parent
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
        "ffmpeg": str(ffmpeg),
        "ffmpeg_sha256": _sha256(ffmpeg),
        "checkout_commit": commit_result.stdout.strip() or None,
        "command": command,
        "asan_options": environment["ASAN_OPTIONS"],
        "ubsan_options": environment["UBSAN_OPTIONS"],
        "returncode": result.returncode,
        "indicators": indicators,
        "expected_observed": expected_observed,
        "scope": (
            "AMBI0 is a public named AVChannel whose numeric value is 1024. "
            "The pan parser accepts that value as an input-channel index even "
            "though its used_in_ch and gain dimensions contain 64 entries. "
            "The first observed invalid operation is the used_in_ch read; if "
            "execution continues, the subsequent assignments also index the "
            "same out-of-range slot."
        ),
        "stdout": result.stdout,
        "stderr": result.stderr,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(output)
    print(output)
    if not expected_observed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
