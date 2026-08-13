"""Run and record the ahistogram positive-full-scale ASan reproducer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.ahistogram-reproducer.v1"


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


def _commit(binary: Path) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(binary.parent), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() or None


def main() -> None:
    args = _arguments()
    ffmpeg = args.ffmpeg.expanduser().resolve()
    output = args.output.expanduser().resolve()
    if not ffmpeg.is_file():
        raise ValueError("ffmpeg binary does not exist")

    output.parent.mkdir(parents=True, exist_ok=True)
    command = [
        str(ffmpeg),
        "-hide_banner",
        "-loglevel",
        "verbose",
        "-f",
        "lavfi",
        "-i",
        "aevalsrc=1:s=48000:d=0.1",
        "-filter_complex",
        "[0:a]ahistogram=ascale=log:hmode=sign:size=1280x720[outv]",
        "-map",
        "[outv]",
        "-frames:v",
        "1",
        "-f",
        "null",
        "-",
    ]
    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0"
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    combined = result.stdout + result.stderr
    indicators = {
        "asan_heap_buffer_overflow": "AddressSanitizer: heap-buffer-overflow" in combined,
        "eight_byte_access": "of size 8" in combined,
        "exact_allocation_end": "0 bytes after 10240-byte region" in combined,
        "filter_frame_in_trace": "filter_frame" in combined,
        "av_calloc_allocation_in_trace": "av_calloc" in combined,
        "config_input_allocation_in_trace": "config_input" in combined,
    }
    expected_observed = all(indicators.values())
    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(UTC).isoformat(),
        "checkout_commit": _commit(ffmpeg),
        "ffmpeg": str(ffmpeg),
        "ffmpeg_sha256": _sha256(ffmpeg),
        "input_sample": 1.0,
        "histogram_width": 1280,
        "histogram_mode": "sign",
        "amplitude_scale": "log",
        "command": command,
        "asan_options": environment["ASAN_OPTIONS"],
        "returncode": result.returncode,
        "indicators": indicators,
        "expected_observed": expected_observed,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output)
    print(output)
    if not expected_observed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
