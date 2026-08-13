"""Run and record the framepack alpha-plane invalid-write reproducer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.framepack-alpha-reproducer.v1"


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
        "color=red:size=16x16,format=yuva420p",
        "-f",
        "lavfi",
        "-i",
        "color=blue:size=16x16,format=yuva420p",
        "-filter_complex",
        "[0:v][1:v]framepack=sbs",
        "-frames:v",
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
        "asan_deadly_signal": "AddressSanitizer:DEADLYSIGNAL" in combined,
        "invalid_write": "caused by a WRITE memory access" in combined,
        "image_copy_plane_sink": "image_copy_plane" in combined,
        "framepack_source_boundary": "horizontal_frame_pack" in combined,
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
            "The public framepack filter advertises alpha-bearing planar "
            "formats. Its side-by-side helper initializes destination planes "
            "zero through two but leaves dst[3] unset before av_image_copy2 "
            "copies every plane in yuva420p. The alpha-plane copy therefore "
            "writes through an indeterminate pointer. The vertical helper "
            "independently leaves both dst[3] and linesizes[3] unset."
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
