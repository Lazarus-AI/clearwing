"""Run and record the NellyMoser trellis off-by-one reproducer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.nellymoser-trellis-reproducer.v1"


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
        "anoisesrc=color=white:sample_rate=44100:duration=0.05,volume=10",
        "-c:a",
        "nellymoser",
        "-trellis",
        "1",
        "-f",
        "null",
        "-",
    ]
    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = (
        "halt_on_error=0:abort_on_error=0:detect_leaks=0"
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
        "trellis_float_index_at_opt_size": (
            "nellymoserenc.c:272:29: runtime error: index 35768 out of bounds"
            in combined
        ),
        "trellis_path_index_at_opt_size": (
            "nellymoserenc.c:274:29: runtime error: index 35768 out of bounds"
            in combined
        ),
        "asan_heap_buffer_overflow": (
            "AddressSanitizer: heap-buffer-overflow" in combined
        ),
        "read_after_trellis_allocation": (
            "READ of size 4" in combined
            and "0 bytes after 3290656-byte region" in combined
        ),
    }
    expected_observed = all(indicators.values())
    commit_result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ffmpeg.parent,
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
