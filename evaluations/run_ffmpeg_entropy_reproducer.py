"""Run and record the high-bit-depth entropy histogram reproducer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.entropy-reproducer.v1"


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

    output.parent.mkdir(parents=True, exist_ok=True)
    width = height = 4
    sample = 1 << 10
    raw_bytes = sample.to_bytes(2, "little") * width * height
    with tempfile.TemporaryDirectory(prefix="ffmpeg-entropy-") as temporary:
        raw = Path(temporary) / "invalid-gray10le.raw"
        raw.write_bytes(raw_bytes)
        command = [
            str(ffmpeg),
            "-hide_banner",
            "-loglevel",
            "error",
            "-f",
            "rawvideo",
            "-pixel_format",
            "gray10le",
            "-video_size",
            f"{width}x{height}",
            "-i",
            str(raw),
            "-vf",
            "entropy",
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
        "eight_byte_histogram_access": (
            "READ of size 8" in combined or "WRITE of size 8" in combined
        ),
        "filter_frame_in_trace": "filter_frame" in combined,
    }
    expected_observed = all(indicators.values())
    commit_result = subprocess.run(
        ["git", "-C", str(ffmpeg.parent), "rev-parse", "HEAD"],
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
        "pixel_format": "gray10le",
        "width": width,
        "height": height,
        "declared_depth": 10,
        "histogram_entries": 1 << 10,
        "sample_value": sample,
        "raw_input_hex": raw_bytes.hex(),
        "command": command,
        "asan_options": "halt_on_error=1:abort_on_error=1:detect_leaks=0",
        "returncode": result.returncode,
        "indicators": indicators,
        "expected_observed": expected_observed,
        "stdout": result.stdout,
        "stderr": result.stderr,
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
