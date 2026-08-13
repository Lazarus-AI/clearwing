"""Run and record the arnndn oversized-output ASan reproducer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from build_ffmpeg_arnndn_model import build_model

SCHEMA_VERSION = "cw.ffmpeg.arnndn-reproducer.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ffmpeg", type=Path, required=True)
    parser.add_argument("--model-output", type=Path, required=True)
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
    model = args.model_output.expanduser().resolve()
    output = args.output.expanduser().resolve()
    if not ffmpeg.is_file():
        raise ValueError("ffmpeg binary does not exist")

    model.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    build_model(model, 23)
    command = [
        str(ffmpeg),
        "-hide_banner",
        "-loglevel",
        "verbose",
        "-f",
        "lavfi",
        "-i",
        "anoisesrc=r=48000:d=0.1",
        "-af",
        f"arnndn=m={model}",
        "-f",
        "null",
        "-",
    ]
    environment = os.environ.copy()
    environment["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1"
    result = subprocess.run(command, check=False, capture_output=True, text=True, env=environment)
    combined = result.stdout + result.stderr
    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(UTC).isoformat(),
        "checkout_commit": _commit(ffmpeg),
        "ffmpeg": str(ffmpeg),
        "ffmpeg_sha256": _sha256(ffmpeg),
        "model": str(model),
        "model_sha256": _sha256(model),
        "denoise_outputs": 23,
        "expected_band_outputs": 22,
        "command": command,
        "returncode": result.returncode,
        "asan_stack_buffer_overflow": "AddressSanitizer: stack-buffer-overflow" in combined,
        "compute_dense_in_trace": "compute_dense" in combined,
        "g_identified_as_overflowed_object": "'g.i'" in combined,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output)
    print(output)

    if not all(
        (
            payload["asan_stack_buffer_overflow"],
            payload["compute_dense_in_trace"],
            payload["g_identified_as_overflowed_object"],
        )
    ):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
