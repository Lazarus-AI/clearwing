"""Record a source/runtime proof for the D3D12VA H.264/HEVC upload overflow."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "cw.ffmpeg.d3d12va-upload-capacity-proof.v1"
START_CODE = bytes.fromhex("000001")
LONG_START_CODE = bytes.fromhex("00000001")


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--ffmpeg", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True)


def _nal_units(data: bytes, codec: str) -> list[dict[str, int]]:
    starts: list[tuple[int, int]] = []
    cursor = 0
    while cursor + 3 < len(data):
        if data[cursor : cursor + 4] == LONG_START_CODE:
            starts.append((cursor, 4))
            cursor += 4
        elif data[cursor : cursor + 3] == START_CODE:
            starts.append((cursor, 3))
            cursor += 3
        else:
            cursor += 1
    units: list[dict[str, int]] = []
    for index, (start, start_size) in enumerate(starts):
        payload = start + start_size
        end = starts[index + 1][0] if index + 1 < len(starts) else len(data)
        if payload >= end:
            continue
        nal_type = (data[payload] >> 1) & 63 if codec == "hevc" else data[payload] & 31
        units.append(
            {
                "type": nal_type,
                "raw_size": end - payload,
                "annex_b_size": end - start,
            }
        )
    return units


def _is_slice(codec: str, nal_type: int) -> bool:
    return nal_type <= 31 if codec == "hevc" else nal_type in {1, 5}


def _codec_case(ffmpeg: Path, directory: Path, codec: str) -> dict[str, object]:
    if codec == "h264":
        width, height = 16, 5400
        encoder = "libx264"
        suffix = "h264"
        options = [
            "-preset",
            "ultrafast",
            "-tune",
            "zerolatency",
            "-qp",
            "0",
            "-x264-params",
            "slices=1",
        ]
    else:
        width = height = 16
        encoder = "libx265"
        suffix = "hevc"
        options = [
            "-preset",
            "ultrafast",
            "-x265-params",
            "log-level=error:lossless=1:slices=1",
        ]

    stream = directory / f"valid-{width}x{height}.{suffix}"
    encode_command = [
        str(ffmpeg),
        "-hide_banner",
        "-loglevel",
        "error",
        "-f",
        "lavfi",
        "-i",
        f"nullsrc=s={width}x{height}:r=1,format=yuv420p,"
        f"noise=alls=100:allf=t+u:all_seed={12345 + width + height}",
        "-frames:v",
        "1",
        "-c:v",
        encoder,
        *options,
        "-f",
        suffix,
        str(stream),
    ]
    encode = _run(encode_command)
    decode_command = [
        str(ffmpeg),
        "-hide_banner",
        "-loglevel",
        "error",
        "-i",
        str(stream),
        "-frames:v",
        "1",
        "-f",
        "null",
        "-",
    ]
    decode = _run(decode_command) if encode.returncode == 0 else None
    units = _nal_units(stream.read_bytes(), codec) if stream.is_file() else []
    slices = [unit for unit in units if _is_slice(codec, unit["type"])]
    raw_image_capacity = width * height * 3 // 2
    physical_allocation_floor = (raw_image_capacity + 65535) // 65536 * 65536
    slice_bytes = sum(unit["raw_size"] for unit in slices)
    d3d12_upload_bytes = slice_bytes + 3 * len(slices)
    return {
        "codec": codec,
        "width": width,
        "height": height,
        "pixel_format": "yuv420p",
        "raw_image_capacity": raw_image_capacity,
        "d3d12_64k_aligned_allocation_floor": physical_allocation_floor,
        "slice_count": len(slices),
        "slice_bytes": slice_bytes,
        "d3d12_start_code_bytes": 3 * len(slices),
        "d3d12_upload_bytes": d3d12_upload_bytes,
        "overflow_bytes": d3d12_upload_bytes - raw_image_capacity,
        "bytes_beyond_64k_aligned_allocation_floor": (
            d3d12_upload_bytes - physical_allocation_floor
        ),
        "nal_units": units,
        "stream_sha256": _sha256(stream) if stream.is_file() else None,
        "encode_command": encode_command,
        "encode_returncode": encode.returncode,
        "encode_stdout": encode.stdout,
        "encode_stderr": encode.stderr,
        "decode_command": decode_command,
        "decode_returncode": decode.returncode if decode else None,
        "decode_stdout": decode.stdout if decode else "",
        "decode_stderr": decode.stderr if decode else "encode failed",
        "valid_stream_decoded": bool(decode and decode.returncode == 0),
        "capacity_exceeded": d3d12_upload_bytes > raw_image_capacity,
        "aligned_allocation_floor_exceeded": (
            d3d12_upload_bytes > physical_allocation_floor
        ),
    }


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    ffmpeg = args.ffmpeg.expanduser().resolve()
    output = args.output.expanduser().resolve()
    sources = [
        checkout / "libavcodec/d3d12va_decode.c",
        checkout / "libavcodec/d3d12va_h264.c",
        checkout / "libavcodec/d3d12va_hevc.c",
    ]
    if not ffmpeg.is_file() or any(not source.is_file() for source in sources):
        raise ValueError("FFmpeg executable and D3D12VA sources must exist")

    version = _run([str(ffmpeg), "-version"])
    with tempfile.TemporaryDirectory(prefix="cw-d3d12va-proof-") as temporary:
        directory = Path(temporary)
        cases = [_codec_case(ffmpeg, directory, codec) for codec in ("h264", "hevc")]

    expected_observed = (
        all(case["valid_stream_decoded"] and case["capacity_exceeded"] for case in cases)
        and cases[0]["aligned_allocation_floor_exceeded"]
    )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "checkout": str(checkout),
        "checkout_commit": _run(
            ["git", "-C", str(checkout), "rev-parse", "HEAD"]
        ).stdout.strip(),
        "ffmpeg": str(ffmpeg),
        "ffmpeg_version": version.stdout,
        "source_sha256": {
            str(source.relative_to(checkout)): _sha256(source) for source in sources
        },
        "cases": cases,
        "expected_observed": expected_observed,
        "scope": (
            "The D3D12VA helper allocates an upload resource using the raw-image "
            "buffer size. H.264 and HEVC then copy every accepted VCL NAL into "
            "that resource and prepend three bytes per slice without a capacity "
            "check. The generated standards-valid streams demonstrate that the "
            "bytes passed to those callbacks can exceed the allocation."
        ),
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
