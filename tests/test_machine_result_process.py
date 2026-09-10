"""Exercise report delivery across an actual worker process and inherited FD."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from clearwing.ui.machine import MAX_RECORD_BYTES


def _worker_result(count: int, description_bytes: int = 0) -> tuple[int, list[dict]]:
    root = Path(__file__).resolve().parents[1]
    parent, child = socket.socketpair()
    parent.settimeout(20)
    environment = dict(os.environ, PYTHONPATH=str(root))
    process = subprocess.Popen(
        [
            sys.executable,
            str(root / "tests/fixtures/machine_result_worker.py"),
            "--machine-fd",
            str(child.fileno()),
        ],
        cwd=root,
        env=environment,
        pass_fds=(child.fileno(),),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    child.close()
    try:
        parent.sendall(
            json.dumps(
                {
                    "v": 1,
                    "type": "sourcehunt.start",
                    "request": {"count": count, "description_bytes": description_bytes},
                }
            ).encode()
            + b"\n"
        )
        parent.shutdown(socket.SHUT_WR)
        with parent.makefile("rb") as stream:
            lines = list(stream)
        _stdout, stderr = process.communicate(timeout=20)
        assert all(len(line) <= MAX_RECORD_BYTES for line in lines), stderr.decode()
        return process.returncode, [json.loads(line) for line in lines]
    finally:
        parent.close()
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)


@pytest.mark.parametrize("count", [0, 16, 17, 64, 512])
def test_subprocess_delivers_all_counted_findings(count):
    returncode, records = _worker_result(count)
    assert returncode == 0
    assert len(records) == 1
    assert records[0]["type"] == "sourcehunt.result"
    result = records[0]["data"]
    assert result["finding_count"] == len(result["findings"]) == count
    assert [finding["id"] for finding in result["findings"]] == [
        f"synthetic-{index}" for index in range(count)
    ]
    assert not result.get("truncated", False)


def test_subprocess_rejects_oversize_report_instead_of_emitting_partial_success():
    returncode, records = _worker_result(300, description_bytes=4096)
    assert returncode == 1
    assert len(records) == 1
    assert records[0]["type"] == "sourcehunt.error"
    assert "incomplete findings" in records[0]["error"]
