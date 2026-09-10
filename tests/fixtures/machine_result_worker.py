"""Emit inert report fixtures through the production machine-result transport."""

from __future__ import annotations

import sys
from types import SimpleNamespace

from clearwing.ui.commands.sourcehunt import _public_result
from clearwing.ui.machine import MachineChannel


def main() -> int:
    descriptor = int(sys.argv[sys.argv.index("--machine-fd") + 1])
    channel = MachineChannel(descriptor, "sourcehunt", require_provider_routing=False)
    try:
        request, _routing = channel.read_start()
        count = int(request.get("count", 20))
        description_bytes = int(request.get("description_bytes", 0))
        findings = [
            {
                "id": f"synthetic-{index}",
                "title": f"Reporting fixture {index}",
                "file": "fixture.txt",
                "severity": "info",
                "description": "x" * description_bytes,
            }
            for index in range(count)
        ]
        report = SimpleNamespace(
            status="completed",
            findings=findings,
            verified_findings=[],
            exploited_findings=[],
            files_ranked=0,
            files_hunted=0,
            duration_seconds=0.0,
            cost_usd=0.0,
            tokens_used=0,
        )
        channel.result(_public_result(report), allow_truncation=False)
        return 0
    except Exception as error:
        channel.error(error)
        return 1
    finally:
        channel.close()


if __name__ == "__main__":
    raise SystemExit(main())
