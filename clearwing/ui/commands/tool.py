"""Inspect and invoke Clearwing tools from the command line."""

from __future__ import annotations

import argparse
import asyncio
import json
from typing import Any


def add_parser(subparsers):
    parser = subparsers.add_parser("tool", help="Inspect or invoke a Clearwing tool")
    actions = parser.add_subparsers(dest="tool_command", required=True)

    catalog = actions.add_parser("catalog", help="Print the tool catalog as JSON")
    catalog.add_argument("--machine-fd", type=int, help=argparse.SUPPRESS)

    call = actions.add_parser("call", help="Invoke one tool with a JSON object")
    call.add_argument("name", help="Tool name")
    call.add_argument("--input-json", default="{}", metavar="JSON")
    call.add_argument("--machine-fd", type=int, help=argparse.SUPPRESS)
    return parser


def handle(_cli, args):
    """List tools or invoke one tool."""
    if args.tool_command == "catalog":
        if args.machine_fd is not None:
            raise SystemExit(_handle_machine_catalog(args.machine_fd))
        print(json.dumps(_catalog(), indent=2, sort_keys=True))
        return

    if args.machine_fd is not None:
        raise SystemExit(_handle_machine_call(args.machine_fd, args.name))
    try:
        value = json.loads(args.input_json)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"--input-json must be valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit("--input-json must contain a JSON object")
    print(json.dumps(asyncio.run(_invoke(args.name, value)), indent=2, default=str))


def _load_tools() -> dict[str, Any]:
    from ...agent.tools import get_all_tools

    return {
        item.name: item
        for item in get_all_tools()
        if isinstance(getattr(item, "name", None), str) and item.name
    }


def _catalog() -> list[dict[str, Any]]:
    return [
        {
            "name": name,
            "description": getattr(item, "description", "") or "",
            "input_schema": getattr(item, "input_schema", {}) or {},
        }
        for name, item in sorted(_load_tools().items())
    ]


async def _invoke(name: str, arguments: dict[str, Any]) -> Any:
    item = _load_tools().get(name)
    if item is None:
        raise ValueError(f"unknown tool `{name}`")
    return await item.ainvoke(arguments)


def _handle_machine_catalog(descriptor: int) -> int:
    from ...providers import install_runtime_routing
    from ..machine import MachineChannel

    channel = MachineChannel(
        descriptor,
        "tools.catalog",
        require_provider_routing=False,
    )
    try:
        request, routing = channel.read_start()
        if request:
            raise ValueError("catalog request must be empty")
        if routing is not None:
            install_runtime_routing(routing)
        channel.result(_catalog())
        return 0
    except BaseException as exc:  # noqa: BLE001
        channel.error(exc)
        return 130 if isinstance(exc, KeyboardInterrupt) else 1
    finally:
        channel.close()


def _handle_machine_call(descriptor: int, name: str) -> int:
    from ...providers import install_runtime_routing
    from ..machine import MachineChannel

    channel = MachineChannel(
        descriptor,
        "tools.call",
        require_provider_routing=False,
    )
    try:
        arguments, routing = channel.read_start()
        if routing is not None:
            install_runtime_routing(routing)
        channel.result(asyncio.run(_invoke(name, arguments)))
        return 0
    except BaseException as exc:  # noqa: BLE001
        channel.error(exc)
        return 130 if isinstance(exc, KeyboardInterrupt) else 1
    finally:
        channel.close()
