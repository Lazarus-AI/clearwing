"""Descriptor transport for machine-driven CLI commands."""

from __future__ import annotations

import base64
import json
import os
from dataclasses import asdict, is_dataclass
from enum import Enum
from typing import Any

PROTOCOL_VERSION = 1
MAX_START_BYTES = 1_048_576


class MachineProtocolError(ValueError):
    """Raised when a machine command receives an invalid protocol record."""


class MachineChannel:
    """Read one command and emit ordered records on an inherited descriptor."""

    def __init__(
        self,
        descriptor: int,
        operation: str,
        *,
        require_provider_routing: bool = True,
    ):
        if descriptor < 3:
            raise MachineProtocolError("machine descriptor must be at least 3")
        self.operation = operation
        self.require_provider_routing = require_provider_routing
        self._reader = os.fdopen(os.dup(descriptor), "rb", buffering=0)
        self._writer = os.fdopen(os.dup(descriptor), "wb", buffering=0)
        os.close(descriptor)
        self._sequence = 0
        self._terminal = False

    def read_start(self) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Read and validate the command's start record."""
        raw = self._reader.readline(MAX_START_BYTES + 1)
        if not raw:
            raise MachineProtocolError("machine channel closed before the start record")
        if len(raw) > MAX_START_BYTES or not raw.endswith(b"\n"):
            raise MachineProtocolError("start record exceeds the protocol limit")
        try:
            record = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MachineProtocolError("start record must be UTF-8 JSON") from exc
        if not isinstance(record, dict):
            raise MachineProtocolError("start record must be an object")
        allowed = {"v", "type", "request", "provider_routing"}
        unknown = sorted(set(record) - allowed)
        if unknown:
            raise MachineProtocolError(f"unknown start field(s): {', '.join(unknown)}")
        if record.get("v") != PROTOCOL_VERSION:
            raise MachineProtocolError("unsupported machine protocol version")
        if record.get("type") != f"{self.operation}.start":
            raise MachineProtocolError(f"expected {self.operation}.start record")
        request = record.get("request")
        if not isinstance(request, dict):
            raise MachineProtocolError("request must be an object")
        routing = _decode_provider_routing(
            record.get("provider_routing"), required=self.require_provider_routing
        )
        return request, routing

    def emit(self, kind: str, data: Any) -> None:
        """Emit an operation-specific non-terminal record."""
        self._write(kind, {"data": _jsonable(data)}, terminal=False)

    def result(self, data: Any) -> None:
        """Emit the command's terminal result."""
        self._write("result", {"data": _jsonable(data)}, terminal=True)

    def error(self, error: BaseException | str) -> None:
        """Emit the command's terminal error."""
        self._write("error", {"error": str(error)}, terminal=True)

    def close(self) -> None:
        """Close both sides of the inherited channel."""
        self._reader.close()
        self._writer.close()

    def _write(self, kind: str, payload: dict[str, Any], *, terminal: bool) -> None:
        if self._terminal:
            raise MachineProtocolError("terminal record already emitted")
        self._sequence += 1
        record = {
            "v": PROTOCOL_VERSION,
            "type": f"{self.operation}.{kind}",
            "seq": self._sequence,
            **payload,
        }
        encoded = json.dumps(record, separators=(",", ":"), ensure_ascii=False).encode()
        self._writer.write(encoded + b"\n")
        if terminal:
            self._terminal = True


def _decode_provider_routing(value: Any, *, required: bool) -> dict[str, Any] | None:
    if value is None and not required:
        return None
    if not isinstance(value, dict) or set(value) != {"encoding", "value"}:
        raise MachineProtocolError("provider_routing must contain encoding and value")
    if value["encoding"] != "base64url" or not isinstance(value["value"], str):
        raise MachineProtocolError("provider_routing must be base64url encoded")
    encoded = value["value"]
    if not encoded or len(encoded) > 262_144:
        raise MachineProtocolError("provider routing exceeds the protocol limit")
    try:
        padding = "=" * (-len(encoded) % 4)
        decoded = base64.b64decode(encoded + padding, altchars=b"-_", validate=True)
        config = json.loads(decoded)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MachineProtocolError("provider routing is not valid base64url JSON") from exc
    if not isinstance(config, dict) or not config:
        raise MachineProtocolError("provider routing must decode to a non-empty object")
    return config


def _jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)
