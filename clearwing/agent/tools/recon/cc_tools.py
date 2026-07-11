"""Confidential Computing session endpoint discovery tools.

1Password's /api/v1/confidential-computing/session endpoint uses Rust serde
deserialization. Invalid requests return structured error messages that
reveal the expected field names and types, enabling iterative schema
discovery.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from typing import Any

from clearwing.agent.tooling import interrupt, tool


def _http_post_raw(
    url: str, body: bytes, headers: dict[str, str] | None = None, timeout: int = 30
) -> tuple[int, dict[str, str], str, float]:
    """POST raw bytes and return (status, headers, body, duration_ms)."""
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, data=body, headers=req_headers, method="POST")
    start = time.time()
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)  # noqa: S310
        status = resp.status
        resp_headers = dict(resp.getheaders())
        resp_body = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        status = e.code
        resp_headers = dict(e.headers.items()) if e.headers else {}
        resp_body = e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return 0, {}, str(e), (time.time() - start) * 1000
    return status, resp_headers, resp_body, (time.time() - start) * 1000


_SERDE_FIELD_PATTERNS: list[str] = [
    r"missing field `([^`]+)`",
    r"unknown field `([^`]+)`",
    r"expected (?:one of )?`([^`]+)`",
    r"invalid type: .*, expected ([a-zA-Z]+)",
    r"field `([^`]+)`: ",
    r'"([a-zA-Z_][a-zA-Z0-9_]*)":\s*(?:null|""|0|false|\[\]|\{\})',
]

_TYPE_GUESSES: dict[str, list[Any]] = {
    "string": ["test", ""],
    "uuid": ["00000000-0000-0000-0000-000000000000"],
    "bytes": ["AAAA"],
    "integer": [0, 1],
    "boolean": [True, False],
    "array": [[]],
    "object": [{}],
}


def _extract_fields_from_error(error_text: str) -> list[str]:
    """Extract field names from serde error messages."""
    fields: list[str] = []
    for pattern in _SERDE_FIELD_PATTERNS[:3]:
        for m in re.finditer(pattern, error_text):
            field = m.group(1)
            if "," in field:
                for f in field.split(","):
                    f = f.strip().strip("`").strip('"')
                    if f and f not in fields:
                        fields.append(f)
            elif field not in fields:
                fields.append(field)
    return fields


def _extract_type_hint(error_text: str, field_name: str) -> str:
    """Try to determine expected type from error message."""
    ctx = error_text.lower()
    if "integer" in ctx or "u64" in ctx or "i64" in ctx or "number" in ctx:
        return "integer"
    if "boolean" in ctx or "bool" in ctx:
        return "boolean"
    if "string" in ctx or "str" in ctx:
        return "string"
    if "array" in ctx or "sequence" in ctx or "vec" in ctx:
        return "array"
    if "map" in ctx or "struct" in ctx or "object" in ctx:
        return "object"
    if "uuid" in field_name.lower() or "id" in field_name.lower():
        return "uuid"
    return "string"


@tool(
    name="cc_discover_schema",
    description=(
        "Iteratively discover the required JSON schema for the "
        "Confidential Computing session endpoint by analyzing serde "
        "error messages. Builds up a valid payload field by field."
    ),
)
def cc_discover_schema(  # noqa: C901
    target: str,
    endpoint_path: str = "/api/v1/confidential-computing/session",
    max_iterations: int = 20,
    initial_fields: dict[str, Any] | None = None,
) -> dict:
    """Discover CC endpoint schema via iterative probing.

    Args:
        target: Base URL.
        endpoint_path: CC session endpoint path.
        max_iterations: Max discovery iterations.
        initial_fields: Known fields to start with.

    Returns:
        Dict with discovered schema, field types, and probing history.
    """
    total_est = max_iterations * 3
    if not interrupt(f"About to send up to {total_est} requests to {target} for schema discovery"):
        return {"error": "User declined schema discovery."}

    url = f"{target.rstrip('/')}{endpoint_path}"
    payload: dict[str, Any] = dict(initial_fields) if initial_fields else {}
    history: list[dict[str, Any]] = []
    discovered_fields: dict[str, dict[str, Any]] = {}

    for iteration in range(max_iterations):
        body = json.dumps(payload).encode()
        status, _, resp_body, duration = _http_post_raw(url, body)

        step: dict[str, Any] = {
            "iteration": iteration,
            "payload_keys": list(payload.keys()),
            "status": status,
            "response_preview": resp_body[:500],
            "duration_ms": round(duration, 2),
        }
        history.append(step)

        if status == 0:
            step["error"] = "connection_failed"
            break

        if status in (200, 201):
            step["result"] = "success"
            break

        if status == 404:
            step["result"] = "endpoint_not_found"
            break

        new_fields = _extract_fields_from_error(resp_body)
        if not new_fields:
            for field_name in list(payload.keys()):
                for type_name, values in _TYPE_GUESSES.items():
                    for val in values:
                        test_payload = dict(payload)
                        test_payload[field_name] = val
                        test_body = json.dumps(test_payload).encode()
                        ts, _, tb, td = _http_post_raw(url, test_body)
                        if ts != status or tb != resp_body:
                            new_fields_inner = _extract_fields_from_error(tb)
                            if new_fields_inner:
                                new_fields.extend(new_fields_inner)
                                payload[field_name] = val
                                discovered_fields[field_name] = {
                                    "type": type_name,
                                    "value": val,
                                    "discovered_at": iteration,
                                }
                                break
                    if new_fields:
                        break

        if not new_fields:
            step["result"] = "no_new_fields"
            break

        for field in new_fields:
            if field not in payload:
                type_hint = _extract_type_hint(resp_body, field)
                default_values = _TYPE_GUESSES.get(type_hint, ["test"])
                payload[field] = default_values[0]
                discovered_fields[field] = {
                    "type": type_hint,
                    "value": default_values[0],
                    "discovered_at": iteration,
                }

    final_status = history[-1]["status"] if history else None

    return {
        "target": target,
        "endpoint": endpoint_path,
        "iterations": len(history),
        "discovered_fields": discovered_fields,
        "current_payload": payload,
        "final_status": final_status,
        "schema_complete": final_status in (200, 201),
        "history": history,
    }


@tool(
    name="cc_fuzz_fields",
    description=(
        "Fuzz individual fields of a Confidential Computing session "
        "payload to find accepted values, bypass validation, or "
        "trigger interesting error responses."
    ),
)
def cc_fuzz_fields(
    target: str,
    base_payload: dict[str, Any],
    fields_to_fuzz: list[str] | None = None,
    endpoint_path: str = "/api/v1/confidential-computing/session",
) -> dict:
    """Fuzz CC endpoint fields with various values.

    Args:
        target: Base URL.
        base_payload: Known-good (or partial) payload to start from.
        fields_to_fuzz: Specific fields to fuzz (all if None).
        endpoint_path: CC session endpoint path.

    Returns:
        Dict with per-field fuzz results.
    """
    fuzz_fields = fields_to_fuzz or list(base_payload.keys())
    if not fuzz_fields:
        return {"error": "No fields to fuzz."}

    fuzz_values: list[tuple[str, Any]] = [
        ("empty_string", ""),
        ("null", None),
        ("zero", 0),
        ("negative", -1),
        ("large_int", 2**63 - 1),
        ("true", True),
        ("false", False),
        ("empty_array", []),
        ("empty_object", {}),
        ("long_string", "A" * 10000),
        ("special_chars", "<script>alert(1)</script>"),
        ("sql_injection", "' OR '1'='1"),
        ("null_bytes", "test\\x00value"),
        ("unicode", "éñü￿"),
        ("uuid", "00000000-0000-0000-0000-000000000000"),
        ("base64", "dGVzdA=="),
    ]

    total = len(fuzz_fields) * len(fuzz_values)
    if not interrupt(f"About to send {total} fuzz requests to {target}{endpoint_path}"):
        return {"error": "User declined field fuzzing."}

    url = f"{target.rstrip('/')}{endpoint_path}"

    baseline_body = json.dumps(base_payload).encode()
    baseline_status, _, baseline_resp, _ = _http_post_raw(url, baseline_body)

    results: dict[str, list[dict[str, Any]]] = {}
    interesting: list[dict[str, Any]] = []

    for field in fuzz_fields:
        field_results: list[dict[str, Any]] = []

        for label, value in fuzz_values:
            test_payload = dict(base_payload)
            test_payload[field] = value

            try:
                body = json.dumps(test_payload).encode()
            except (TypeError, ValueError):
                continue

            status, _, resp_body, duration = _http_post_raw(url, body)

            entry: dict[str, Any] = {
                "value_type": label,
                "status": status,
                "response_preview": resp_body[:300],
                "duration_ms": round(duration, 2),
                "differs_from_baseline": status != baseline_status or resp_body[:200] != baseline_resp[:200],
            }
            field_results.append(entry)

            if status in (200, 201):
                interesting.append({
                    "field": field,
                    "value_type": label,
                    "value": str(value)[:100],
                    "severity": "HIGH",
                    "description": f"Server accepted {label} for field '{field}'",
                })
            elif status != baseline_status and status not in (400, 422):
                interesting.append({
                    "field": field,
                    "value_type": label,
                    "status": status,
                    "severity": "MEDIUM",
                    "description": f"Unexpected status {status} for {label} in field '{field}'",
                })

        results[field] = field_results

    return {
        "target": target,
        "endpoint": endpoint_path,
        "baseline_status": baseline_status,
        "fields_fuzzed": len(fuzz_fields),
        "total_requests": total,
        "results": results,
        "interesting_findings": interesting,
        "summary": (
            f"{len(interesting)} interesting finding(s) across {len(fuzz_fields)} fields"
            if interesting
            else f"No unexpected responses across {len(fuzz_fields)} fields"
        ),
    }


def get_cc_tools() -> list[Any]:
    """Return all Confidential Computing tools."""
    return [cc_discover_schema, cc_fuzz_fields]
