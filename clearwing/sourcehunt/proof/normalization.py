"""Canonical memory and control-flow fact normalization.

Extractors deliberately emit syntax-level observations.  This module turns
those observations into a small, stable vocabulary that candidate generators
and resolvers can consume without reparsing source snippets independently.
It does not make vulnerability conclusions.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from .models import Fact, Provenance

NORMALIZATION_SCHEMA_VERSION = 1

_IDENTIFIER = re.compile(r"[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)*")
_COMPARISON = re.compile(
    r"(?P<left>[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)*|0x[0-9A-Fa-f]+|\d+)"
    r"\s*(?P<operator><=|>=|==|!=|<|>)\s*"
    r"(?P<right>[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)*|0x[0-9A-Fa-f]+|\d+)"
)
_ARRAY = re.compile(
    r"(?P<target>[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)*)"
    r"\s*\[(?P<offset>[^\]]+)\]"
)
_TYPE_PREFIX = re.compile(
    r"^(?:(?:const|volatile|static|unsigned|signed|struct|class)\s+)*"
    r"(?:[A-Za-z_]\w*(?:::\w+)*(?:\s*[*&]+)?\s+)+"
)
_NOISE = {
    "alloca",
    "bytearray",
    "calloc",
    "malloc",
    "make",
    "memcpy",
    "memmove",
    "memset",
    "new",
    "realloc",
    "sizeof",
    "strcpy",
    "strncpy",
    "write",
}


class FactNormalizer:
    """Normalize facts and derive explicit extent-role observations."""

    producer = "proof-fact-normalizer"
    version = str(NORMALIZATION_SCHEMA_VERSION)

    def normalize(self, facts: list[Fact]) -> list[Fact]:
        normalized = [self._normalize_fact(fact) for fact in facts]
        normalized.extend(self._derived_array_writes(normalized))
        normalized.extend(self._derived_lengths(normalized))
        by_id = {fact.id: fact for fact in normalized}
        return sorted(
            by_id.values(),
            key=lambda fact: (
                fact.location.file if fact.location else "",
                fact.location.line if fact.location else 0,
                fact.kind,
                fact.id,
            ),
        )

    def _normalize_fact(self, fact: Fact) -> Fact:
        properties = dict(fact.properties)
        expression = _expression(fact)
        properties.setdefault("expression", expression)
        properties["normalization_schema"] = NORMALIZATION_SCHEMA_VERSION

        if fact.kind == "allocation":
            properties.update(_normalize_allocation(expression))
        elif fact.kind in {"memory_access", "memory_write"}:
            properties.update(_normalize_access(fact.kind, expression))
        elif fact.kind == "cast":
            properties.update(_normalize_cast(expression, properties))
        elif fact.kind == "guard":
            properties.update(_normalize_guard(expression, properties))
        elif fact.kind in {"call", "call_edge"}:
            properties.update(_normalize_call(fact, expression))

        payload = fact.model_dump(mode="python")
        payload.update({"id": "", "properties": properties})
        return Fact.model_validate(payload)

    def _derived_array_writes(self, facts: list[Fact]) -> list[Fact]:
        derived: list[Fact] = []
        existing_locations = {
            (fact.location.file, fact.location.line, fact.location.function)
            for fact in facts
            if fact.kind == "memory_write" and fact.location is not None
        }
        for assignment in facts:
            if assignment.kind != "assignment" or assignment.location is None:
                continue
            lhs = str(assignment.properties.get("lhs") or "")
            match = _ARRAY.search(lhs)
            if match is None:
                continue
            location_key = (
                assignment.location.file,
                assignment.location.line,
                assignment.location.function,
            )
            if location_key in existing_locations:
                continue
            target = match.group("target")
            offset = match.group("offset").strip()
            derived.append(
                Fact(
                    snapshot_id=assignment.snapshot_id,
                    kind="memory_write",
                    subject=target,
                    predicate="writes_element",
                    object=target,
                    properties={
                        "normalization_schema": NORMALIZATION_SCHEMA_VERSION,
                        "expression": _expression(assignment),
                        "operation": "indexed_assignment",
                        "access_mode": "write",
                        "target": target,
                        "offset": offset,
                        "extent": "1",
                        "extent_symbols": _symbols(offset),
                        "source_fact_ids": [assignment.id],
                    },
                    location=assignment.location,
                    provenance=Provenance(
                        producer=self.producer,
                        producer_version=self.version,
                        source_digest=assignment.provenance.source_digest,
                    ),
                )
            )
        return derived

    def _derived_lengths(self, facts: list[Fact]) -> list[Fact]:
        roles: dict[tuple[str, str, int, str], dict[str, Any]] = defaultdict(
            lambda: {"roles": set(), "source_fact_ids": set()}
        )
        type_facts: dict[str, list[Fact]] = defaultdict(list)
        for fact in facts:
            if fact.kind in {"variable", "field", "parameter"}:
                type_facts[fact.subject].append(fact)
            role = {
                "allocation": "allocation_extent",
                "memory_access": "access_extent",
                "memory_write": "access_extent",
            }.get(fact.kind)
            if role is None or fact.location is None:
                continue
            for symbol in fact.properties.get("extent_symbols", []):
                key = (
                    str(symbol),
                    fact.location.file,
                    fact.location.line,
                    fact.location.function,
                )
                roles[key]["roles"].add(role)
                roles[key]["source_fact_ids"].add(fact.id)

        derived: list[Fact] = []
        for (symbol, file, line, function), details in sorted(roles.items()):
            matching_types = [
                item
                for name, items in type_facts.items()
                if name == symbol or name.endswith(f".{symbol}") or name.endswith(f"->{symbol}")
                for item in items
            ]
            widths = sorted(
                {
                    int(width)
                    for item in matching_types
                    if (width := item.properties.get("integer_width")) is not None
                }
            )
            derived.append(
                Fact(
                    snapshot_id=facts[0].snapshot_id if facts else "",
                    kind="length",
                    subject=symbol,
                    predicate="controls_extent",
                    object=sorted(details["roles"]),
                    properties={
                        "normalization_schema": NORMALIZATION_SCHEMA_VERSION,
                        "roles": sorted(details["roles"]),
                        "integer_widths": widths,
                        "source_fact_ids": sorted(details["source_fact_ids"]),
                    },
                    location={
                        "file": file,
                        "line": line,
                        "function": function,
                    },
                    provenance=Provenance(
                        producer=self.producer,
                        producer_version=self.version,
                    ),
                )
            )
        return derived


def _normalize_allocation(expression: str) -> dict[str, Any]:
    operation = _first_call(expression)
    arguments = _call_arguments(expression, operation)
    lhs, _rhs = _assignment(expression)
    target = _strip_declaration(lhs) if lhs else ""
    extent = ""
    if operation in {"calloc"} and len(arguments) >= 2:
        extent = f"({arguments[0]}) * ({arguments[1]})"
    elif operation in {"realloc"} and len(arguments) >= 2:
        extent = arguments[1]
    elif arguments:
        extent = arguments[0]
    if operation == "new":
        array = _ARRAY.search(expression)
        if array:
            extent = array.group("offset").strip()
    return {
        "operation": operation or "allocation",
        "target": target,
        "extent": extent,
        "extent_symbols": _symbols(extent),
        "unit": "elements" if operation in {"new", "make"} else "bytes",
    }


def _normalize_access(kind: str, expression: str) -> dict[str, Any]:
    operation = _first_call(expression)
    arguments = _call_arguments(expression, operation)
    target = ""
    offset = "0"
    extent = "1"
    array = _ARRAY.search(expression)
    if array is not None:
        target = array.group("target")
        offset = array.group("offset").strip()
    elif arguments:
        target = arguments[0]
        if operation in {"memcpy", "memmove", "strncpy"} and len(arguments) >= 3:
            extent = arguments[2]
        elif operation == "memset" and len(arguments) >= 3:
            extent = arguments[2]
        elif operation in {"write", "Buffer.write", "copy_from_slice"}:
            extent = arguments[-1] if len(arguments) > 1 else "unknown"
        elif operation in {"strcpy"}:
            extent = "strlen(source) + 1"
    return {
        "operation": operation or ("indexed_access" if array else kind),
        "access_mode": "write" if kind == "memory_write" else "read_or_write",
        "target": target,
        "offset": offset,
        "extent": extent,
        "offset_symbols": _symbols(offset),
        "extent_symbols": _symbols(extent),
    }


def _normalize_cast(expression: str, properties: dict[str, Any]) -> dict[str, Any]:
    target_type = ""
    match = re.search(
        r"\(\s*(u?int(?:8|16|32|64)_t|short|int|long|size_t)\s*\)",
        expression,
    )
    if match:
        target_type = match.group(1)
    else:
        match = re.search(r"\bas\s+(u8|u16|u32|u64|i8|i16|i32|i64|usize)\b", expression)
        if match:
            target_type = match.group(1)
    width = properties.get("integer_width") or _type_width(target_type)
    return {
        "target_type": target_type,
        "target_width": width,
        "source_symbols": _symbols(expression),
        "may_narrow": width is not None and int(width) < 64,
    }


def _normalize_guard(expression: str, properties: dict[str, Any]) -> dict[str, Any]:
    comparisons = [
        {
            "left": match.group("left"),
            "operator": match.group("operator"),
            "right": match.group("right"),
        }
        for match in _COMPARISON.finditer(expression)
    ]
    control_effect = str(properties.get("control_effect") or "")
    rejecting = bool(
        control_effect
        or re.search(r"\b(?:return|raise|throw|goto|break|abort|continue)\b", expression)
    )
    return {
        "comparisons": comparisons,
        "guarded_symbols": sorted(
            {
                symbol
                for comparison in comparisons
                for side in (comparison["left"], comparison["right"])
                for symbol in _symbols(side)
            }
        ),
        "rejecting": rejecting,
        "control_effect": control_effect,
    }


def _normalize_call(fact: Fact, expression: str) -> dict[str, Any]:
    callee = str(fact.properties.get("callee") or fact.object or _first_call(expression))
    caller = (
        fact.location.function
        if fact.location is not None and fact.location.function
        else fact.subject
    )
    return {
        "caller": caller,
        "callee": callee,
        "arguments": _call_arguments(expression, callee),
        "resolution": str(fact.properties.get("resolution") or "syntax-level"),
    }


def _expression(fact: Fact) -> str:
    return str(
        fact.properties.get("expression")
        or fact.properties.get("excerpt")
        or fact.properties.get("rhs")
        or fact.object
        or ""
    )


def _assignment(expression: str) -> tuple[str, str]:
    if "=" not in expression or re.search(r"(?:==|!=|<=|>=)", expression):
        return "", ""
    left, right = expression.split("=", 1)
    return left.strip(), right.rstrip(";").strip()


def _strip_declaration(value: str) -> str:
    stripped = _TYPE_PREFIX.sub("", value.strip())
    stripped = stripped.lstrip("*& ")
    match = _IDENTIFIER.search(stripped)
    return match.group(0) if match else stripped


def _first_call(expression: str) -> str:
    calls = re.findall(r"\b([A-Za-z_]\w*(?:\.\w+)*)\s*\(", expression)
    for call in calls:
        if call not in {"if", "for", "while", "sizeof", "return"}:
            return call
    if re.search(r"\bnew\b", expression):
        return "new"
    return ""


def _call_arguments(expression: str, callee: str) -> list[str]:
    if not callee:
        return []
    match = re.search(rf"\b{re.escape(callee)}\s*\(", expression)
    if match is None:
        return []
    start = match.end()
    depth = 1
    current: list[str] = []
    arguments: list[str] = []
    for char in expression[start:]:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                value = "".join(current).strip()
                if value:
                    arguments.append(value)
                break
        if char == "," and depth == 1:
            arguments.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    return arguments


def _symbols(expression: str) -> list[str]:
    return sorted(
        {
            match.group(0)
            for match in _IDENTIFIER.finditer(expression)
            if match.group(0) not in _NOISE and not match.group(0).isdigit()
        }
    )


def _type_width(type_name: str) -> int | None:
    match = re.search(r"(?:u?int|[ui])(8|16|32|64)", type_name)
    if match:
        return int(match.group(1))
    return {"short": 16, "int": 32, "long": 64}.get(type_name)
