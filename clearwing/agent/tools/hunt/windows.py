"""Generic security-relevant source-window ranking for small-model scaffolds."""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Literal

from pydantic import Field

from clearwing.llm import NativeToolSpec, ToolInputModel
from clearwing.sourcehunt.static_signals import (
    is_production_source_path,
    line_security_signals,
)

from .discovery import _normalize_path
from .sandbox import HunterContext


class RankSourceWindowsInput(ToolInputModel):
    path: str = Field(description="Repo-relative source file")
    max_windows: int = Field(default=12, ge=1, le=30)
    window_lines: int = Field(default=80, ge=20, le=200)


class ReadRankedWindowInput(ToolInputModel):
    window_id: str = Field(description="Opaque ID returned by rank_source_windows, for example W1")


class ReadStateInteractionsInput(ToolInputModel):
    window_id: str = Field(description="Ranked window whose dominant state should be expanded")


class ReadDomainConsequencesInput(ToolInputModel):
    domain_id: str = Field(description="Recorded overlapping domain, for example D1")


class ReadDomainProofRefinementInput(ToolInputModel):
    domain_id: str = Field(description="Tracked unresolved domain, for example D1")
    obligation: Literal[
        "attacker_reaches_producer",
        "producer_reaches_distinguished",
        "changed_branch_reaches_effect",
        "boundary_effect_unguarded",
    ] = Field(description="One obligation returned unresolved by record_domain_proof")


_MEMBER_RE = re.compile(r"(?:->|\.)\s*([A-Za-z_]\w*)")
_SOURCE_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".rs"})
_STATE_STOPWORDS = frozenset(
    {
        "const",
        "else",
        "false",
        "return",
        "sizeof",
        "struct",
        "true",
    }
)
_INTERACTION_SCORES = {
    "declare": 10,
    "initialize": 12,
    "write": 11,
    "compare": 9,
    "read": 2,
}
_CONSUMER_BRANCH_RE = re.compile(r"(?:==|!=|\?|\bif\s*\(|\bswitch\s*\()")
_CONSEQUENCE_EFFECT_RE = re.compile(
    r"\b(?:memcpy|memmove|memset|strcpy|strncpy|sprintf|snprintf|"
    r"XCHG|[A-Z][A-Z0-9_]*(?:COPY|MOVE|XCHG|WRITE|STORE)[A-Z0-9_]*)\s*\("
)
_IDENTIFIER_RE = re.compile(r"\b[A-Za-z_]\w*\b")
_FUNCTION_DEFINITION_RE = re.compile(
    r"(?m)^[ \t]*(?:(?:[A-Za-z_]\w*|\*+)[ \t]+)+"
    r"(?P<name>[A-Za-z_]\w*)[ \t]*\([^;{}]*\)[ \t\r\n]*\{"
)
_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_LOOP_RE = re.compile(r"\b(?:for|while)\s*\(")


def _dominant_anchor_state(lines: list[str], anchor_line: int) -> str | None:
    """Choose a mutable state name from an anchor without project knowledge."""

    line = lines[anchor_line - 1]
    scores: Counter[str] = Counter(_MEMBER_RE.findall(line))
    first_argument = re.search(
        r"\b(?:memcpy|memmove|memset|strcpy|strncpy|sprintf|snprintf)\s*\(([^,]+)",
        line,
    )
    if first_argument:
        destination_names = _MEMBER_RE.findall(first_argument.group(1))
        if destination_names:
            scores[destination_names[0]] += 40
    for name in list(scores):
        if name in _STATE_STOPWORDS or len(name) < 3:
            del scores[name]
    if not scores:
        return None
    return min(scores, key=lambda name: (-scores[name], name))


def _interaction_kind(line: str, name: str) -> str:
    escaped = re.escape(name)
    if re.search(rf"\b(?:memset|memcpy|memmove)\s*\([^,]*\b{escaped}\b", line):
        return "initialize"
    if re.search(rf"\b{escaped}\b(?:\s*\[[^]]*\])?\s*=(?!=)", line):
        return "write"
    if re.search(
        rf"\b(?:u?int(?:8|16|32|64)_t|char|short|int|long|size_t)\b[^=;]*\b{escaped}\b",
        line,
    ):
        return "declare"
    without_member_arrows = line.replace("->", ".")
    if re.search(rf"\b{escaped}\b[^;]*(?:==|!=|<=|>=|<|>)", without_member_arrows):
        return "compare"
    return "read"


def _source_files(repo: Path, target: Path) -> list[Path]:
    """Bound expansion to the target's generic source subsystem."""

    root = target.parent
    return [
        path
        for path in sorted(root.rglob("*"))
        if path.is_file()
        and path.suffix.lower() in _SOURCE_SUFFIXES
        and is_production_source_path(path.relative_to(repo).as_posix())
        and path.stat().st_size <= 2_000_000
    ]


def _read_source_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _following_context(repo: Path, item: dict, *, lines: int = 3) -> str:
    source = _read_source_lines(repo / item["path"])
    start = int(item["line"])
    return " ".join(
        source[index - 1].strip()
        for index in range(start, min(len(source), start + lines - 1) + 1)
    )


def _derived_effect_chain(source: list[str], branch_line: int, stored_state: str) -> dict:
    branch = source[branch_line - 1]
    assignment = re.search(
        rf"\b([A-Za-z_]\w*)\s*=(?!=)[^;]*\b{re.escape(stored_state)}\b",
        branch,
    )
    if assignment is None:
        return {}
    derived = assignment.group(1)
    scan_end = min(len(source), branch_line + 80)
    dependent_guards = [
        line_number
        for line_number in range(branch_line + 1, scan_end + 1)
        if re.search(rf"\bif\s*\([^)]*\b{re.escape(derived)}\b", source[line_number - 1])
    ]
    if not dependent_guards:
        return {}
    effects: list[int] = []
    for guard_line in dependent_guards:
        effects.extend(
            line_number
            for line_number in range(guard_line + 1, min(scan_end, guard_line + 24) + 1)
            if _CONSEQUENCE_EFFECT_RE.search(source[line_number - 1])
        )
    effects = list(dict.fromkeys(effects))
    if not effects:
        return {}
    effect_names = {
        match.group(0).split("(", 1)[0].strip()
        for line_number in effects
        if (match := _CONSEQUENCE_EFFECT_RE.search(source[line_number - 1]))
    }
    effect_identifiers = {
        identifier
        for line_number in effects
        for identifier in _IDENTIFIER_RE.findall(source[line_number - 1])
        if identifier not in effect_names
    }
    setup: list[int] = []
    for line_number in range(branch_line + 1, min(effects) + 1):
        line = source[line_number - 1]
        assigned = re.search(r"\b([A-Za-z_]\w*)\s*=(?!=)", line)
        if assigned and assigned.group(1) in effect_identifiers:
            setup.append(line_number)
    tokens = [derived, *sorted(effect_names)]
    tokens.extend(
        sorted(
            {
                re.search(r"\b([A-Za-z_]\w*)\s*=(?!=)", source[line_number - 1]).group(1)
                for line_number in setup
            }
        )
    )
    boundary_facts: list[dict] = []
    for line_number in [branch_line, *setup, *effects]:
        line = source[line_number - 1]
        for match in re.finditer(
            r"\[([^]]*?\b(?:[A-Za-z_]\w*(?:->|\.)\s*)?([A-Za-z_]\w*)\s*-\s*[1-9]\d*[^]]*)\]",
            line,
        ):
            boundary_facts.append(
                {
                    "line": line_number,
                    "token": match.group(2),
                    "expression": match.group(1).strip(),
                }
            )
    return {
        "derived": derived,
        "branch_line": branch_line,
        "guard_lines": dependent_guards[:3],
        "setup_lines": setup[:4],
        "effect_lines": effects[:5],
        "impact_tokens": list(dict.fromkeys(tokens)),
        "boundary_facts": boundary_facts,
    }


def _domain_consequence_packet(
    repo: Path,
    plan: dict,
    *,
    max_lines: int = 8,
) -> tuple[str, dict]:
    stored_state = str(plan.get("stored_state", ""))
    producer_state = str(plan.get("producer_state", ""))
    distinguished = [str(value) for value in plan.get("distinguished_tokens", []) if value]
    roots = _source_files(repo, repo / plan["target_path"])
    matches: list[dict] = []
    chains: list[dict] = []
    for path in roots:
        rel = path.relative_to(repo).as_posix()
        source = _read_source_lines(path)
        for line_number, line in enumerate(source, start=1):
            if not stored_state or not re.search(rf"\b{re.escape(stored_state)}\b", line):
                continue
            if not _CONSUMER_BRANCH_RE.search(line):
                continue
            if re.search(r"\b(?:memcpy|memmove|memset)\s*\(", line) and not re.search(
                r"\b(?:if|switch)\s*\(", line
            ):
                continue
            downstream = []
            for candidate_line, candidate in enumerate(
                source[line_number : line_number + 80],
                start=line_number + 1,
            ):
                signals = line_security_signals(candidate)
                if signals:
                    downstream.append(
                        (
                            sum(weight for _signal, weight in signals),
                            candidate_line,
                            candidate.strip(),
                        )
                    )
            downstream = sorted(downstream, key=lambda value: (-value[0], value[1]))[:5]
            context = " | ".join(
                [f"branch {line_number}: {line.strip()}"]
                + [f"effect {number}: {text}" for _score, number, text in downstream]
            )
            signal_score = sum(score for score, _number, _text in downstream)
            effect_score = 12 * sum(
                bool(_CONSEQUENCE_EFFECT_RE.search(text))
                for _score, _number, text in downstream
            )
            matches.append(
                {
                    "path": rel,
                    "line": line_number,
                    "text": context,
                    "score": signal_score
                    + effect_score
                    + 12 * int(bool(producer_state and producer_state in line))
                    + 8 * sum(value.casefold() in context.casefold() for value in distinguished),
                }
            )
            chain = _derived_effect_chain(source, line_number, stored_state)
            if chain:
                chains.append({"path": rel, **chain})
    selected: list[dict] = []
    for item in sorted(
        matches,
        key=lambda value: (-value["score"], value["path"], value["line"]),
    ):
        if any(
            item["path"] == prior["path"] and abs(item["line"] - prior["line"]) < 8
            for prior in selected
        ):
            continue
        selected.append(item)
        if len(selected) >= max_lines:
            break
    body = "\n".join(
        f"C{index} | {item['path']}:{item['line']} | {item['text'][:480]}"
        for index, item in enumerate(selected, start=1)
    )
    chain_lines: list[str] = []
    for index, chain in enumerate(chains[:3], start=1):
        path = chain["path"]
        source = _read_source_lines(repo / path)
        parts = [
            f"branch {path}:{chain['branch_line']} {source[chain['branch_line'] - 1].strip()}"
        ]
        parts.extend(
            f"setup {path}:{line} {source[line - 1].strip()}" for line in chain["setup_lines"]
        )
        parts.extend(
            f"gate {path}:{line} {source[line - 1].strip()}" for line in chain["guard_lines"]
        )
        parts.extend(
            f"effect {path}:{line} {source[line - 1].strip()}"
            for line in chain["effect_lines"]
        )
        parts.extend(
            f"boundary {path}:{fact['line']} [{fact['expression']}] can underflow when "
            f"{fact['token']} is at its lower bound; check a dominating positive-bound guard"
            for fact in chain["boundary_facts"]
        )
        chain_lines.append(f"P{index} | " + " | ".join(parts))
    best_chain = chains[0] if chains else {}
    consequence_plan = {
        "domain_id": plan.get("domain_id", ""),
        "impact_tokens": best_chain.get("impact_tokens", []),
        "impact_locations": [
            f"{best_chain['path']}:{line}"
            for key in ("guard_lines", "effect_lines")
            for line in best_chain.get(key, [])
        ]
        if best_chain
        else [],
        "boundary_facts": best_chain.get("boundary_facts", []),
        "trace_facts": (
            [
                {
                    "role": "condition",
                    "file": best_chain["path"],
                    "line": best_chain["branch_line"],
                    "code_snippet": _read_source_lines(repo / best_chain["path"])[
                        best_chain["branch_line"] - 1
                    ].strip(),
                },
                *[
                    {
                        "role": "effect sink",
                        "file": best_chain["path"],
                        "line": line,
                        "code_snippet": _read_source_lines(repo / best_chain["path"])[
                            line - 1
                        ].strip(),
                    }
                    for line in best_chain.get("effect_lines", [])[:1]
                ],
            ]
            if best_chain
            else []
        ),
    }
    rendered = (
        "Domain consequence packet (orientation, not evidence). Compare the normal and "
        "overlapping branch outcomes, then follow accepted state into a memory, lifetime, "
        "privilege, or availability effect.\n"
        f"Derived branch-to-effect chains:\n{chr(10).join(chain_lines) or 'None extracted.'}\n"
        f"Ranked consumer contexts:\n{body or 'No consumer branches found.'}"
    )
    return rendered, consequence_plan


def _function_index(repo: Path, paths: list[Path]) -> dict[str, list[dict]]:
    """Index ordinary C-family function definitions without compiler metadata."""

    by_path: dict[str, list[dict]] = {}
    for path in paths:
        rel = path.relative_to(repo).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        definitions = [
            {
                "name": match.group("name"),
                "path": rel,
                "line": text.count("\n", 0, match.start("name")) + 1,
            }
            for match in _FUNCTION_DEFINITION_RE.finditer(text)
        ]
        line_count = len(text.splitlines())
        for index, definition in enumerate(definitions):
            definition["end_line"] = (
                definitions[index + 1]["line"] - 1
                if index + 1 < len(definitions)
                else line_count
            )
        if definitions:
            by_path[rel] = definitions
    return by_path


def _containing_function(index: dict[str, list[dict]], path: str, line: int) -> dict | None:
    return next(
        (
            definition
            for definition in index.get(path, [])
            if int(definition["line"]) <= line <= int(definition["end_line"])
        ),
        None,
    )


def _attacker_reachability_facts(repo: Path, domain: dict, *, max_facts: int = 6) -> list[dict]:
    """Walk a small reverse call chain from the extracted producer function."""

    source_fact = next(
        (fact for fact in domain.get("trace_facts", []) if fact.get("role") == "source"),
        None,
    )
    if source_fact is None:
        return []
    target = repo / str(domain["target_path"])
    paths = _source_files(repo, target)
    index = _function_index(repo, paths)
    producer_function = _containing_function(
        index,
        str(source_fact["file"]),
        int(source_fact["line"]),
    )
    if producer_function is None:
        return []

    known_functions = {
        str(definition["name"])
        for definitions in index.values()
        for definition in definitions
    }
    reverse_calls: dict[str, list[dict]] = {}
    for path, definitions in index.items():
        lines = _read_source_lines(repo / path)
        for definition in definitions:
            start = int(definition["line"])
            end = min(int(definition["end_line"]), len(lines))
            for line_number in range(start, end + 1):
                text = lines[line_number - 1]
                for callee in _CALL_RE.findall(text):
                    if callee not in known_functions:
                        continue
                    if callee == definition["name"] and line_number == start:
                        continue
                    reverse_calls.setdefault(callee, []).append(
                        {
                            "caller": definition["name"],
                            "file": path,
                            "line": line_number,
                            "code_snippet": text.strip(),
                            "function_start": start,
                        }
                    )

    facts: list[dict] = []
    queued = [str(producer_function["name"])]
    seen = set(queued)
    while queued and len(facts) < max_facts:
        callee = queued.pop(0)
        for call in reverse_calls.get(callee, []):
            facts.append(
                {
                    "role": "dispatch",
                    "file": call["file"],
                    "line": call["line"],
                    "code_snippet": call["code_snippet"],
                }
            )
            lines = _read_source_lines(repo / str(call["file"]))
            loop_line = next(
                (
                    line_number
                    for line_number in range(
                        int(call["line"]) - 1,
                        max(int(call["function_start"]), int(call["line"]) - 80) - 1,
                        -1,
                    )
                    if _LOOP_RE.search(lines[line_number - 1])
                ),
                None,
            )
            if loop_line is not None and len(facts) < max_facts:
                facts.append(
                    {
                        "role": "repetition",
                        "file": call["file"],
                        "line": loop_line,
                        "code_snippet": lines[loop_line - 1].strip(),
                    }
                )
            caller = str(call["caller"])
            if caller not in seen:
                seen.add(caller)
                queued.append(caller)
            if len(facts) >= max_facts:
                break
    facts.reverse()
    return facts


def _producer_domain_facts(repo: Path, domain: dict, *, max_facts: int = 6) -> list[dict]:
    target = repo / str(domain["target_path"])
    paths = _source_files(repo, target)
    selected: list[dict] = []
    seen: set[tuple[str, int]] = set()
    for token in domain.get("producer_tokens", []):
        occurrences = _state_occurrences(repo, paths, str(token), target=target)
        for kind in ("write", "compare", "declare", "initialize"):
            item = next((candidate for candidate in occurrences if candidate["kind"] == kind), None)
            if item is None or (item["path"], item["line"]) in seen:
                continue
            context = _following_context(repo, item, lines=8 if kind == "compare" else 2)
            role = kind
            if kind == "compare":
                role = (
                    "terminating comparison"
                    if re.search(r"\b(?:return|break|continue|goto)\b", context)
                    else "non-terminating comparison"
                )
            selected.append(
                {
                    "role": role,
                    "file": item["path"],
                    "line": item["line"],
                    "code_snippet": context,
                }
            )
            seen.add((item["path"], item["line"]))
            if len(selected) >= max_facts:
                return selected
    return selected


def _effect_chain_facts(repo: Path, consequence: dict, *, max_facts: int = 6) -> list[dict]:
    facts = list(consequence.get("trace_facts", []))
    seen = {(str(fact.get("file")), int(fact.get("line", 0))) for fact in facts}
    for location in consequence.get("impact_locations", []):
        path, separator, line_text = str(location).rpartition(":")
        if not separator or not line_text.isdigit() or (path, int(line_text)) in seen:
            continue
        lines = _read_source_lines(repo / path)
        line = int(line_text)
        if 1 <= line <= len(lines):
            facts.append(
                {
                    "role": "effect path",
                    "file": path,
                    "line": line,
                    "code_snippet": lines[line - 1].strip(),
                }
            )
            seen.add((path, line))
        if len(facts) >= max_facts:
            break
    return facts[:max_facts]


def _boundary_guard_facts(repo: Path, consequence: dict, *, max_lines: int = 22) -> list[dict]:
    boundary = next(iter(consequence.get("boundary_facts", [])), None)
    condition = next(
        (fact for fact in consequence.get("trace_facts", []) if fact.get("role") == "condition"),
        None,
    )
    if boundary is None or condition is None:
        return []
    path = str(condition["file"])
    lines = _read_source_lines(repo / path)
    boundary_line = int(boundary["line"])
    condition_line = int(condition["line"])
    start = max(1, min(condition_line, boundary_line) - 2)
    end = min(len(lines), max(condition_line, boundary_line) + 3, start + max_lines - 1)
    return [
        {
            "role": "boundary path",
            "file": path,
            "line": line_number,
            "code_snippet": lines[line_number - 1].strip(),
        }
        for line_number in range(start, end + 1)
    ]


def _domain_proof_refinement_packet(
    repo: Path,
    domain: dict,
    consequence: dict,
    obligation: str,
) -> str:
    extractors = {
        "attacker_reaches_producer": lambda: _attacker_reachability_facts(repo, domain),
        "producer_reaches_distinguished": lambda: _producer_domain_facts(repo, domain),
        "changed_branch_reaches_effect": lambda: _effect_chain_facts(repo, consequence),
        "boundary_effect_unguarded": lambda: _boundary_guard_facts(repo, consequence),
    }
    facts = extractors[obligation]()
    body = "\n".join(
        f"R{index} {fact['role']} | {fact['file']}:{fact['line']} | "
        f"{fact['code_snippet'][:420]}"
        for index, fact in enumerate(facts, start=1)
    )
    return (
        f"Proof refinement for {obligation} (source-derived orientation only).\n"
        f"{body or 'No additional facts extracted; keep this obligation false.'}\n"
        "Re-evaluate only this obligation, then call record_domain_proof again."
    )


def _state_occurrences(
    repo: Path,
    paths: list[Path],
    name: str,
    *,
    target: Path,
    anchor_line: int | None = None,
) -> list[dict]:
    pattern = re.compile(rf"\b{re.escape(name)}\b")
    occurrences: list[dict] = []
    for path in paths:
        rel = path.relative_to(repo).as_posix()
        lines = _read_source_lines(path)
        for line_number, line in enumerate(lines, start=1):
            if not pattern.search(line):
                continue
            kind = _interaction_kind(line, name)
            score = _INTERACTION_SCORES[kind] + sum(
                weight for _signal, weight in line_security_signals(line)
            )
            if path == target:
                score += 5
            if path == target and line_number == anchor_line:
                score += 20
            occurrences.append(
                {
                    "path": rel,
                    "line": line_number,
                    "kind": kind,
                    "text": line.strip(),
                    "score": score,
                }
            )
    return sorted(
        occurrences,
        key=lambda item: (-item["score"], item["path"], item["line"]),
    )


def _select_primary_interactions(occurrences: list[dict], *, max_lines: int) -> list[dict]:
    selected: list[dict] = []
    seen: set[tuple[str, int]] = set()

    def add(item: dict | None) -> None:
        if item is None:
            return
        location = (item["path"], item["line"])
        if location not in seen and len(selected) < max_lines:
            selected.append(item)
            seen.add(location)

    for kind in ("declare", "initialize", "write", "compare"):
        add(next((item for item in occurrences if item["kind"] == kind), None))
    for item in occurrences:
        add(item)
        if len(selected) >= 10:
            break
    return selected


def _related_state_names(primary: str, interactions: list[dict]) -> list[str]:
    scores: Counter[str] = Counter()
    for item in interactions:
        if item["kind"] not in {"initialize", "write", "compare"}:
            continue
        for name in _MEMBER_RE.findall(item["text"]):
            if name != primary and name not in _STATE_STOPWORDS and len(name) >= 3:
                scores[name] += 1
    return sorted(scores, key=lambda name: (-scores[name], name))[:1]


def _best_related_producer(
    repo: Path,
    paths: list[Path],
    name: str,
    *,
    target: Path,
) -> dict | None:
    occurrences = _state_occurrences(repo, paths, name, target=target)
    for kind in ("write", "declare", "initialize"):
        item = next((item for item in occurrences if item["kind"] == kind), None)
        if item is not None:
            return item
    return None


def _related_producer_chain(
    repo: Path,
    paths: list[Path],
    names: list[str],
    *,
    target: Path,
    excluded_names: set[str],
) -> list[dict]:
    producers: list[dict] = []
    queued = list(names)
    seen_names = set(names)
    while queued and len(producers) < 8:
        name = queued.pop(0)
        item = _best_related_producer(repo, paths, name, target=target)
        if item is None:
            continue
        occurrences = _state_occurrences(repo, paths, name, target=target)
        declaration = next(
            (candidate for candidate in occurrences if candidate["kind"] == "declare"),
            None,
        )
        if declaration is not None and declaration != item:
            producers.append({**declaration, "kind": f"{name}:declare"})
        producers.append({**item, "kind": f"{name}:{item['kind']}"})
        guard = next(
            (
                candidate
                for candidate in occurrences
                if candidate["kind"] == "compare"
            ),
            None,
        )
        if guard is not None:
            producers.append({**guard, "kind": f"{name}:compare"})
        for upstream in _MEMBER_RE.findall(item["text"]):
            if (
                upstream != name
                and upstream not in excluded_names
                and upstream not in seen_names
                and upstream not in _STATE_STOPWORDS
                and len(upstream) >= 3
            ):
                queued.append(upstream)
                seen_names.add(upstream)
    return producers


def _state_interaction_packet(
    repo: Path,
    planned: dict,
    *,
    max_lines: int = 18,
) -> tuple[str, dict]:
    target = repo / planned["path"]
    target_lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    primary = _dominant_anchor_state(target_lines, int(planned["anchor_line"]))
    if primary is None:
        return (
            "No stable state identifier could be extracted from this anchor; read another window.",
            {},
        )

    paths = _source_files(repo, target)
    occurrences = _state_occurrences(
        repo,
        paths,
        primary,
        target=target,
        anchor_line=int(planned["anchor_line"]),
    )
    selected = _select_primary_interactions(occurrences, max_lines=max_lines)
    related = _related_state_names(primary, selected)
    selected_locations = {(item["path"], item["line"]) for item in selected}
    related_chain = _related_producer_chain(
        repo,
        paths,
        related,
        target=target,
        excluded_names={primary},
    )
    for item in related_chain:
        if (item["path"], item["line"]) in selected_locations:
            continue
        selected.append(item)
        selected_locations.add((item["path"], item["line"]))
        if len(selected) >= max_lines:
            break

    body = "\n".join(
        f"{item['kind']:>16} | {item['path']}:{item['line']} | {item['text'][:220]}"
        for item in selected
    )
    related_label = ", ".join(
        dict.fromkeys(item["kind"].partition(":")[0] for item in related_chain)
    ) or "none"
    primary_declaration = next(
        (item for item in selected if item["kind"] == "declare"),
        None,
    )
    distinguished = [
        item
        for item in selected
        if item["kind"] in {"initialize", "compare"}
        and ("-1" in item["text"] or re.search(r"0x[fF]+", item["text"]))
    ]
    transfer = next(
        (
            item
            for item in selected
            if item["kind"] == "write" and any(name in item["text"] for name in related)
        ),
        None,
    )
    direct_name = related[0] if transfer and related else "unknown"
    producer_assignment = next(
        (
            item
            for item in related_chain
            if item["kind"] == f"{direct_name}:write"
        ),
        None,
    )
    producer_names = {
        name
        for name in _MEMBER_RE.findall(producer_assignment["text"] if producer_assignment else "")
        if name != direct_name
    }
    producer_tokens = [
        name
        for name in (direct_name, *sorted(producer_names))
        if name and name != "unknown"
    ]
    producer_facts = [
        item
        for item in related_chain
        if item["kind"] in {f"{direct_name}:declare", f"{direct_name}:write"}
        or (
            item["kind"].endswith(":declare")
            and item["kind"].partition(":")[0] in producer_names
        )
    ]
    guards = [
        item
        for item in related_chain
        if item["kind"].endswith(":compare")
        and item["kind"].partition(":")[0] in {direct_name, *producer_names}
    ]
    distinguished_tokens = sorted(
        {
            match.group(0)
            for item in distinguished
            for match in re.finditer(r"(?:0x[0-9a-fA-F]+|(?<!\w)-1\b)", item["text"])
        },
        key=lambda value: (len(value), value),
    )
    guard_contexts = [
        f"{item['path']}:{item['line']} {_following_context(repo, item)}" for item in guards
    ]
    blocking_guards = [
        {
            "location": f"{item['path']}:{item['line']}",
            "text": _following_context(repo, item),
        }
        for item in guards
        if re.search(
            r"\b(?:return|break|continue|goto)\b",
            _following_context(repo, item),
        )
    ]
    plan_payload = {
        "target_path": planned["path"],
        "stored_state": primary,
        "storage_domain": primary_declaration["text"] if primary_declaration else "unresolved",
        "distinguished_states": " | ".join(item["text"] for item in distinguished)
        or "none observed",
        "producer_state": direct_name,
        "producer_tokens": producer_tokens,
        "producer_domain": " | ".join(item["text"] for item in producer_facts)
        or "unresolved",
        "transfer": transfer["text"] if transfer else "unresolved",
        "trace_facts": [
            *(
                [
                    {
                        "role": "source",
                        "file": producer_assignment["path"],
                        "line": producer_assignment["line"],
                        "code_snippet": producer_assignment["text"],
                    }
                ]
                if producer_assignment
                else []
            ),
        ],
        "guard_candidates": " | ".join(guard_contexts) or "none observed",
        "blocking_guard_locations": [item["location"] for item in blocking_guards],
        "blocking_guard_candidates": " | ".join(
            f"{item['location']} {item['text']}" for item in blocking_guards
        )
        or "none observed",
        "distinguished_tokens": distinguished_tokens,
    }
    if transfer:
        plan_payload["trace_facts"].append(
            {
                "role": "state sink",
                "file": transfer["path"],
                "line": transfer["line"],
                "code_snippet": transfer["text"],
            }
        )
    rendered = (
        f"State interaction packet for {planned['window_id']} (orientation, not evidence).\n"
        f"Primary state: {primary}; related state: {related_label}.\n"
        f"Compare representation, initialization, producers, writes, and guards:\n{body}\n"
        "Domain D1 is fixed by these extracted facts; call record_value_domain(D1).\n"
        f"D1 stored={plan_payload['stored_state']} storage={plan_payload['storage_domain']}\n"
        f"D1 distinguished={plan_payload['distinguished_states']}\n"
        f"D1 producer={plan_payload['producer_state']} domain={plan_payload['producer_domain']}\n"
        f"D1 transfer={plan_payload['transfer']}\n"
        f"D1 guard_candidates={plan_payload['guard_candidates']}\n"
        f"D1 blocking_guards={plan_payload['blocking_guard_candidates']}"
    )
    return rendered, plan_payload


def rank_source_windows(
    source: str,
    *,
    max_windows: int = 12,
    window_lines: int = 80,
) -> list[dict]:
    """Rank non-overlapping windows using only language-generic signal classes."""

    lines = source.splitlines()
    anchors: list[tuple[int, int, list[str], str]] = []
    for index, line in enumerate(lines, start=1):
        matched_signals = line_security_signals(line)
        if not matched_signals:
            continue
        categories = [name for name, _weight in matched_signals]
        score = sum(weight for _name, weight in matched_signals)
        anchors.append((score, index, categories, line.strip()[:240]))

    selected: list[dict] = []
    half_window = max(10, window_lines // 2)
    for score, line, categories, snippet in sorted(
        anchors,
        key=lambda item: (-item[0], item[1]),
    ):
        if any(abs(line - existing["anchor_line"]) < half_window for existing in selected):
            continue
        selected.append(
            {
                "start_line": max(1, line - half_window),
                "end_line": min(len(lines), line + half_window),
                "anchor_line": line,
                "score": score,
                "signals": categories,
                "anchor": snippet,
            }
        )
        if len(selected) >= max_windows:
            break
    return selected


def build_window_tools(ctx: HunterContext) -> list[NativeToolSpec]:  # noqa: C901
    def rank_windows(path: str, max_windows: int = 12, window_lines: int = 80, **_: object):
        if ctx.source_window_plan:
            return {
                "path": next(iter(ctx.source_window_plan.values()))["path"],
                "windows": list(ctx.source_window_plan.values()),
                "instruction": (
                    "The reading plan already exists. Do not rank again. Continue with an unread "
                    "window_id or the active candidate's next_check."
                ),
            }
        try:
            rel = _normalize_path(ctx.repo_path, path)
        except ValueError as exc:
            return {"error": str(exc)}
        target = Path(ctx.repo_path) / rel
        try:
            source = target.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return {"error": f"could not read {rel}: {exc}"}
        windows = rank_source_windows(
            source,
            max_windows=max(1, min(30, max_windows)),
            window_lines=max(20, min(200, window_lines)),
        )
        planned_windows = []
        for index, window in enumerate(windows, start=1):
            planned = {"window_id": f"W{index}", "path": rel, **window}
            ctx.source_window_plan[planned["window_id"]] = planned
            planned_windows.append(planned)
        ctx.source_windows_ranked = True
        return {
            "path": rel,
            "line_count": len(source.splitlines()),
            "windows": planned_windows,
            "instruction": (
                "Read windows only through read_ranked_window(window_id). Start with W1, then "
                "choose different signal mixes. Anchors are orientation, not evidence."
            ),
        }

    def read_window(window_id: str, **_: object) -> str:
        normalized_id = window_id.strip().upper()
        planned = ctx.source_window_plan.get(normalized_id)
        if planned is None:
            choices = ", ".join(ctx.source_window_plan) or "none; rank first"
            return f"ERROR: unknown ranked window {window_id!r}. Available: {choices}."
        if not ctx.source_windows_read and normalized_id != "W1":
            return "ERROR: read W1 first; it has the strongest composite signal."
        target = Path(ctx.repo_path) / planned["path"]
        try:
            lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            return f"ERROR: could not read {planned['path']}: {exc}"
        start = int(planned["start_line"])
        end = int(planned["end_line"])
        ctx.source_windows_read.add(normalized_id)
        seen_signals = {
            signal
            for read_id in ctx.source_windows_read
            for signal in ctx.source_window_plan[read_id]["signals"]
        }
        unread = [
            item
            for item in ctx.source_window_plan.values()
            if item["window_id"] not in ctx.source_windows_read
        ]
        next_diverse = max(
            unread,
            key=lambda item: (
                len(set(item["signals"]) - seen_signals),
                item["score"],
                -int(item["window_id"][1:]),
            ),
            default=None,
        )
        body = "\n".join(
            f"{line_number:6d} | {lines[line_number - 1]}"
            for line_number in range(start, min(end, len(lines)) + 1)
        )
        continuation = (
            f"\nNext diverse window: {next_diverse['window_id']} "
            f"signals={','.join(next_diverse['signals'])}."
            if next_diverse is not None
            else ""
        )
        return (
            f"{normalized_id} {planned['path']}:{start}-{end} "
            f"signals={','.join(planned['signals'])}\n{body}{continuation}"
        )

    def read_state_interactions(window_id: str, **_: object) -> str:
        normalized_id = window_id.strip().upper()
        planned = ctx.source_window_plan.get(normalized_id)
        if planned is None:
            choices = ", ".join(ctx.source_window_plan) or "none; rank first"
            return f"ERROR: unknown ranked window {window_id!r}. Available: {choices}."
        if normalized_id not in ctx.source_windows_read:
            return f"ERROR: read {normalized_id} before expanding its state interactions."
        if normalized_id in ctx.state_packets_read:
            return (
                f"ERROR: state interactions for {normalized_id} were already read. "
                "Use the packet to form or update a candidate."
            )
        try:
            packet, domain_plan = _state_interaction_packet(Path(ctx.repo_path), planned)
        except OSError as exc:
            return f"ERROR: could not build state interactions for {normalized_id}: {exc}"
        ctx.state_packets_read.add(normalized_id)
        if domain_plan:
            ctx.value_domain_plans["D1"] = domain_plan
        return packet

    def read_domain_consequences(domain_id: str, **_: object) -> str:
        normalized_id = domain_id.strip().upper()
        domain = ctx.value_domains.get(normalized_id)
        if domain is None:
            choices = ", ".join(ctx.value_domains) or "none; record a domain first"
            return f"ERROR: unknown recorded domain {domain_id!r}. Available: {choices}."
        if domain.get("assessment") not in {"overlap_possible", "unresolved"}:
            return f"Domain {normalized_id} is {domain.get('assessment')}; no consequence expansion needed."
        packet, consequence_plan = _domain_consequence_packet(Path(ctx.repo_path), domain)
        ctx.domain_consequence_plans[normalized_id] = consequence_plan
        return packet

    def read_domain_proof_refinement(
        domain_id: str,
        obligation: str,
        **_: object,
    ) -> str:
        normalized_id = domain_id.strip().upper()
        domain = ctx.value_domains.get(normalized_id)
        consequence = ctx.domain_consequence_plans.get(normalized_id)
        if domain is None or consequence is None:
            return f"ERROR: expand and record domain {normalized_id} before refining its proof."
        unresolved = ctx.domain_proof_obligations.get(normalized_id, [])
        if not unresolved:
            return (
                f"ERROR: call record_domain_proof for {normalized_id} first; "
                "no unresolved obligation is recorded."
            )
        if obligation not in unresolved:
            choices = ", ".join(unresolved)
            return f"ERROR: refine only a recorded unresolved obligation: {choices}."
        refinement_key = (normalized_id, obligation)
        if refinement_key in ctx.domain_refinements_read:
            return (
                f"ERROR: refinement for {normalized_id}/{obligation} was already read. "
                "Call record_domain_proof again and keep the obligation false if unresolved."
            )
        packet = _domain_proof_refinement_packet(
            Path(ctx.repo_path),
            domain,
            consequence,
            obligation,
        )
        ctx.domain_refinements_read.add(refinement_key)
        ctx.domain_refinement_pending_proof.add(normalized_id)
        return packet

    return [
        NativeToolSpec(
            name="rank_source_windows",
            description=(
                "Rank security-relevant windows in one source file using generic static "
                "signals. This prioritizes where to read; it does not identify vulnerabilities."
            ),
            schema=RankSourceWindowsInput.model_json_schema(),
            handler=rank_windows,
        ),
        NativeToolSpec(
            name="read_ranked_window",
            description=(
                "Read one source window from the current ranked plan by opaque window_id. "
                "This avoids manual line/offset translation."
            ),
            schema=ReadRankedWindowInput.model_json_schema(),
            handler=read_window,
        ),
        NativeToolSpec(
            name="read_state_interactions",
            description=(
                "Expand one read anchor into a compact target-blind packet of declarations, "
                "initialization, writes, comparisons, and one-hop state producers."
            ),
            schema=ReadStateInteractionsInput.model_json_schema(),
            handler=read_state_interactions,
        ),
        NativeToolSpec(
            name="read_domain_consequences",
            description=(
                "Expand a recorded overlapping value domain into compact consumer-branch "
                "contexts and nearby security-sensitive effects."
            ),
            schema=ReadDomainConsequencesInput.model_json_schema(),
            handler=read_domain_consequences,
        ),
        NativeToolSpec(
            name="read_domain_proof_refinement",
            description=(
                "After record_domain_proof returns false, read a small source-derived packet "
                "for exactly one unresolved proof obligation."
            ),
            schema=ReadDomainProofRefinementInput.model_json_schema(),
            handler=read_domain_proof_refinement,
        ),
    ]


__all__ = ["build_window_tools", "rank_source_windows"]
