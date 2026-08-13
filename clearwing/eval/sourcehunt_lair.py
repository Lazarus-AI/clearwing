"""Leakage-safe offline adapter for LAIR source-verified CVE goldens.

The LAIR goldens are answer-bearing evaluation artifacts.  This module keeps
their prose and source coordinates outside the hunter boundary and emits only
delexicalized proof-routing supervision.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

LAIR_SCHEMA_VERSION = "cwpro.cve-golden-chain.v2"
ROUTER_ROW_SCHEMA_VERSION = "cw.sourcehunt.lair-router-row.v1"
ADAPTER_MANIFEST_SCHEMA_VERSION = "cw.sourcehunt.lair-adapter-manifest.v1"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class LairRevision(str, Enum):
    VULNERABLE = "vulnerable"
    FIX = "fix"


class LairTraceKind(str, Enum):
    ATTACK_SOURCE = "attack_source"
    ENTRY_POINT = "entry_point"
    PROPAGATION = "propagation"
    STATE_TRANSITION = "state_transition"
    GUARD_FAILURE = "guard_failure"
    VULNERABLE_OPERATION = "vulnerable_operation"
    SECURITY_EFFECT = "security_effect"


class LairCitation(_StrictModel):
    revision: LairRevision
    path: str = Field(min_length=1)
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    excerpt: str = Field(min_length=1)
    supports: str = Field(min_length=10)

    @model_validator(mode="after")
    def _validate_location(self) -> LairCitation:
        if self.line_end < self.line_start or self.line_end - self.line_start >= 80:
            raise ValueError("LAIR citations must contain a valid range of at most 80 lines")
        path = PurePosixPath(self.path)
        if (
            path.is_absolute()
            or self.path != path.as_posix()
            or self.path in {".", ".."}
            or ".." in path.parts
            or "\\" in self.path
        ):
            raise ValueError("LAIR citation paths must be canonical repository-relative paths")
        return self


class LairCandidate(_StrictModel):
    title: str = Field(min_length=1)
    location: str = Field(min_length=1)
    hypothesis: str = Field(min_length=20)
    why_prioritize: str = Field(min_length=20)
    evidence: list[LairCitation] = Field(min_length=1)


class LairDiscovery(_StrictModel):
    id: Literal["discovery"]
    candidate: LairCandidate


class LairTraceStep(_StrictModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9_-]*$")
    kind: LairTraceKind
    claim: str = Field(min_length=20)
    evidence: list[LairCitation] = Field(min_length=1)


class LairInvestigation(_StrictModel):
    id: Literal["investigation"]
    preconditions: list[str] = Field(min_length=1)
    causal_trace: list[LairTraceStep] = Field(min_length=3)
    security_impact: str = Field(min_length=20)

    @model_validator(mode="after")
    def _validate_trace(self) -> LairInvestigation:
        ids = [step.id for step in self.causal_trace]
        if len(ids) != len(set(ids)):
            raise ValueError("LAIR causal trace step ids must be unique")
        kinds = [step.kind for step in self.causal_trace]
        if kinds[0] not in {LairTraceKind.ATTACK_SOURCE, LairTraceKind.ENTRY_POINT}:
            raise ValueError("LAIR causal trace must begin at an attack source or entry point")
        try:
            operation_index = kinds.index(LairTraceKind.VULNERABLE_OPERATION)
        except ValueError as exc:
            raise ValueError("LAIR causal trace requires a vulnerable operation") from exc
        try:
            effect_index = kinds.index(LairTraceKind.SECURITY_EFFECT, operation_index + 1)
        except ValueError as exc:
            raise ValueError(
                "LAIR causal trace requires a security effect after the vulnerable operation"
            ) from exc
        if effect_index != len(kinds) - 1:
            raise ValueError("LAIR causal trace must terminate at the security effect")
        return self


class LairChallengeCheck(_StrictModel):
    assumption: str = Field(min_length=20)
    conclusion: str = Field(min_length=20)
    evidence: list[LairCitation] = Field(min_length=1)


class LairRegressionTest(_StrictModel):
    status: Literal["present_in_fix", "proposed"]
    description: str = Field(min_length=10)
    expected_result: str = Field(min_length=10)


class LairFixValidation(_StrictModel):
    strategy: str = Field(min_length=20)
    behavior_before: str = Field(min_length=20)
    behavior_after: str = Field(min_length=20)
    changed_files: list[str] = Field(min_length=1)
    evidence: list[LairCitation] = Field(min_length=1)
    regression_tests: list[LairRegressionTest] = Field(min_length=1)


class LairChallenge(_StrictModel):
    id: Literal["challenge"]
    verdict: Literal["confirmed"]
    checks: list[LairChallengeCheck] = Field(min_length=1)
    fix_validation: LairFixValidation


class LairAgentChain(_StrictModel):
    discovery: LairDiscovery
    investigation: LairInvestigation
    challenge: LairChallenge

    @model_validator(mode="after")
    def _validate_evidence_revisions(self) -> LairAgentChain:
        vulnerable_groups = [
            self.discovery.candidate.evidence,
            *(step.evidence for step in self.investigation.causal_trace),
            *(check.evidence for check in self.challenge.checks),
        ]
        if any(
            citation.revision != LairRevision.VULNERABLE
            for group in vulnerable_groups
            for citation in group
        ):
            raise ValueError("LAIR discovery, investigation, and challenge must cite vulnerable")
        if any(
            citation.revision != LairRevision.FIX
            for citation in self.challenge.fix_validation.evidence
        ):
            raise ValueError("LAIR fix validation must cite the fixed revision")
        return self


class LairGoldenChain(_StrictModel):
    schema_version: Literal["cwpro.cve-golden-chain.v2"]
    cve: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]+$")
    repo: str = Field(min_length=1)
    vulnerable_commit: str = Field(pattern=r"^[0-9a-fA-F]{7,64}$")
    fix_commit: str = Field(pattern=r"^[0-9a-fA-F]{7,64}$")
    title: str = Field(min_length=1)
    vulnerability_class: str = Field(min_length=1)
    summary: str = Field(min_length=20)
    chain: LairAgentChain


class RouterObligation(str, Enum):
    ATTACKER_REACHES_ENTRY = "attacker_reaches_entry"
    INPUT_REACHES_OPERATION = "input_reaches_operation"
    RELEVANT_GUARDS_RESOLVED = "relevant_guards_resolved"
    OPERATION_REACHES_SECURITY_EFFECT = "operation_reaches_security_effect"
    CANDIDATE_SURVIVES_CHALLENGE = "candidate_survives_challenge"


class RouterContextCategory(str, Enum):
    INPUT_BOUNDARY_AND_CALLERS = "input_boundary_and_callers"
    DATAFLOW_AND_TRANSFERS = "dataflow_and_transfers"
    STATE_WRITERS_AND_REPRESENTATION = "state_writers_and_representation"
    GUARDS_AND_CONTROL_FLOW = "guards_and_control_flow"
    OPERATION_AND_SECURITY_EFFECT = "operation_and_security_effect"
    COUNTEREVIDENCE = "counterevidence"


class RouterState(_StrictModel):
    phase: Literal["investigation", "challenge"]
    completed_trace_kinds: list[LairTraceKind]
    completed_obligations: list[RouterObligation]


class RouterTarget(_StrictModel):
    action: Literal["request_context", "challenge_candidate"]
    next_trace_kind: LairTraceKind | None
    next_obligation: RouterObligation
    context_category: RouterContextCategory


class RouterTrainingRow(_StrictModel):
    schema_version: Literal["cw.sourcehunt.lair-router-row.v1"] = (
        "cw.sourcehunt.lair-router-row.v1"
    )
    state: RouterState
    target: RouterTarget


class LairSplitConfig(_StrictModel):
    train: float = Field(default=0.70, ge=0.0, le=1.0)
    development: float = Field(default=0.15, ge=0.0, le=1.0)
    test: float = Field(default=0.15, ge=0.0, le=1.0)
    seed: str = Field(default="lair-sourcehunt-v1", min_length=1)

    @model_validator(mode="after")
    def _validate_total(self) -> LairSplitConfig:
        if abs(self.train + self.development + self.test - 1.0) > 1e-9:
            raise ValueError("LAIR split fractions must sum to 1.0")
        return self

    def assign(self, repository: str) -> Literal["train", "development", "test"]:
        digest = hashlib.sha256(f"{self.seed}\0{_normalize_repository(repository)}".encode()).digest()
        bucket = int.from_bytes(digest[:8], "big") / 2**64
        if bucket < self.train:
            return "train"
        if bucket < self.train + self.development:
            return "development"
        return "test"


class LairSplitSummary(_StrictModel):
    golden_count: int = Field(ge=0)
    repository_count: int = Field(ge=0)
    row_count: int = Field(ge=0)
    file: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class LairAdapterManifest(_StrictModel):
    schema_version: Literal["cw.sourcehunt.lair-adapter-manifest.v1"] = (
        "cw.sourcehunt.lair-adapter-manifest.v1"
    )
    source_schema_version: Literal["cwpro.cve-golden-chain.v2"] = (
        "cwpro.cve-golden-chain.v2"
    )
    corpus_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    split_seed: str
    split_fractions: dict[str, float]
    reserved_repository_names: list[str]
    golden_count: int = Field(ge=0)
    excluded_golden_count: int = Field(ge=0)
    router_row_count: int = Field(ge=0)
    splits: dict[str, LairSplitSummary]


class LairLeakage(_StrictModel):
    row_index: int = Field(ge=0)
    value: str


class LairAdapterDataset(_StrictModel):
    rows: dict[str, list[RouterTrainingRow]]
    manifest: LairAdapterManifest


_TRACE_ROUTE: dict[LairTraceKind, tuple[RouterObligation, RouterContextCategory]] = {
    LairTraceKind.ATTACK_SOURCE: (
        RouterObligation.ATTACKER_REACHES_ENTRY,
        RouterContextCategory.INPUT_BOUNDARY_AND_CALLERS,
    ),
    LairTraceKind.ENTRY_POINT: (
        RouterObligation.ATTACKER_REACHES_ENTRY,
        RouterContextCategory.INPUT_BOUNDARY_AND_CALLERS,
    ),
    LairTraceKind.PROPAGATION: (
        RouterObligation.INPUT_REACHES_OPERATION,
        RouterContextCategory.DATAFLOW_AND_TRANSFERS,
    ),
    LairTraceKind.STATE_TRANSITION: (
        RouterObligation.INPUT_REACHES_OPERATION,
        RouterContextCategory.STATE_WRITERS_AND_REPRESENTATION,
    ),
    LairTraceKind.GUARD_FAILURE: (
        RouterObligation.RELEVANT_GUARDS_RESOLVED,
        RouterContextCategory.GUARDS_AND_CONTROL_FLOW,
    ),
    LairTraceKind.VULNERABLE_OPERATION: (
        RouterObligation.INPUT_REACHES_OPERATION,
        RouterContextCategory.OPERATION_AND_SECURITY_EFFECT,
    ),
    LairTraceKind.SECURITY_EFFECT: (
        RouterObligation.OPERATION_REACHES_SECURITY_EFFECT,
        RouterContextCategory.OPERATION_AND_SECURITY_EFFECT,
    ),
}

_ROUTER_VOCABULARY = {
    ROUTER_ROW_SCHEMA_VERSION,
    "investigation",
    "challenge",
    "request_context",
    "challenge_candidate",
    *(kind.value for kind in LairTraceKind),
    *(obligation.value for obligation in RouterObligation),
    *(category.value for category in RouterContextCategory),
}


def _normalize_repository(repository: str) -> str:
    value = repository.strip().lower().removesuffix(".git").rstrip("/")
    return value


def _repository_name(repository: str) -> str:
    return _normalize_repository(repository).rsplit("/", 1)[-1]


def _is_reserved(repository: str, reserved_names: set[str]) -> bool:
    normalized = _normalize_repository(repository)
    return normalized in reserved_names or _repository_name(normalized) in reserved_names


def _completed_obligations(
    kinds: list[LairTraceKind],
    before_index: int,
) -> list[RouterObligation]:
    last_index: dict[RouterObligation, int] = {}
    for index, kind in enumerate(kinds):
        last_index[_TRACE_ROUTE[kind][0]] = index
    return [
        obligation
        for obligation in RouterObligation
        if obligation != RouterObligation.CANDIDATE_SURVIVES_CHALLENGE
        and last_index.get(obligation, len(kinds)) < before_index
    ]


def _router_rows(
    golden: LairGoldenChain,
) -> list[RouterTrainingRow]:
    kinds = [step.kind for step in golden.chain.investigation.causal_trace]
    rows: list[RouterTrainingRow] = []
    for index, kind in enumerate(kinds):
        obligation, context_category = _TRACE_ROUTE[kind]
        rows.append(
            RouterTrainingRow(
                state=RouterState(
                    phase="investigation",
                    completed_trace_kinds=kinds[:index],
                    completed_obligations=_completed_obligations(kinds, index),
                ),
                target=RouterTarget(
                    action="request_context",
                    next_trace_kind=kind,
                    next_obligation=obligation,
                    context_category=context_category,
                ),
            )
        )
    rows.append(
        RouterTrainingRow(
            state=RouterState(
                phase="challenge",
                completed_trace_kinds=kinds,
                completed_obligations=_completed_obligations(kinds, len(kinds)),
            ),
            target=RouterTarget(
                action="challenge_candidate",
                next_trace_kind=None,
                next_obligation=RouterObligation.CANDIDATE_SURVIVES_CHALLENGE,
                context_category=RouterContextCategory.COUNTEREVIDENCE,
            ),
        )
    )
    return rows


def answer_bearing_terms(golden: LairGoldenChain) -> set[str]:
    terms = {
        golden.cve,
        golden.repo,
        _repository_name(golden.repo),
        golden.vulnerable_commit,
        golden.fix_commit,
        golden.title,
        golden.vulnerability_class,
        golden.summary,
        golden.chain.discovery.candidate.location,
    }
    citations = [
        *golden.chain.discovery.candidate.evidence,
        *(
            citation
            for step in golden.chain.investigation.causal_trace
            for citation in step.evidence
        ),
        *(citation for check in golden.chain.challenge.checks for citation in check.evidence),
        *golden.chain.challenge.fix_validation.evidence,
    ]
    for citation in citations:
        path = PurePosixPath(citation.path)
        terms.update({citation.path, path.name, path.stem, citation.excerpt})
        terms.update(
            token
            for token in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]{3,}\b", citation.excerpt)
            if "_" in token
        )
    location = golden.chain.discovery.candidate.location
    terms.update(part for part in re.split(r"[:/\\]", location) if len(part) >= 4)
    return {term.strip().casefold() for term in terms if term.strip()}


def _string_values(value: Any) -> list[str]:
    if isinstance(value, Mapping):
        return [text for child in value.values() for text in _string_values(child)]
    if isinstance(value, list):
        return [text for child in value for text in _string_values(child)]
    return [value.casefold()] if isinstance(value, str) else []


def lint_router_rows(
    rows: Iterable[RouterTrainingRow],
    goldens: Sequence[LairGoldenChain],
) -> list[LairLeakage]:
    """Return any direct answer-bearing string copied into router row values."""

    forbidden = set().union(*(answer_bearing_terms(golden) for golden in goldens))
    leaks: list[LairLeakage] = []
    for row_index, row in enumerate(rows):
        for value in _string_values(row.model_dump(mode="json")):
            # Every valid router row is composed entirely from this fixed,
            # case-independent ontology.  A source identifier such as
            # ``context`` may legitimately be a substring of an ontology value
            # such as ``request_context``; that collision is not copied case
            # information.  Continue to lint any non-ontology value so model
            # construction bypasses or future free-text fields fail closed.
            if value in _ROUTER_VOCABULARY:
                continue
            for term in forbidden:
                if term in value:
                    leaks.append(LairLeakage(row_index=row_index, value=term))
    return sorted(leaks, key=lambda leak: (leak.row_index, leak.value))


def adapt_lair_goldens(
    goldens: Sequence[LairGoldenChain],
    *,
    split_config: LairSplitConfig | None = None,
    reserved_repository_names: Iterable[str] = ("ffmpeg",),
) -> LairAdapterDataset:
    """Build repository-grouped, delexicalized routing rows from LAIR goldens."""

    config = split_config or LairSplitConfig()
    identifiers = [golden.cve for golden in goldens]
    duplicates = sorted(name for name, count in Counter(identifiers).items() if count > 1)
    if duplicates:
        raise ValueError("Duplicate LAIR goldens: " + ", ".join(duplicates))

    reserved = {_normalize_repository(value) for value in reserved_repository_names}
    included = sorted(
        (golden for golden in goldens if not _is_reserved(golden.repo, reserved)),
        key=lambda golden: (golden.repo.casefold(), golden.cve),
    )
    rows: dict[str, list[RouterTrainingRow]] = {
        "train": [],
        "development": [],
        "test": [],
    }
    golden_counts: Counter[str] = Counter()
    repositories: dict[str, set[str]] = defaultdict(set)
    for golden in included:
        split = config.assign(golden.repo)
        golden_counts[split] += 1
        repositories[split].add(_normalize_repository(golden.repo))
        rows[split].extend(_router_rows(golden))

    all_rows = [row for split_rows in rows.values() for row in split_rows]
    leaks = lint_router_rows(all_rows, included)
    if leaks:
        preview = ", ".join(f"row {leak.row_index}={leak.value!r}" for leak in leaks[:5])
        raise ValueError(f"LAIR router rows contain answer-bearing strings: {preview}")

    source_payloads = [
        json.dumps(golden.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        for golden in sorted(included, key=lambda item: item.cve)
    ]
    corpus_digest = hashlib.sha256("\n".join(source_payloads).encode()).hexdigest()
    split_summaries = {
        split: LairSplitSummary(
            golden_count=golden_counts[split],
            repository_count=len(repositories[split]),
            row_count=len(split_rows),
            file=f"router/{split}.jsonl",
            sha256=_rows_digest(split_rows),
        )
        for split, split_rows in rows.items()
    }
    manifest = LairAdapterManifest(
        corpus_digest=corpus_digest,
        split_seed=config.seed,
        split_fractions={
            "train": config.train,
            "development": config.development,
            "test": config.test,
        },
        reserved_repository_names=sorted(reserved),
        golden_count=len(included),
        excluded_golden_count=len(goldens) - len(included),
        router_row_count=len(all_rows),
        splits=split_summaries,
    )
    return LairAdapterDataset(rows=rows, manifest=manifest)


def _row_json(row: RouterTrainingRow) -> str:
    return json.dumps(row.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


def _rows_digest(rows: Sequence[RouterTrainingRow]) -> str:
    payload = "".join(f"{_row_json(row)}\n" for row in rows)
    return hashlib.sha256(payload.encode()).hexdigest()


def load_lair_goldens(path: str | Path) -> list[LairGoldenChain]:
    """Load collected ``GoldenChain`` JSON files from a LAIR output directory."""

    source = Path(path).expanduser()
    if source.is_file():
        files = [source]
    else:
        golden_root = source / "goldens" if (source / "goldens").is_dir() else source
        files = sorted(golden_root.glob("CVE-*.json"))
    if not files:
        raise ValueError(f"No LAIR CVE golden JSON files found under {source}")
    return [
        LairGoldenChain.model_validate(json.loads(file.read_text(encoding="utf-8")))
        for file in files
    ]


def write_lair_adapter_dataset(
    dataset: LairAdapterDataset,
    output_dir: str | Path,
    *,
    overwrite: bool = False,
) -> Path:
    """Write audited router splits and a non-answer-bearing manifest."""

    output = Path(output_dir).expanduser()
    targets = [output / summary.file for summary in dataset.manifest.splits.values()]
    targets.append(output / "manifest.json")
    existing = [path for path in targets if path.exists()]
    if existing and not overwrite:
        raise FileExistsError(f"Refusing to overwrite LAIR adapter output: {existing[0]}")
    (output / "router").mkdir(parents=True, exist_ok=True)
    for split, rows in dataset.rows.items():
        target = output / dataset.manifest.splits[split].file
        target.write_text("".join(f"{_row_json(row)}\n" for row in rows), encoding="utf-8")
    manifest_path = output / "manifest.json"
    manifest_path.write_text(
        json.dumps(dataset.manifest.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest_path


__all__ = [
    "ADAPTER_MANIFEST_SCHEMA_VERSION",
    "LAIR_SCHEMA_VERSION",
    "ROUTER_ROW_SCHEMA_VERSION",
    "LairAdapterDataset",
    "LairAdapterManifest",
    "LairGoldenChain",
    "LairLeakage",
    "LairSplitConfig",
    "LairTraceKind",
    "RouterContextCategory",
    "RouterObligation",
    "RouterTrainingRow",
    "adapt_lair_goldens",
    "answer_bearing_terms",
    "lint_router_rows",
    "load_lair_goldens",
    "write_lair_adapter_dataset",
]
