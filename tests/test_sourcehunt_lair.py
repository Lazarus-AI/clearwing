"""Leakage and split invariants for LAIR-to-SourceHunt supervision."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from clearwing.eval.sourcehunt_lair import (
    LairGoldenChain,
    LairSplitConfig,
    RouterContextCategory,
    RouterObligation,
    adapt_lair_goldens,
    lint_router_rows,
    load_lair_goldens,
    write_lair_adapter_dataset,
)


def _citation(revision: str, path: str, line: int, excerpt: str) -> dict:
    return {
        "revision": revision,
        "path": path,
        "line_start": line,
        "line_end": line,
        "excerpt": excerpt,
        "supports": "This exact source line supports the causal step.",
    }


def _golden_payload(
    *,
    cve: str = "CVE-2099-1001",
    repo: str = "example/parser",
    vulnerable: str = "1" * 40,
    fix: str = "2" * 40,
) -> dict:
    vulnerable_path = "src/secret_parser.c"
    fixed_path = "src/secret_parser.c"
    return {
        "schema_version": "cwpro.cve-golden-chain.v2",
        "cve": cve,
        "repo": repo,
        "vulnerable_commit": vulnerable,
        "fix_commit": fix,
        "title": "Secret sentinel collision",
        "vulnerability_class": "CWE-787 Out-of-bounds Write",
        "summary": "An attacker-controlled counter collides with a reserved sentinel value.",
        "chain": {
            "discovery": {
                "id": "discovery",
                "candidate": {
                    "title": "Secret counter collision",
                    "location": "src/secret_parser.c:parse_secret",
                    "hypothesis": "A remote counter may collide with a reserved internal value.",
                    "why_prioritize": "The same representation is used for state and a boundary marker.",
                    "evidence": [
                        _citation(
                            "vulnerable",
                            vulnerable_path,
                            10,
                            "state->secret_slot = remote_counter;",
                        )
                    ],
                },
            },
            "investigation": {
                "id": "investigation",
                "preconditions": ["A remote peer can repeatedly advance the secret counter."],
                "causal_trace": [
                    {
                        "id": "input",
                        "kind": "attack_source",
                        "claim": "A remote packet controls the initial counter update.",
                        "evidence": [
                            _citation(
                                "vulnerable", vulnerable_path, 4, "parse_secret(packet);"
                            )
                        ],
                    },
                    {
                        "id": "copy",
                        "kind": "propagation",
                        "claim": "The remote value propagates into a local counter.",
                        "evidence": [
                            _citation(
                                "vulnerable",
                                vulnerable_path,
                                8,
                                "remote_counter = packet->counter;",
                            )
                        ],
                    },
                    {
                        "id": "store",
                        "kind": "state_transition",
                        "claim": "The counter is stored in the secret slot representation.",
                        "evidence": [
                            _citation(
                                "vulnerable",
                                vulnerable_path,
                                10,
                                "state->secret_slot = remote_counter;",
                            )
                        ],
                    },
                    {
                        "id": "guard",
                        "kind": "guard_failure",
                        "claim": "No terminating guard excludes the reserved representation.",
                        "evidence": [
                            _citation(
                                "vulnerable",
                                vulnerable_path,
                                11,
                                "if (state->secret_slot == SECRET_SENTINEL) {",
                            )
                        ],
                    },
                    {
                        "id": "write",
                        "kind": "vulnerable_operation",
                        "claim": "The sentinel branch performs a write through a shifted pointer.",
                        "evidence": [
                            _citation(
                                "vulnerable", vulnerable_path, 12, "shifted[-1] = packet->byte;"
                            )
                        ],
                    },
                    {
                        "id": "effect",
                        "kind": "security_effect",
                        "claim": "The shifted write can modify memory outside the destination.",
                        "evidence": [
                            _citation(
                                "vulnerable", vulnerable_path, 12, "shifted[-1] = packet->byte;"
                            )
                        ],
                    },
                ],
                "security_impact": "A remote peer can cause an out-of-bounds memory write.",
            },
            "challenge": {
                "id": "challenge",
                "verdict": "confirmed",
                "checks": [
                    {
                        "assumption": "A caller may reject the reserved counter before parsing.",
                        "conclusion": "All callers forward the remote counter without that rejection.",
                        "evidence": [
                            _citation(
                                "vulnerable", vulnerable_path, 4, "parse_secret(packet);"
                            )
                        ],
                    }
                ],
                "fix_validation": {
                    "strategy": "Reject the reserved value before storing the remote counter.",
                    "behavior_before": "The reserved value reached the shifted pointer write.",
                    "behavior_after": "The reserved value returns an error before state mutation.",
                    "changed_files": [fixed_path],
                    "evidence": [
                        _citation(
                            "fix",
                            fixed_path,
                            9,
                            "if (remote_counter == SECRET_SENTINEL) return ERROR;",
                        )
                    ],
                    "regression_tests": [
                        {
                            "status": "proposed",
                            "description": "Send the reserved remote counter value.",
                            "expected_result": "Parsing fails without writing through shifted.",
                        }
                    ],
                },
            },
        },
    }


def _golden(**kwargs: str) -> LairGoldenChain:
    return LairGoldenChain.model_validate(_golden_payload(**kwargs))


def test_adapter_emits_only_delexicalized_routing_state() -> None:
    golden = _golden()
    dataset = adapt_lair_goldens(
        [golden],
        split_config=LairSplitConfig(train=1.0, development=0.0, test=0.0),
    )
    rows = dataset.rows["train"]

    assert len(rows) == len(golden.chain.investigation.causal_trace) + 1
    assert rows[0].target.next_obligation == RouterObligation.ATTACKER_REACHES_ENTRY
    assert rows[2].target.context_category == (
        RouterContextCategory.STATE_WRITERS_AND_REPRESENTATION
    )
    assert rows[-1].target.next_obligation == RouterObligation.CANDIDATE_SURVIVES_CHALLENGE
    assert lint_router_rows(rows, [golden]) == []

    serialized = "\n".join(row.model_dump_json() for row in rows).casefold()
    for forbidden in (
        "cve-2099-1001",
        "example/parser",
        "secret_parser.c",
        "parse_secret",
        "secret_sentinel",
        "out-of-bounds",
        "111111111111",
        "222222222222",
    ):
        assert forbidden not in serialized


def test_leakage_linter_rejects_answer_bearing_identifier() -> None:
    golden = _golden()
    dataset = adapt_lair_goldens(
        [golden],
        split_config=LairSplitConfig(train=1.0, development=0.0, test=0.0),
    )
    clean = dataset.rows["train"][0]
    leaked = clean.model_copy(
        update={"target": clean.target.model_copy(update={"action": "src/secret_parser.c"})}
    )

    leaks = lint_router_rows([leaked], [golden])

    assert leaks
    assert any(leak.value == "secret_parser.c" for leak in leaks)


def test_leakage_linter_allows_source_identifier_collision_with_router_ontology() -> None:
    payload = _golden_payload()
    payload["chain"]["investigation"]["causal_trace"][0]["evidence"][0]["excerpt"] = (
        "context = packet->counter;"
    )
    golden = LairGoldenChain.model_validate(payload)

    dataset = adapt_lair_goldens(
        [golden],
        split_config=LairSplitConfig(train=1.0, development=0.0, test=0.0),
    )

    assert dataset.manifest.router_row_count == 7
    assert lint_router_rows(dataset.rows["train"], [golden]) == []


def test_repository_groups_never_cross_splits() -> None:
    goldens = [
        _golden(cve="CVE-2099-1001", repo="org/shared", vulnerable="1" * 40, fix="2" * 40),
        _golden(cve="CVE-2099-1002", repo="org/shared", vulnerable="3" * 40, fix="4" * 40),
        _golden(cve="CVE-2099-1003", repo="org/other", vulnerable="5" * 40, fix="6" * 40),
    ]
    config = LairSplitConfig(seed="stable-test")
    dataset = adapt_lair_goldens(goldens, split_config=config)
    shared_split = config.assign("org/shared")

    assert dataset.manifest.splits[shared_split].golden_count >= 2
    assert sum(summary.repository_count for summary in dataset.manifest.splits.values()) == 2


def test_ffmpeg_is_excluded_from_optimization_rows() -> None:
    dataset = adapt_lair_goldens(
        [
            _golden(repo="FFmpeg/FFmpeg"),
            _golden(
                cve="CVE-2099-1002",
                repo="example/other",
                vulnerable="3" * 40,
                fix="4" * 40,
            ),
        ],
        split_config=LairSplitConfig(train=1.0, development=0.0, test=0.0),
    )

    assert dataset.manifest.golden_count == 1
    assert dataset.manifest.excluded_golden_count == 1
    assert len(dataset.rows["train"]) == 7


def test_loader_writer_and_manifest_digests_are_reproducible(tmp_path: Path) -> None:
    golden_root = tmp_path / "source" / "goldens"
    golden_root.mkdir(parents=True)
    source = golden_root / "CVE-2099-1001.json"
    source.write_text(json.dumps(_golden_payload()), encoding="utf-8")

    goldens = load_lair_goldens(tmp_path / "source")
    first = adapt_lair_goldens(
        goldens,
        split_config=LairSplitConfig(train=1.0, development=0.0, test=0.0),
    )
    second = adapt_lair_goldens(
        goldens,
        split_config=LairSplitConfig(train=1.0, development=0.0, test=0.0),
    )
    manifest_path = write_lair_adapter_dataset(first, tmp_path / "output")

    assert first == second
    assert manifest_path.is_file()
    assert len((tmp_path / "output" / "router" / "train.jsonl").read_text().splitlines()) == 7
    assert json.loads(manifest_path.read_text())["corpus_digest"] == (
        first.manifest.corpus_digest
    )
    with pytest.raises(FileExistsError, match="Refusing to overwrite"):
        write_lair_adapter_dataset(first, tmp_path / "output")


def test_duplicate_cves_and_invalid_split_fractions_fail_closed() -> None:
    with pytest.raises(ValueError, match="sum to 1.0"):
        LairSplitConfig(train=0.8, development=0.2, test=0.2)
    with pytest.raises(ValueError, match="Duplicate LAIR goldens"):
        adapt_lair_goldens([_golden(), _golden()])
