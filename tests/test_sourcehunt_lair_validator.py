"""Differential replay tests for the LAIR validator harness."""

from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path

from clearwing.eval.sourcehunt_lair import LairGoldenChain
from clearwing.eval.sourcehunt_lair_validator import (
    SourceWindow,
    build_lair_validator_finding,
    render_revision_context,
    replay_lair_validator_case,
    source_windows_for_golden,
    summarize_lair_validator_replay,
)
from clearwing.sourcehunt.state import Axes, AxisResult, ValidatorVerdict


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout.strip()


def _replay_golden(repo: Path) -> LairGoldenChain:
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "config", "user.email", "test@example.invalid")
    source = repo / "src" / "secret_parser.c"
    source.parent.mkdir()
    vulnerable_lines = ["int filler = 0;" for _ in range(14)]
    vulnerable_lines[3] = "parse_secret(packet);"
    vulnerable_lines[7] = "remote_counter = packet->counter;"
    vulnerable_lines[9] = "state->secret_slot = remote_counter;"
    vulnerable_lines[10] = "if (state->secret_slot == SECRET_SENTINEL) {"
    vulnerable_lines[11] = "shifted[-1] = packet->byte;"
    source.write_text("\n".join(vulnerable_lines) + "\n", encoding="utf-8")
    _git(repo, "add", "src/secret_parser.c")
    _git(repo, "commit", "-qm", "vulnerable")
    vulnerable = _git(repo, "rev-parse", "HEAD")
    vulnerable_lines[8] = "if (remote_counter == SECRET_SENTINEL) return ERROR;"
    source.write_text("\n".join(vulnerable_lines) + "\n", encoding="utf-8")
    _git(repo, "add", "src/secret_parser.c")
    _git(repo, "commit", "-qm", "fixed")
    fix = _git(repo, "rev-parse", "HEAD")
    def citation(revision: str, line: int, excerpt: str) -> dict:
        return {
            "revision": revision,
            "path": "src/secret_parser.c",
            "line_start": line,
            "line_end": line,
            "excerpt": excerpt,
            "supports": "This exact source line supports the causal step.",
        }

    payload = {
        "schema_version": "cwpro.cve-golden-chain.v2",
        "cve": "CVE-2099-1001",
        "repo": "example/parser",
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
                    "why_prioritize": "The representation is shared by state and a boundary marker.",
                    "evidence": [
                        citation("vulnerable", 10, "state->secret_slot = remote_counter;")
                    ],
                },
            },
            "investigation": {
                "id": "investigation",
                "preconditions": ["A remote peer can supply the secret counter."],
                "causal_trace": [
                    {
                        "id": "input",
                        "kind": "attack_source",
                        "claim": "A remote packet reaches the secret parser entry point.",
                        "evidence": [citation("vulnerable", 4, "parse_secret(packet);")],
                    },
                    {
                        "id": "copy",
                        "kind": "propagation",
                        "claim": "The packet value propagates into the local counter.",
                        "evidence": [
                            citation("vulnerable", 8, "remote_counter = packet->counter;")
                        ],
                    },
                    {
                        "id": "write",
                        "kind": "vulnerable_operation",
                        "claim": "The reserved state causes a shifted pointer write.",
                        "evidence": [
                            citation("vulnerable", 12, "shifted[-1] = packet->byte;")
                        ],
                    },
                    {
                        "id": "effect",
                        "kind": "security_effect",
                        "claim": "The shifted write can modify memory outside the destination.",
                        "evidence": [
                            citation("vulnerable", 12, "shifted[-1] = packet->byte;")
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
                        "conclusion": "The caller forwards the packet without that rejection.",
                        "evidence": [citation("vulnerable", 4, "parse_secret(packet);")],
                    }
                ],
                "fix_validation": {
                    "strategy": "Reject the reserved counter before changing the state.",
                    "behavior_before": "The reserved value reached the shifted pointer write.",
                    "behavior_after": "The reserved value returns an error before state mutation.",
                    "changed_files": ["src/secret_parser.c"],
                    "evidence": [
                        citation(
                            "fix",
                            9,
                            "if (remote_counter == SECRET_SENTINEL) return ERROR;",
                        )
                    ],
                    "regression_tests": [
                        {
                            "status": "proposed",
                            "description": "Send the reserved remote counter value.",
                            "expected_result": "Parsing fails before the shifted write.",
                        }
                    ],
                },
            },
        },
    }
    return LairGoldenChain.model_validate(payload)


def _verdict(advance: bool) -> ValidatorVerdict:
    result = AxisResult(passed=advance, confidence="high", rationale="source-backed")
    return ValidatorVerdict(
        finding_id="test",
        axes=Axes(real=result, triggerable=result, impactful=result, general=result),
        advance=advance,
        severity_validated="high" if advance else None,
        evidence_level="static_corroboration",
        pro_argument="strong source chain",
        counter_argument="fixed guard",
        tie_breaker="current source snapshot",
        duplicate_cve=None,
    )


def test_same_finding_and_windows_are_used_for_both_revisions(tmp_path: Path) -> None:
    golden = _replay_golden(tmp_path / "repo")
    finding = build_lair_validator_finding(golden)
    windows = source_windows_for_golden(golden, radius=1)
    vulnerable = render_revision_context(tmp_path / "repo", golden.vulnerable_commit, windows)
    fixed = render_revision_context(tmp_path / "repo", golden.fix_commit, windows)

    assert finding.code_snippet == "shifted[-1] = packet->byte;"
    assert [window.path for window in windows] == ["src/secret_parser.c"]
    assert "return ERROR" not in vulnerable
    assert "return ERROR" in fixed


def test_renderer_balances_paths_and_centers_on_vulnerable_anchors(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "config", "user.email", "test@example.invalid")
    for name, marker in (("a.c", "FIRST_ANCHOR"), ("z.c", "LAST_ANCHOR")):
        lines = [f"int filler_{index};" for index in range(1, 81)]
        lines[39] = marker
        (repo / name).write_text("\n".join(lines) + "\n", encoding="utf-8")
    _git(repo, "add", "a.c", "z.c")
    _git(repo, "commit", "-qm", "source")
    revision = _git(repo, "rev-parse", "HEAD")
    windows = [
        SourceWindow(path="a.c", start=1, end=80, anchors=(40,)),
        SourceWindow(path="z.c", start=1, end=80, anchors=(40,)),
    ]

    context = render_revision_context(repo, revision, windows, max_chars=1200)

    assert "FIRST_ANCHOR" in context
    assert "LAST_ANCHOR" in context
    assert len(context) <= 1200


def test_renderer_uses_identical_line_selection_across_revisions(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "config", "user.email", "test@example.invalid")
    source = repo / "source.c"
    source.write_text(
        "\n".join(f"int old_{index};" for index in range(1, 101)) + "\n",
        encoding="utf-8",
    )
    _git(repo, "add", "source.c")
    _git(repo, "commit", "-qm", "old")
    old = _git(repo, "rev-parse", "HEAD")
    source.write_text(
        "\n".join(f"int new_{index}_with_longer_text;" for index in range(1, 101))
        + "\n",
        encoding="utf-8",
    )
    _git(repo, "add", "source.c")
    _git(repo, "commit", "-qm", "new")
    new = _git(repo, "rev-parse", "HEAD")
    windows = [SourceWindow(path="source.c", start=1, end=100, anchors=(50,))]

    old_context = render_revision_context(repo, old, windows, max_chars=1200)
    new_context = render_revision_context(repo, new, windows, max_chars=1200)
    old_lines = [line.split(":", 1)[0] for line in old_context.splitlines()[1:]]
    new_lines = [line.split(":", 1)[0] for line in new_context.splitlines()[1:]]

    assert old_lines == new_lines


def test_replay_scores_vulnerable_advance_and_fixed_rejection(tmp_path: Path) -> None:
    golden = _replay_golden(tmp_path / "repo")
    calls: list[tuple[str, str]] = []

    async def validate(finding, source_context):
        calls.append((finding.description, source_context))
        return _verdict("return ERROR" not in source_context)

    result = asyncio.run(replay_lair_validator_case(golden, tmp_path / "repo", validate))

    assert len(calls) == 2
    assert calls[0][0] == calls[1][0]
    assert result.vulnerable_correct is True
    assert result.fixed_correct is True
    assert result.pair_correct is True


def test_summary_reports_false_negatives_and_fixed_false_positives(tmp_path: Path) -> None:
    golden = _replay_golden(tmp_path / "repo")

    async def reject_both(_finding, _source_context):
        return _verdict(False)

    result = asyncio.run(
        replay_lair_validator_case(golden, tmp_path / "repo", reject_both)
    )
    summary = summarize_lair_validator_replay([result], model="small-model")

    assert summary.prompt_profile == "legacy-v1"
    assert summary.temperature is None
    assert summary.vulnerable_recall == 0.0
    assert summary.fixed_rejection_rate == 1.0
    assert summary.pair_accuracy == 0.0
    assert summary.vulnerable_false_negatives == 1
    assert summary.fixed_false_positives == 0


def test_model_error_is_never_scored_as_a_correct_fixed_rejection(tmp_path: Path) -> None:
    golden = _replay_golden(tmp_path / "repo")
    empty = ValidatorVerdict(
        finding_id="test",
        axes=Axes(),
        advance=False,
        severity_validated=None,
        evidence_level="suspicion",
        pro_argument="",
        counter_argument="",
        tie_breaker="validator error",
        duplicate_cve=None,
    )

    async def fail_both(_finding, _source_context):
        return empty

    result = asyncio.run(
        replay_lair_validator_case(golden, tmp_path / "repo", fail_both)
    )
    summary = summarize_lair_validator_replay([result], model="small-model")

    assert result.vulnerable.model_error is True
    assert result.fixed.model_error is True
    assert result.fixed_correct is False
    assert summary.fixed_rejection_rate == 0.0
    assert summary.fixed_false_positives == 1
    assert summary.model_errors == 2
