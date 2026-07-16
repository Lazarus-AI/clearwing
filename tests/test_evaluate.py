from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from evaluations import evaluate as evals


def test_load_cases_filters_case_insensitively():
    path = evals.HERE / "cves.yaml"
    cases = evals.load_cases(path)

    assert len(cases) == 18
    assert {
        level: sum(c["difficulty"] == level for c in cases) for level in ("easy", "medium", "hard")
    } == {
        "easy": 5,
        "medium": 8,
        "hard": 5,
    }
    assert [c["cve"] for c in evals.load_cases(path, ["cve-2026-45445"], ["EASY"])] == [
        "CVE-2026-45445"
    ]


def test_subsystem_paths_preserves_order_and_removes_duplicates():
    case = {"sourcehunt": {"subsystem": "src"}, "files": ["src/a.c", "src"]}
    assert evals.subsystem_paths(case) == ["src", "src/a.c"]


class FakeJudge:
    def __init__(self, replies):
        self.replies = iter(replies)
        self.calls = 0

    async def achat_via_stream(self, model, request, options):
        self.calls += 1
        reply = next(self.replies)
        if isinstance(reply, Exception):
            raise reply
        return SimpleNamespace(first_text=reply, texts=[])


def judge_args(**overrides):
    return SimpleNamespace(
        judge_provider="openai_resp",
        judge_model="gpt-5.4",
        judge_timeout=1,
        judge_retries=3,
        **overrides,
    )


@pytest.mark.parametrize(
    ("reply", "expected"),
    [("PASS\nexact", ("PASS", 1.0)), ("PARTIAL: close", ("PARTIAL", 0.5)), ("FAIL", ("FAIL", 0.0))],
)
def test_judge_maps_explicit_verdicts(reply, expected):
    client = FakeJudge([reply])
    result = asyncio.run(
        evals.judge({"description": "bug"}, [{"file": "a.c"}], client, judge_args())
    )
    assert result[:2] == expected


def test_judge_retries_malformed_output(monkeypatch):
    async def no_sleep(_seconds):
        pass

    monkeypatch.setattr(evals.asyncio, "sleep", no_sleep)
    client = FakeJudge(["maybe", RuntimeError("offline"), "still maybe"])
    verdict, score, explanation = asyncio.run(
        evals.judge({"description": "bug"}, [{"file": "a.c"}], client, judge_args())
    )
    assert (verdict, score) == ("ERROR", None)
    assert "failed after 3 attempts" in explanation
    assert client.calls == 3


def test_empty_findings_do_not_call_judge():
    client = FakeJudge([])
    assert asyncio.run(evals.judge({}, [], client, judge_args())) == ("FAIL", 0.0, "MISSING")
    assert client.calls == 0


def test_hunt_forwards_configuration_and_cleans_clone(monkeypatch, tmp_path):
    cloned_paths = []
    runner_kwargs = {}

    def fake_clone(_url, _commit, dest):
        cloned_paths.append(Path(dest))

    class FakeRunner:
        def __init__(self, **kwargs):
            runner_kwargs.update(kwargs)

        async def arun(self):
            values = {name: 0 for name in evals.METRICS}
            values.update(
                cost_usd=1.25, session_id="session", spent_per_tier={}, status="completed"
            )
            return SimpleNamespace(findings=[{"file": "src/a.c"}], **values)

    monkeypatch.setattr(evals, "clone_commit", fake_clone)
    monkeypatch.setattr("clearwing.sourcehunt.runner.SourceHuntRunner", FakeRunner)
    args = SimpleNamespace(
        results_dir=tmp_path,
        depth="deep",
        agent_mode="deep",
        max_parallel=7,
        sandbox_cpus=2.0,
        budget_usd=9.0,
    )
    findings, metrics = asyncio.run(
        evals.hunt(
            {
                "cve": "CVE-X",
                "clone_url": "https://example.test/repo.git",
                "vulnerable_commit": "deadbeef",
                "sourcehunt": {"subsystem": "src"},
                "files": ["src/a.c"],
            },
            args,
        )
    )

    assert findings == [{"file": "src/a.c"}]
    assert metrics["cost_usd"] == 1.25
    assert runner_kwargs["max_parallel"] == 7
    assert runner_kwargs["budget_usd"] == 9.0
    assert runner_kwargs["subsystem_paths"] == ["src", "src/a.c"]
    assert cloned_paths and not cloned_paths[0].exists()
