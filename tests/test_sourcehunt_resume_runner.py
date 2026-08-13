from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from clearwing.llm import ProviderExhaustedError
from clearwing.sourcehunt.preprocessor import PreprocessResult
from clearwing.sourcehunt.resume import SourceHuntResumeError, SourceHuntResumeStore
from clearwing.sourcehunt.runner import SourceHuntRunner


def _target(repo: Path, name: str) -> dict:
    return {
        "path": name,
        "absolute_path": str(repo / name),
        "surface": 0,
        "influence": 0,
        "reachability": 3,
        "priority": 0.0,
        "tier": "C",
        "tags": [],
        "language": "python",
        "loc": 1,
        "surface_rationale": "",
        "influence_rationale": "",
        "reachability_rationale": "",
        "static_hint": 0,
        "semgrep_hint": 0,
        "taint_hits": 0,
        "imports_by": 0,
        "transitive_callers": 0,
        "defines_constants": False,
        "has_fuzz_entry_point": False,
        "fuzz_harness_path": None,
    }


def _preprocess(repo: Path, names: tuple[str, ...] = ("a.py", "b.py")) -> PreprocessResult:
    repo.mkdir(parents=True, exist_ok=True)
    for name in names:
        path = repo / name
        if not path.exists():
            path.write_text(f"value = {name!r}\n", encoding="utf-8")
    return PreprocessResult(
        repo_path=str(repo),
        file_targets=[_target(repo, name) for name in names],
        static_findings=[],
    )


def _runner(repo: Path, output: Path, **overrides) -> SourceHuntRunner:
    options = {
        "repo_url": str(repo),
        "local_path": str(repo),
        "depth": "standard",
        "output_dir": str(output),
        "max_parallel": 1,
        "ranker_llm": SimpleNamespace(provider_name="test"),
        "hunter_llm": object(),
        "sandbox_factory": lambda: None,
        "no_verify": True,
        "no_exploit": True,
        "enable_calibration": False,
        "enable_mechanism_memory": False,
        "enable_patch_oracle": False,
        "enable_stability_verification": False,
        "enable_variant_loop": False,
        "enable_knowledge_graph": False,
        "enable_findings_pool": False,
        "enable_behavior_monitor": False,
    }
    options.update(overrides)
    return SourceHuntRunner(**options)


def _prepare(runner: SourceHuntRunner, result: PreprocessResult, monkeypatch) -> None:
    monkeypatch.setattr(runner, "_preprocess", lambda: result)
    monkeypatch.setattr(runner, "_ensure_sandbox_factory", lambda *_args: None)
    monkeypatch.setattr(runner, "_write_report", lambda **_kwargs: {})


class _EmptyPool:
    def __init__(self, config):
        self.config = config
        self.spent_per_tier = {"A": 0.0, "B": 0.0, "C": 0.0}
        self.spent_per_band = {"fast": 0.0, "standard": 0.0, "deep": 0.0}
        self.runs_per_band = {"fast": 0, "standard": 0, "deep": 0}
        self.promotion_counts = {"fast→standard": 0, "standard→deep": 0}
        self.total_spent = 0.0
        self.budget_exhausted = False

    @property
    def completed_target_count(self):
        return self.config.resume_store.completed_target_count()

    async def arun(self):
        return self.config.resume_store.completed_findings()


def test_partial_ranking_restarts_from_pristine_inputs(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    output = tmp_path / "output"
    preprocess = _preprocess(repo)
    runner = _runner(repo, output)
    _prepare(runner, preprocess, monkeypatch)
    calls: list[list[float]] = []

    async def rank(self, files):
        calls.append([target["priority"] for target in files])
        files[0]["priority"] = 5.0
        if len(calls) == 1:
            raise KeyboardInterrupt
        for index, target in enumerate(files):
            target["surface"] = 5 - index
            target["influence"] = 4
            target["priority"] = 4.3 - index
        self.completed_successfully = True
        return files

    monkeypatch.setattr("clearwing.sourcehunt.runner.Ranker.arank", rank)
    monkeypatch.setattr("clearwing.sourcehunt.runner.HunterPool", _EmptyPool)

    with pytest.raises(KeyboardInterrupt):
        runner.run()

    store = SourceHuntResumeStore.load(output / runner.session_id)
    assert store.load_rank_plan() is None

    resumed = SourceHuntRunner.resume(runner.session_id, output_dir=str(output))
    resumed.ranker_llm = SimpleNamespace(provider_name="test")
    resumed.hunter_llm = object()
    _prepare(resumed, _preprocess(repo), monkeypatch)
    result = resumed.run()

    assert result.status == "completed"
    assert calls == [[0.0, 0.0], [0.0, 0.0]]
    assert [target["priority"] for target in store.load_rank_plan()] == [4.3, 3.3]


def test_completed_rank_plan_is_restored_without_ranking(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    output = tmp_path / "output"
    runner = _runner(repo, output)
    _prepare(runner, _preprocess(repo), monkeypatch)
    captured: list[list[dict]] = []

    async def rank(self, files):
        for index, target in enumerate(files):
            target["surface"] = 5 - index
            target["influence"] = index + 1
            target["priority"] = 4.75 - index
            target["surface_rationale"] = f"rank-{index}"
        self.completed_successfully = True
        return files

    class CapturingPool(_EmptyPool):
        async def arun(self):
            captured.append([dict(target) for target in self.config.files])
            return []

    monkeypatch.setattr("clearwing.sourcehunt.runner.Ranker.arank", rank)
    monkeypatch.setattr("clearwing.sourcehunt.runner.HunterPool", CapturingPool)
    runner.run()
    saved = SourceHuntResumeStore.load(output / runner.session_id).load_rank_plan()

    async def should_not_rank(self, files):
        raise AssertionError("completed rank plan must be reused")

    resumed = SourceHuntRunner.resume(runner.session_id, output_dir=str(output))
    resumed.hunter_llm = object()
    _prepare(resumed, _preprocess(repo), monkeypatch)
    monkeypatch.setattr("clearwing.sourcehunt.runner.Ranker.arank", should_not_rank)
    resumed.run()

    restored = [
        {key: value for key, value in target.items() if key != "absolute_path"}
        for target in captured[-1]
    ]
    assert restored == saved


def test_degraded_ranking_is_not_committed(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    output = tmp_path / "output"
    runner = _runner(repo, output)
    _prepare(runner, _preprocess(repo), monkeypatch)

    async def degraded_rank(self, files):
        for target in files:
            target["surface"] = 3
            target["influence"] = 2
            target["priority"] = 2.8
        self.completed_successfully = False
        return files

    monkeypatch.setattr("clearwing.sourcehunt.runner.Ranker.arank", degraded_rank)
    monkeypatch.setattr("clearwing.sourcehunt.runner.HunterPool", _EmptyPool)

    runner.run()

    assert SourceHuntResumeStore.load(output / runner.session_id).load_rank_plan() is None


def test_provider_exhaustion_is_resumable_with_replacement_provider(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    output = tmp_path / "output"
    preprocess = _preprocess(repo, ("a.py", "b.py", "c.py"))
    calls: list[tuple[str, str]] = []
    active_provider = "old"

    class Provider:
        def __init__(self, name):
            self.name = name

        def get_native_client(self, _task):
            return self

    def build_hunter_agent(*, file_target, **_kwargs):
        calls.append((active_provider, file_target["path"]))

        class Hunter:
            async def arun(self):
                if active_provider == "old" and file_target["path"] == "b.py":
                    raise ProviderExhaustedError("old credentials exhausted")
                return SimpleNamespace(
                    findings=[], cost_usd=0.0, tokens_used=0, stop_reason="completed"
                )

        return Hunter(), MagicMock(cleanup_variants=MagicMock())

    monkeypatch.setattr("clearwing.sourcehunt.hunter.build_hunter_agent", build_hunter_agent)
    monkeypatch.setattr("clearwing.sourcehunt.pool._DEFAULT_HUNTER_FACTORY", build_hunter_agent)
    runner = _runner(
        repo,
        output,
        no_rank=True,
        ranker_llm=None,
        hunter_llm=None,
        provider_manager=Provider("old"),
    )
    _prepare(runner, preprocess, monkeypatch)
    first = runner.run()

    assert first.status == "provider_exhausted"
    assert calls == [("old", "a.py"), ("old", "b.py")]
    store = SourceHuntResumeStore.load(output / runner.session_id)
    assert {item.file for item in store.load_completed_work().values()} == {"a.py"}

    active_provider = "replacement"
    resumed = SourceHuntRunner.resume(
        runner.session_id,
        output_dir=str(output),
        provider_manager=Provider("replacement"),
    )
    _prepare(resumed, _preprocess(repo, ("a.py", "b.py", "c.py")), monkeypatch)
    second = resumed.run()

    assert second.status == "completed"
    assert calls[-2:] == [("replacement", "b.py"), ("replacement", "c.py")]
    reloaded = SourceHuntResumeStore.load(output / runner.session_id)
    assert {item.file for item in reloaded.load_completed_work().values()} == {
        "a.py",
        "b.py",
        "c.py",
    }


def test_reporting_may_rerun_without_new_work_results(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    output = tmp_path / "output"
    runner = _runner(repo, output, no_rank=True)
    _prepare(runner, _preprocess(repo), monkeypatch)
    hunter_runs = 0

    def build_hunter_agent(**_kwargs):
        nonlocal hunter_runs
        hunter_runs += 1

        class Hunter:
            async def arun(self):
                return SimpleNamespace(
                    findings=[], cost_usd=0.0, tokens_used=0, stop_reason="completed"
                )

        return Hunter(), MagicMock(cleanup_variants=MagicMock())

    monkeypatch.setattr("clearwing.sourcehunt.hunter.build_hunter_agent", build_hunter_agent)
    monkeypatch.setattr("clearwing.sourcehunt.pool._DEFAULT_HUNTER_FACTORY", build_hunter_agent)
    reports = 0

    def report(**_kwargs):
        nonlocal reports
        reports += 1
        return {}

    monkeypatch.setattr(runner, "_write_report", report)
    runner.run()
    store = SourceHuntResumeStore.load(output / runner.session_id)
    before = sorted(store.work_results_dir.glob("*.json"))

    resumed = SourceHuntRunner.resume(runner.session_id, output_dir=str(output))
    resumed.hunter_llm = object()
    _prepare(resumed, _preprocess(repo), monkeypatch)
    monkeypatch.setattr(resumed, "_write_report", report)
    resumed.run()

    assert reports == 2
    assert hunter_runs == 2
    assert len(before) == 2
    assert sorted(store.work_results_dir.glob("*.json")) == before


def test_completed_findings_are_returned_when_hunting_is_disabled_on_resume(
    tmp_path,
    monkeypatch,
):
    repo = tmp_path / "repo"
    output = tmp_path / "output"
    runner = _runner(repo, output, no_rank=True)
    _prepare(runner, _preprocess(repo, ("a.py",)), monkeypatch)

    from clearwing.findings.types import Finding

    finding = Finding(id="restored", file="a.py", description="saved")

    def build_hunter_agent(**_kwargs):
        class Hunter:
            async def arun(self):
                return SimpleNamespace(
                    findings=[finding],
                    cost_usd=0.0,
                    tokens_used=0,
                    stop_reason="completed",
                )

        return Hunter(), MagicMock(cleanup_variants=MagicMock())

    monkeypatch.setattr("clearwing.sourcehunt.hunter.build_hunter_agent", build_hunter_agent)
    monkeypatch.setattr("clearwing.sourcehunt.pool._DEFAULT_HUNTER_FACTORY", build_hunter_agent)
    runner.run()

    resumed = SourceHuntRunner.resume(runner.session_id, output_dir=str(output))
    resumed._no_per_file_hunt = True
    _prepare(resumed, _preprocess(repo, ("a.py",)), monkeypatch)

    result = resumed.run()

    assert [item.id for item in result.findings] == ["restored"]
    assert result.files_hunted == 1


def test_runner_rejects_concurrent_resume_and_releases_lock(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    output = tmp_path / "output"
    runner = _runner(repo, output, no_rank=True)
    _prepare(runner, _preprocess(repo), monkeypatch)
    monkeypatch.setattr("clearwing.sourcehunt.runner.HunterPool", _EmptyPool)
    runner.run()

    session_dir = output / runner.session_id
    from clearwing.sourcehunt.resume import SourceHuntSessionLock

    held = SourceHuntSessionLock(session_dir)
    held.acquire()
    try:
        with pytest.raises(SourceHuntResumeError, match="already running"):
            SourceHuntRunner.resume(runner.session_id, output_dir=str(output)).run()
    finally:
        held.release()

    resumed = SourceHuntRunner.resume(runner.session_id, output_dir=str(output))
    resumed.hunter_llm = object()
    _prepare(resumed, _preprocess(repo), monkeypatch)
    assert resumed.run().status == "completed"


def test_session_output_is_excluded_but_source_change_rejects_resume(tmp_path):
    repo = tmp_path / "repo"
    output = repo / "results"
    source = repo / "app.py"
    repo.mkdir()
    source.write_text("value = 1\n", encoding="utf-8")
    runner = SourceHuntRunner(
        repo_url=str(repo),
        local_path=str(repo),
        depth="quick",
        no_rank=True,
        output_dir=str(output),
        enable_knowledge_graph=False,
    )
    first = runner.run()
    session_dir = output / runner.session_id
    (session_dir / "generated.py").write_text("generated = True\n", encoding="utf-8")

    unchanged = SourceHuntRunner.resume(runner.session_id, output_dir=str(output)).run()
    assert unchanged.status == "completed"

    source.write_text("value = 2\n", encoding="utf-8")
    with pytest.raises(SourceHuntResumeError, match="source inputs changed"):
        SourceHuntRunner.resume(runner.session_id, output_dir=str(output)).run()

    session = json.loads(Path(first.output_paths["session"]).read_text(encoding="utf-8"))
    assert session["source_identity"]["paths"] == ["app.py"]


def test_parent_owned_campaign_run_does_not_create_standalone_resume_state(
    tmp_path,
    monkeypatch,
):
    repo = tmp_path / "repo"
    output = tmp_path / "output"
    runner = _runner(
        repo,
        output,
        parent_session_id="campaign-parent-project",
        depth="quick",
        no_rank=True,
        ranker_llm=None,
        hunter_llm=None,
    )
    _prepare(runner, _preprocess(repo, ("a.py",)), monkeypatch)

    result = runner.run()

    assert result.status == "completed"
    assert "session" not in result.output_paths
    assert not (output / runner.session_id / "session.json").exists()
