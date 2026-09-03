from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from clearwing.remediation.dynamic import SandboxPatchValidator
from clearwing.remediation.models import (
    DynamicValidation,
    FindingSnapshot,
    ProposedFix,
    RemediationDTO,
    ValidationVerdict,
)
from clearwing.remediation.panel import RemediationValidationPanel
from clearwing.remediation.policy import RemediationPolicy, analyze_unified_diff
from clearwing.remediation.store import RemediationStore
from clearwing.remediation.transaction import PatchTransaction, PatchTransactionError
from clearwing.remediation.workflow import RemediationWorkflow, load_findings
from clearwing.ui.cli import CLI

GOOD_DIFF = """diff --git a/src/a.c b/src/a.c
--- a/src/a.c
+++ b/src/a.c
@@ -1 +1 @@
-int value = 0;
+int value = 1;
"""

TWO_FILE_DIFF = (
    GOOD_DIFF
    + """diff --git a/src/b.c b/src/b.c
--- a/src/b.c
+++ b/src/b.c
@@ -1 +1 @@
-int other = 0;
+int other = 1;
"""
)


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=str(repo),
        capture_output=True,
        text=True,
        check=True,
    )
    return completed.stdout.strip()


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "a.c").write_text("int value = 0;\n", encoding="utf-8")
    _git(repo, "init", "-q")
    _git(repo, "add", "src/a.c")
    _git(
        repo,
        "-c",
        "user.name=Clearwing Tests",
        "-c",
        "user.email=tests@example.test",
        "commit",
        "-qm",
        "initial",
    )
    return repo


def _finding(**updates) -> dict:
    finding = {
        "id": "finding-1",
        "file": "src/a.c",
        "line_number": 1,
        "cwe": "CWE-787",
        "severity": "critical",
        "evidence_level": "root_cause_explained",
        "verified": True,
        "description": "attacker-controlled value is not checked",
        "code_snippet": "int value = 0;",
    }
    finding.update(updates)
    return finding


def _opinion(*, root_cause: bool = True) -> dict:
    signal = {"passed": True, "confidence": "high", "rationale": "passes"}
    return {
        "root_cause": {
            "passed": root_cause,
            "confidence": "high",
            "rationale": "root cause reviewed",
        },
        "bypass_resistance": signal,
        "regression_safety": signal,
        "minimality": signal,
        "recommendation": "pass" if root_cause else "fail",
    }


class _PanelClient:
    def __init__(self, response: dict | Exception):
        self.response = response

    async def aask_json(self, **_kwargs):
        if isinstance(self.response, Exception):
            raise self.response
        return self.response, SimpleNamespace()


class _RemediatorClient:
    def __init__(self, diff: str = GOOD_DIFF):
        self.diff = diff
        self.calls = 0

    async def aask_text(self, **_kwargs):
        self.calls += 1
        return SimpleNamespace(
            first_text=json.dumps(
                {
                    "diff": self.diff,
                    "commit_message": "bound the attacker-controlled value",
                    "explanation": "enforces the missing invariant",
                    "confidence": "high",
                }
            )
        )


class _WorkflowPanel:
    def __init__(self, status: str):
        self.status = status
        self.calls = 0

    async def validate(self, **_kwargs):
        self.calls += 1
        return ValidationVerdict(
            status=self.status,
            score=1.0 if self.status == "validated" else 0.4,
            threshold=0.8,
        )


def test_diff_policy_is_target_scoped_and_fail_closed(tmp_path: Path, monkeypatch) -> None:
    repo = _repo(tmp_path)
    finding = FindingSnapshot.from_finding(_finding())
    policy = RemediationPolicy()

    pre = policy.pre_generation(repo, finding)
    post, summary = policy.post_diff(repo, finding, GOOD_DIFF)
    assert pre.allowed is True
    assert post.allowed is True
    assert summary.touched_files == ["src/a.c"]
    assert summary.changed_lines == 2

    forbidden = GOOD_DIFF.replace("src/a.c", ".github/workflows/release.yml")
    decision, _ = policy.post_diff(repo, finding, forbidden)
    assert decision.allowed is False
    assert any("forbidden" in reason or "target" in reason for reason in decision.reasons)

    monkeypatch.setenv("CLEARWING_REMEDIATION_DISABLED", "1")
    killed = policy.pre_generation(repo, finding)
    assert killed.allowed is False
    assert killed.kill_switch_active is True


def test_diff_parser_rejects_non_diff_and_path_escape() -> None:
    plain = analyze_unified_diff("replace the whole function")
    assert plain.errors
    escaped = analyze_unified_diff(GOOD_DIFF.replace("src/a.c", "../../outside.c"))
    assert any("unsafe" in reason for reason in escaped.errors)
    mode_change = analyze_unified_diff(GOOD_DIFF.replace("--- ", "old mode 100644\n--- "))
    assert any("mode changes" in reason for reason in mode_change.errors)


def test_patch_transaction_applies_and_restores_exact_bytes(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    transaction = PatchTransaction(repo, GOOD_DIFF, ["src/a.c"])
    record = transaction.prepare()
    assert transaction.before_contents()["src/a.c"] == b"int value = 0;\n"

    transaction.apply(record)
    assert (repo / "src/a.c").read_text(encoding="utf-8") == "int value = 1;\n"
    transaction.rollback(record)
    assert (repo / "src/a.c").read_bytes() == b"int value = 0;\n"
    assert record.rolled_back is True


def test_patch_transaction_verifies_all_targets_before_rollback(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "src/b.c").write_text("int other = 0;\n", encoding="utf-8")
    _git(repo, "add", "src/b.c")
    _git(
        repo,
        "-c",
        "user.name=Clearwing Tests",
        "-c",
        "user.email=tests@example.test",
        "commit",
        "-qm",
        "add second target",
    )
    transaction = PatchTransaction(repo, TWO_FILE_DIFF, ["src/a.c", "src/b.c"])
    record = transaction.prepare()
    transaction.apply(record)
    (repo / "src/b.c").write_text("independent change\n", encoding="utf-8")

    with pytest.raises(PatchTransactionError, match="changed after patch"):
        transaction.rollback(record)
    assert (repo / "src/a.c").read_text(encoding="utf-8") == "int value = 1;\n"


def test_patch_transaction_refuses_dirty_target(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "src/a.c").write_text("local work\n", encoding="utf-8")
    with pytest.raises(PatchTransactionError, match="working-tree changes"):
        PatchTransaction(repo, GOOD_DIFF, ["src/a.c"]).prepare()


def test_patch_transaction_rejects_changed_head_and_symlink(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    reviewed_sha = _git(repo, "rev-parse", "HEAD")
    (repo / "README.md").write_text("new commit\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(
        repo,
        "-c",
        "user.name=Clearwing Tests",
        "-c",
        "user.email=tests@example.test",
        "commit",
        "-qm",
        "advance head",
    )
    with pytest.raises(PatchTransactionError, match="HEAD changed"):
        PatchTransaction(
            repo,
            GOOD_DIFF,
            ["src/a.c"],
            expected_git_sha=reviewed_sha,
        ).prepare()

    outside = tmp_path / "outside.c"
    outside.write_text("int value = 0;\n", encoding="utf-8")
    (repo / "src/a.c").unlink()
    (repo / "src/a.c").symlink_to(outside)
    with pytest.raises(PatchTransactionError, match="symlinked"):
        PatchTransaction(
            repo,
            GOOD_DIFF,
            ["src/a.c"],
            require_clean_target_paths=False,
        ).prepare()


def test_panel_host_verdict_and_incomplete_panel_are_fail_closed() -> None:
    clients = {
        "security_architect": _PanelClient(_opinion(root_cause=False)),
        "penetration_tester": _PanelClient(_opinion(root_cause=False)),
        "regression_reviewer": _PanelClient(_opinion()),
    }
    panel = RemediationValidationPanel(clients)  # type: ignore[arg-type]
    verdict = asyncio.run(
        panel.validate(
            finding=_finding(),
            fix=ProposedFix(diff=GOOD_DIFF),
            checkout_source="int value = 0;",
        )
    )
    assert verdict.status == "validation_failed"
    assert "root_cause" in verdict.host_reasons[0]

    clients["security_architect"] = _PanelClient(RuntimeError("provider down"))
    incomplete = asyncio.run(
        RemediationValidationPanel(clients).validate(  # type: ignore[arg-type]
            finding=_finding(),
            fix=ProposedFix(diff=GOOD_DIFF),
            checkout_source="int value = 0;",
        )
    )
    assert incomplete.status == "needs_review"


def test_panel_can_require_dynamic_validation() -> None:
    client = _PanelClient(_opinion())
    panel = RemediationValidationPanel(  # type: ignore[arg-type]
        client,
        require_dynamic_validation=True,
    )
    missing = asyncio.run(
        panel.validate(
            finding=_finding(),
            fix=ProposedFix(diff=GOOD_DIFF),
            checkout_source="int value = 0;",
        )
    )
    assert missing.status == "needs_review"
    passed = asyncio.run(
        panel.validate(
            finding=_finding(),
            fix=ProposedFix(diff=GOOD_DIFF),
            checkout_source="int value = 0;",
            dynamic=DynamicValidation(attempted=True, passed=True),
        )
    )
    assert passed.status == "validated"


def test_sandbox_dynamic_validator_replays_exact_diff(monkeypatch, tmp_path: Path) -> None:
    class Sandbox:
        def stop(self):
            return None

    class Manager:
        def __init__(self):
            self.builds = 0
            self.spawns = 0

        def prepare_environment(self):
            self.builds += 1

        def spawn(self, **_kwargs):
            self.spawns += 1
            return Sandbox()

        def cleanup(self):
            return None

    observed = []

    class Runner:
        def __init__(self, _sandbox):
            pass

        def replay(self, finding, diff):
            observed.append((finding["id"], diff))
            return {
                "applied": True,
                "compiled": True,
                "ran": True,
                "still_crashes": False,
                "notes": "fixed",
            }

    monkeypatch.setattr("clearwing.remediation.dynamic.PocRunner", Runner)
    manager = Manager()
    validator = SandboxPatchValidator(tmp_path, sandbox_manager=manager)
    result = validator({**_finding(), "poc": "input"}, GOOD_DIFF)

    assert result.passed is True
    assert observed == [("finding-1", GOOD_DIFF)]
    assert manager.builds == 1
    assert manager.spawns == 1


def test_store_redacts_dto_but_restores_encrypted_exact_diff(tmp_path: Path) -> None:
    secret = "super-secret-value"
    store = RemediationStore(tmp_path / "workspace")
    try:
        dto = RemediationDTO(
            remediation_id="rem-1",
            run_id="run-1",
            mode="report-only",
            repository="repo",
            fingerprint="abc",
            finding=FindingSnapshot.from_finding(_finding(description=f"api_key={secret}")),
            proposed_fix=ProposedFix(diff=GOOD_DIFF + f" api_key={secret}\n"),
        )
        path = store.save(dto)
        assert secret not in path.read_text(encoding="utf-8")
        artifact = Path(dto.proposed_fix.encrypted_diff_path or "")
        assert secret.encode() not in artifact.read_bytes()
        loaded = store.load(path)
        assert secret in loaded.proposed_fix.diff
        serialized = json.loads(path.read_text(encoding="utf-8"))
        serialized["proposed_fix"]["diff_sha256"] = "0" * 64
        path.write_text(json.dumps(serialized), encoding="utf-8")
        with pytest.raises(ValueError, match="integrity check"):
            store.load(path)
    finally:
        store.close()


def test_store_keeps_distinct_history_for_one_finding(tmp_path: Path) -> None:
    store = RemediationStore(tmp_path / "workspace")
    try:
        first = RemediationDTO(
            remediation_id="rem-1",
            run_id="run-1",
            mode="report-only",
            repository="repo",
            fingerprint="one",
            finding=FindingSnapshot.from_finding(_finding()),
        )
        second = first.model_copy(
            update={
                "remediation_id": "rem-2",
                "run_id": "run-2",
                "fingerprint": "two",
            },
            deep=True,
        )
        first_path = store.save(first)
        second_path = store.save(second)
        assert first_path != second_path
        assert first_path.is_file()
        assert second_path.is_file()
        assert len(store.load_all()) == 2
    finally:
        store.close()


def test_report_only_workflow_is_resumable_and_does_not_edit(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    remediator = _RemediatorClient()
    panel = _WorkflowPanel("validated")
    store = RemediationStore(tmp_path / "output")
    try:
        workflow = RemediationWorkflow(
            repo=repo,
            store=store,
            remediator_llm=remediator,  # type: ignore[arg-type]
            validation_panel=panel,  # type: ignore[arg-type]
        )
        first = asyncio.run(workflow.run([_finding()]))
        second = asyncio.run(workflow.run([_finding()], resume=True))
        assert first[0].status == "proposed"
        assert second[0].remediation_id == first[0].remediation_id
        assert remediator.calls == 1
        assert (repo / "src/a.c").read_text(encoding="utf-8") == "int value = 0;\n"
    finally:
        store.close()


def test_resume_can_promote_reviewed_proposal_to_apply_without_regeneration(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    report_remediator = _RemediatorClient()
    apply_remediator = _RemediatorClient()
    store = RemediationStore(tmp_path / "output")
    try:
        report = RemediationWorkflow(
            repo=repo,
            store=store,
            remediator_llm=report_remediator,  # type: ignore[arg-type]
            validation_panel=_WorkflowPanel("validated"),  # type: ignore[arg-type]
        )
        proposed = asyncio.run(report.run([_finding()]))[0]
        assert proposed.status == "proposed"

        apply = RemediationWorkflow(
            repo=repo,
            store=store,
            remediator_llm=apply_remediator,  # type: ignore[arg-type]
            validation_panel=_WorkflowPanel("validated"),  # type: ignore[arg-type]
            mode="apply",
        )
        applied = asyncio.run(apply.run([_finding()], resume=True))[0]
        assert applied.status == "validated"
        assert apply_remediator.calls == 0
        assert (repo / "src/a.c").read_text(encoding="utf-8") == "int value = 1;\n"
    finally:
        store.close()


def test_revalidation_updates_a_previously_validated_status(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    store = RemediationStore(tmp_path / "output")
    try:
        workflow = RemediationWorkflow(
            repo=repo,
            store=store,
            remediator_llm=_RemediatorClient(),  # type: ignore[arg-type]
            validation_panel=_WorkflowPanel("validation_failed"),  # type: ignore[arg-type]
        )
        dto = RemediationDTO(
            remediation_id="rem-existing",
            run_id="run-existing",
            mode="apply",
            status="validated",
            repository=str(repo),
            fingerprint="existing",
            finding=FindingSnapshot.from_finding(_finding()),
            proposed_fix=ProposedFix(diff=GOOD_DIFF, touched_files=["src/a.c"]),
        )
        result = asyncio.run(workflow.validate_existing(dto))
        assert result.status == "validation_failed"
        assert (repo / "src/a.c").read_text(encoding="utf-8") == "int value = 0;\n"
    finally:
        store.close()


@pytest.mark.parametrize(
    ("panel_status", "expected_status", "expected_source"),
    [
        ("validated", "validated", "int value = 1;\n"),
        ("validation_failed", "rolled_back", "int value = 0;\n"),
    ],
)
def test_apply_workflow_keeps_only_validated_patch(
    tmp_path: Path,
    panel_status: str,
    expected_status: str,
    expected_source: str,
) -> None:
    repo = _repo(tmp_path)
    store = RemediationStore(tmp_path / "output")
    try:
        workflow = RemediationWorkflow(
            repo=repo,
            store=store,
            remediator_llm=_RemediatorClient(),  # type: ignore[arg-type]
            validation_panel=_WorkflowPanel(panel_status),  # type: ignore[arg-type]
            mode="apply",
        )
        result = asyncio.run(workflow.run([_finding()]))[0]
        assert result.status == expected_status
        assert (repo / "src/a.c").read_text(encoding="utf-8") == expected_source
    finally:
        store.close()


def test_findings_loader_and_cli_surface(tmp_path: Path) -> None:
    report = tmp_path / "findings.json"
    report.write_text(json.dumps({"verified_findings": [_finding()]}), encoding="utf-8")
    assert load_findings(report)[0]["id"] == "finding-1"

    parser = CLI()._create_parser()
    args = parser.parse_args(
        [
            "remediate",
            "run",
            "--repo",
            "repo",
            "--findings",
            "findings.json",
            "--mode",
            "apply",
            "--resume",
        ]
    )
    assert args.command == "remediate"
    assert args.remediate_action == "run"
    assert args.mode == "apply"
    assert args.resume is True
