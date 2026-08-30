"""Verifier-only tool-loop and per-finding sandbox lifecycle tests."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from genai_pyo3 import ChatResponse, ToolCall

from clearwing.agent.tools.hunt import (
    HunterContext,
    build_hunter_tools,
    build_verification_tools,
)
from clearwing.llm import BudgetExceeded
from clearwing.sandbox.container import ExecResult
from clearwing.sourcehunt.checkpoints import SourceHuntCheckpoint
from clearwing.sourcehunt.dynamic_verification import (
    ToolAssistedVerificationResult,
    _qualifies_as_product_crash,
    run_tool_assisted_verification,
)
from clearwing.sourcehunt.runner import SourceHuntRunner
from clearwing.sourcehunt.state import Finding, PipelineStatus
from clearwing.sourcehunt.validator import Validator
from clearwing.sourcehunt.verifier import Verifier, VerifierResult


class _FakeSandbox:
    def __init__(self, exec_result: ExecResult | None = None) -> None:
        self.commands: list[object] = []
        self.stop_calls = 0
        self.exec_result = exec_result or ExecResult(0, "/workspace\n", "", 0.01)

    def exec(self, command, timeout=None):
        self.commands.append(command)
        return self.exec_result

    def write_file(self, path: str, content: bytes) -> None:
        pass

    def stop(self) -> None:
        self.stop_calls += 1


class _FakeResponse:
    def __init__(self, text: str = "", tool_calls: list[ToolCall] | None = None):
        self.first_text = text
        self.tool_calls = tool_calls or []


class _ToolLoopLLM:
    def __init__(self, responses: list[_FakeResponse] | None = None) -> None:
        self.calls: list[dict] = []
        self.responses = responses or [
            _FakeResponse(
                tool_calls=[ToolCall("call-1", "execute", json.dumps({"command": "pwd"}))]
            ),
            _FakeResponse(text="The command completed successfully in /workspace."),
        ]

    async def achat(self, **kwargs):
        self.calls.append(kwargs)
        return self.responses.pop(0)


def _finding() -> dict:
    return {
        "id": "finding-1",
        "file": "src/example.c",
        "line_number": 7,
        "finding_type": "memory_safety",
        "cwe": "CWE-787",
        "severity": "high",
        "description": "reported overflow",
        "evidence_level": "static_corroboration",
    }


def _verdict_payload() -> dict:
    axis = {"passed": True, "confidence": "high", "rationale": "confirmed"}
    return {
        "axes": {
            "real": axis,
            "triggerable": axis,
            "impactful": {**axis, "boundary_crossed": "user"},
            "general": axis,
        },
        "advance": True,
        "severity": "high",
        "evidence_level": "root_cause_explained",
        "pro_argument": "sandbox evidence supports the report",
        "counter_argument": "none survived",
        "tie_breaker": "the reproducer",
        "duplicate_cve": None,
    }


def _legacy_verdict_payload(finding_id: str = "finding-1") -> dict:
    return {
        "is_real": True,
        "severity": "high",
        "evidence_level": "crash_reproduced",
        "pro_argument": "the sandbox reproducer confirms the report",
        "counter_argument": "the command completed under normal invocation",
        "tie_breaker": "the sanitizer result",
        "duplicate_cve": None,
        "finding_id": finding_id,
    }


def test_downstream_checkpoint_digest_tracks_finding_content() -> None:
    original = _finding()
    changed = {**original, "description": "different root cause"}

    assert SourceHuntRunner._finding_set_digest([original]) != (
        SourceHuntRunner._finding_set_digest([changed])
    )


def test_dynamic_tools_are_verifier_only() -> None:
    ctx = HunterContext(repo_path="/tmp/repo", sandbox=_FakeSandbox())
    hunter_names = {tool.name for tool in build_hunter_tools(ctx)}
    verifier_names = {tool.name for tool in build_verification_tools(ctx)}

    assert "compile_file" not in hunter_names
    assert "execute" not in hunter_names
    assert verifier_names == {"execute", "read_file", "write_file"}


def test_verification_sandbox_bypasses_deep_factory_keyword_collision(tmp_path) -> None:
    sandbox = _FakeSandbox()
    manager = MagicMock()
    manager.spawn.return_value = sandbox
    runner = SourceHuntRunner(
        repo_url="test",
        output_dir=str(tmp_path),
        sandbox_factory=lambda **kwargs: manager.spawn(
            writable_workspace=True,
            timeout_seconds=kwargs.pop("timeout_seconds", 30),
            **kwargs,
        ),
        enable_calibration=False,
        enable_mechanism_memory=False,
        enable_patch_oracle=False,
    )
    runner._sandbox_manager = manager

    assert runner._spawn_verification_sandbox() is sandbox
    manager.spawn.assert_called_once_with(
        writable_workspace=True,
        timeout_seconds=600,
        session_id=runner._session_id + "-v",
        runtime=None,
    )


@pytest.mark.asyncio
async def test_verifier_loop_executes_tools_then_returns_verdict() -> None:
    llm = _ToolLoopLLM()
    sandbox = _FakeSandbox()

    verification = await run_tool_assisted_verification(
        llm,
        system_prompt="independent verifier",
        user_message="Verify finding-1 without hunter context.",
        tools=build_verification_tools(HunterContext(repo_path="/tmp/repo", sandbox=sandbox)),
    )

    assert sandbox.commands == ["pwd"]
    assert verification.response.first_text == (
        "The command completed successfully in /workspace."
    )
    assert verification.attempted_dynamic_calls == 1
    assert verification.completed_dynamic_calls == 1
    assert {tool.name for tool in llm.calls[0]["tools"]} == {
        "execute",
        "read_file",
        "write_file",
    }
    tool_message = llm.calls[1]["messages"][-1]
    assert tool_message.role == "tool"
    assert tool_message.tool_response_call_id == "call-1"
    assert '"stdout": "/workspace\\n"' in tool_message.content


@pytest.mark.asyncio
async def test_verifier_loop_forces_final_synthesis_after_tool_limit() -> None:
    llm = _ToolLoopLLM()
    tools = build_verification_tools(HunterContext(repo_path="/tmp/repo", sandbox=_FakeSandbox()))

    verification = await run_tool_assisted_verification(
        llm,
        system_prompt="independent verifier",
        user_message="Verify finding-1.",
        tools=tools,
        max_tool_rounds=1,
    )

    assert verification.response.first_text == (
        "The command completed successfully in /workspace."
    )
    assert llm.calls[0]["tools"]
    assert llm.calls[1]["tools"] is None


@pytest.mark.asyncio
async def test_verifier_retries_then_rejects_unsubstantiated_dynamic_claim() -> None:
    claimed_verdict = json.dumps(_legacy_verdict_payload())
    llm = _ToolLoopLLM(
        responses=[
            _FakeResponse(text=claimed_verdict),
            _FakeResponse(text=claimed_verdict),
        ]
    )

    result = await Verifier(llm).averify(
        _finding(),
        verification_tools=build_verification_tools(
            HunterContext(repo_path="/tmp/repo", sandbox=_FakeSandbox())
        ),
    )

    assert result.is_real is False
    assert result.evidence_level == "suspicion"
    assert "dynamic verification incomplete" in result.tie_breaker
    assert len(llm.calls) == 2
    reminder = llm.calls[1]["messages"][-1]
    assert reminder.role == "user"
    assert "Do not claim" in reminder.content


@pytest.mark.asyncio
async def test_legacy_verifier_does_not_trust_model_only_crash_claim() -> None:
    sandbox = _FakeSandbox()
    llm = _ToolLoopLLM(
        responses=[
            _FakeResponse(
                tool_calls=[ToolCall("legacy-call", "execute", json.dumps({"command": "pwd"}))]
            ),
            _FakeResponse(text=json.dumps(_legacy_verdict_payload())),
        ]
    )

    result = await Verifier(llm).averify(
        _finding(),
        verification_tools=build_verification_tools(
            HunterContext(repo_path="/tmp/repo", sandbox=sandbox)
        ),
    )

    assert result.is_real is True
    assert result.evidence_level == "static_corroboration"
    assert "Host evidence gate" in result.tie_breaker
    assert sandbox.commands == ["pwd"]
    assert len(llm.calls) == 2
    assert llm.calls[1]["messages"][-1].tool_response_call_id == "legacy-call"


@pytest.mark.asyncio
async def test_legacy_verifier_clamps_every_level_above_host_evidence() -> None:
    payload = _legacy_verdict_payload()
    payload["evidence_level"] = "root_cause_explained"
    llm = _ToolLoopLLM(
        responses=[
            _FakeResponse(
                tool_calls=[ToolCall("static-call", "execute", json.dumps({"command": "pwd"}))]
            ),
            _FakeResponse(text=json.dumps(payload)),
        ]
    )

    result = await Verifier(llm).averify(
        _finding(),
        verification_tools=build_verification_tools(
            HunterContext(repo_path="/tmp/repo", sandbox=_FakeSandbox())
        ),
    )

    assert result.evidence_level == "static_corroboration"
    assert "Host evidence gate" in result.tie_breaker


@pytest.mark.asyncio
async def test_legacy_verifier_accepts_product_sanitizer_crash() -> None:
    sandbox = _FakeSandbox(
        ExecResult(
            1,
            "",
            "ERROR: AddressSanitizer: heap-buffer-overflow\n    #0 src/example.c:7",
            0.01,
        )
    )
    llm = _ToolLoopLLM(
        responses=[
            _FakeResponse(
                tool_calls=[
                    ToolCall("asan-call", "execute", json.dumps({"command": "./repro"}))
                ]
            ),
            _FakeResponse(text=json.dumps(_legacy_verdict_payload())),
        ]
    )

    result = await Verifier(llm).averify(
        _finding(),
        verification_tools=build_verification_tools(
            HunterContext(repo_path="/tmp/repo", sandbox=sandbox)
        ),
    )

    assert result.is_real is True
    assert result.evidence_level == "crash_reproduced"
    assert result.dynamic_evidence[0]["qualifying_crash"] is True
    assert result.dynamic_evidence[0]["arguments"] == {"command": "./repro"}


def test_host_crash_gate_rejects_echo_timeout_oom_and_unrelated_crashes() -> None:
    real_output = {
        "exit_code": 1,
        "stdout": "",
        "stderr": "AddressSanitizer: heap-buffer-overflow at src/example.c:7",
        "timed_out": False,
    }

    assert not _qualifies_as_product_crash(
        tool_name="execute",
        arguments={"command": "echo AddressSanitizer: src/example.c:7"},
        output=real_output,
        product_file="src/example.c",
    )
    assert not _qualifies_as_product_crash(
        tool_name="execute",
        arguments={"command": "./repro"},
        output={**real_output, "exit_code": -1},
        product_file="src/example.c",
    )
    assert _qualifies_as_product_crash(
        tool_name="execute",
        arguments={"command": "./repro"},
        output={
            **real_output,
            "exit_code": 0,
            "stderr": "runtime error: src/example.c:7 out of bounds",
        },
        product_file="src/example.c",
    )
    assert not _qualifies_as_product_crash(
        tool_name="execute",
        arguments={"command": "./repro"},
        output={**real_output, "timed_out": True},
        product_file="src/example.c",
    )
    assert not _qualifies_as_product_crash(
        tool_name="execute",
        arguments={"command": "./repro"},
        output={**real_output, "stderr": "OOM killed after AddressSanitizer src/example.c:7"},
        product_file="src/example.c",
    )
    assert not _qualifies_as_product_crash(
        tool_name="execute",
        arguments={"command": "./repro"},
        output={**real_output, "stderr": "AddressSanitizer in harness.c:4"},
        product_file="src/example.c",
    )


@pytest.mark.asyncio
async def test_verifier_records_written_harness_and_rejects_its_fake_crash_text() -> None:
    sandbox = _FakeSandbox(
        ExecResult(
            1,
            "",
            "AddressSanitizer: heap-buffer-overflow at src/example.c:7",
            0.01,
        )
    )
    harness = 'puts("AddressSanitizer: heap-buffer-overflow src/example.c:7");'
    llm = _ToolLoopLLM(
        responses=[
            _FakeResponse(
                tool_calls=[
                    ToolCall(
                        "write-call",
                        "write_file",
                        json.dumps({"path": "/scratch/fake.c", "contents": harness}),
                    )
                ]
            ),
            _FakeResponse(
                tool_calls=[
                    ToolCall("fake-call", "execute", json.dumps({"command": "./fake"}))
                ]
            ),
            _FakeResponse(text=json.dumps(_legacy_verdict_payload())),
        ]
    )

    result = await Verifier(llm).averify(
        _finding(),
        verification_tools=build_verification_tools(
            HunterContext(repo_path="/tmp/repo", sandbox=sandbox)
        ),
    )

    assert [item["tool"] for item in result.dynamic_evidence] == [
        "write_file",
        "execute",
    ]
    written = result.dynamic_evidence[0]["arguments"]
    assert written["contents"] == harness
    assert len(written["contents_sha256"]) == 64
    assert result.dynamic_evidence[1]["qualifying_crash"] is False
    assert result.evidence_level == "static_corroboration"


@pytest.mark.asyncio
async def test_runner_leaves_finding_unverified_when_sandbox_is_unavailable(tmp_path) -> None:
    finding = _finding()
    runner = SourceHuntRunner(
        repo_url="test",
        output_dir=str(tmp_path),
        sandbox_factory=lambda **_kwargs: None,
        enable_calibration=False,
        enable_mechanism_memory=False,
        enable_patch_oracle=False,
    )
    runner._verification_sandbox_failed = False
    runner._load_file_content = MagicMock(return_value="int vulnerable(void);")
    verifier = MagicMock()
    verifier.averify = AsyncMock()

    with patch("clearwing.sourcehunt.runner.Verifier", return_value=verifier):
        verified = await runner._verify_v1(MagicMock(), [finding], "/tmp/repo")

    assert verified == []
    assert finding["verified"] is False
    assert "unavailable" in finding["verifier_tie_breaker"]
    assert runner._verification_sandbox_failed is True
    verifier.averify.assert_not_awaited()


@pytest.mark.asyncio
async def test_runner_fails_closed_when_verifier_model_is_unavailable(tmp_path) -> None:
    provider_manager = MagicMock()
    provider_manager.get_native_client.return_value = None
    finding = Finding(**_finding())
    runner = SourceHuntRunner(
        repo_url="test",
        local_path=str(tmp_path),
        output_dir=str(tmp_path / "results"),
        provider_manager=provider_manager,
        enable_calibration=False,
        enable_mechanism_memory=False,
        enable_patch_oracle=False,
    )
    runner._checkpoint = SourceHuntCheckpoint()

    result = await runner._verify(
        [finding],
        repo_path=str(tmp_path),
        pipeline_status=PipelineStatus(),
    )

    assert result.status == "incomplete"
    assert result.verified == []
    assert finding.verified is False
    assert runner._checkpoint.verification is None
    assert runner._verification_incomplete is True


@pytest.mark.asyncio
async def test_runner_gives_each_v1_finding_a_fresh_sandbox_and_cleans_it(
    tmp_path,
) -> None:
    sandboxes: list[_FakeSandbox] = []

    def sandbox_factory(**_kwargs) -> _FakeSandbox:
        sandbox = _FakeSandbox()
        sandboxes.append(sandbox)
        return sandbox

    runner = SourceHuntRunner(
        repo_url="test",
        output_dir=str(tmp_path),
        sandbox_factory=sandbox_factory,
        enable_calibration=False,
        enable_mechanism_memory=False,
        enable_patch_oracle=False,
    )
    runner._load_file_content = MagicMock(return_value="int vulnerable(void);")
    seen_tool_lists: list[list] = []

    async def verify_one(finding, file_content="", *, verification_tools=None):
        assert file_content == "int vulnerable(void);"
        tools = list(verification_tools or [])
        seen_tool_lists.append(tools)
        execute = next(tool for tool in tools if tool.name == "execute")
        await execute.ainvoke({"command": "pwd"})
        return VerifierResult(
            finding_id=finding.get("id", "unknown"),
            is_real=True,
            severity_verified="high",
            evidence_level="crash_reproduced",
            pro_argument="reproduced",
            counter_argument="",
            tie_breaker="sandbox",
            duplicate_cve=None,
        )

    fake_verifier = MagicMock()
    fake_verifier.averify = AsyncMock(side_effect=verify_one)
    cleaned_contexts = []
    original_cleanup = HunterContext.cleanup_variants

    def track_cleanup(ctx):
        cleaned_contexts.append(ctx)
        original_cleanup(ctx)

    findings = [_finding(), {**_finding(), "id": "finding-2"}]
    with (
        patch("clearwing.sourcehunt.runner.Verifier", return_value=fake_verifier),
        patch.object(HunterContext, "cleanup_variants", new=track_cleanup),
    ):
        verified = await runner._verify_v1(MagicMock(), findings, "/tmp/repo")

    assert len(verified) == 2
    assert len(sandboxes) == 2
    assert sandboxes[0] is not sandboxes[1]
    assert [sandbox.commands for sandbox in sandboxes] == [["pwd"], ["pwd"]]
    assert [sandbox.stop_calls for sandbox in sandboxes] == [1, 1]
    assert len(cleaned_contexts) == 2
    assert cleaned_contexts[0] is not cleaned_contexts[1]
    assert seen_tool_lists[0] is not seen_tool_lists[1]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [RuntimeError("verifier failed"), BudgetExceeded("verification budget exhausted")],
    ids=["error", "budget_exceeded"],
)
async def test_runner_cleans_v1_sandbox_when_verification_stops(
    tmp_path,
    failure: Exception,
) -> None:
    sandboxes: list[_FakeSandbox] = []

    def sandbox_factory(**_kwargs) -> _FakeSandbox:
        sandbox = _FakeSandbox()
        sandboxes.append(sandbox)
        return sandbox

    runner = SourceHuntRunner(
        repo_url="test",
        output_dir=str(tmp_path),
        sandbox_factory=sandbox_factory,
        enable_calibration=False,
        enable_mechanism_memory=False,
        enable_patch_oracle=False,
    )
    runner._load_file_content = MagicMock(return_value="int vulnerable(void);")
    fake_verifier = MagicMock()
    fake_verifier.averify = AsyncMock(side_effect=failure)
    cleaned_contexts = []
    original_cleanup = HunterContext.cleanup_variants

    def track_cleanup(ctx):
        cleaned_contexts.append(ctx)
        original_cleanup(ctx)

    with (
        patch("clearwing.sourcehunt.runner.Verifier", return_value=fake_verifier),
        patch.object(HunterContext, "cleanup_variants", new=track_cleanup),
    ):
        verified = await runner._verify_v1(
            MagicMock(),
            [_finding(), {**_finding(), "id": "finding-2"}],
            "/tmp/repo",
        )

    assert verified == []
    expected_attempts = 1 if isinstance(failure, BudgetExceeded) else 2
    assert len(sandboxes) == expected_attempts
    assert [sandbox.stop_calls for sandbox in sandboxes] == [1] * expected_attempts
    assert len(cleaned_contexts) == expected_attempts


@pytest.mark.asyncio
async def test_validator_judges_sandbox_evidence_without_hunter_reasoning() -> None:
    llm = AsyncMock()
    llm.aask_text.return_value = ChatResponse(content=[{"text": json.dumps(_verdict_payload())}])
    validator = Validator(llm)

    with patch(
        "clearwing.sourcehunt.validator.run_tool_assisted_verification",
        new=AsyncMock(
            return_value=ToolAssistedVerificationResult(
                response=ChatResponse(
                    content=[{"text": json.dumps(_verdict_payload())}]
                ),
                attempted_dynamic_calls=1,
                completed_dynamic_calls=1,
            )
        ),
    ) as tool_loop:
        verdict = await validator.avalidate(
            _finding(),
            file_content="int vulnerable(void);",
            verification_tools=[MagicMock()],
        )

    assert verdict.advance is True
    tool_loop.assert_awaited_once()
    tool_request = tool_loop.await_args.kwargs["user_message"]
    assert "reported overflow" in tool_request
    assert "hunter reasoning" not in tool_request
    assert tool_loop.await_args.kwargs["response_schema_name"] == "ValidatorVerdict"
    llm.aask_text.assert_not_awaited()
