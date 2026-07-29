"""Runnable proof-flow orchestration tests."""

from __future__ import annotations

import json

import pytest

from clearwing.llm.budget import current_spend_metadata
from clearwing.sourcehunt.proof import (
    Certificate,
    CertificateKind,
    ProofFlowRunner,
    ProofRunConfig,
    ProofStore,
)
from clearwing.sourcehunt.runner import SourceHuntRunner


def _write_sentinel_fixture(path, *, fixed: bool) -> None:
    guard = "    if slice_num >= 0xFFFF:\n        return None\n" if fixed else ""
    (path / "decoder.py").write_text(
        "def decode_slice(slice_num, index, neighbor):\n"
        "    state_table = [0xFFFF] * 8\n"
        "    slice_num += 1\n"
        f"{guard}"
        "    state_table[index] = slice_num\n"
        "    return state_table[neighbor]\n"
    )


class _MetadataLLM:
    model_name = "local-proof-test"
    provider_name = "test"

    def __init__(self) -> None:
        self.metadata: list[dict[str, object]] = []

    async def aask_text(self, **kwargs):
        del kwargs
        self.metadata.append(current_spend_metadata())
        return type(
            "Response",
            (),
            {
                "first_text": json.dumps(
                    {
                        "status": "blocked",
                        "conclusion": "Caller-side reachability is unresolved.",
                        "cited_fact_ids": [],
                        "cited_evidence_ids": [],
                        "cited_claim_ids": [],
                        "missing_context": ["direct callers"],
                        "limitations": [],
                    }
                ),
                "texts": [],
            },
        )()


@pytest.mark.asyncio
async def test_engine_emits_rejection_for_fixed_counter_sentinel(tmp_path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_sentinel_fixture(repo, fixed=True)
    output = tmp_path / "results"
    result = await ProofFlowRunner(
        repo_url=str(repo),
        config=ProofRunConfig(
            output_dir=str(output),
            max_actions=60,
            falsify=False,
        ),
    ).arun()

    assert result.status == "completed"
    assert result.candidates
    assert any(certificate.kind == CertificateKind.REJECTION for certificate in result.certificates)
    manifest = json.loads((output / result.session_id / "manifest.json").read_text())
    assert manifest["engine"] == "proof"
    assert manifest["blind_boundary"]["sealed"] is True
    assert manifest["certificate_counts"]["rejection"] >= 1


@pytest.mark.asyncio
async def test_engine_preserves_vulnerable_but_unproven_case_as_incomplete(
    tmp_path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_sentinel_fixture(repo, fixed=False)
    result = await ProofFlowRunner(
        repo_url=str(repo),
        config=ProofRunConfig(
            output_dir=str(tmp_path / "results"),
            max_actions=60,
            falsify=False,
        ),
    ).arun()

    assert result.status == "incomplete"
    assert result.findings == []
    assert any(
        certificate.kind == CertificateKind.INCOMPLETE for certificate in result.certificates
    )
    assert any(
        certificate.blocked_obligation_ids or certificate.unresolved_obligation_ids
        for certificate in result.certificates
    )


@pytest.mark.asyncio
async def test_engine_attributes_model_calls_to_atomic_actions(tmp_path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_sentinel_fixture(repo, fixed=False)
    llm = _MetadataLLM()

    await ProofFlowRunner(
        repo_url=str(repo),
        config=ProofRunConfig(
            output_dir=str(tmp_path / "results"),
            max_actions=30,
            max_model_calls=1,
            exploration_fraction=0.0,
            falsify=False,
        ),
        model_client_factory=(lambda route: llm if route == "proof_local" else None),
    ).arun()

    assert len(llm.metadata) == 1
    metadata = llm.metadata[0]
    assert metadata["proof_role"] == "obligation_resolution"
    assert str(metadata["proof_action_id"]).startswith("actionl-")
    assert str(metadata["proof_attempt_id"]).startswith("attempt-")
    assert str(metadata["candidate_id"]).startswith("candidatel-")
    assert str(metadata["obligation_id"]).startswith("obligationl-")
    assert metadata["model_route"] == "proof_local"


@pytest.mark.asyncio
async def test_hidden_incomplete_certificates_still_degrade_run_status(
    tmp_path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_sentinel_fixture(repo, fixed=False)
    output = tmp_path / "results"
    result = await ProofFlowRunner(
        repo_url=str(repo),
        config=ProofRunConfig(
            output_dir=str(output),
            max_actions=60,
            falsify=False,
            retain_incomplete_certificates=False,
        ),
    ).arun()

    assert result.status == "incomplete"
    assert result.certificates == []
    store = ProofStore(output / result.session_id)
    assert store.read_all(Certificate) == []
    manifest = json.loads((store.root / "manifest.json").read_text())
    assert manifest["certificate_counts"]["incomplete"] == 0
    assert manifest["compiled_certificate_counts"]["incomplete"] >= 1


@pytest.mark.asyncio
async def test_engine_fails_closed_for_c_without_compilation_database(
    tmp_path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "decoder.c").write_text("int decode(void) { return 0; }\n")
    result = await ProofFlowRunner(
        repo_url=str(repo),
        config=ProofRunConfig(output_dir=str(tmp_path / "results")),
    ).arun()

    assert result.status == "incomplete"
    assert result.candidates == []
    assert result.errors[0]["missing"] == ["compile_commands.json"]
    report = next(iter(result.output_paths.values()))
    assert "No legacy or heuristic fallback was used" in open(report).read()


def test_public_runner_merges_proof_and_spend_manifests(tmp_path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "safe.py").write_text(
        "def add(left, right):\n    return left + right\n",
        encoding="utf-8",
    )
    output = tmp_path / "results"

    result = SourceHuntRunner(
        repo_url=str(repo),
        local_path=str(repo),
        output_dir=str(output),
        flow="proof",
        proof_max_model_calls=0,
        proof_exploration_fraction=0.0,
        falsify=False,
        enable_calibration=False,
        enable_mechanism_memory=False,
    ).run()

    manifest_path = output / result.session_id / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["engine"] == "proof"
    assert manifest["blind_boundary"]["sealed"] is True
    assert manifest["proof_status"] == "completed"
    assert manifest["spend"]["call_count"] == 0
    assert manifest["total_spent"] == 0.0
    assert manifest["metrics"]["totals"]["actions"] == 0
    assert manifest["outputs"]["manifest"] == str(manifest_path)
    assert manifest["outputs"]["ledger"].endswith("spend-ledger.jsonl")
    assert manifest["outputs"]["spend_summary"].endswith(
        "spend-summary.json"
    )
    spend_summary = json.loads(
        (output / result.session_id / "spend-summary.json").read_text(
            encoding="utf-8"
        )
    )
    assert spend_summary["call_count"] == 0
    assert spend_summary["status"] == "completed"
    assert result.output_paths["manifest"] == str(manifest_path)
    assert result.output_paths["metrics"].endswith("metrics/run-metrics.json")
