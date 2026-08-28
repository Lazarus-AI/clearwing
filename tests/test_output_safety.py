from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from clearwing.agent.tools.hunt.deep_agent import _cap_output
from clearwing.agent.tools.hunt.discovery import build_discovery_tools
from clearwing.agent.tools.hunt.sandbox import HunterContext
from clearwing.reporting import ReportGenerator
from clearwing.reporting.safety import redact_text
from clearwing.sourcehunt.disclosure import (
    DisclosureBundle,
    DisclosureGenerator,
    DisclosureTemplate,
    write_bundle,
)
from clearwing.sourcehunt.findings_pool import FindingsPool
from clearwing.sourcehunt.historical_findings_db import HistoricalFindingsDB
from clearwing.sourcehunt.patcher import AutoPatcher
from clearwing.sourcehunt.reporter import write_sourcehunt_report


def test_redaction_is_precise_and_idempotent() -> None:
    source = (
        "api_key=super-secret-value "
        "card=4111 1111 1111 1111 "
        "ssn=123-45-6789 id=123456789 timestamp=1712345678901"
    )
    redacted = redact_text(source)
    assert "super-secret-value" not in redacted
    assert "4111" not in redacted
    assert "123-45-6789" not in redacted
    assert "id=123456789" in redacted
    assert "timestamp=1712345678901" in redacted
    assert redact_text(redacted) == redacted


def test_sourcehunt_outputs_redact_and_neutralize_markdown(tmp_path: Path) -> None:
    secret = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
    finding = {
        "id": "f1",
        "finding_type": "overflow\n## Forged section",
        "file": "src/a`b.c",
        "line_number": 7,
        "severity": "high",
        "cwe": "CWE-787",
        "description": f"<script>alert(1)</script> token={secret}",
        "code_snippet": "```\nmalicious fence\n```",
        "evidence_level": "static_corroboration",
        "discovered_by": "test",
    }
    paths = write_sourcehunt_report(
        output_dir=str(tmp_path),
        session_id="session",
        repo_url="https://user:password@example.test/repo.git",
        findings=[finding],
        verified_findings=[],
        spent_per_tier={"A": 0.0, "B": 0.0, "C": 0.0},
    )

    markdown = Path(paths["markdown"]).read_text(encoding="utf-8")
    json_report = Path(paths["json"]).read_text(encoding="utf-8")
    sarif = Path(paths["sarif"]).read_text(encoding="utf-8")
    manifest = Path(paths["manifest"]).read_text(encoding="utf-8")
    combined = "\n".join((markdown, json_report, sarif, manifest))
    assert secret not in combined
    assert "password@example" not in combined
    assert "<script>" not in markdown
    assert "\n## Forged section\n" not in markdown
    assert "````\n```\nmalicious fence\n```\n````" in markdown


def test_general_reports_escape_html_and_markdown_tables() -> None:
    result = SimpleNamespace(
        target="<img src=x onerror=alert(1)>",
        start_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
        end_time=None,
        os_info="Linux",
        state=SimpleNamespace(value="completed"),
        open_ports=[
            {"port": 80, "protocol": "tcp", "service": "http|## injected", "state": "open"}
        ],
        services=[],
        vulnerabilities=[],
        exploits=[],
        errors=[],
    )
    generator = ReportGenerator()
    html = generator.generate(result, "html")
    markdown = generator.generate(result, "markdown")
    assert "<img src=x" not in html
    assert "&lt;img src=x" in html
    assert "http\\|\\#\\# injected" in markdown


def test_manifest_accepts_provenance_metadata(tmp_path: Path) -> None:
    paths = write_sourcehunt_report(
        output_dir=str(tmp_path),
        session_id="session",
        repo_url="repo",
        findings=[],
        verified_findings=[],
        spent_per_tier={"A": 0.0, "B": 0.0, "C": 0.0},
        run_metadata={
            "schema_version": 2,
            "tool_version": "1.0.0",
            "configuration_sha256": "abc",
            "target_git_sha": "def",
            "model_roles": {"hunter": {"model": "m", "provider": "p"}},
        },
    )
    manifest = json.loads(Path(paths["manifest"]).read_text(encoding="utf-8"))
    assert manifest["schema_version"] == 2
    assert manifest["configuration_sha256"] == "abc"
    assert manifest["target_git_sha"] == "def"


def test_source_tools_and_model_prompts_redact_before_dispatch(tmp_path: Path) -> None:
    secret = "super-secret-value"
    source = tmp_path / "source.py"
    source.write_text(f"api_key={secret}\nprint('safe')\n", encoding="utf-8")
    tools = {tool.name: tool for tool in build_discovery_tools(HunterContext(str(tmp_path)))}

    file_output = tools["read_source_file"].invoke({"path": "source.py"})
    grep_output = tools["grep_source"].invoke({"pattern": "api_key", "path": "."})
    assert secret not in file_output
    assert secret not in grep_output[0]["matched_text"]
    assert "[REDACTED-SECRET]" in file_output
    assert secret not in _cap_output(f"api_key={secret}")

    finding = {
        "id": "f1",
        "file": "source.py",
        "description": f"credential is api_key={secret}",
        "code_snippet": f"api_key={secret}",
        "crash_evidence": f"api_key={secret}",
    }
    prompt = AutoPatcher(llm=object())._build_user_message(
        finding, f"const api_key={secret};"
    )
    assert secret not in prompt
    assert "[REDACTED-SECRET]" in prompt


def test_checkpoints_and_disclosure_bundles_redact_on_write(tmp_path: Path) -> None:
    secret = "super-secret-value"
    checkpoint = tmp_path / "findings.jsonl"
    pool = FindingsPool(checkpoint_path=checkpoint)
    pool._checkpoint(
        {
            "id": "f1",
            "description": f"api_key={secret}",
            "code_snippet": f"api_key={secret}",
        }
    )
    bundle = DisclosureBundle(
        templates=[
            DisclosureTemplate(
                finding_id="f1",
                format="hackerone",
                title="Finding",
                body=f"api_key={secret}",
                severity="high",
                cwe="CWE-798",
                evidence_level="root_cause_explained",
                validated=False,
            )
        ],
        repo_url=f"https://user:{secret}@example.test/repo.git",
    )
    paths = write_bundle(bundle, str(tmp_path), "session")
    disclosure = Path(paths["hackerone"][0]).read_text(encoding="utf-8")
    manifest = Path(paths["manifest"][0]).read_text(encoding="utf-8")

    assert secret not in checkpoint.read_text(encoding="utf-8")
    assert secret not in disclosure
    assert secret not in manifest


def test_historical_store_redacts_and_keeps_repo_lookup_stable(tmp_path: Path) -> None:
    secret = "super-secret-value"
    repo_url = f"https://user:{secret}@example.test/repo.git"
    database = HistoricalFindingsDB(tmp_path / "historical.db")
    try:
        database.ingest_campaign(
            [
                {
                    "id": "f1",
                    "file": "source.py",
                    "line_number": 1,
                    "cwe": "CWE-798",
                    "description": f"api_key={secret}",
                    "code_snippet": f"api_key={secret}",
                }
            ],
            repo_url=repo_url,
            session_id="session",
        )
        rows = database.query_prior(repo_url)
    finally:
        database.close()

    assert len(rows) == 1
    assert secret not in json.dumps(rows)


def test_generated_disclosure_neutralizes_markdown_injection() -> None:
    bundle = DisclosureGenerator(repo_url="https://example.test/repo.git").generate_bundle(
        [
            {
                "id": "f1",
                "verified": True,
                "evidence_level": "root_cause_explained",
                "finding_type": "overflow\n## Forged section",
                "file": "src/a`b.c",
                "line_number": 7,
                "description": "summary\n## Forged section",
                "code_snippet": "```\nmalicious fence\n```",
            }
        ],
        formats=["hackerone"],
    )
    body = bundle.templates[0].body

    assert "\n## Forged section\n" not in body
    assert "````\n```\nmalicious fence\n```\n````" in body
