"""Tests for the v0.4 coordinated-disclosure helper."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnexploit.sourcehunt.disclosure import (
    DEFAULT_MIN_EVIDENCE,
    DisclosureBundle,
    DisclosureGenerator,
    DisclosureTemplate,
    write_bundle,
)


def _finding(**kwargs) -> dict:
    base = {
        "id": "hunter-abc",
        "file": "src/codec.c",
        "line_number": 47,
        "cwe": "CWE-787",
        "severity": "critical",
        "severity_verified": "critical",
        "verified": True,
        "evidence_level": "root_cause_explained",
        "description": "memcpy with unchecked length",
        "code_snippet": "memcpy(buf, input, user_len);",
        "crash_evidence": "==1==ERROR: AddressSanitizer: heap-buffer-overflow",
        "poc": "AAAA...AAAA",
        "finding_type": "memory_safety_heap_overflow",
        "discovered_by": "hunter:memory_safety",
        "verifier_pro_argument": "user_len comes from an attacker-controlled header",
        "verifier_counter_argument": "caller does not validate length",
    }
    base.update(kwargs)
    return base


# --- Eligibility gate ------------------------------------------------------


class TestEligibility:
    def test_unverified_skipped(self):
        gen = DisclosureGenerator()
        bundle = gen.generate_bundle([_finding(verified=False)])
        assert bundle.templates == []
        assert bundle.skipped == 1
        assert "unverified" in bundle.skipped_reasons

    def test_low_evidence_skipped(self):
        gen = DisclosureGenerator()
        bundle = gen.generate_bundle([_finding(evidence_level="crash_reproduced")])
        assert bundle.templates == []
        assert bundle.skipped == 1
        assert any("evidence_level" in k for k in bundle.skipped_reasons)

    def test_variant_loop_skipped(self):
        """variant_loop matches must be re-verified separately."""
        gen = DisclosureGenerator()
        bundle = gen.generate_bundle([_finding(discovered_by="variant_loop")])
        assert bundle.templates == []
        assert "variant_loop_hypothesis" in bundle.skipped_reasons

    def test_root_cause_eligible(self):
        gen = DisclosureGenerator(project_name="test-project")
        bundle = gen.generate_bundle([_finding()])
        assert len(bundle.templates) == 2  # mitre + hackerone by default

    def test_exploit_demonstrated_eligible(self):
        gen = DisclosureGenerator(project_name="x")
        bundle = gen.generate_bundle([
            _finding(evidence_level="exploit_demonstrated"),
        ])
        assert len(bundle.templates) == 2

    def test_patch_validated_eligible(self):
        gen = DisclosureGenerator(project_name="x")
        bundle = gen.generate_bundle([
            _finding(
                evidence_level="patch_validated",
                auto_patch="# diff",
                auto_patch_validated=True,
            ),
        ])
        assert len(bundle.templates) == 2
        # Validated templates should reflect that
        assert all(t.validated for t in bundle.templates)


# --- MITRE template --------------------------------------------------------


class TestMitreTemplate:
    def test_mitre_body_includes_cve_form_fields(self):
        gen = DisclosureGenerator(
            repo_url="https://github.com/example/codec",
            project_name="codec",
            reporter_name="Alice",
            reporter_affiliation="Acme Security",
            reporter_email="alice@acme.com",
        )
        bundle = gen.generate_bundle([_finding()], formats=["mitre"])
        assert len(bundle.templates) == 1
        body = bundle.templates[0].body
        # MITRE form field headers
        assert "[Vulnerability type]:" in body
        assert "[Vendor of product]:" in body
        assert "[Affected component]:" in body
        assert "[Suggested description" in body
        assert "[Discoverer]:" in body
        assert "[Reference]:" in body
        assert "[Contact email]:" in body
        # Reporter info filled in
        assert "Alice" in body
        assert "Acme Security" in body
        assert "alice@acme.com" in body
        # File / CWE / snippet / crash
        assert "src/codec.c" in body
        assert "CWE-787" in body
        assert "memcpy(buf, input, user_len);" in body
        assert "AddressSanitizer" in body

    def test_mitre_vuln_type_memory_for_heap_overflow(self):
        gen = DisclosureGenerator(project_name="x")
        bundle = gen.generate_bundle(
            [_finding(finding_type="memory_safety_heap_overflow")],
            formats=["mitre"],
        )
        assert "Memory Corruption" in bundle.templates[0].body

    def test_mitre_vuln_type_injection_for_sqli(self):
        gen = DisclosureGenerator(project_name="x")
        bundle = gen.generate_bundle(
            [_finding(finding_type="sql_injection", cwe="CWE-89")],
            formats=["mitre"],
        )
        assert "Injection" in bundle.templates[0].body

    def test_mitre_includes_validated_patch(self):
        gen = DisclosureGenerator(project_name="x")
        bundle = gen.generate_bundle([
            _finding(
                auto_patch="-bad\n+good",
                auto_patch_validated=True,
                evidence_level="patch_validated",
            ),
        ], formats=["mitre"])
        body = bundle.templates[0].body
        assert "Candidate patch" in body
        assert "VALIDATED" in body
        assert "-bad" in body


# --- HackerOne template ----------------------------------------------------


class TestHackerOneTemplate:
    def test_h1_body_includes_standard_sections(self):
        gen = DisclosureGenerator(
            repo_url="https://github.com/example/codec",
            project_name="codec",
        )
        bundle = gen.generate_bundle([_finding()], formats=["hackerone"])
        body = bundle.templates[0].body
        assert "## Summary" in body
        assert "## Steps to Reproduce" in body
        assert "## Code Snippet" in body
        assert "## Impact" in body
        assert "## Reporter" in body

    def test_h1_body_includes_verifier_arguments(self):
        gen = DisclosureGenerator(project_name="x")
        bundle = gen.generate_bundle([_finding()], formats=["hackerone"])
        body = bundle.templates[0].body
        assert "Pro-vulnerability argument" in body
        assert "attacker-controlled header" in body
        assert "Steel-manned counter-argument" in body

    def test_h1_body_has_clone_step(self):
        gen = DisclosureGenerator(
            repo_url="https://github.com/example/codec",
            project_name="codec",
        )
        bundle = gen.generate_bundle([_finding()], formats=["hackerone"])
        body = bundle.templates[0].body
        assert "git clone https://github.com/example/codec" in body

    def test_h1_impact_memory_corruption_phrasing(self):
        gen = DisclosureGenerator(project_name="x")
        bundle = gen.generate_bundle(
            [_finding(finding_type="heap_overflow")],
            formats=["hackerone"],
        )
        body = bundle.templates[0].body
        assert "arbitrary code execution" in body


# --- Project name extraction ----------------------------------------------


class TestProjectNameFromUrl:
    def test_github_url(self):
        gen = DisclosureGenerator(repo_url="https://github.com/FFmpeg/FFmpeg")
        assert gen.project_name == "FFmpeg"

    def test_git_suffix_stripped(self):
        gen = DisclosureGenerator(repo_url="https://github.com/example/project.git")
        assert gen.project_name == "project"

    def test_local_path(self):
        gen = DisclosureGenerator(repo_url="/tmp/example-repo")
        assert gen.project_name == "example-repo"

    def test_empty(self):
        gen = DisclosureGenerator(repo_url="")
        assert "project" in gen.project_name.lower()


# --- Writer ----------------------------------------------------------------


class TestWriteBundle:
    def test_writes_templates_to_disk(self, tmp_path: Path):
        gen = DisclosureGenerator(project_name="codec")
        bundle = gen.generate_bundle([_finding()])
        paths = write_bundle(bundle, str(tmp_path), "session-123")

        # Each format has its subdir
        mitre_dir = tmp_path / "session-123" / "disclosures" / "mitre"
        h1_dir = tmp_path / "session-123" / "disclosures" / "hackerone"
        assert mitre_dir.is_dir()
        assert h1_dir.is_dir()

        # Template files exist
        mitre_files = list(mitre_dir.glob("*.md"))
        h1_files = list(h1_dir.glob("*.md"))
        assert len(mitre_files) == 1
        assert len(h1_files) == 1

        # paths dict matches
        assert len(paths["mitre"]) == 1
        assert len(paths["hackerone"]) == 1

        # Manifest exists and is valid JSON
        manifest_path = tmp_path / "session-123" / "disclosures" / "manifest.json"
        assert manifest_path.exists()
        manifest = json.loads(manifest_path.read_text())
        assert manifest["templates_generated"] == 2
        assert manifest["skipped"] == 0

    def test_unsafe_finding_id_sanitized(self, tmp_path: Path):
        gen = DisclosureGenerator(project_name="x")
        bundle = gen.generate_bundle([_finding(id="../../etc/passwd")])
        paths = write_bundle(bundle, str(tmp_path), "session-999")
        # No file outside the session directory
        for fmt_paths in (paths["mitre"], paths["hackerone"]):
            for p in fmt_paths:
                assert "session-999" in p
                assert "/etc/passwd" not in p

    def test_skipped_reasons_in_manifest(self, tmp_path: Path):
        gen = DisclosureGenerator(project_name="x")
        bundle = gen.generate_bundle([
            _finding(verified=False),
            _finding(evidence_level="suspicion"),
            _finding(),   # eligible
        ])
        write_bundle(bundle, str(tmp_path), "s1")
        manifest = json.loads(
            (tmp_path / "s1" / "disclosures" / "manifest.json").read_text()
        )
        assert manifest["skipped"] == 2
        assert "unverified" in manifest["skipped_reasons"]


# --- Runner integration ----------------------------------------------------


class TestRunnerDisclosureIntegration:
    def test_disclosures_opt_in(self, tmp_path: Path):
        """Disclosures should NOT be exported when the flag is off."""
        from vulnexploit.sourcehunt.runner import SourceHuntRunner
        fixture = Path(__file__).parent / "fixtures" / "vuln_samples" / "py_sqli"
        runner = SourceHuntRunner(
            repo_url=str(fixture),
            local_path=str(fixture),
            depth="quick",
            output_dir=str(tmp_path),
            export_disclosures=False,
        )
        runner.run()
        disc = tmp_path / runner.session_id / "disclosures"
        assert not disc.exists()

    def test_disclosures_runner_flag(self):
        """The runner stores the flag and reporter fields."""
        from vulnexploit.sourcehunt.runner import SourceHuntRunner
        runner = SourceHuntRunner(
            repo_url="x",
            local_path="/tmp",
            depth="quick",
            output_dir="/tmp/out",
            export_disclosures=True,
            disclosure_reporter_name="Alice",
            disclosure_reporter_affiliation="Acme",
            disclosure_reporter_email="a@b.c",
        )
        assert runner.export_disclosures is True
        assert runner.disclosure_reporter_name == "Alice"
