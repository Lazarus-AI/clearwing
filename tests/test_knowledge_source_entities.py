"""Tests for the v0.3 knowledge-graph source entities."""
from __future__ import annotations

from pathlib import Path

import pytest

from vulnexploit.data.knowledge import KnowledgeGraph


def _finding(**kwargs) -> dict:
    base = {
        "id": "hunter-abc",
        "file": "src/codec.c",
        "line_number": 47,
        "cwe": "CWE-787",
        "severity": "critical",
        "evidence_level": "crash_reproduced",
        "discovered_by": "hunter:memory_safety",
        "description": "memcpy with unchecked length",
        "verified": True,
    }
    base.update(kwargs)
    return base


class TestSourceEntityTypes:
    def test_new_entity_types_registered(self):
        assert "repo" in KnowledgeGraph.ENTITY_TYPES
        assert "source_file" in KnowledgeGraph.ENTITY_TYPES
        assert "source_finding" in KnowledgeGraph.ENTITY_TYPES

    def test_new_relationship_types_registered(self):
        assert "HAS_FILE" in KnowledgeGraph.RELATIONSHIP_TYPES
        assert "HAS_FINDING" in KnowledgeGraph.RELATIONSHIP_TYPES
        assert "VARIANT_OF" in KnowledgeGraph.RELATIONSHIP_TYPES
        assert "RELATED_TO_CVE" in KnowledgeGraph.RELATIONSHIP_TYPES


class TestAddRepo:
    def test_add_repo_creates_entity(self, tmp_path: Path):
        kg = KnowledgeGraph(persist_path=str(tmp_path / "kg.json"))
        kg.add_repo("https://github.com/example/repo")
        entity = kg.get_entity("https://github.com/example/repo")
        assert entity is not None
        assert entity.entity_type == "repo"


class TestAddSourceFile:
    def test_add_file_links_to_repo(self, tmp_path: Path):
        kg = KnowledgeGraph(persist_path=str(tmp_path / "kg.json"))
        kg.add_repo("https://x/y")
        kg.add_source_file("https://x/y", "src/foo.c", language="c")
        file_id = "https://x/y::src/foo.c"
        entity = kg.get_entity(file_id)
        assert entity is not None
        assert entity.entity_type == "source_file"
        assert entity.properties["language"] == "c"
        # HAS_FILE edge
        rels = kg.get_relationships("https://x/y", direction="out")
        assert any(r.rel_type == "HAS_FILE" and r.target_id == file_id for r in rels)


class TestAddSourceFinding:
    def test_add_finding_autolinks_file_and_repo(self, tmp_path: Path):
        kg = KnowledgeGraph(persist_path=str(tmp_path / "kg.json"))
        repo = "https://x/y"
        kg.add_repo(repo)
        f = _finding()
        kg.add_source_finding(repo, "src/codec.c", f)
        # Finding entity exists
        finding_entity = kg.get_entity("hunter-abc")
        assert finding_entity is not None
        assert finding_entity.entity_type == "source_finding"
        assert finding_entity.properties["cwe"] == "CWE-787"
        assert finding_entity.properties["severity"] == "critical"
        assert finding_entity.properties["evidence_level"] == "crash_reproduced"
        # File entity was auto-created
        file_entity = kg.get_entity(f"{repo}::src/codec.c")
        assert file_entity is not None
        # HAS_FINDING edge from file to finding
        rels = kg.get_relationships(f"{repo}::src/codec.c", direction="out")
        assert any(r.rel_type == "HAS_FINDING" for r in rels)

    def test_variant_finding_links_to_parent(self, tmp_path: Path):
        kg = KnowledgeGraph(persist_path=str(tmp_path / "kg.json"))
        repo = "https://x/y"
        kg.add_repo(repo)
        # Add parent first
        parent = _finding(id="parent-1")
        kg.add_source_finding(repo, "src/codec.c", parent)
        # Then add a variant pointing at the parent
        variant = _finding(
            id="variant-1",
            file="src/codec_b.c",
            line_number=10,
            related_finding_id="parent-1",
            discovered_by="variant_loop",
        )
        kg.add_source_finding(repo, "src/codec_b.c", variant)

        # VARIANT_OF edge from variant to parent
        rels = kg.get_relationships("variant-1", direction="out")
        assert any(r.rel_type == "VARIANT_OF" and r.target_id == "parent-1" for r in rels)

    def test_finding_with_related_cve_links_to_cve_entity(self, tmp_path: Path):
        kg = KnowledgeGraph(persist_path=str(tmp_path / "kg.json"))
        repo = "https://x/y"
        kg.add_repo(repo)
        retro_finding = _finding(
            id="retro-1",
            discovered_by="retro_hunt",
            related_cve="CVE-2024-9999",
        )
        kg.add_source_finding(repo, "src/codec.c", retro_finding)
        # CVE entity auto-created
        cve_entity = kg.get_entity("CVE-2024-9999")
        assert cve_entity is not None
        assert cve_entity.entity_type == "cve"
        # RELATED_TO_CVE edge
        rels = kg.get_relationships("retro-1", direction="out")
        assert any(
            r.rel_type == "RELATED_TO_CVE" and r.target_id == "CVE-2024-9999"
            for r in rels
        )


class TestRunnerKgIntegration:
    def test_runner_populates_kg_on_run(self, tmp_path: Path):
        """After a full run, the injected KG contains the finding entities."""
        from vulnexploit.sourcehunt.runner import SourceHuntRunner

        kg = KnowledgeGraph(persist_path=str(tmp_path / "kg.json"))
        fixture = Path(__file__).parent / "fixtures" / "vuln_samples" / "py_sqli"
        runner = SourceHuntRunner(
            repo_url=str(fixture),
            local_path=str(fixture),
            depth="quick",
            output_dir=str(tmp_path / "out"),
            knowledge_graph=kg,
        )
        runner.run()
        # The repo entity was added
        repo_entity = kg.get_entity(str(fixture))
        assert repo_entity is not None
        # At least one source_finding entity
        findings = kg.get_entities_by_type("source_finding")
        assert len(findings) >= 1

    def test_runner_can_disable_kg(self, tmp_path: Path):
        from vulnexploit.sourcehunt.runner import SourceHuntRunner
        runner = SourceHuntRunner(
            repo_url=str(tmp_path),
            local_path=str(tmp_path),
            depth="quick",
            output_dir=str(tmp_path / "out"),
            enable_knowledge_graph=False,
        )
        assert runner.enable_knowledge_graph is False
