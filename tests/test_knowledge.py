"""Tests for the Knowledge Graph module."""

import json
import tempfile
from pathlib import Path

import pytest

from vulnexploit.data.knowledge import KnowledgeGraph


@pytest.fixture
def kg(tmp_path):
    """Create a KnowledgeGraph with a temp persist path."""
    path = str(tmp_path / "kg.json")
    return KnowledgeGraph(persist_path=path)


@pytest.fixture
def populated_kg(kg):
    """A KG with some test data pre-loaded."""
    kg.add_target("10.0.0.1", hostname="victim")
    kg.add_port("10.0.0.1", 22, "tcp")
    kg.add_port("10.0.0.1", 80, "tcp")
    kg.add_service("10.0.0.1:80/tcp", "apache", "2.4.49")
    kg.add_vulnerability("10.0.0.1:80/tcp:apache", "CVE-2021-41773", cvss=7.5)
    kg.add_exploit_result("CVE-2021-41773", "path_traversal", success=True)
    return kg


# --- Entity CRUD ---

class TestEntityManagement:
    def test_add_and_get_entity(self, kg):
        entity = kg.add_entity("target", "10.0.0.1", hostname="test")
        assert entity.id == "10.0.0.1"
        assert entity.entity_type == "target"
        assert entity.properties["hostname"] == "test"

        retrieved = kg.get_entity("10.0.0.1")
        assert retrieved is not None
        assert retrieved.entity_type == "target"

    def test_get_nonexistent_entity(self, kg):
        assert kg.get_entity("nope") is None

    def test_get_entities_by_type(self, kg):
        kg.add_entity("target", "10.0.0.1")
        kg.add_entity("target", "10.0.0.2")
        kg.add_entity("port", "10.0.0.1:80/tcp")

        targets = kg.get_entities_by_type("target")
        assert len(targets) == 2
        ports = kg.get_entities_by_type("port")
        assert len(ports) == 1

    def test_update_entity_properties(self, kg):
        kg.add_entity("target", "10.0.0.1", hostname="old")
        kg.add_entity("target", "10.0.0.1", hostname="new")
        entity = kg.get_entity("10.0.0.1")
        assert entity.properties["hostname"] == "new"


# --- Relationship CRUD ---

class TestRelationshipManagement:
    def test_add_and_get_relationship(self, kg):
        kg.add_entity("target", "10.0.0.1")
        kg.add_entity("port", "10.0.0.1:80/tcp")
        rel = kg.add_relationship("10.0.0.1", "10.0.0.1:80/tcp", "HAS_PORT")
        assert rel.rel_type == "HAS_PORT"

        rels = kg.get_relationships("10.0.0.1", direction="out")
        assert len(rels) == 1
        assert rels[0].target_id == "10.0.0.1:80/tcp"

    def test_get_relationships_in(self, kg):
        kg.add_entity("target", "10.0.0.1")
        kg.add_entity("port", "10.0.0.1:80/tcp")
        kg.add_relationship("10.0.0.1", "10.0.0.1:80/tcp", "HAS_PORT")

        rels = kg.get_relationships("10.0.0.1:80/tcp", direction="in")
        assert len(rels) == 1
        assert rels[0].source_id == "10.0.0.1"

    def test_get_relationships_both(self, kg):
        kg.add_entity("target", "10.0.0.1")
        kg.add_entity("port", "10.0.0.1:80/tcp")
        kg.add_entity("service", "10.0.0.1:80/tcp:apache")
        kg.add_relationship("10.0.0.1", "10.0.0.1:80/tcp", "HAS_PORT")
        kg.add_relationship("10.0.0.1:80/tcp", "10.0.0.1:80/tcp:apache", "RUNS_SERVICE")

        rels = kg.get_relationships("10.0.0.1:80/tcp", direction="both")
        assert len(rels) == 2

    def test_get_neighbors(self, populated_kg):
        neighbors = populated_kg.get_neighbors("10.0.0.1")
        assert len(neighbors) == 2  # two ports

    def test_get_neighbors_filtered(self, populated_kg):
        neighbors = populated_kg.get_neighbors("10.0.0.1", rel_type="HAS_PORT")
        assert len(neighbors) == 2


# --- Convenience methods ---

class TestConvenienceMethods:
    def test_add_target(self, kg):
        entity = kg.add_target("10.0.0.1", hostname="victim")
        assert entity.entity_type == "target"

    def test_add_port(self, kg):
        kg.add_target("10.0.0.1")
        entity = kg.add_port("10.0.0.1", 80, "tcp")
        assert entity.id == "10.0.0.1:80/tcp"
        # Check relationship was created
        rels = kg.get_relationships("10.0.0.1", direction="out")
        assert any(r.rel_type == "HAS_PORT" for r in rels)

    def test_add_service(self, kg):
        kg.add_target("10.0.0.1")
        kg.add_port("10.0.0.1", 80)
        entity = kg.add_service("10.0.0.1:80/tcp", "apache", "2.4.49")
        assert entity.entity_type == "service"

    def test_add_vulnerability(self, kg):
        kg.add_target("10.0.0.1")
        kg.add_port("10.0.0.1", 80)
        kg.add_service("10.0.0.1:80/tcp", "apache")
        entity = kg.add_vulnerability("10.0.0.1:80/tcp:apache", "CVE-2021-41773", cvss=7.5)
        assert entity.entity_type == "cve"

    def test_add_exploit_result(self, kg):
        entity = kg.add_exploit_result("CVE-2021-41773", "path_traversal", success=True)
        assert entity.entity_type == "exploit"
        assert entity.id == "exploit:path_traversal"


# --- Query interface ---

class TestQuery:
    def test_stats(self, populated_kg):
        result = populated_kg.query("stats")
        assert "entities" in result
        assert "relationships" in result

    def test_all_targets(self, populated_kg):
        result = populated_kg.query("all targets")
        assert "10.0.0.1" in result

    def test_ports_for_target(self, populated_kg):
        result = populated_kg.query("ports for 10.0.0.1")
        assert "80" in result

    def test_services_for_port(self, populated_kg):
        result = populated_kg.query("services on 10.0.0.1:80/tcp")
        assert "apache" in result

    def test_no_results(self, populated_kg):
        result = populated_kg.query("ports for 10.0.0.99")
        assert "No port" in result or "No" in result

    def test_fallback_to_stats(self, populated_kg):
        result = populated_kg.query("something random")
        assert "entities" in result


# --- Persistence ---

class TestPersistence:
    def test_save_and_load(self, tmp_path):
        path = str(tmp_path / "kg.json")
        kg1 = KnowledgeGraph(persist_path=path)
        kg1.add_target("10.0.0.1")
        kg1.add_port("10.0.0.1", 80)
        kg1.save()

        # Load into a new instance
        kg2 = KnowledgeGraph(persist_path=path)
        entity = kg2.get_entity("10.0.0.1")
        assert entity is not None
        assert entity.entity_type == "target"

        ports = kg2.get_entities_by_type("port")
        assert len(ports) == 1

    def test_persist_file_is_valid_json(self, tmp_path):
        path = tmp_path / "kg.json"
        kg = KnowledgeGraph(persist_path=str(path))
        kg.add_target("10.0.0.1")
        kg.save()

        data = json.loads(path.read_text())
        assert "nodes" in data or "directed" in data

    def test_no_persist_path(self):
        kg = KnowledgeGraph()
        kg.add_target("10.0.0.1")
        kg.save()  # Should not raise

    def test_clear(self, populated_kg):
        populated_kg.clear()
        assert populated_kg.get_entity("10.0.0.1") is None
        assert len(populated_kg.get_entities_by_type("target")) == 0
