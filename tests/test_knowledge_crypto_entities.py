"""Tests for the v0.4 knowledge-graph crypto entities."""

from __future__ import annotations

from pathlib import Path

from clearwing.data.knowledge import KnowledgeGraph


class TestCryptoEntityTypes:
    def test_new_entity_types_registered(self):
        for et in ("protocol", "algorithm", "key_material", "certificate", "kdf_config"):
            assert et in KnowledgeGraph.ENTITY_TYPES

    def test_new_relationship_types_registered(self):
        for rt in (
            "USES_ALGORITHM",
            "DERIVES_KEY",
            "WRAPS_KEY",
            "DECRYPTS",
            "AUTHENTICATES_WITH",
            "PRESENTS_CERT",
            "VULNERABLE_TO",
        ):
            assert rt in KnowledgeGraph.RELATIONSHIP_TYPES


class TestAddProtocol:
    def test_creates_entity(self, tmp_path: Path):
        kg = KnowledgeGraph(persist_path=str(tmp_path / "kg.json"))
        kg.add_protocol("SRP-6a")
        entity = kg.get_entity("protocol:SRP-6a")
        assert entity is not None
        assert entity.entity_type == "protocol"
        assert entity.properties["name"] == "SRP-6a"


class TestAddAlgorithm:
    def test_creates_entity(self, tmp_path: Path):
        kg = KnowledgeGraph(persist_path=str(tmp_path / "kg.json"))
        kg.add_algorithm("AES-256-GCM")
        entity = kg.get_entity("algorithm:AES-256-GCM")
        assert entity is not None
        assert entity.entity_type == "algorithm"
        assert entity.properties["name"] == "AES-256-GCM"

    def test_with_properties(self, tmp_path: Path):
        kg = KnowledgeGraph(persist_path=str(tmp_path / "kg.json"))
        kg.add_algorithm("RSA-OAEP", key_bits=2048, mode="OAEP")
        entity = kg.get_entity("algorithm:RSA-OAEP")
        assert entity.properties["key_bits"] == 2048
        assert entity.properties["mode"] == "OAEP"


class TestAddKeyMaterial:
    def test_creates_entity(self, tmp_path: Path):
        kg = KnowledgeGraph(persist_path=str(tmp_path / "kg.json"))
        kg.add_key_material("auk", "10.0.0.1")
        entity = kg.get_entity("key:auk:10.0.0.1")
        assert entity is not None
        assert entity.entity_type == "key_material"
        assert entity.properties["key_type"] == "auk"
        assert entity.properties["target"] == "10.0.0.1"

    def test_with_properties(self, tmp_path: Path):
        kg = KnowledgeGraph(persist_path=str(tmp_path / "kg.json"))
        kg.add_key_material("vault_key", "10.0.0.1", key_length_bytes=32, extractable=False)
        entity = kg.get_entity("key:vault_key:10.0.0.1")
        assert entity.properties["key_length_bytes"] == 32
        assert entity.properties["extractable"] is False


class TestAddCertificate:
    def test_creates_entity(self, tmp_path: Path):
        kg = KnowledgeGraph(persist_path=str(tmp_path / "kg.json"))
        kg.add_certificate("example.com")
        entity = kg.get_entity("cert:example.com:443")
        assert entity is not None
        assert entity.entity_type == "certificate"
        assert entity.properties["host"] == "example.com"
        assert entity.properties["port"] == 443

    def test_auto_links_to_target(self, tmp_path: Path):
        kg = KnowledgeGraph(persist_path=str(tmp_path / "kg.json"))
        kg.add_target("example.com")
        kg.add_certificate("example.com", subject_cn="example.com")
        rels = kg.get_relationships("example.com", direction="out")
        assert any(r.rel_type == "PRESENTS_CERT" and r.target_id == "cert:example.com:443" for r in rels)

    def test_no_auto_link_without_target(self, tmp_path: Path):
        kg = KnowledgeGraph(persist_path=str(tmp_path / "kg.json"))
        kg.add_certificate("example.com")
        rels = kg.get_relationships("cert:example.com:443", direction="in")
        assert not any(r.rel_type == "PRESENTS_CERT" for r in rels)


class TestAddKdfConfig:
    def test_creates_entity(self, tmp_path: Path):
        kg = KnowledgeGraph(persist_path=str(tmp_path / "kg.json"))
        kg.add_kdf_config("PBKDF2-HMAC-SHA256", 650000, "10.0.0.1")
        entity = kg.get_entity("kdf:PBKDF2-HMAC-SHA256:650000:10.0.0.1")
        assert entity is not None
        assert entity.entity_type == "kdf_config"
        assert entity.properties["algorithm"] == "PBKDF2-HMAC-SHA256"
        assert entity.properties["iterations"] == 650000
        assert entity.properties["target"] == "10.0.0.1"


class TestCryptoRelationships:
    def test_uses_algorithm(self, tmp_path: Path):
        kg = KnowledgeGraph(persist_path=str(tmp_path / "kg.json"))
        kg.add_protocol("SRP-6a")
        kg.add_algorithm("PBKDF2-HMAC-SHA256")
        kg.add_relationship("protocol:SRP-6a", "algorithm:PBKDF2-HMAC-SHA256", "USES_ALGORITHM")
        rels = kg.get_relationships("protocol:SRP-6a", direction="out")
        assert any(r.rel_type == "USES_ALGORITHM" and r.target_id == "algorithm:PBKDF2-HMAC-SHA256" for r in rels)

    def test_derives_key(self, tmp_path: Path):
        kg = KnowledgeGraph(persist_path=str(tmp_path / "kg.json"))
        kg.add_kdf_config("PBKDF2-HMAC-SHA256", 650000, "10.0.0.1")
        kg.add_key_material("auk", "10.0.0.1")
        kg.add_relationship("kdf:PBKDF2-HMAC-SHA256:650000:10.0.0.1", "key:auk:10.0.0.1", "DERIVES_KEY")
        neighbors = kg.get_neighbors("kdf:PBKDF2-HMAC-SHA256:650000:10.0.0.1", rel_type="DERIVES_KEY")
        assert any(n.id == "key:auk:10.0.0.1" for n in neighbors)

    def test_wraps_key(self, tmp_path: Path):
        kg = KnowledgeGraph(persist_path=str(tmp_path / "kg.json"))
        kg.add_key_material("personal_keyset", "10.0.0.1")
        kg.add_key_material("vault_key", "10.0.0.1")
        kg.add_relationship("key:personal_keyset:10.0.0.1", "key:vault_key:10.0.0.1", "WRAPS_KEY")
        rels = kg.get_relationships("key:personal_keyset:10.0.0.1", direction="out")
        assert any(r.rel_type == "WRAPS_KEY" for r in rels)

    def test_authenticates_with(self, tmp_path: Path):
        kg = KnowledgeGraph(persist_path=str(tmp_path / "kg.json"))
        kg.add_protocol("SRP-6a")
        kg.add_key_material("srp_x", "10.0.0.1")
        kg.add_relationship("protocol:SRP-6a", "key:srp_x:10.0.0.1", "AUTHENTICATES_WITH")
        neighbors = kg.get_neighbors("protocol:SRP-6a", rel_type="AUTHENTICATES_WITH")
        assert any(n.id == "key:srp_x:10.0.0.1" for n in neighbors)

    def test_vulnerable_to(self, tmp_path: Path):
        kg = KnowledgeGraph(persist_path=str(tmp_path / "kg.json"))
        kg.add_algorithm("AES-256-GCM")
        kg.add_entity("exploit", "nonce-reuse-attack", description="AES-GCM nonce reuse")
        kg.add_relationship("algorithm:AES-256-GCM", "nonce-reuse-attack", "VULNERABLE_TO")
        neighbors = kg.get_neighbors("algorithm:AES-256-GCM", rel_type="VULNERABLE_TO")
        assert any(n.id == "nonce-reuse-attack" for n in neighbors)


class TestCryptoQueries:
    def test_all_protocols(self, tmp_path: Path):
        kg = KnowledgeGraph(persist_path=str(tmp_path / "kg.json"))
        kg.add_protocol("SRP-6a")
        kg.add_protocol("TLS")
        result = kg.query("all protocols")
        assert "protocol:SRP-6a" in result
        assert "protocol:TLS" in result

    def test_algorithms_for_protocol(self, tmp_path: Path):
        kg = KnowledgeGraph(persist_path=str(tmp_path / "kg.json"))
        kg.add_protocol("SRP-6a")
        kg.add_algorithm("PBKDF2-HMAC-SHA256")
        kg.add_algorithm("SHA-256")
        kg.add_relationship("protocol:SRP-6a", "algorithm:PBKDF2-HMAC-SHA256", "USES_ALGORITHM")
        kg.add_relationship("protocol:SRP-6a", "algorithm:SHA-256", "USES_ALGORITHM")
        result = kg.query("algorithms for SRP-6a")
        assert "PBKDF2-HMAC-SHA256" in result
        assert "SHA-256" in result

    def test_key_material_for_target(self, tmp_path: Path):
        kg = KnowledgeGraph(persist_path=str(tmp_path / "kg.json"))
        kg.add_key_material("auk", "10.0.0.1")
        kg.add_key_material("vault_key", "10.0.0.1")
        kg.add_key_material("auk", "10.0.0.2")
        result = kg.query("key material for 10.0.0.1")
        assert "key:auk:10.0.0.1" in result
        assert "key:vault_key:10.0.0.1" in result
        assert "10.0.0.2" not in result

    def test_key_chain(self, tmp_path: Path):
        kg = KnowledgeGraph(persist_path=str(tmp_path / "kg.json"))
        kg.add_key_material("auk", "10.0.0.1")
        kg.add_key_material("personal_keyset", "10.0.0.1")
        kg.add_key_material("vault_key", "10.0.0.1")
        kg.add_relationship("key:auk:10.0.0.1", "key:personal_keyset:10.0.0.1", "WRAPS_KEY")
        kg.add_relationship("key:personal_keyset:10.0.0.1", "key:vault_key:10.0.0.1", "WRAPS_KEY")
        result = kg.query("key chain for key:auk:10.0.0.1")
        assert "personal_keyset" in result
        assert "vault_key" in result
        assert "WRAPS_KEY" in result

    def test_certificates_for_target(self, tmp_path: Path):
        kg = KnowledgeGraph(persist_path=str(tmp_path / "kg.json"))
        kg.add_target("example.com")
        kg.add_certificate("example.com", subject_cn="example.com")
        result = kg.query("certificates for example.com")
        assert "cert:example.com:443" in result

    def test_kdf_config_for_target(self, tmp_path: Path):
        kg = KnowledgeGraph(persist_path=str(tmp_path / "kg.json"))
        kg.add_kdf_config("PBKDF2-HMAC-SHA256", 650000, "10.0.0.1")
        result = kg.query("kdf config for 10.0.0.1")
        assert "PBKDF2-HMAC-SHA256" in result
        assert "650000" in result


class TestKeyChainTraversal:
    def test_linear_chain(self, tmp_path: Path):
        kg = KnowledgeGraph(persist_path=str(tmp_path / "kg.json"))
        kg.add_key_material("a", "t")
        kg.add_key_material("b", "t")
        kg.add_key_material("c", "t")
        kg.add_relationship("key:a:t", "key:b:t", "DERIVES_KEY")
        kg.add_relationship("key:b:t", "key:c:t", "WRAPS_KEY")
        chain = kg._get_key_chain("key:a:t")
        ids = [e.id for e, _, _ in chain]
        assert ids == ["key:b:t", "key:c:t"]

    def test_handles_cycles(self, tmp_path: Path):
        kg = KnowledgeGraph(persist_path=str(tmp_path / "kg.json"))
        kg.add_key_material("a", "t")
        kg.add_key_material("b", "t")
        kg.add_relationship("key:a:t", "key:b:t", "WRAPS_KEY")
        kg.add_relationship("key:b:t", "key:a:t", "WRAPS_KEY")
        chain = kg._get_key_chain("key:a:t")
        ids = [e.id for e, _, _ in chain]
        assert "key:b:t" in ids
        assert len(ids) == 1

    def test_empty_chain(self, tmp_path: Path):
        kg = KnowledgeGraph(persist_path=str(tmp_path / "kg.json"))
        kg.add_key_material("isolated", "t")
        chain = kg._get_key_chain("key:isolated:t")
        assert chain == []


class TestCryptoPersistence:
    def test_save_load_roundtrip(self, tmp_path: Path):
        path = str(tmp_path / "kg.json")
        kg = KnowledgeGraph(persist_path=path)
        kg.add_protocol("SRP-6a")
        kg.add_algorithm("AES-256-GCM")
        kg.add_key_material("auk", "10.0.0.1")
        kg.add_certificate("example.com")
        kg.add_kdf_config("PBKDF2-HMAC-SHA256", 650000, "10.0.0.1")
        kg.add_relationship("protocol:SRP-6a", "algorithm:AES-256-GCM", "USES_ALGORITHM")
        kg.save()

        kg2 = KnowledgeGraph(persist_path=path)
        assert kg2.get_entity("protocol:SRP-6a") is not None
        assert kg2.get_entity("algorithm:AES-256-GCM") is not None
        assert kg2.get_entity("key:auk:10.0.0.1") is not None
        assert kg2.get_entity("cert:example.com:443") is not None
        assert kg2.get_entity("kdf:PBKDF2-HMAC-SHA256:650000:10.0.0.1") is not None
        rels = kg2.get_relationships("protocol:SRP-6a", direction="out")
        assert any(r.rel_type == "USES_ALGORITHM" for r in rels)
