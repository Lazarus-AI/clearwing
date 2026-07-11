"""Knowledge graph for tracking penetration testing entity relationships."""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import networkx as nx

logger = logging.getLogger(__name__)


def _extract_after(text: str, marker: str) -> str:
    idx = text.lower().find(marker.lower())
    if idx == -1:
        return text.strip()
    return text[idx + len(marker) :].strip()


@dataclass
class Entity:
    """A node in the knowledge graph."""

    id: str
    entity_type: str  # target, port, service, cve, exploit, component, credential
    properties: dict = field(default_factory=dict)
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(tz=timezone.utc).isoformat()


@dataclass
class Relationship:
    """An edge in the knowledge graph."""

    source_id: str
    target_id: str
    rel_type: (
        str  # HAS_PORT, RUNS_SERVICE, AFFECTED_BY, EXPLOITED_WITH, HAS_COMPONENT, HAS_CREDENTIAL
    )
    properties: dict = field(default_factory=dict)


class KnowledgeGraph:
    """NetworkX-based entity relationship tracker for pentest findings.

    Entities: Target, Port, Service, CVE, Exploit, Component, Credential
    Relationships: HAS_PORT, RUNS_SERVICE, AFFECTED_BY, EXPLOITED_WITH, HAS_COMPONENT, HAS_CREDENTIAL
    """

    _lock = threading.Lock()

    ENTITY_TYPES = (
        "target",
        "port",
        "service",
        "cve",
        "exploit",
        "component",
        "credential",
        # v0.3: source-hunt entities
        "repo",
        "source_file",
        "source_finding",
        # v0.4: crypto entities
        "protocol",
        "algorithm",
        "key_material",
        "certificate",
        "kdf_config",
    )
    RELATIONSHIP_TYPES = (
        "HAS_PORT",
        "RUNS_SERVICE",
        "AFFECTED_BY",
        "EXPLOITED_WITH",
        "HAS_COMPONENT",
        "HAS_CREDENTIAL",
        # v0.3: source-hunt relationships
        "HAS_FILE",
        "HAS_FINDING",
        "VARIANT_OF",
        "RELATED_TO_CVE",
        # v0.4: crypto relationships
        "USES_ALGORITHM",
        "DERIVES_KEY",
        "WRAPS_KEY",
        "DECRYPTS",
        "AUTHENTICATES_WITH",
        "PRESENTS_CERT",
        "VULNERABLE_TO",
    )

    def __init__(
        self,
        persist_path: str | None = None,
        *,
        auto_save: bool = False,
        auto_save_interval: float = 30.0,
        auto_save_after_n: int = 10,
    ):
        self._graph = nx.DiGraph()
        self._persist_path = Path(persist_path).expanduser() if persist_path else None
        self._auto_save = auto_save
        self._auto_save_interval = auto_save_interval
        self._auto_save_after_n = auto_save_after_n
        self._mutation_count = 0
        self._last_save_time = time.monotonic()
        if self._persist_path and self._persist_path.exists():
            self._load()

    # ------------------------------------------------------------------
    # Entity management
    # ------------------------------------------------------------------

    def _maybe_auto_save(self) -> None:
        if not self._auto_save or not self._persist_path:
            return
        self._mutation_count += 1
        elapsed = time.monotonic() - self._last_save_time
        if self._mutation_count >= self._auto_save_after_n or elapsed >= self._auto_save_interval:
            self._do_save()
            self._mutation_count = 0
            self._last_save_time = time.monotonic()

    def add_entity(self, entity_type: str, entity_id: str, **properties) -> Entity:
        """Add or update an entity node."""
        entity = Entity(id=entity_id, entity_type=entity_type, properties=properties)
        with self._lock:
            self._graph.add_node(
                entity_id,
                entity_type=entity_type,
                properties=properties,
                created_at=entity.created_at,
            )
        self._maybe_auto_save()
        return entity

    def get_entity(self, entity_id: str) -> Entity | None:
        """Retrieve an entity by ID."""
        with self._lock:
            if entity_id not in self._graph:
                return None
            data = self._graph.nodes[entity_id]
            return Entity(
                id=entity_id,
                entity_type=data.get("entity_type", "unknown"),
                properties=data.get("properties", {}),
                created_at=data.get("created_at", ""),
            )

    def get_entities_by_type(self, entity_type: str) -> list[Entity]:
        """Get all entities of a given type."""
        with self._lock:
            results = []
            for node_id, data in self._graph.nodes(data=True):
                if data.get("entity_type") == entity_type:
                    results.append(
                        Entity(
                            id=node_id,
                            entity_type=entity_type,
                            properties=data.get("properties", {}),
                            created_at=data.get("created_at", ""),
                        )
                    )
            return results

    # ------------------------------------------------------------------
    # Relationship management
    # ------------------------------------------------------------------

    def add_relationship(
        self, source_id: str, target_id: str, rel_type: str, **properties
    ) -> Relationship:
        """Add a directed relationship between two entities."""
        rel = Relationship(
            source_id=source_id, target_id=target_id, rel_type=rel_type, properties=properties
        )
        with self._lock:
            self._graph.add_edge(source_id, target_id, rel_type=rel_type, properties=properties)
        self._maybe_auto_save()
        return rel

    def get_relationships(self, entity_id: str, direction: str = "out") -> list[Relationship]:
        """Get relationships for an entity. direction: 'out', 'in', or 'both'."""
        results = []
        with self._lock:
            if direction in ("out", "both"):
                for _, target, data in self._graph.out_edges(entity_id, data=True):
                    results.append(
                        Relationship(
                            source_id=entity_id,
                            target_id=target,
                            rel_type=data.get("rel_type", ""),
                            properties=data.get("properties", {}),
                        )
                    )
            if direction in ("in", "both"):
                for source, _, data in self._graph.in_edges(entity_id, data=True):
                    results.append(
                        Relationship(
                            source_id=source,
                            target_id=entity_id,
                            rel_type=data.get("rel_type", ""),
                            properties=data.get("properties", {}),
                        )
                    )
        return results

    def get_neighbors(self, entity_id: str, rel_type: str | None = None) -> list[Entity]:
        """Get neighboring entities, optionally filtered by relationship type."""
        with self._lock:
            neighbors = []
            for _, target, data in self._graph.out_edges(entity_id, data=True):
                if rel_type is None or data.get("rel_type") == rel_type:
                    node_data = self._graph.nodes.get(target, {})
                    neighbors.append(
                        Entity(
                            id=target,
                            entity_type=node_data.get("entity_type", "unknown"),
                            properties=node_data.get("properties", {}),
                            created_at=node_data.get("created_at", ""),
                        )
                    )
            return neighbors

    # ------------------------------------------------------------------
    # Query methods
    # ------------------------------------------------------------------

    def query(self, query_str: str) -> str:
        """Natural-language-ish query interface for the agent.

        Supports queries like:
        - "ports for target 10.0.0.1"
        - "services on port 80"
        - "vulnerabilities for service apache"
        - "all targets"
        - "stats"
        """
        q = query_str.lower().strip()

        if q == "stats":
            return self._get_stats()

        if q.startswith("all "):
            entity_type = q[4:].rstrip("s")  # "all targets" -> "target"
            entities = self.get_entities_by_type(entity_type)
            if not entities:
                return f"No {entity_type} entities found."
            return "\n".join(f"- {e.id}: {e.properties}" for e in entities)

        crypto_result = self._query_crypto(q, query_str.strip())
        if crypto_result is not None:
            return crypto_result

        if "for" in q or "on" in q:
            # "ports for target 10.0.0.1" or "services on port 80"
            parts = q.replace(" for ", " on ").split(" on ")
            if len(parts) == 2:
                what = parts[0].strip().rstrip("s")  # "ports" -> "port"
                entity_id = parts[1].strip().split()[-1]  # last word is the ID
                neighbors = self.get_neighbors(entity_id)
                matched = [n for n in neighbors if n.entity_type == what]
                if not matched:
                    return f"No {what} entities connected to {entity_id}."
                return "\n".join(f"- {n.id}: {n.properties}" for n in matched)

        return self._get_stats()

    def _query_crypto(self, q: str, original: str) -> str | None:
        if "algorithms for" in q:
            proto_name = _extract_after(original, "algorithms for")
            proto_id = f"protocol:{proto_name}" if not proto_name.startswith("protocol:") else proto_name
            neighbors = self.get_neighbors(proto_id, rel_type="USES_ALGORITHM")
            if not neighbors:
                return f"No algorithms found for {proto_name}."
            return "\n".join(f"- {n.id}: {n.properties}" for n in neighbors)

        if "key chain" in q:
            parts = _extract_after(original, "key chain")
            start_id = _extract_after(parts, "for") if "for" in parts.lower() else parts.split()[-1]
            chain = self._get_key_chain(start_id)
            if not chain:
                return f"No key chain found from {start_id}."
            lines = [f"Key chain from {start_id}:"]
            for entity, rel_type, depth in chain:
                indent = "  " * depth
                lines.append(f"{indent}--[{rel_type}]--> {entity.id}: {entity.properties}")
            return "\n".join(lines)

        if "key material for" in q:
            target = _extract_after(original, "key material for")
            all_keys = self.get_entities_by_type("key_material")
            matched = [k for k in all_keys if k.properties.get("target") == target or target in k.id]
            if not matched:
                return f"No key material found for {target}."
            return "\n".join(f"- {k.id}: {k.properties}" for k in matched)

        if "certificates for" in q:
            target = _extract_after(original, "certificates for")
            all_certs = self.get_entities_by_type("certificate")
            matched = [c for c in all_certs if c.properties.get("host") == target or target in c.id]
            if not matched:
                return f"No certificates found for {target}."
            return "\n".join(f"- {c.id}: {c.properties}" for c in matched)

        if "kdf config for" in q:
            target = _extract_after(original, "kdf config for")
            all_kdf = self.get_entities_by_type("kdf_config")
            matched = [k for k in all_kdf if k.properties.get("target") == target or target in k.id]
            if not matched:
                return f"No KDF config found for {target}."
            return "\n".join(f"- {k.id}: {k.properties}" for k in matched)

        return None

    def _get_stats(self) -> str:
        with self._lock:
            node_count = self._graph.number_of_nodes()
            edge_count = self._graph.number_of_edges()

        type_counts = {}
        for entity_type in self.ENTITY_TYPES:
            count = len(self.get_entities_by_type(entity_type))
            if count > 0:
                type_counts[entity_type] = count

        lines = [f"Knowledge Graph: {node_count} entities, {edge_count} relationships"]
        for et, count in type_counts.items():
            lines.append(f"  {et}: {count}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Convenience methods for pentest workflow
    # ------------------------------------------------------------------

    def add_target(self, ip: str, **kwargs) -> Entity:
        return self.add_entity("target", ip, **kwargs)

    def add_port(self, target_ip: str, port: int, protocol: str = "tcp", **kwargs) -> Entity:
        port_id = f"{target_ip}:{port}/{protocol}"
        entity = self.add_entity("port", port_id, port=port, protocol=protocol, **kwargs)
        self.add_relationship(target_ip, port_id, "HAS_PORT")
        return entity

    def add_service(self, port_id: str, service_name: str, version: str = "", **kwargs) -> Entity:
        svc_id = f"{port_id}:{service_name}"
        entity = self.add_entity("service", svc_id, service=service_name, version=version, **kwargs)
        self.add_relationship(port_id, svc_id, "RUNS_SERVICE")
        return entity

    def add_vulnerability(self, service_id: str, cve: str, cvss: float = 0.0, **kwargs) -> Entity:
        entity = self.add_entity("cve", cve, cvss=cvss, **kwargs)
        self.add_relationship(service_id, cve, "AFFECTED_BY")
        return entity

    def add_exploit_result(
        self, cve: str, exploit_name: str, success: bool = False, **kwargs
    ) -> Entity:
        exploit_id = f"exploit:{exploit_name}"
        entity = self.add_entity(
            "exploit", exploit_id, name=exploit_name, success=success, **kwargs
        )
        self.add_relationship(cve, exploit_id, "EXPLOITED_WITH")
        return entity

    # ------------------------------------------------------------------
    # v0.3 source-hunt helpers
    # ------------------------------------------------------------------

    def add_repo(self, repo_url: str, **kwargs) -> Entity:
        """Register a source repository (or local path)."""
        return self.add_entity("repo", repo_url, **kwargs)

    def add_source_file(
        self,
        repo_url: str,
        file_path: str,
        language: str = "",
        **kwargs,
    ) -> Entity:
        """Register a source file within a repo. file_path is repo-relative."""
        file_id = f"{repo_url}::{file_path}"
        entity = self.add_entity(
            "source_file",
            file_id,
            file_path=file_path,
            language=language,
            **kwargs,
        )
        self.add_relationship(repo_url, file_id, "HAS_FILE")
        return entity

    def add_source_finding(
        self,
        repo_url: str,
        file_path: str,
        finding: dict,
    ) -> Entity:
        """Add a source-hunt Finding into the graph and link it to its file.

        If the finding has `related_finding_id`, an edge is drawn from this
        finding to that parent finding (VARIANT_OF). If it has `related_cve`,
        an edge is drawn to the CVE entity (RELATED_TO_CVE).
        """
        file_id = f"{repo_url}::{file_path}"
        # Auto-ensure the file entity exists
        if self.get_entity(file_id) is None:
            self.add_source_file(
                repo_url,
                file_path,
                language=finding.get("language", ""),
            )

        finding_id = finding.get("id") or f"finding:{uuid.uuid4().hex[:8]}"
        entity = self.add_entity(
            "source_finding",
            finding_id,
            file_path=file_path,
            line_number=finding.get("line_number"),
            cwe=finding.get("cwe", ""),
            severity=finding.get("severity_verified") or finding.get("severity", ""),
            evidence_level=finding.get("evidence_level", "suspicion"),
            discovered_by=finding.get("discovered_by", "unknown"),
            verified=finding.get("verified", False),
            description=(finding.get("description") or "")[:500],
        )
        self.add_relationship(file_id, finding_id, "HAS_FINDING")

        related = finding.get("related_finding_id")
        if related:
            # Only draw the edge if the parent is already in the graph
            if self.get_entity(related) is not None:
                self.add_relationship(finding_id, related, "VARIANT_OF")

        related_cve = finding.get("related_cve")
        if related_cve:
            # Ensure the CVE entity exists
            if self.get_entity(related_cve) is None:
                self.add_entity("cve", related_cve)
            self.add_relationship(finding_id, related_cve, "RELATED_TO_CVE")

        return entity

    # ------------------------------------------------------------------
    # v0.4 crypto helpers
    # ------------------------------------------------------------------

    def add_protocol(self, name: str, **kwargs) -> Entity:
        """Register a cryptographic protocol (e.g., SRP-6a, TLS)."""
        return self.add_entity("protocol", f"protocol:{name}", name=name, **kwargs)

    def add_algorithm(self, name: str, **kwargs) -> Entity:
        """Register a cryptographic algorithm (e.g., AES-256-GCM)."""
        return self.add_entity("algorithm", f"algorithm:{name}", name=name, **kwargs)

    def add_key_material(self, key_type: str, target: str, **kwargs) -> Entity:
        """Register key material (e.g., AUK, vault key, SRP verifier)."""
        key_id = f"key:{key_type}:{target}"
        return self.add_entity("key_material", key_id, key_type=key_type, target=target, **kwargs)

    def add_certificate(self, host: str, port: int = 443, **kwargs) -> Entity:
        """Register a TLS certificate. Auto-links to target if it exists."""
        cert_id = f"cert:{host}:{port}"
        entity = self.add_entity("certificate", cert_id, host=host, port=port, **kwargs)
        if self.get_entity(host) is not None:
            self.add_relationship(host, cert_id, "PRESENTS_CERT")
        return entity

    def add_kdf_config(self, algorithm: str, iterations: int, target: str, **kwargs) -> Entity:
        """Register a KDF configuration (algorithm + iteration count + target)."""
        kdf_id = f"kdf:{algorithm}:{iterations}:{target}"
        return self.add_entity(
            "kdf_config", kdf_id, algorithm=algorithm, iterations=iterations, target=target, **kwargs
        )

    def _get_key_chain(self, start_id: str) -> list[tuple[Entity, str, int]]:
        """BFS traversal of DERIVES_KEY and WRAPS_KEY edges from a starting entity."""
        chain: list[tuple[Entity, str, int]] = []
        visited: set[str] = {start_id}
        queue: list[tuple[str, int]] = [(start_id, 0)]
        while queue:
            current_id, depth = queue.pop(0)
            for rel in self.get_relationships(current_id, direction="out"):
                if rel.rel_type in ("DERIVES_KEY", "WRAPS_KEY", "DECRYPTS") and rel.target_id not in visited:
                    visited.add(rel.target_id)
                    neighbor = self.get_entity(rel.target_id)
                    if neighbor:
                        chain.append((neighbor, rel.rel_type, depth + 1))
                        queue.append((rel.target_id, depth + 1))
        return chain

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: str | None = None):
        """Serialize the graph to a JSON file."""
        save_path = Path(path).expanduser() if path else self._persist_path
        if not save_path:
            return
        self._do_save(save_path)

    def _do_save(self, save_path: Path | None = None):
        save_path = save_path or self._persist_path
        if not save_path:
            return
        save_path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            data = nx.node_link_data(self._graph)
        tmp_path = save_path.with_suffix(".tmp")
        try:
            tmp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            tmp_path.replace(save_path)
        except Exception:
            logger.debug("KnowledgeGraph save failed", exc_info=True)
            if tmp_path.exists():
                tmp_path.unlink(missing_ok=True)

    def _load(self):
        """Load graph from persist path."""
        if not self._persist_path or not self._persist_path.exists():
            return
        raw = json.loads(self._persist_path.read_text(encoding="utf-8"))
        self._graph = nx.node_link_graph(raw)

    def clear(self):
        """Remove all nodes and edges."""
        with self._lock:
            self._graph.clear()
