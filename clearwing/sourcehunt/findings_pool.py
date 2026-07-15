"""Shared findings pool for cross-agent dedup and primitive chaining (spec 005).

Provides:
    - Root-cause deduplication via LLM clustering
    - Primitive classification (CWE mapping + LLM fallback)
    - Mid-run query API for complementary primitives
    - JSONL checkpointing for resume
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from clearwing.findings.types import Finding

logger = logging.getLogger(__name__)

PRIMITIVE_TYPES = [
    "arbitrary_read",
    "bounded_read",
    "arbitrary_write",
    "bounded_write",
    "single_bit_flip",
    "type_confusion",
    "use_after_free",
    "double_free",
    "info_leak",
    "integer_overflow",
    "format_string",
    "stack_overflow",
    "heap_overflow",
    "race_condition",
    "auth_bypass",
    "code_execution",
    "sql_injection",
    "command_injection",
    "path_traversal",
    "xss",
    "timing_side_channel",
    "nonce_reuse",
    "key_lifecycle",
    "weak_kdf",
    "protocol_downgrade",
    "parameter_validation",
    "padding_oracle",
    "crypto_bypass",
    "unknown",
]

_CWE_PRIMITIVE_MAP: dict[str, str] = {
    "CWE-787": "bounded_write",
    "CWE-125": "bounded_read",
    "CWE-416": "use_after_free",
    "CWE-415": "double_free",
    "CWE-190": "integer_overflow",
    "CWE-191": "integer_overflow",
    "CWE-122": "heap_overflow",
    "CWE-121": "stack_overflow",
    "CWE-134": "format_string",
    "CWE-200": "info_leak",
    "CWE-532": "info_leak",
    "CWE-367": "race_condition",
    "CWE-362": "race_condition",
    "CWE-843": "type_confusion",
    "CWE-862": "auth_bypass",
    "CWE-287": "auth_bypass",
    "CWE-306": "auth_bypass",
    "CWE-89": "sql_injection",
    "CWE-78": "command_injection",
    "CWE-77": "command_injection",
    "CWE-22": "path_traversal",
    "CWE-79": "xss",
    "CWE-119": "heap_overflow",
    "CWE-120": "stack_overflow",
    "CWE-476": "use_after_free",
    "CWE-401": "info_leak",
    "CWE-208": "timing_side_channel",
    "CWE-323": "nonce_reuse",
    "CWE-327": "crypto_bypass",
    "CWE-328": "weak_kdf",
    "CWE-330": "crypto_bypass",
    "CWE-338": "crypto_bypass",
    "CWE-347": "crypto_bypass",
    "CWE-354": "padding_oracle",
    "CWE-325": "key_lifecycle",
    "CWE-326": "weak_kdf",
}

_FINDING_TYPE_PRIMITIVE_MAP: dict[str, str] = {
    "buffer_overflow": "heap_overflow",
    "heap_overflow": "heap_overflow",
    "stack_overflow": "stack_overflow",
    "use_after_free": "use_after_free",
    "double_free": "double_free",
    "integer_overflow": "integer_overflow",
    "format_string": "format_string",
    "info_leak": "info_leak",
    "information_disclosure": "info_leak",
    "race_condition": "race_condition",
    "type_confusion": "type_confusion",
    "sql_injection": "sql_injection",
    "command_injection": "command_injection",
    "path_traversal": "path_traversal",
    "xss": "xss",
    "auth_bypass": "auth_bypass",
    "memory_safety": "heap_overflow",
    "timing_side_channel": "timing_side_channel",
    "nonce_reuse": "nonce_reuse",
    "weak_kdf": "weak_kdf",
    "key_lifecycle": "key_lifecycle",
    "protocol_downgrade": "protocol_downgrade",
    "parameter_validation": "parameter_validation",
    "padding_oracle": "padding_oracle",
    "crypto_primitive": "crypto_bypass",
}

MAX_DEDUP_CANDIDATES = 3


DEDUP_PROMPT = """Here is a new bug report:
File: {file}:{line_number}
CWE: {cwe}
Type: {finding_type}
Description: {description}
Code: {code_snippet}

Here are existing confirmed findings that might share a root cause:
{candidate_summaries}

Is this new finding a duplicate of any of them — meaning it shares the same
ROOT CAUSE (not just symptoms)? Two bugs with identical stack traces but
different root causes are NOT duplicates. One bug presenting with different
crashes IS a duplicate.

Return JSON: {{"duplicate_of": "<cluster_id>" or null, "reasoning": "..."}}"""

CLASSIFY_PROMPT = """Classify this vulnerability finding into exactly one primitive type.

Finding:
  CWE: {cwe}
  Type: {finding_type}
  Description: {description}

Primitive types: {primitive_types}

Return JSON: {{"primitive_type": "<type>"}}"""


@dataclass
class FindingCluster:
    cluster_id: str
    root_cause_summary: str
    primitive_type: str
    cwe: str
    finding_ids: list[str] = field(default_factory=list)
    file_paths: set[str] = field(default_factory=set)


class FindingsPool:
    """Live, thread-safe findings database for a campaign."""

    def __init__(
        self,
        llm: Any = None,
        checkpoint_path: Path | None = None,
        *,
        max_dedup_candidates: int = MAX_DEDUP_CANDIDATES,
    ):
        self._lock = asyncio.Lock()
        self._findings: dict[str, Finding] = {}
        self._clusters: dict[str, FindingCluster] = {}
        self._llm = llm
        self._checkpoint_path = checkpoint_path
        self._max_dedup_candidates = max_dedup_candidates
        if checkpoint_path is not None:
            checkpoint_path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def count(self) -> int:
        return len(self._findings)

    async def add(self, finding: Finding) -> Finding:
        """Add a finding, classify primitive, run dedup, return updated finding."""
        async with self._lock:
            if not finding.get("primitive_type"):
                finding.primitive_type = await self._classify_primitive(finding)

            cluster_id = await self._assign_cluster(finding)
            finding.cluster_id = cluster_id

            self._findings[finding.get("id", "")] = finding

            self._checkpoint(finding)

        return finding

    def query(
        self,
        primitive_type: str | None = None,
        cwe: str | None = None,
        file_path: str | None = None,
        exclude_session: str | None = None,
    ) -> list[Finding]:
        """Query for complementary findings."""
        results: list[Finding] = []
        for f in self._findings.values():
            if exclude_session and f.get("hunter_session_id") == exclude_session:
                continue
            if primitive_type and f.get("primitive_type") != primitive_type:
                continue
            if cwe and f.get("cwe") != cwe:
                continue
            if file_path and f.get("file") != file_path:
                continue
            results.append(f)
        return results

    def all_findings(self) -> list[Finding]:
        return list(self._findings.values())

    def clusters(self) -> list[FindingCluster]:
        return list(self._clusters.values())

    def deduplicated_findings(self) -> list[Finding]:
        """Return one representative finding per cluster."""
        seen_clusters: set[str] = set()
        result: list[Finding] = []
        for f in self._findings.values():
            cid = f.get("cluster_id", "")
            if cid and cid in seen_clusters:
                continue
            if cid:
                seen_clusters.add(cid)
            result.append(f)
        return result

    def summary(self, max_entries: int = 10) -> str:
        """Render a text summary for prompt injection."""
        if not self._findings:
            return ""
        lines: list[str] = []
        for f in list(self._findings.values())[:max_entries]:
            prim = f.get("primitive_type", "unknown")
            lines.append(
                f"- [{prim}] {f.get('file', '?')}:{f.get('line_number', '?')} "
                f"({f.get('cwe', '?')}, {f.get('severity', '?')}): "
                f"{f.get('description', '')[:150]}"
            )
        if len(self._findings) > max_entries:
            lines.append(f"  ... and {len(self._findings) - max_entries} more")
        return "\n".join(lines)

    def pool_stats(self) -> dict[str, int]:
        return {
            "total_findings": len(self._findings),
            "total_clusters": len(self._clusters),
            "unique_findings": len(self.deduplicated_findings()),
            "duplicates": len(self._findings) - len(self.deduplicated_findings()),
        }

    @classmethod
    def from_checkpoint(cls, path: Path, llm: Any = None) -> FindingsPool:
        """Reconstruct a pool from a JSONL checkpoint file."""
        pool = cls(llm=llm, checkpoint_path=path)
        if not path.exists():
            return pool
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                finding = Finding(**{
                    k: v for k, v in data.items()
                    if k in Finding.__dataclass_fields__
                })
                fid = finding.get("id", "")
                pool._findings[fid] = finding
                cid = finding.get("cluster_id", "")
                if cid and cid not in pool._clusters:
                    pool._clusters[cid] = FindingCluster(
                        cluster_id=cid,
                        root_cause_summary=finding.get("description", "")[:200],
                        primitive_type=finding.get("primitive_type", "unknown"),
                        cwe=finding.get("cwe", ""),
                        finding_ids=[fid],
                        file_paths={finding.get("file", "")},
                    )
                elif cid:
                    cluster = pool._clusters[cid]
                    cluster.finding_ids.append(fid)
                    cluster.file_paths.add(finding.get("file", ""))
            except Exception:
                logger.debug("Failed to parse checkpoint line", exc_info=True)
        return pool

    # --- Internals ------------------------------------------------------------

    async def _classify_primitive(self, finding: Finding) -> str:
        cwe = finding.get("cwe", "")
        if cwe in _CWE_PRIMITIVE_MAP:
            return _CWE_PRIMITIVE_MAP[cwe]

        ft = finding.get("finding_type", "").lower()
        for pattern, prim in _FINDING_TYPE_PRIMITIVE_MAP.items():
            if pattern in ft:
                return prim

        if self._llm is not None:
            try:
                return await self._llm_classify(finding)
            except Exception:
                logger.debug("LLM primitive classification failed", exc_info=True)

        return "unknown"

    async def _llm_classify(self, finding: Finding) -> str:
        from clearwing.llm.native import ChatMessage

        prompt = CLASSIFY_PROMPT.format(
            cwe=finding.get("cwe", ""),
            finding_type=finding.get("finding_type", ""),
            description=finding.get("description", "")[:500],
            primitive_types=", ".join(PRIMITIVE_TYPES),
        )
        response = await self._llm.achat(
            messages=[ChatMessage("user", prompt)],
            system="You are a vulnerability classification expert. Return only JSON.",
            tools=[],
        )
        text = response.first_text or ""
        match = re.search(r'"primitive_type"\s*:\s*"([^"]+)"', text)
        if match and match.group(1) in PRIMITIVE_TYPES:
            return match.group(1)
        return "unknown"

    async def _assign_cluster(self, finding: Finding) -> str:
        fid = finding.get("id", "")
        file_path = finding.get("file", "")
        cwe = finding.get("cwe", "")
        prim = finding.get("primitive_type", "")

        candidates = self._find_dedup_candidates(file_path, cwe, prim)

        if candidates and self._llm is not None:
            try:
                dup_cluster = await self._dedup_check(finding, candidates)
                if dup_cluster is not None:
                    cluster = self._clusters[dup_cluster]
                    cluster.finding_ids.append(fid)
                    cluster.file_paths.add(file_path)
                    return dup_cluster
            except Exception:
                logger.debug("LLM dedup check failed", exc_info=True)

        cluster_id = f"cluster-{uuid.uuid4().hex[:8]}"
        self._clusters[cluster_id] = FindingCluster(
            cluster_id=cluster_id,
            root_cause_summary=finding.get("description", "")[:200],
            primitive_type=prim or "unknown",
            cwe=cwe,
            finding_ids=[fid],
            file_paths={file_path},
        )
        return cluster_id

    def _find_dedup_candidates(
        self, file_path: str, cwe: str, primitive_type: str,
    ) -> list[FindingCluster]:
        candidates: list[FindingCluster] = []
        for cluster in self._clusters.values():
            if file_path in cluster.file_paths and (
                cluster.cwe == cwe or cluster.primitive_type == primitive_type
            ):
                candidates.append(cluster)
                if len(candidates) >= self._max_dedup_candidates:
                    break
        return candidates

    async def _dedup_check(
        self, finding: Finding, candidates: list[FindingCluster],
    ) -> str | None:
        from clearwing.llm.native import ChatMessage

        summaries = []
        for c in candidates:
            summaries.append(
                f"Cluster {c.cluster_id}: {c.root_cause_summary} "
                f"(CWE: {c.cwe}, files: {', '.join(c.file_paths)})"
            )

        prompt = DEDUP_PROMPT.format(
            file=finding.get("file", "?"),
            line_number=finding.get("line_number", "?"),
            cwe=finding.get("cwe", "?"),
            finding_type=finding.get("finding_type", "?"),
            description=finding.get("description", "")[:500],
            code_snippet=finding.get("code_snippet", "")[:300],
            candidate_summaries="\n".join(summaries),
        )
        response = await self._llm.achat(
            messages=[ChatMessage("user", prompt)],
            system="You are a vulnerability deduplication expert. Return only JSON.",
            tools=[],
        )
        text = response.first_text or ""
        match = re.search(r'"duplicate_of"\s*:\s*"([^"]+)"', text)
        if match:
            candidate_id = match.group(1)
            if candidate_id in self._clusters:
                return candidate_id
        return None

    def _checkpoint(self, finding: Finding) -> None:
        if self._checkpoint_path is None:
            return
        try:
            data = {
                k: v for k, v in {
                    "id": finding.get("id", ""),
                    "file": finding.get("file"),
                    "line_number": finding.get("line_number"),
                    "finding_type": finding.get("finding_type", ""),
                    "primitive_type": finding.get("primitive_type", ""),
                    "cluster_id": finding.get("cluster_id", ""),
                    "cwe": finding.get("cwe", ""),
                    "severity": finding.get("severity", "info"),
                    "description": finding.get("description", ""),
                    "code_snippet": finding.get("code_snippet", ""),
                    "evidence_level": finding.get("evidence_level", "suspicion"),
                    "hunter_session_id": finding.get("hunter_session_id", ""),
                    "crypto_protocol": finding.get("crypto_protocol"),
                    "algorithm": finding.get("algorithm"),
                    "crypto_attack_class": finding.get("crypto_attack_class"),
                    "ts": time.time(),
                }.items() if v is not None
            }
            with self._checkpoint_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(data, sort_keys=True) + "\n")
        except Exception:
            logger.debug("Checkpoint write failed", exc_info=True)
