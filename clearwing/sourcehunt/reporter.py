"""Sourcehunt report writer — SARIF + markdown + JSON.

Reuses clearwing/runners/cicd/sarif.py::SARIFGenerator (now file-aware via R2)
for SARIF output. Markdown and JSON are written directly.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from clearwing.runners.cicd.sarif import SARIFGenerator

from .state import EVIDENCE_LEVELS, Finding, PipelineStatus

logger = logging.getLogger(__name__)


_EVIDENCE_RANK = {level: idx for idx, level in enumerate(EVIDENCE_LEVELS)}


def write_sourcehunt_report(
    output_dir: str,
    session_id: str,
    repo_url: str,
    findings: list[Finding],
    verified_findings: list[Finding],
    spent_per_tier: dict,
    formats: list[str] | None = None,
    band_stats: dict | None = None,
    pool_stats: dict | None = None,
    subsystem_stats: dict | None = None,
    pipeline_status: PipelineStatus | None = None,
) -> dict[str, str]:
    """Write the requested formats. Returns {format: filesystem_path}."""
    formats = formats or ["sarif", "markdown", "json"]
    if "all" in formats:
        formats = ["sarif", "markdown", "json"]

    session_dir = Path(output_dir) / session_id
    session_dir.mkdir(parents=True, exist_ok=True)

    paths: dict[str, str] = {}

    if "sarif" in formats:
        sarif_path = session_dir / "findings.sarif"
        sarif = SARIFGenerator().generate(
            findings=_to_sarif_findings(findings),
            target=repo_url,
            tool_name="clearwing-sourcehunt",
        )
        with open(sarif_path, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2)
        paths["sarif"] = str(sarif_path)

    if "markdown" in formats:
        md_path = session_dir / "report.md"
        md = _render_markdown(
            session_id=session_id,
            repo_url=repo_url,
            findings=findings,
            verified_findings=verified_findings,
            spent_per_tier=spent_per_tier,
            band_stats=band_stats,
            pool_stats=pool_stats,
            subsystem_stats=subsystem_stats,
            pipeline_status=pipeline_status,
        )
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md)
        paths["markdown"] = str(md_path)

    if "json" in formats:
        json_path = session_dir / "findings.json"
        json_data: dict[str, Any] = {
            "session_id": session_id,
            "repo_url": repo_url,
            "spent_per_tier": spent_per_tier,
            "findings": findings,
            "verified_findings": verified_findings,
        }
        if band_stats:
            json_data["band_stats"] = band_stats
        if pool_stats:
            json_data["pool_stats"] = pool_stats
        if subsystem_stats:
            json_data["subsystem_stats"] = subsystem_stats
        if pipeline_status and pipeline_status.stages:
            json_data["pipeline_status"] = {
                name: {
                    "outcome": s.outcome.value,
                    "error": s.error,
                    "fallback": s.fallback_description,
                }
                for name, s in pipeline_status.stages.items()
            }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, default=_json_default)
        paths["json"] = str(json_path)

    # Always write a manifest
    manifest_path = session_dir / "manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "session_id": session_id,
                "repo_url": repo_url,
                "finding_count": len(findings),
                "verified_count": len(verified_findings),
                "spent_per_tier": spent_per_tier,
                "total_spent": sum(spent_per_tier.values()),
                "outputs": paths,
            },
            f,
            indent=2,
        )
    paths["manifest"] = str(manifest_path)

    return paths


# --- Format-specific helpers ------------------------------------------------


def _to_sarif_findings(findings: list[Finding]) -> list[dict]:
    """Convert Finding entries into the dict shape SARIFGenerator expects.

    SARIFGenerator (after R2) honors `file` and `line_number` if present.
    """
    out = []
    for f in findings:
        out.append(
            {
                "description": f.get("description", ""),
                "severity": f.get("severity_verified") or f.get("severity") or "info",
                "cve": f.get("cwe"),  # use CWE as the rule_id
                "details": _details_block(f),
                "file": f.get("file"),
                "line_number": f.get("line_number"),
                "end_line": f.get("end_line"),
            }
        )
    return out


def _details_block(f: Finding) -> str:
    parts = []
    if f.get("evidence_level"):
        parts.append(f"evidence_level: {f['evidence_level']}")
    if f.get("discovered_by"):
        parts.append(f"discovered_by: {f['discovered_by']}")
    if f.get("crash_evidence"):
        parts.append(f"crash:\n{f['crash_evidence']}")
    if f.get("verifier_pro_argument"):
        parts.append(f"verifier_pro: {f['verifier_pro_argument']}")
    if f.get("verifier_counter_argument"):
        parts.append(f"verifier_counter: {f['verifier_counter_argument']}")
    if f.get("stability_classification"):
        rate = f.get("stability_success_rate", 0) * 100
        parts.append(
            f"stability: {f['stability_classification']} ({rate:.0f}% reproduction)"
        )
    if f.get("crypto_protocol"):
        parts.append(f"crypto_protocol: {f['crypto_protocol']}")
    if f.get("algorithm"):
        parts.append(f"algorithm: {f['algorithm']}")
    if f.get("crypto_attack_class"):
        parts.append(f"attack_class: {f['crypto_attack_class']}")
    if f.get("key_material_exposed"):
        parts.append(f"key_material: {f['key_material_exposed']}")
    return "\n\n".join(parts)


def _render_markdown(
    session_id: str,
    repo_url: str,
    findings: list[Finding],
    verified_findings: list[Finding],
    spent_per_tier: dict,
    band_stats: dict | None = None,
    pool_stats: dict | None = None,
    subsystem_stats: dict | None = None,
    pipeline_status: PipelineStatus | None = None,
) -> str:
    lines = []
    lines.append(f"# Sourcehunt Report — {session_id}")
    lines.append("")
    lines.append(f"- **Repo:** {repo_url}")
    lines.append(f"- **Findings:** {len(findings)} ({len(verified_findings)} verified)")
    lines.append(
        f"- **Spend by tier:** "
        f"A=${spent_per_tier.get('A', 0):.4f}, "
        f"B=${spent_per_tier.get('B', 0):.4f}, "
        f"C=${spent_per_tier.get('C', 0):.4f}"
    )
    lines.append(f"- **Total spend:** ${sum(spent_per_tier.values()):.4f}")
    lines.append("")

    if band_stats:
        lines.append("## Band Distribution")
        for band in ("fast", "standard", "deep"):
            runs = band_stats.get(f"{band}_runs", 0)
            cost = band_stats.get(f"{band}_cost", 0.0)
            avg = cost / runs if runs else 0.0
            lines.append(
                f"- **{band.title()}:** {runs} runs, ${cost:.2f} (avg ${avg:.2f}/run)"
            )
        promos = band_stats.get("promotions", {})
        if promos:
            promo_parts = ", ".join(f"{k}: {v}" for k, v in promos.items() if v)
            if promo_parts:
                lines.append(f"- **Promotions:** {promo_parts}")
        lines.append("")

    if pool_stats:
        lines.append("## Dedup Summary")
        lines.append(
            f"- **Total findings:** {pool_stats.get('total_findings', 0)}"
        )
        lines.append(
            f"- **Unique clusters:** {pool_stats.get('total_clusters', 0)}"
        )
        lines.append(
            f"- **Duplicates removed:** {pool_stats.get('duplicates', 0)}"
        )
        lines.append("")

    if subsystem_stats:
        lines.append("## Subsystem Hunts")
        lines.append(
            f"- **Subsystems hunted:** {subsystem_stats.get('subsystems_hunted', 0)}"
        )
        lines.append(
            f"- **Subsystem spend:** ${subsystem_stats.get('subsystem_spent_usd', 0):.2f}"
        )
        lines.append("")

    if pipeline_status and pipeline_status.stages:
        lines.append("## Pipeline Health")
        for status_line in pipeline_status.summary_lines():
            lines.append(status_line)
        lines.append("")

    # Severity histogram
    sev_counts: dict[str, int] = {}
    for f in findings:
        s = (f.get("severity_verified") or f.get("severity") or "info").lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1
    if sev_counts:
        lines.append("## Severity Histogram")
        for sev in ("critical", "high", "medium", "low", "info"):
            if sev in sev_counts:
                lines.append(f"- **{sev}**: {sev_counts[sev]}")
        lines.append("")

    # Findings sorted by evidence_level descending, then severity
    lines.append("## Findings")
    sorted_findings = sorted(
        findings,
        key=lambda f: (
            -_EVIDENCE_RANK.get(f.get("evidence_level", "suspicion"), 0),
            -_severity_rank(f),
        ),
    )
    for i, f in enumerate(sorted_findings, 1):
        sev = (f.get("severity_verified") or f.get("severity") or "info").upper()
        lines.append(
            f"### {i}. [{sev}] {f.get('finding_type', 'unknown')} "
            f"at `{f.get('file', '?')}:{f.get('line_number', '?')}`"
        )
        lines.append("")
        lines.append(f"- **CWE:** {f.get('cwe', 'N/A')}")
        lines.append(f"- **Evidence:** {f.get('evidence_level', 'suspicion')}")
        lines.append(f"- **Discovered by:** {f.get('discovered_by', 'unknown')}")
        if f.get("verified") is True:
            lines.append("- **Verified:** yes")
        if f.get("crypto_protocol"):
            lines.append(f"- **Crypto protocol:** {f['crypto_protocol']}")
        if f.get("algorithm"):
            lines.append(f"- **Algorithm:** {f['algorithm']}")
        if f.get("crypto_attack_class"):
            lines.append(f"- **Attack class:** {f['crypto_attack_class']}")
        if f.get("key_material_exposed"):
            lines.append(f"- **Key material at risk:** {f['key_material_exposed']}")
        lines.append("")
        lines.append(f.get("description", ""))
        if f.get("code_snippet"):
            lines.append("")
            lines.append("```")
            lines.append(f["code_snippet"])
            lines.append("```")
        if f.get("crash_evidence"):
            lines.append("")
            lines.append("**Crash evidence:**")
            lines.append("```")
            lines.append(f["crash_evidence"][:2000])
            lines.append("```")
        if f.get("validator_axes"):
            lines.append("")
            lines.append("- **Validation axes:**")
            for axis_name, axis_data in f["validator_axes"].items():
                status = "PASS" if axis_data["passed"] else "FAIL"
                lines.append(f"  - {axis_name}: {status} ({axis_data['confidence']})")
        if f.get("severity_disagreement"):
            lines.append(f"- **Severity disagreement:** {f['severity_disagreement']}")
        if f.get("verifier_counter_argument"):
            lines.append("")
            lines.append(f"_Verifier counter-argument:_ {f['verifier_counter_argument']}")
        if f.get("exploit_partial"):
            lines.append("")
            lines.append(
                f"- **Exploit partial:** primitive={f.get('exploit_primitive_type', '?')}"
            )
        if f.get("exploit_mitigations_bypassed"):
            lines.append(
                f"- **Mitigations bypassed:** {', '.join(f['exploit_mitigations_bypassed'])}"
            )
        if f.get("exploit_mitigations_blocking"):
            lines.append(
                f"- **Mitigations blocking:** {', '.join(f['exploit_mitigations_blocking'])}"
            )
        if f.get("exploit_chained_findings"):
            lines.append(
                f"- **Chained findings:** {', '.join(f['exploit_chained_findings'])}"
            )
        if f.get("exploit_cost_usd"):
            lines.append(f"- **Exploit cost:** ${f['exploit_cost_usd']:.2f}")
        if f.get("discovered_by") == "elaboration_agent":
            lines.append(
                f"- **Elaborated from:** {f.get('related_finding_id', '?')}"
            )
        if f.get("elaboration_upgrade_path"):
            lines.append(
                f"- **Upgrade path:** {f['elaboration_upgrade_path']}"
            )
        if f.get("stability_classification"):
            cls = f["stability_classification"]
            rate = f.get("stability_success_rate", 0) * 100
            lines.append(f"- **Stability:** {cls} ({rate:.0f}% reproduction rate)")
            if f.get("stability_hardened"):
                improved = "improved" if f.get("stability_hardening_improved") else "no improvement"
                lines.append(f"- **Hardened:** {improved}")
        lines.append("")

    # Tier disagreements section
    disagreements = [f for f in findings if f.get("severity_disagreement")]
    if disagreements:
        lines.append("## Tier Disagreements")
        lines.append("")
        lines.append("Findings where discoverer and validator severity differ by 2+ levels:")
        lines.append("")
        for f in disagreements:
            lines.append(
                f"- `{f.get('id', '?')}` at `{f.get('file', '?')}:{f.get('line_number', '?')}`: "
                f"{f['severity_disagreement']}"
            )
        lines.append("")

    # Rejected findings appendix
    rejected = [f for f in findings if f.get("rejected_axes")]
    if rejected:
        lines.append("## Rejected Findings")
        lines.append("")
        for f in rejected:
            fid = f.get("id", "?")
            axes = ", ".join(f["rejected_axes"])
            lines.append(
                f"- `{fid}` at `{f.get('file', '?')}:{f.get('line_number', '?')}` "
                f"— failed: {axes}"
            )
        lines.append("")

    return "\n".join(lines)


_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _severity_rank(f: Finding) -> int:
    sev = (f.get("severity_verified") or f.get("severity") or "info").lower()
    return _SEVERITY_ORDER.get(sev, 0)


def _json_default(obj: Any) -> Any:
    if hasattr(obj, "__dict__"):
        return obj.__dict__
    return str(obj)
