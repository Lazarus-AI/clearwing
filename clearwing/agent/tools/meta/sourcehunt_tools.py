"""Interactive-agent @tool wrapper for the sourcehunt pipeline.

Lets the existing network-pentest interactive agent invoke the source-hunt
pipeline against a git URL or local path that it has access to. Matches the
wargame/remediation tool pattern.
"""

from __future__ import annotations

import logging

from langchain_core.tools import tool

logger = logging.getLogger(__name__)


# Module-level cache so list_sourcehunt_findings can recall results from
# the most recent runs in this process. Keyed by session_id.
_RECENT_SESSIONS: dict[str, dict] = {}


@tool
def hunt_source_code(
    repo_url_or_path: str,
    branch: str = "main",
    depth: str = "quick",
    budget_usd: float = 2.0,
    output_dir: str = "./sourcehunt-results",
) -> str:
    """Run the Overwing source-code vulnerability hunting pipeline against a repo.

    Use this when the interactive agent has access to a target's source code
    (via a github URL, a local clone, or an MCP filesystem path) and wants
    to perform white-box analysis alongside its network scans.

    Args:
        repo_url_or_path: Git URL or local filesystem path to the repository.
        branch: Git branch (ignored for local paths).
        depth: 'quick' (preprocessor + static analysis only, no LLM hunters),
               'standard' (LLM hunters on rank A/B + verifier),
               'deep' (everything + Tier C propagation audit + exploit triage).
        budget_usd: Max dollars to spend. Default $2.
        output_dir: Where to write the SARIF / markdown / JSON outputs.

    Returns:
        A human-readable summary with the top findings. Full reports are
        written to {output_dir}/{session_id}/.
    """
    try:
        from clearwing.sourcehunt.runner import SourceHuntRunner
    except ImportError as e:
        return f"sourcehunt module unavailable: {e}"

    # Decide whether the input is a local path or a remote URL
    import os

    local_path: str | None = None
    if os.path.isdir(repo_url_or_path):
        local_path = repo_url_or_path

    runner = SourceHuntRunner(
        repo_url=repo_url_or_path,
        branch=branch,
        local_path=local_path,
        depth=depth,
        budget_usd=budget_usd,
        output_dir=output_dir,
    )

    try:
        result = runner.run()
    except Exception as e:
        logger.warning("hunt_source_code failed", exc_info=True)
        return f"Source hunt failed: {e}"

    # Cache for list_sourcehunt_findings
    _RECENT_SESSIONS[result.session_id] = {
        "session_id": result.session_id,
        "repo_url": result.repo_url,
        "findings": result.findings,
        "verified_findings": result.verified_findings,
        "output_paths": result.output_paths,
    }

    return _format_summary(result)


@tool
def list_sourcehunt_findings(session_id: str = "") -> list[dict]:
    """Return findings from a previous hunt_source_code run in this session.

    Args:
        session_id: The session id from a prior hunt_source_code call.
            If empty, returns findings from the most recent run.

    Returns:
        A list of finding dicts (file, line_number, severity, description, etc.).
    """
    if not _RECENT_SESSIONS:
        return [{"error": "no source hunts have run in this session yet"}]

    if not session_id:
        # Most recent (insertion order)
        session_id = list(_RECENT_SESSIONS.keys())[-1]

    cached = _RECENT_SESSIONS.get(session_id)
    if cached is None:
        return [{"error": f"session_id not found: {session_id}"}]

    return cached["findings"]


def get_sourcehunt_tools() -> list:
    """Return the interactive-agent sourcehunt tool list."""
    return [hunt_source_code, list_sourcehunt_findings]


# --- Helpers ----------------------------------------------------------------


def _format_summary(result) -> str:
    """Build a one-screen summary that the interactive agent can show the user."""
    lines = [
        f"Source hunt complete (session={result.session_id})",
        f"  Repo: {result.repo_url}",
        f"  Files ranked: {result.files_ranked}",
        f"  Files hunted: {result.files_hunted}",
        f"  Findings: {len(result.findings)} ({len(result.verified_findings)} verified)",
        f"  Critical/High: {result.critical_count}/{result.high_count}",
        f"  Spend: ${result.cost_usd:.4f}",
    ]
    if result.output_paths:
        lines.append("  Reports written:")
        for fmt, path in result.output_paths.items():
            lines.append(f"    {fmt}: {path}")

    if result.findings:
        lines.append("")
        lines.append("Top findings:")
        for f in result.findings[:5]:
            sev = (f.get("severity_verified") or f.get("severity") or "info").upper()
            file = f.get("file", "?")
            line_num = f.get("line_number", "?")
            desc = (f.get("description") or "")[:100]
            evidence = f.get("evidence_level", "suspicion")
            lines.append(f"  [{sev}] {file}:{line_num} — {desc} ({evidence})")

    return "\n".join(lines)
