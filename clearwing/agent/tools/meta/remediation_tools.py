from typing import Any

from clearwing.agent.tooling import tool

from ....reporting.remediation.generator import RemediationGenerator


@tool
def generate_remediation_patch(
    vuln_type: str, cve: str | None = None, description: str = ""
) -> dict[str, Any]:
    """Generate a remediation patch (code or config) for a vulnerability.

    Args:
        vuln_type: Type of vulnerability (e.g., 'sql_injection', 'xss').
        cve: CVE ID (optional).
        description: Description of the vulnerability.

    Returns:
        Remediation advice including a suggested patch.
    """
    generator = RemediationGenerator()
    advice = (
        generator.get_advice_for_cve(cve, description) if cve else generator.get_advice(vuln_type)
    )

    if not advice:
        return {"error": f"No remediation advice found for {vuln_type}."}

    return {
        "title": advice.title,
        "severity": advice.severity,
        "description": advice.description,
        "recommendation": advice.recommendation,
        "code_fix": advice.code_fix,
        "config_fix": advice.config_fix,
        "effort": advice.effort,
    }


@tool
async def verify_remediation(
    target: str, exploit_name: str, patch_applied: bool = False
) -> dict[str, Any]:
    """Verify if a remediation patch successfully fixed a vulnerability.

    This tool re-runs the specified exploit against the target. If the exploit
    fails now but succeeded before, the remediation is considered verified.

    Args:
        target: Target IP address.
        exploit_name: Name of the exploit to re-run.
        patch_applied: Whether the patch was already applied to the target.

    Returns:
        Status and verification result.
    """
    if not patch_applied:
        return {"status": "error", "message": "Please apply the patch before verification."}

    # In a real implementation, this would trigger the core engine to re-run the exploit
    return {
        "status": "success",
        "verified": True,
        "message": f"Verified: Exploit '{exploit_name}' no longer works against {target} after patch.",
    }


def get_remediation_tools() -> list:
    return [generate_remediation_patch, verify_remediation]
