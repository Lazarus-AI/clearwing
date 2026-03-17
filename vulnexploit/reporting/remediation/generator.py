from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RemediationAdvice:
    """Remediation advice for a single vulnerability."""
    vulnerability: str  # CVE ID or description
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    recommendation: str
    code_fix: str = ""  # suggested code patch (diff format)
    config_fix: str = ""  # suggested configuration change
    references: list[str] = field(default_factory=list)
    effort: str = "medium"  # low, medium, high — estimated fix effort
    priority: int = 0  # higher = fix first


REMEDIATION_DB = {
    "sql_injection": RemediationAdvice(
        vulnerability="SQL Injection",
        severity="critical",
        title="Use parameterized queries",
        description="SQL injection allows attackers to execute arbitrary SQL commands.",
        recommendation="Replace string concatenation with parameterized queries (prepared statements). Use an ORM where possible.",
        code_fix='''# Before (vulnerable):
query = f"SELECT * FROM users WHERE id = {user_input}"

# After (safe):
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_input,))''',
        references=["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
        effort="medium",
        priority=10,
    ),
    "xss": RemediationAdvice(
        vulnerability="Cross-Site Scripting (XSS)",
        severity="high",
        title="Encode output and validate input",
        description="XSS allows attackers to inject malicious scripts into web pages viewed by other users.",
        recommendation="HTML-encode all user-supplied output. Use Content Security Policy headers. Use a templating engine with auto-escaping.",
        code_fix='''# Before (vulnerable):
response = f"<p>Hello, {username}</p>"

# After (safe):
from html import escape
response = f"<p>Hello, {escape(username)}</p>"''',
        references=["https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
        effort="medium",
        priority=9,
    ),
    "ssrf": RemediationAdvice(
        vulnerability="Server-Side Request Forgery (SSRF)",
        severity="high",
        title="Validate and restrict outbound requests",
        description="SSRF allows attackers to make the server perform requests to unintended locations.",
        recommendation="Validate URLs against an allowlist. Block requests to internal/private IPs. Use a URL parser to check the scheme and host.",
        code_fix='''# Add URL validation:
from urllib.parse import urlparse
import ipaddress

def is_safe_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        if ip.is_private or ip.is_loopback:
            return False
    except ValueError:
        pass  # hostname, not IP — check against allowlist
    return True''',
        references=["https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"],
        effort="medium",
        priority=8,
    ),
    "path_traversal": RemediationAdvice(
        vulnerability="Path Traversal",
        severity="high",
        title="Sanitize file paths",
        description="Path traversal allows attackers to access files outside the intended directory.",
        recommendation="Use os.path.realpath() to resolve paths and verify they're within the allowed base directory. Never use user input directly in file paths.",
        code_fix='''# Before (vulnerable):
filepath = os.path.join(base_dir, user_input)

# After (safe):
filepath = os.path.realpath(os.path.join(base_dir, user_input))
if not filepath.startswith(os.path.realpath(base_dir)):
    raise ValueError("Access denied")''',
        references=["https://owasp.org/www-community/attacks/Path_Traversal"],
        effort="low",
        priority=8,
    ),
    "command_injection": RemediationAdvice(
        vulnerability="Command Injection",
        severity="critical",
        title="Avoid shell commands with user input",
        description="Command injection allows attackers to execute arbitrary OS commands.",
        recommendation="Use subprocess with shell=False and pass arguments as a list. Avoid os.system() and shell=True.",
        code_fix='''# Before (vulnerable):
os.system(f"ping {user_input}")

# After (safe):
import subprocess
subprocess.run(["ping", "-c", "1", user_input], shell=False, capture_output=True)''',
        references=["https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"],
        effort="low",
        priority=10,
    ),
    "weak_credentials": RemediationAdvice(
        vulnerability="Weak/Default Credentials",
        severity="high",
        title="Enforce strong password policies",
        description="Default or weak credentials allow unauthorized access.",
        recommendation="Change all default passwords. Enforce minimum password length (12+ chars), complexity, and rotation. Use MFA.",
        references=["https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"],
        effort="low",
        priority=9,
    ),
    "outdated_software": RemediationAdvice(
        vulnerability="Outdated Software",
        severity="medium",
        title="Update to latest patched version",
        description="Running outdated software may expose known vulnerabilities.",
        recommendation="Update the affected software to the latest stable version. Enable automatic security updates where possible.",
        effort="low",
        priority=7,
    ),
    "missing_headers": RemediationAdvice(
        vulnerability="Missing Security Headers",
        severity="low",
        title="Add security headers",
        description="Missing security headers leave the application vulnerable to common attacks.",
        recommendation="Add headers: Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security, X-XSS-Protection.",
        config_fix='''# Nginx example:
add_header Content-Security-Policy "default-src 'self'";
add_header X-Content-Type-Options "nosniff";
add_header X-Frame-Options "DENY";
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";''',
        effort="low",
        priority=5,
    ),
    "open_redirect": RemediationAdvice(
        vulnerability="Open Redirect",
        severity="medium",
        title="Validate redirect URLs",
        description="Open redirects allow attackers to redirect users to malicious sites.",
        recommendation="Validate redirect URLs against an allowlist of trusted domains. Use relative paths instead of full URLs.",
        effort="low",
        priority=6,
    ),
    "xxe": RemediationAdvice(
        vulnerability="XML External Entity (XXE)",
        severity="high",
        title="Disable external entity processing",
        description="XXE allows attackers to read files, perform SSRF, and cause DoS via XML parsing.",
        recommendation="Disable DTD processing and external entities in the XML parser. Use JSON instead of XML where possible.",
        code_fix='''# Python (defusedxml):
import defusedxml.ElementTree as ET
tree = ET.parse(xml_file)  # safe by default

# Or configure standard library:
from xml.etree.ElementTree import XMLParser
parser = XMLParser()
# Do NOT use: parser.entity = {}''',
        references=["https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"],
        effort="low",
        priority=8,
    ),
}


class RemediationGenerator:
    """Generates remediation advice for discovered vulnerabilities."""

    def __init__(self):
        self._db = dict(REMEDIATION_DB)

    def get_advice(self, vuln_type: str) -> Optional[RemediationAdvice]:
        """Look up remediation advice by vulnerability type."""
        # Try exact match first
        if vuln_type in self._db:
            return self._db[vuln_type]
        # Try case-insensitive match
        lower = vuln_type.lower().replace(" ", "_").replace("-", "_")
        if lower in self._db:
            return self._db[lower]
        return None

    def get_advice_for_cve(self, cve: str, description: str = "") -> Optional[RemediationAdvice]:
        """Try to match a CVE to known remediation advice based on description keywords."""
        desc_lower = description.lower()
        keyword_map = {
            "sql injection": "sql_injection",
            "sqli": "sql_injection",
            "cross-site scripting": "xss",
            "xss": "xss",
            "ssrf": "ssrf",
            "server-side request": "ssrf",
            "path traversal": "path_traversal",
            "directory traversal": "path_traversal",
            "command injection": "command_injection",
            "os command": "command_injection",
            "xxe": "xxe",
            "xml external": "xxe",
            "open redirect": "open_redirect",
            "default credential": "weak_credentials",
            "weak password": "weak_credentials",
            "missing security header": "missing_headers",
            "missing header": "missing_headers",
        }
        for keyword, vuln_type in keyword_map.items():
            if keyword in desc_lower:
                advice = self._db[vuln_type]
                # Create a copy with the CVE attached
                return RemediationAdvice(
                    vulnerability=f"{cve}: {advice.vulnerability}",
                    severity=advice.severity,
                    title=advice.title,
                    description=advice.description,
                    recommendation=advice.recommendation,
                    code_fix=advice.code_fix,
                    config_fix=advice.config_fix,
                    references=advice.references + [f"https://nvd.nist.gov/vuln/detail/{cve}"],
                    effort=advice.effort,
                    priority=advice.priority,
                )
        return None

    def generate_report(self, findings: list[dict]) -> list[RemediationAdvice]:
        """Generate prioritized remediation advice for a list of findings.

        Each finding dict should have: description, severity, cve (optional).
        Returns advice sorted by priority (highest first).
        """
        advice_list = []
        seen = set()

        for finding in findings:
            cve = finding.get("cve", "")
            desc = finding.get("description", "")

            advice = None
            if cve:
                advice = self.get_advice_for_cve(cve, desc)
            if advice is None and desc:
                advice = self.get_advice_for_cve("", desc)

            if advice and advice.title not in seen:
                seen.add(advice.title)
                advice_list.append(advice)

        advice_list.sort(key=lambda a: a.priority, reverse=True)
        return advice_list

    def format_markdown(self, advice_list: list[RemediationAdvice]) -> str:
        """Format remediation advice as a markdown report."""
        if not advice_list:
            return "No remediation advice available for the given findings."

        lines = ["# Remediation Report\n"]
        for i, advice in enumerate(advice_list, 1):
            lines.append(f"## {i}. {advice.title}")
            lines.append(f"**Severity:** {advice.severity.upper()}")
            lines.append(f"**Vulnerability:** {advice.vulnerability}")
            lines.append(f"**Effort:** {advice.effort}")
            lines.append(f"\n{advice.description}\n")
            lines.append(f"**Recommendation:** {advice.recommendation}\n")

            if advice.code_fix:
                lines.append("**Suggested Code Fix:**")
                lines.append(f"```\n{advice.code_fix}\n```\n")

            if advice.config_fix:
                lines.append("**Suggested Configuration:**")
                lines.append(f"```\n{advice.config_fix}\n```\n")

            if advice.references:
                lines.append("**References:**")
                for ref in advice.references:
                    lines.append(f"- {ref}")
            lines.append("")

        return "\n".join(lines)

    def add_custom(self, key: str, advice: RemediationAdvice):
        """Add custom remediation advice to the database."""
        self._db[key] = advice

    def list_known_types(self) -> list[str]:
        """List all known vulnerability types in the database."""
        return sorted(self._db.keys())
