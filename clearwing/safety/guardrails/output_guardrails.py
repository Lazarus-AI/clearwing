"""Output guardrails for checking commands before execution."""

from .patterns import (
    DANGEROUS_COMMAND_PATTERNS,
    GuardrailResult,
    normalize_unicode,
)

# Patterns whose indices in DANGEROUS_COMMAND_PATTERNS are considered
# "warning" rather than "critical".  Suspicious chains (the last group)
# are warnings; everything else is critical.
_SUSPICIOUS_CHAIN_LABELS = frozenset(
    [
        "base64 decode piped to shell",
        "curl/wget piped to shell",
    ]
)


class OutputGuardrail:
    """Check generated commands for safety before execution."""

    def check_command(self, command: str) -> GuardrailResult:
        """Check if a command is safe to execute.

        1. Normalize unicode homographs.
        2. Check against dangerous command patterns.
        3. Return pass/fail with reason and severity.
           - Critical for destructive / exfiltration commands.
           - Warning for suspicious chains.
        """
        normalized = normalize_unicode(command)

        for pattern in DANGEROUS_COMMAND_PATTERNS:
            match = pattern.search(normalized)
            if match:
                severity = self._classify_severity(pattern)
                return GuardrailResult(
                    passed=False,
                    reason=f"Dangerous command detected: matched pattern '{pattern.pattern}' at '{match.group()}'",
                    severity=severity,
                )

        return GuardrailResult(passed=True, reason="", severity="info")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _classify_severity(pattern) -> str:
        """Return 'warning' for suspicious-chain patterns, 'critical' otherwise."""
        pat = pattern.pattern
        # Suspicious chains: base64 decode piped to shell, curl/wget piped to shell
        suspicious_indicators = [
            r"base64",
            r"(curl|wget)\s+.*\|\s*(bash|sh)",
            r"(curl|wget)\s+.*\|\s*sudo",
        ]
        for indicator in suspicious_indicators:
            if indicator in pat:
                return "warning"
        return "critical"
