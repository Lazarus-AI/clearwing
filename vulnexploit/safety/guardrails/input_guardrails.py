"""Input guardrails for detecting prompt injection attempts."""

import base64
import re

from .patterns import (
    INJECTION_PATTERNS,
    GuardrailResult,
    normalize_unicode,
)

# Regex to find plausible base64-encoded strings (length > 20)
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")


class InputGuardrail:
    """Check user-supplied text for prompt injection attempts."""

    def check(self, text: str) -> GuardrailResult:
        """Check text for prompt injection attempts.

        1. Normalize unicode homographs.
        2. Check against each injection pattern.
        3. Detect base64-encoded payloads (find base64 strings, decode,
           re-check decoded content against injection patterns).
        4. Return pass/fail with reason and severity.
        """
        normalized = normalize_unicode(text)

        # --- Direct pattern matching ---
        result = self._check_patterns(normalized)
        if not result.passed:
            return result

        # --- Base64 payload detection ---
        result = self._check_base64(normalized)
        if not result.passed:
            return result

        return GuardrailResult(passed=True, reason="", severity="info")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _check_patterns(text: str) -> GuardrailResult:
        """Match *text* against every known injection pattern."""
        for pattern in INJECTION_PATTERNS:
            match = pattern.search(text)
            if match:
                return GuardrailResult(
                    passed=False,
                    reason=f"Prompt injection detected: matched pattern '{pattern.pattern}' at '{match.group()}'",
                    severity="critical",
                )
        return GuardrailResult(passed=True)

    @staticmethod
    def _check_base64(text: str) -> GuardrailResult:
        """Find base64-encoded strings, decode them, then re-check."""
        for b64_match in _BASE64_RE.finditer(text):
            candidate = b64_match.group()
            try:
                decoded_bytes = base64.b64decode(candidate, validate=True)
                decoded = decoded_bytes.decode("utf-8", errors="ignore")
            except Exception:
                continue

            # Re-check decoded content against injection patterns
            decoded_normalized = normalize_unicode(decoded)
            for pattern in INJECTION_PATTERNS:
                match = pattern.search(decoded_normalized)
                if match:
                    return GuardrailResult(
                        passed=False,
                        reason=(
                            f"Prompt injection detected in base64 payload: "
                            f"decoded '{decoded[:80]}' matched pattern '{pattern.pattern}'"
                        ),
                        severity="critical",
                    )

        return GuardrailResult(passed=True)
