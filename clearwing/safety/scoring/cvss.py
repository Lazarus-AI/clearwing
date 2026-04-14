from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass
class CVSSVector:
    """CVSS v3.1 Base Score vector."""

    # Attack Vector
    attack_vector: str = "N"  # N=Network, A=Adjacent, L=Local, P=Physical
    # Attack Complexity
    attack_complexity: str = "L"  # L=Low, H=High
    # Privileges Required
    privileges_required: str = "N"  # N=None, L=Low, H=High
    # User Interaction
    user_interaction: str = "N"  # N=None, R=Required
    # Scope
    scope: str = "U"  # U=Unchanged, C=Changed
    # Impact
    confidentiality: str = "H"  # N=None, L=Low, H=High
    integrity: str = "H"  # N=None, L=Low, H=High
    availability: str = "H"  # N=None, L=Low, H=High

    def to_string(self) -> str:
        """Generate CVSS v3.1 vector string."""
        return (
            f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}/"
            f"PR:{self.privileges_required}/UI:{self.user_interaction}/S:{self.scope}/"
            f"C:{self.confidentiality}/I:{self.integrity}/A:{self.availability}"
        )

    @classmethod
    def from_string(cls, vector_string: str) -> CVSSVector:
        """Parse a CVSS v3.1 vector string."""
        parts = {}
        # Remove prefix
        vs = vector_string.replace("CVSS:3.1/", "").replace("CVSS:3.0/", "")
        for segment in vs.split("/"):
            if ":" in segment:
                key, value = segment.split(":", 1)
                parts[key] = value

        return cls(
            attack_vector=parts.get("AV", "N"),
            attack_complexity=parts.get("AC", "L"),
            privileges_required=parts.get("PR", "N"),
            user_interaction=parts.get("UI", "N"),
            scope=parts.get("S", "U"),
            confidentiality=parts.get("C", "H"),
            integrity=parts.get("I", "H"),
            availability=parts.get("A", "H"),
        )


# CVSS v3.1 metric value weights
_AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC_WEIGHTS = {"L": 0.77, "H": 0.44}
_PR_WEIGHTS_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_WEIGHTS_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI_WEIGHTS = {"N": 0.85, "R": 0.62}
_IMPACT_WEIGHTS = {"N": 0.0, "L": 0.22, "H": 0.56}


class CVSSCalculator:
    """Calculate CVSS v3.1 base scores."""

    def calculate(self, vector: CVSSVector) -> float:
        """Calculate the CVSS v3.1 base score (0.0 - 10.0)."""
        # Impact Sub Score
        isc_base = 1 - (
            (1 - _IMPACT_WEIGHTS[vector.confidentiality])
            * (1 - _IMPACT_WEIGHTS[vector.integrity])
            * (1 - _IMPACT_WEIGHTS[vector.availability])
        )

        if vector.scope == "U":
            impact = 6.42 * isc_base
        else:
            impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15

        # Exploitability Sub Score
        pr_weights = _PR_WEIGHTS_CHANGED if vector.scope == "C" else _PR_WEIGHTS_UNCHANGED
        exploitability = (
            8.22
            * _AV_WEIGHTS[vector.attack_vector]
            * _AC_WEIGHTS[vector.attack_complexity]
            * pr_weights[vector.privileges_required]
            * _UI_WEIGHTS[vector.user_interaction]
        )

        if impact <= 0:
            return 0.0

        if vector.scope == "U":
            score = min(impact + exploitability, 10.0)
        else:
            score = min(1.08 * (impact + exploitability), 10.0)

        # Round up to 1 decimal
        return math.ceil(score * 10) / 10

    def severity_rating(self, score: float) -> str:
        """Convert a CVSS score to a severity rating."""
        if score == 0.0:
            return "none"
        elif score <= 3.9:
            return "low"
        elif score <= 6.9:
            return "medium"
        elif score <= 8.9:
            return "high"
        else:
            return "critical"

    def score_from_string(self, vector_string: str) -> tuple[float, str]:
        """Parse vector string, calculate score, and return (score, severity)."""
        vector = CVSSVector.from_string(vector_string)
        score = self.calculate(vector)
        return score, self.severity_rating(score)


# Common vulnerability type presets
VULN_PRESETS = {
    "rce_network": CVSSVector(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="N",
        scope="C",
        confidentiality="H",
        integrity="H",
        availability="H",
    ),
    "rce_authenticated": CVSSVector(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="L",
        user_interaction="N",
        scope="U",
        confidentiality="H",
        integrity="H",
        availability="H",
    ),
    "sqli": CVSSVector(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="N",
        scope="U",
        confidentiality="H",
        integrity="H",
        availability="N",
    ),
    "xss_reflected": CVSSVector(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="R",
        scope="C",
        confidentiality="L",
        integrity="L",
        availability="N",
    ),
    "xss_stored": CVSSVector(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="L",
        user_interaction="R",
        scope="C",
        confidentiality="L",
        integrity="L",
        availability="N",
    ),
    "ssrf": CVSSVector(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="N",
        scope="C",
        confidentiality="H",
        integrity="N",
        availability="N",
    ),
    "path_traversal": CVSSVector(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="N",
        scope="U",
        confidentiality="H",
        integrity="N",
        availability="N",
    ),
    "info_disclosure": CVSSVector(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="N",
        scope="U",
        confidentiality="L",
        integrity="N",
        availability="N",
    ),
    "dos": CVSSVector(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="N",
        scope="U",
        confidentiality="N",
        integrity="N",
        availability="H",
    ),
}
