"""CVSS v4.0 scoring and vulnerability assessment for security findings."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from shared.logging import get_logger

logger = get_logger(__name__)


class CVSSVersion(str, Enum):
    """CVSS version indicator."""

    V3_1 = "3.1"
    V4_0 = "4.0"


class AttackVector(str, Enum):
    """CVSS Attack Vector (AV)."""

    NETWORK = "N"
    ADJACENT = "A"
    LOCAL = "L"
    PHYSICAL = "P"


class AttackComplexity(str, Enum):
    """CVSS Attack Complexity (AC)."""

    LOW = "L"
    HIGH = "H"


class PrivilegesRequired(str, Enum):
    """CVSS Privileges Required (PR)."""

    NONE = "N"
    LOW = "L"
    HIGH = "H"


class UserInteraction(str, Enum):
    """CVSS User Interaction (UI)."""

    NONE = "N"
    REQUIRED = "R"


class Scope(str, Enum):
    """CVSS Scope (S)."""

    UNCHANGED = "U"
    CHANGED = "C"


class Confidentiality(str, Enum):
    """CVSS Confidentiality Impact (C)."""

    NONE = "N"
    LOW = "L"
    HIGH = "H"


class Integrity(str, Enum):
    """CVSS Integrity Impact (I)."""

    NONE = "N"
    LOW = "L"
    HIGH = "H"


class Availability(str, Enum):
    """CVSS Availability Impact (A)."""

    NONE = "N"
    LOW = "L"
    HIGH = "H"


@dataclass
class CVSSScore:
    """Represents a CVSS score and metrics."""

    version: CVSSVersion
    score: float
    vector: str
    severity: str  # NONE, LOW, MEDIUM, HIGH, CRITICAL
    attack_vector: str
    attack_complexity: str
    privileges_required: str
    user_interaction: str
    scope: str
    confidentiality: str
    integrity: str
    availability: str

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "version": self.version.value,
            "score": self.score,
            "vector": self.vector,
            "severity": self.severity,
            "metrics": {
                "attack_vector": self.attack_vector,
                "attack_complexity": self.attack_complexity,
                "privileges_required": self.privileges_required,
                "user_interaction": self.user_interaction,
                "scope": self.scope,
                "confidentiality": self.confidentiality,
                "integrity": self.integrity,
                "availability": self.availability,
            },
        }


class CVSSv31Scorer:
    """CVSS v3.1 scorer implementation."""

    # Score mapping tables for CVSS 3.1
    AV_SCORE = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    AC_SCORE = {"L": 0.77, "H": 0.44}
    PR_SCORE_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
    PR_SCORE_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
    UI_SCORE = {"N": 0.85, "R": 0.62}
    IMPACT_SCORE = {"N": 0.0, "L": 0.22, "H": 0.56}

    @staticmethod
    def calculate(
        attack_vector: str,
        attack_complexity: str,
        privileges_required: str,
        user_interaction: str,
        scope: str,
        confidentiality: str,
        integrity: str,
        availability: str,
    ) -> CVSSScore:
        """
        Calculate CVSS 3.1 score.

        Args:
            attack_vector: AV (N, A, L, P)
            attack_complexity: AC (L, H)
            privileges_required: PR (N, L, H)
            user_interaction: UI (N, R)
            scope: S (U, C)
            confidentiality: C (N, L, H)
            integrity: I (N, L, H)
            availability: A (N, L, H)

        Returns:
            CVSSScore object with calculated score
        """
        # Validate inputs
        av = attack_vector.upper()
        ac = attack_complexity.upper()
        pr = privileges_required.upper()
        ui = user_interaction.upper()
        s = scope.upper()
        c = confidentiality.upper()
        i = integrity.upper()
        a = availability.upper()

        # Calculate exploitability
        av_score = CVSSv31Scorer.AV_SCORE.get(av, 0)
        ac_score = CVSSv31Scorer.AC_SCORE.get(ac, 0)

        # PR depends on scope
        pr_scores = CVSSv31Scorer.PR_SCORE_CHANGED if s == "C" else CVSSv31Scorer.PR_SCORE_UNCHANGED
        pr_score = pr_scores.get(pr, 0)

        ui_score = CVSSv31Scorer.UI_SCORE.get(ui, 0)
        exploitability = 8.23 * av_score * ac_score * pr_score * ui_score

        # Calculate impact
        impact_score = 1 - (
            (1 - CVSSv31Scorer.IMPACT_SCORE.get(c, 0))
            * (1 - CVSSv31Scorer.IMPACT_SCORE.get(i, 0))
            * (1 - CVSSv31Scorer.IMPACT_SCORE.get(a, 0))
        )

        # Calculate final score
        if impact_score <= 0:
            score = 0.0
        elif s == "U":
            score = min(6.42 * impact_score * exploitability, 10.0)
        else:
            score = min(1.08 * (6.42 * impact_score * exploitability + 0.029) - 3.4, 10.0)

        # Round to one decimal
        score = round(score, 1)

        # Determine severity
        severity = CVSSv31Scorer.score_to_severity(score)

        # Build vector string
        vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"

        return CVSSScore(
            version=CVSSVersion.V3_1,
            score=score,
            vector=vector,
            severity=severity,
            attack_vector=av,
            attack_complexity=ac,
            privileges_required=pr,
            user_interaction=ui,
            scope=s,
            confidentiality=c,
            integrity=i,
            availability=a,
        )

    @staticmethod
    def score_to_severity(score: float) -> str:
        """Convert CVSS score to severity rating."""
        if score == 0.0:
            return "NONE"
        elif score < 4.0:
            return "LOW"
        elif score < 7.0:
            return "MEDIUM"
        elif score < 9.0:
            return "HIGH"
        else:
            return "CRITICAL"


class CVSSv40Scorer:
    """CVSS v4.0 scorer implementation."""

    @staticmethod
    def calculate(
        attack_vector: str,
        attack_complexity: str,
        privileges_required: str,
        user_interaction: str,
        scope: str,
        confidentiality: str,
        integrity: str,
        availability: str,
    ) -> CVSSScore:
        """
        Calculate CVSS 4.0 score (simplified implementation).

        CVSS 4.0 is more granular but we provide a simplified version
        that can be extended for full 4.0 support.

        Args:
            attack_vector: AV (N, A, L, P)
            attack_complexity: AC (L, H)
            privileges_required: PR (N, L, H)
            user_interaction: UI (N, R)
            scope: S (U, C)
            confidentiality: C (N, L, H)
            integrity: I (N, L, H)
            availability: A (N, L, H)

        Returns:
            CVSSScore object with calculated score
        """
        # For now, use CVSS 3.1 as base, with adjustments for 4.0 concepts
        base_score = CVSSv31Scorer.calculate(
            attack_vector,
            attack_complexity,
            privileges_required,
            user_interaction,
            scope,
            confidentiality,
            integrity,
            availability,
        )

        # Convert to CVSS 4.0 vector format
        vector = (
            f"CVSS:4.0/AV:{attack_vector.upper()}/AC:{attack_complexity.upper()}/AT:N/"
            f"PR:{privileges_required.upper()}/UI:{user_interaction.upper()}/VC:{confidentiality.upper()}/"
            f"VI:{integrity.upper()}/VA:{availability.upper()}/SC:U/SI:U/SA:U"
        )

        return CVSSScore(
            version=CVSSVersion.V4_0,
            score=base_score.score,
            vector=vector,
            severity=base_score.severity,
            attack_vector=base_score.attack_vector,
            attack_complexity=base_score.attack_complexity,
            privileges_required=base_score.privileges_required,
            user_interaction=base_score.user_interaction,
            scope=base_score.scope,
            confidentiality=base_score.confidentiality,
            integrity=base_score.integrity,
            availability=base_score.availability,
        )


class VulnerabilityScorerFactory:
    """Factory for creating CVSS scorers."""

    @staticmethod
    def create_scorer(version: CVSSVersion):
        """Create a scorer for the specified CVSS version."""
        if version == CVSSVersion.V3_1:
            return CVSSv31Scorer
        elif version == CVSSVersion.V4_0:
            return CVSSv40Scorer
        else:
            return CVSSv31Scorer  # Default to 3.1


class VulnerabilityAssessment:
    """Comprehensive vulnerability assessment with CVSS scoring."""

    def __init__(self, cvss_version: CVSSVersion = CVSSVersion.V3_1):
        """Initialize assessment with CVSS version."""
        self.cvss_version = cvss_version
        self.scorer = VulnerabilityScorerFactory.create_scorer(cvss_version)

    def assess(
        self,
        vulnerability: dict,
        context: Optional[dict] = None,
    ) -> dict:
        """
        Perform comprehensive vulnerability assessment.

        Args:
            vulnerability: Vulnerability data from scanner
            context: Additional context (affected systems, etc.)

        Returns:
            Assessment results with CVSS score and recommendations
        """
        # Extract CVSS metrics if available, otherwise use defaults
        av = vulnerability.get("attack_vector", "N")
        ac = vulnerability.get("attack_complexity", "L")
        pr = vulnerability.get("privileges_required", "N")
        ui = vulnerability.get("user_interaction", "N")
        s = vulnerability.get("scope", "U")
        c = vulnerability.get("confidentiality", "H")
        i = vulnerability.get("integrity", "H")
        a = vulnerability.get("availability", "H")

        # Calculate CVSS score
        cvss_score = self.scorer.calculate(av, ac, pr, ui, s, c, i, a)

        # Build assessment
        assessment = {
            "cve_id": vulnerability.get("cve_id"),
            "package_name": vulnerability.get("package_name"),
            "installed_version": vulnerability.get("installed_version"),
            "fixed_version": vulnerability.get("fixed_version"),
            "cvss": cvss_score.to_dict(),
            "description": vulnerability.get("description"),
            "impact": self._assess_impact(vulnerability, cvss_score),
            "exploitability": self._assess_exploitability(av, ac, pr, ui),
            "remediation": self._recommend_remediation(vulnerability, cvss_score),
            "affected_systems": context.get("affected_systems", []) if context else [],
            "business_impact": self._assess_business_impact(cvss_score, vulnerability),
        }

        return assessment

    @staticmethod
    def _assess_impact(vulnerability: dict, cvss_score: CVSSScore) -> dict:
        """Assess impact of vulnerability."""
        return {
            "severity": cvss_score.severity,
            "confidentiality": cvss_score.confidentiality,
            "integrity": cvss_score.integrity,
            "availability": cvss_score.availability,
            "data_exposed": (
                vulnerability.get("description", "").lower().count("data") > 0
                or cvss_score.confidentiality in ["L", "H"]
            ),
            "data_modified": cvss_score.integrity in ["L", "H"],
            "service_impacted": cvss_score.availability in ["L", "H"],
        }

    @staticmethod
    def _assess_exploitability(av: str, ac: str, pr: str, ui: str) -> dict:
        """Assess how easily vulnerability can be exploited."""
        return {
            "attack_vector": av,
            "complexity": "Low" if ac == "L" else "High",
            "privileges_required": pr,
            "user_interaction_required": ui == "R",
            "exploitability_score": (
                "HIGH"
                if av == "N" and ac == "L" and pr == "N" and ui == "N"
                else "MEDIUM" if av in ["N", "A"] and ac == "L" else "LOW"
            ),
        }

    @staticmethod
    def _recommend_remediation(vulnerability: dict, cvss_score: CVSSScore) -> dict:
        """Generate remediation recommendations."""
        fixed_version = vulnerability.get("fixed_version")
        priority = (
            "IMMEDIATE"
            if cvss_score.severity == "CRITICAL"
            else (
                "HIGH"
                if cvss_score.severity == "HIGH"
                else "MEDIUM" if cvss_score.severity == "MEDIUM" else "LOW"
            )
        )

        return {
            "priority": priority,
            "action": (
                f"Update {vulnerability.get('package_name')} to version {fixed_version}"
                if fixed_version
                else "Investigate alternative packages or mitigations"
            ),
            "timeline": {
                "CRITICAL": "Immediately (within 24 hours)",
                "HIGH": "Within 7 days",
                "MEDIUM": "Within 30 days",
                "LOW": "Within 90 days",
            }.get(priority, "As scheduled"),
            "workarounds": [
                "Restrict network access to affected service",
                "Monitor for exploitation attempts",
                "Implement input validation",
            ],
        }

    @staticmethod
    def _assess_business_impact(cvss_score: CVSSScore, vulnerability: dict) -> dict:
        """Assess business impact of vulnerability."""
        impact_level = (
            "Critical"
            if cvss_score.severity == "CRITICAL"
            else (
                "High"
                if cvss_score.severity == "HIGH"
                else "Medium" if cvss_score.severity == "MEDIUM" else "Low"
            )
        )

        return {
            "impact_level": impact_level,
            "financial_risk": "High" if cvss_score.severity in ["CRITICAL", "HIGH"] else "Medium",
            "compliance_impact": True if cvss_score.confidentiality == "H" else False,
            "reputation_risk": True if cvss_score.integrity == "H" else False,
        }
