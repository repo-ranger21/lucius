"""
Feature engineering for vulnerability threat scoring.

Extracts and transforms raw vulnerability data into ML-ready features.
"""

from datetime import datetime
from typing import Dict, List, Optional
import re

import numpy as np
from talon.models import Vulnerability
from shared.logging import get_logger

logger = get_logger(__name__)


class VulnerabilityFeatureExtractor:
    """
    Extract ML features from vulnerability data.

    Features extracted:
    1. CVSS score (0-10) - Base vulnerability severity
    2. Package popularity - Downloads/usage metrics
    3. Exploit availability - Public exploits existence
    4. CVE age - Days since publication
    5. CVSS vector features - Attack vector, complexity, etc.
    6. Affected packages count - Impact scope
    7. Reference count - Documentation/attention level
    """

    # Known popular packages (simplified - extend with actual data)
    POPULAR_PACKAGES = {
        # JavaScript/Node.js
        "react", "lodash", "express", "axios", "webpack", "moment",
        "request", "commander", "debug", "chalk", "jquery", "angular",
        # Python
        "requests", "numpy", "pandas", "django", "flask", "tensorflow",
        "scipy", "matplotlib", "urllib3", "certifi", "setuptools",
        # Java
        "log4j", "spring-boot", "jackson", "junit", "slf4j", "guava",
        # PHP
        "symfony", "laravel", "guzzle", "monolog", "phpunit",
        # Ruby
        "rails", "bundler", "rack", "puma", "devise",
    }

    # Known exploit databases/keywords
    EXPLOIT_INDICATORS = [
        "exploit-db",
        "metasploit",
        "poc",
        "proof of concept",
        "exploit available",
        "github.com/.*exploit",
        "packetstorm",
        "exploit code",
    ]

    def extract_features(
        self,
        vulnerability: Vulnerability,
        package_stats: Optional[Dict] = None
    ) -> Dict[str, float]:
        """
        Extract all features from a vulnerability.

        Args:
            vulnerability: Vulnerability model instance
            package_stats: Optional external package popularity stats

        Returns:
            Dictionary of feature name -> normalized value (0-1)
        """
        features = {
            # Core CVSS features
            "cvss_score": self._extract_cvss_score(vulnerability),
            "cvss_impact": self._extract_cvss_impact(vulnerability),
            "cvss_exploitability": self._extract_cvss_exploitability(
                vulnerability
            ),

            # Package features
            "package_popularity": self._extract_package_popularity(
                vulnerability,
                package_stats
            ),
            "affected_packages_count": self._extract_affected_count(
                vulnerability
            ),

            # Exploit features
            "exploit_availability": self._extract_exploit_availability(
                vulnerability
            ),
            "exploit_complexity": self._extract_exploit_complexity(
                vulnerability
            ),

            # Temporal features
            "cve_age_days": self._extract_cve_age(vulnerability),
            "cve_freshness": self._extract_cve_freshness(vulnerability),

            # Attention features
            "reference_count": self._extract_reference_count(vulnerability),
            "has_nvd_reference": self._extract_has_nvd_reference(
                vulnerability
            ),

            # Attack vector features
            "is_network_attack": self._extract_is_network_attack(
                vulnerability
            ),
            "requires_privileges": self._extract_requires_privileges(
                vulnerability
            ),
            "requires_user_interaction": self._extract_requires_ui(
                vulnerability
            ),

            # Severity features
            "is_critical": float(vulnerability.severity == "CRITICAL"),
            "is_high": float(vulnerability.severity == "HIGH"),
        }

        return features

    def extract_features_batch(
        self,
        vulnerabilities: List[Vulnerability],
        package_stats: Optional[Dict] = None
    ) -> np.ndarray:
        """
        Extract features for multiple vulnerabilities.

        Returns:
            2D numpy array of shape (n_samples, n_features)
        """
        features_list = []

        for vuln in vulnerabilities:
            features = self.extract_features(vuln, package_stats)
            features_list.append(list(features.values()))

        return np.array(features_list)

    def get_feature_names(self) -> List[str]:
        """Get ordered list of feature names."""
        return [
            "cvss_score",
            "cvss_impact",
            "cvss_exploitability",
            "package_popularity",
            "affected_packages_count",
            "exploit_availability",
            "exploit_complexity",
            "cve_age_days",
            "cve_freshness",
            "reference_count",
            "has_nvd_reference",
            "is_network_attack",
            "requires_privileges",
            "requires_user_interaction",
            "is_critical",
            "is_high",
        ]

    # ========================================================================
    # Feature extraction methods
    # ========================================================================

    def _extract_cvss_score(self, vuln: Vulnerability) -> float:
        """Extract normalized CVSS score (0-1)."""
        if vuln.cvss_score is None:
            return 0.5  # Unknown
        return float(vuln.cvss_score) / 10.0

    def _extract_cvss_impact(self, vuln: Vulnerability) -> float:
        """Extract CVSS impact subscore from vector."""
        vector = vuln.cvss_vector or ""

        # Check for high impact (C:H, I:H, A:H)
        impact_score = 0.0
        if "C:H" in vector:
            impact_score += 0.33
        if "I:H" in vector:
            impact_score += 0.33
        if "A:H" in vector:
            impact_score += 0.34

        return impact_score

    def _extract_cvss_exploitability(self, vuln: Vulnerability) -> float:
        """Extract CVSS exploitability from vector."""
        vector = vuln.cvss_vector or ""

        score = 0.0
        # Network attack vector
        if "AV:N" in vector:
            score += 0.4
        # Low complexity
        if "AC:L" in vector:
            score += 0.3
        # No privileges required
        if "PR:N" in vector:
            score += 0.2
        # No user interaction
        if "UI:N" in vector:
            score += 0.1

        return score

    def _extract_package_popularity(
        self,
        vuln: Vulnerability,
        package_stats: Optional[Dict]
    ) -> float:
        """
        Extract package popularity score.

        Checks against known popular packages or external stats.
        """
        affected = vuln.affected_packages or []

        if not affected:
            return 0.3  # Unknown

        # Check if any affected package is popular
        max_popularity = 0.0

        for pkg in affected:
            pkg_name = pkg.get("name", "").lower()

            # Check against known popular packages
            if pkg_name in self.POPULAR_PACKAGES:
                max_popularity = max(max_popularity, 0.9)

            # Check external stats if provided
            if package_stats and pkg_name in package_stats:
                downloads = package_stats[pkg_name].get("downloads", 0)
                # Normalize downloads (log scale)
                if downloads > 0:
                    normalized = min(1.0, np.log10(downloads) / 9.0)
                    max_popularity = max(max_popularity, normalized)

        return max_popularity

    def _extract_affected_count(self, vuln: Vulnerability) -> float:
        """Extract normalized affected packages count."""
        affected = vuln.affected_packages or []
        count = len(affected)

        # Normalize using logarithmic scale
        if count == 0:
            return 0.1
        return min(1.0, np.log10(count + 1) / 2.0)

    def _extract_exploit_availability(self, vuln: Vulnerability) -> float:
        """
        Check if public exploits are available.

        Searches references and description for exploit indicators.
        """
        # Check references
        references = vuln.references or []
        description = (vuln.description or "").lower()

        for ref in references:
            url = ref.get("url", "").lower()
            for indicator in self.EXPLOIT_INDICATORS:
                if re.search(indicator, url):
                    return 1.0

        # Check description
        for indicator in self.EXPLOIT_INDICATORS:
            if re.search(indicator, description):
                return 0.8

        return 0.0

    def _extract_exploit_complexity(self, vuln: Vulnerability) -> float:
        """Extract exploit complexity (inverse - lower is easier)."""
        vector = vuln.cvss_vector or ""

        # AC:L = Low complexity = easy to exploit = high score
        if "AC:L" in vector:
            return 1.0
        elif "AC:H" in vector:
            return 0.3
        else:
            return 0.5  # Unknown

    def _extract_cve_age(self, vuln: Vulnerability) -> float:
        """Extract CVE age in days, normalized."""
        if not vuln.published_date:
            return 0.5  # Unknown

        now = datetime.utcnow()
        if vuln.published_date.tzinfo:
            from datetime import timezone
            now = now.replace(tzinfo=timezone.utc)

        age_days = (now - vuln.published_date).days

        # Normalize: 0-365 days -> 0-1
        return min(1.0, age_days / 365.0)

    def _extract_cve_freshness(self, vuln: Vulnerability) -> float:
        """Extract CVE freshness (inverse of age - newer is higher)."""
        age = self._extract_cve_age(vuln)
        return 1.0 - age

    def _extract_reference_count(self, vuln: Vulnerability) -> float:
        """Extract normalized reference count."""
        references = vuln.references or []
        count = len(references)

        # Normalize using logarithmic scale
        if count == 0:
            return 0.0
        return min(1.0, np.log10(count + 1) / 2.0)

    def _extract_has_nvd_reference(self, vuln: Vulnerability) -> float:
        """Check if vulnerability has NVD reference."""
        references = vuln.references or []

        for ref in references:
            url = ref.get("url", "").lower()
            if "nvd.nist.gov" in url:
                return 1.0

        return 0.0

    def _extract_is_network_attack(self, vuln: Vulnerability) -> float:
        """Check if attack vector is network."""
        vector = vuln.cvss_vector or ""
        return 1.0 if "AV:N" in vector else 0.0

    def _extract_requires_privileges(self, vuln: Vulnerability) -> float:
        """Check if privileges are required (inverse - easier without)."""
        vector = vuln.cvss_vector or ""

        if "PR:N" in vector:
            return 0.0  # No privileges = easier
        elif "PR:L" in vector:
            return 0.5  # Low privileges
        elif "PR:H" in vector:
            return 1.0  # High privileges = harder
        else:
            return 0.5  # Unknown

    def _extract_requires_ui(self, vuln: Vulnerability) -> float:
        """Check if user interaction is required (inverse)."""
        vector = vuln.cvss_vector or ""

        if "UI:N" in vector:
            return 0.0  # No interaction = easier
        elif "UI:R" in vector:
            return 1.0  # Interaction required = harder
        else:
            return 0.5  # Unknown
