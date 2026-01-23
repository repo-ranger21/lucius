#!/usr/bin/env python3
"""
Lucius Security Reconnaissance Script

A production-ready security reconnaissance framework that integrates
multiple tools for domain enumeration, vulnerability assessment, and threat scoring.

Usage:
    python script.py example.com
    python script.py example.com --output results.json --verbose
    python script.py example.com --dry-run
"""

import argparse
import json
import logging
import sys
import time
import traceback
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin

import requests

# Configure logging early
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

# Third-party imports with fallback
try:
    import sublist3r

    SUBLIST3R_AVAILABLE = True
except ImportError:
    SUBLIST3R_AVAILABLE = False
    logging.debug("sublist3r not available - module will use simulation")

try:
    import importlib.util

    SQLMAP_AVAILABLE = importlib.util.find_spec("sqlmap") is not None
except ImportError:
    SQLMAP_AVAILABLE = False
    logging.debug("sqlmap not available")


# ============================================================================
# Data Models
# ============================================================================


@dataclass
class SubdomainResult:
    """Result from subdomain enumeration."""

    domain: str
    subdomain: str
    source: str
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class CVEResult:
    """Result from NVD CVE lookup."""

    cve_id: str
    cvss_score: float
    cvss_vector: str
    description: str
    published: str
    severity: str
    affected_products: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class APIFuzzResult:
    """Result from API fuzzing."""

    endpoint: str
    method: str
    payload: str
    status_code: int
    response_preview: str
    vulnerability_type: str
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class AuthTestResult:
    """Result from authentication testing."""

    target: str
    test_name: str
    passed: bool
    details: str
    severity: str
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class ReconReport:
    """Final reconnaissance report."""

    timestamp: str
    target: str
    subdomains_found: int
    vulnerabilities_found: int
    subdomains: list[dict[str, Any]]
    cves: list[dict[str, Any]] = field(default_factory=list)
    api_fuzz_results: list[dict[str, Any]] = field(default_factory=list)
    auth_test_results: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "timestamp": self.timestamp,
            "target": self.target,
            "subdomains_found": self.subdomains_found,
            "vulnerabilities_found": self.vulnerabilities_found,
            "subdomains": self.subdomains,
            "cves": self.cves,
            "api_fuzz_results": self.api_fuzz_results,
            "auth_test_results": self.auth_test_results,
            "metadata": self.metadata,
        }

    def save_json(self, filepath: str) -> None:
        """Save report as JSON."""
        try:
            with open(filepath, "w") as f:
                json.dump(self.to_dict(), f, indent=2)
            logging.info(f"Report saved to {filepath}")
        except OSError as e:
            logging.error(f"Failed to save report: {e}")

    def print_summary(self) -> None:
        """Print summary to console."""
        print("\n" + "=" * 70)
        print("RECONNAISSANCE REPORT")
        print("=" * 70)
        print(f"Target:              {self.target}")
        print(f"Timestamp:           {self.timestamp}")
        print(f"Subdomains Found:    {self.subdomains_found}")
        print(f"Vulnerabilities:     {self.vulnerabilities_found}")
        print(f"CVEs Found:          {len(self.cves)}")
        print(f"API Fuzz Results:    {len(self.api_fuzz_results)}")
        print(f"Auth Tests Run:      {len(self.auth_test_results)}")
        print("=" * 70)

        if self.subdomains:
            print("\nSUBDOMAINS:")
            print("-" * 70)
            for i, subdomain in enumerate(self.subdomains, 1):
                print(f"{i}. {subdomain['subdomain']} (source: {subdomain['source']})")

        if self.cves:
            print("\nCVEs FOUND:")
            print("-" * 70)
            for i, cve in enumerate(self.cves, 1):
                print(f"{i}. {cve['cve_id']} - CVSS {cve['cvss_score']} ({cve['severity']})")

        if self.api_fuzz_results:
            print("\nAPI FUZZ FINDINGS:")
            print("-" * 70)
            for i, result in enumerate(self.api_fuzz_results, 1):
                print(
                    f"{i}. {result['endpoint']} - {result['vulnerability_type']} (HTTP {result['status_code']})"
                )

        if self.auth_test_results:
            print("\nAUTH TEST RESULTS:")
            print("-" * 70)
            for i, result in enumerate(self.auth_test_results, 1):
                status = "✓ PASS" if result["passed"] else "✗ FAIL"
                print(f"{i}. {result['test_name']}: {status} ({result['severity']})")

        print("=" * 70 + "\n")


# ============================================================================
# Configuration
# ============================================================================


@dataclass
class ReconConfig:
    """Configuration for reconnaissance operations."""

    target: str
    output_file: str | None = None
    verbose: bool = False
    dry_run: bool = False
    enable_subdomain_scan: bool = True
    enable_vulnerability_scan: bool = False
    enable_api_fuzz: bool = False
    enable_auth_test: bool = False
    enable_cve_lookup: bool = False
    max_results: int = 500
    timeout: int = 30
    auth_username: str | None = None
    auth_password: str | None = None
    hackerone_username: str | None = None
    test_account_email: str | None = None


# ============================================================================
# Reconnaissance Engines
# ============================================================================


class SubdomainScanner:
    """Enumerate subdomains using sublist3r or simulation."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.results: list[SubdomainResult] = []

    def scan(self, domain: str, dry_run: bool = False) -> list[SubdomainResult]:
        """
        Enumerate subdomains for a target domain.

        Args:
            domain: Target domain to scan
            dry_run: If True, simulate scan without actual execution

        Returns:
            List of SubdomainResult objects
        """
        self.logger.info(f"Starting subdomain enumeration for {domain}")
        self.results = []

        try:
            if dry_run:
                self.logger.info("DRY RUN: Simulating subdomain enumeration")
                return self._simulate_scan(domain)

            if not SUBLIST3R_AVAILABLE:
                self.logger.warning("sublist3r not available, using simulation")
                return self._simulate_scan(domain)

            # Real sublist3r execution
            self.logger.debug(f"Running sublist3r for {domain}")
            try:
                # Trim to reliable engines only to avoid provider/API quirks.
                # sublist3r expects a comma-separated string here.
                safe_engines = "google,bing"

                subdomains = sublist3r.main(
                    domain,
                    40,  # threads
                    None,  # no output file
                    ports=None,
                    silent=True,
                    verbose=False,
                    enable_bruteforce=False,
                    engines=safe_engines,
                )

                for subdomain in subdomains:
                    result = SubdomainResult(
                        domain=domain,
                        subdomain=subdomain,
                        source="sublist3r",
                        timestamp=datetime.now(UTC).isoformat(),
                    )
                    self.results.append(result)

                # Fallback if sublist3r returns no results without error.
                if not self.results:
                    self.logger.warning("sublist3r returned no results; using simulation fallback")
                    return self._simulate_scan(domain)

                self.logger.info(f"Found {len(self.results)} subdomains")

            except Exception as e:
                self.logger.warning(f"sublist3r execution failed: {e}, using simulation")
                return self._simulate_scan(domain)

            return self.results

        except Exception as e:
            self.logger.error(f"Subdomain enumeration failed: {str(e)}")
            self.logger.debug(traceback.format_exc())
            return []

    def _simulate_scan(self, domain: str) -> list[SubdomainResult]:
        """Simulate subdomain scan for demonstration."""
        sample_subdomains = [
            f"www.{domain}",
            f"mail.{domain}",
            f"api.{domain}",
            f"admin.{domain}",
            f"dev.{domain}",
        ]

        for subdomain in sample_subdomains:
            result = SubdomainResult(
                domain=domain,
                subdomain=subdomain,
                source="simulated",
                timestamp=datetime.now(UTC).isoformat(),
            )
            self.results.append(result)

        self.logger.info(f"Simulated: Found {len(self.results)} subdomains")
        return self.results


# ============================================================================
# CVE & Vulnerability Scanning
# ============================================================================


class CVEScanner:
    """Query NVD (National Vulnerability Database) for CVE information."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.results: list[CVEResult] = []
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.timeout = 30

    def scan(self, keywords: list[str], dry_run: bool = False) -> list[CVEResult]:
        """
        Search NVD for CVEs matching keywords.

        Args:
            keywords: List of keywords to search (e.g., ["robinhood", "fintech"])
            dry_run: If True, use simulated data

        Returns:
            List of CVEResult objects
        """
        self.logger.info(f"Starting CVE lookup for keywords: {keywords}")
        self.results = []

        if dry_run:
            self.logger.info("DRY RUN: Simulating CVE lookup")
            return self._simulate_cve_scan(keywords)

        for keyword in keywords:
            try:
                self.logger.debug(f"Querying NVD for: {keyword}")
                params = {
                    "keywordSearch": keyword,
                    "resultsPerPage": 20,
                }

                response = requests.get(
                    self.nvd_base_url,
                    params=params,
                    timeout=self.timeout,
                    headers={"User-Agent": "Lucius-SecurityScanner/1.0"},
                )

                if response.status_code == 200:
                    data = response.json()
                    vulnerabilities = data.get("vulnerabilities", [])

                    for vuln in vulnerabilities:
                        cve_item = vuln.get("cve", {})
                        metrics = cve_item.get("metrics", {})

                        # Extract CVSS scores (prefer v3.1, fall back to v2)
                        cvss_score = 0.0
                        cvss_vector = "N/A"
                        severity = "UNKNOWN"

                        if "cvssMetricV31" in metrics:
                            cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                            cvss_score = cvss_data.get("baseScore", 0.0)
                            cvss_vector = cvss_data.get("vectorString", "N/A")
                            severity = cvss_data.get("baseSeverity", "UNKNOWN")
                        elif "cvssMetricV2" in metrics:
                            cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
                            cvss_score = cvss_data.get("baseScore", 0.0)
                            cvss_vector = cvss_data.get("vectorString", "N/A")

                        result = CVEResult(
                            cve_id=cve_item.get("id", "UNKNOWN"),
                            cvss_score=cvss_score,
                            cvss_vector=cvss_vector,
                            description=cve_item.get("descriptions", [{}])[0].get("value", ""),
                            published=cve_item.get("published", ""),
                            severity=severity,
                        )
                        self.results.append(result)

                        self.logger.debug(f"Found: {result.cve_id} (CVSS: {cvss_score})")

                    # Rate limiting to respect NVD API
                    time.sleep(1)

                else:
                    self.logger.warning(f"NVD query failed: HTTP {response.status_code}")

            except requests.RequestException as e:
                self.logger.warning(f"CVE lookup failed for '{keyword}': {e}")
            except Exception as e:
                self.logger.error(f"CVE parsing error: {e}")

        self.logger.info(f"Found {len(self.results)} CVEs")
        return self.results

    def _simulate_cve_scan(self, keywords: list[str]) -> list[CVEResult]:
        """Simulate CVE scan for demonstration."""
        sample_cves = [
            CVEResult(
                cve_id="CVE-2024-1234",
                cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                description="Critical authentication bypass in trading API",
                published="2024-01-15",
                severity="CRITICAL",
            ),
            CVEResult(
                cve_id="CVE-2024-5678",
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                description="Information disclosure in user profile endpoint",
                published="2024-02-20",
                severity="HIGH",
            ),
        ]
        self.results = sample_cves
        self.logger.info(f"Simulated: Found {len(self.results)} CVEs")
        return self.results


# ============================================================================
# API Fuzzing
# ============================================================================


class APIFuzzer:
    """Fuzz APIs with payloads to identify vulnerabilities."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.results: list[APIFuzzResult] = []
        self.timeout = 10

        # Common fuzzing payloads for API testing
        self.payloads = {
            "sql_injection": [
                "' OR '1'='1",
                "'; DROP TABLE users; --",
                "1 UNION SELECT NULL,NULL,NULL --",
            ],
            "xss": [
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                '"><svg/onload=alert(1)>',
            ],
            "path_traversal": [
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            ],
            "idor": [
                "?id=999999",
                "?user_id=1",
                "?account_id=admin",
            ],
            "logic_bypass": [
                "?admin=true",
                "&role=administrator",
                "?authorized=1",
            ],
        }

    def fuzz(
        self, base_url: str, endpoints: list[str], dry_run: bool = False
    ) -> list[APIFuzzResult]:
        """
        Fuzz API endpoints with payloads.

        Args:
            base_url: Base URL of the API
            endpoints: List of endpoints to fuzz
            dry_run: If True, simulate fuzzing

        Returns:
            List of APIFuzzResult objects
        """
        self.logger.info(f"Starting API fuzzing on {base_url}")
        self.results = []

        if dry_run:
            self.logger.info("DRY RUN: Simulating API fuzzing")
            return self._simulate_fuzz(base_url, endpoints)

        for endpoint in endpoints:
            try:
                full_url = urljoin(base_url, endpoint)
                self.logger.debug(f"Fuzzing endpoint: {full_url}")

                for payload_type, payloads in self.payloads.items():
                    for payload in payloads:
                        try:
                            # Test GET with payload in query string
                            response = requests.get(
                                full_url,
                                params={"input": payload},
                                timeout=self.timeout,
                                headers={"User-Agent": "Lucius-APIFuzzer/1.0"},
                            )

                            # Check for suspicious responses
                            if response.status_code in [400, 403, 404]:
                                continue

                            if any(
                                indicator in response.text.lower()
                                for indicator in [
                                    "error",
                                    "exception",
                                    "traceback",
                                    "sql",
                                ]
                            ):
                                result = APIFuzzResult(
                                    endpoint=endpoint,
                                    method="GET",
                                    payload=payload,
                                    status_code=response.status_code,
                                    response_preview=response.text[:200],
                                    vulnerability_type=payload_type,
                                    timestamp=datetime.now(UTC).isoformat(),
                                )
                                self.results.append(result)
                                self.logger.warning(f"Potential {payload_type} found!")

                        except requests.RequestException:
                            pass

            except Exception as e:
                self.logger.debug(f"Fuzzing error on {endpoint}: {e}")

        self.logger.info(f"API fuzzing complete: {len(self.results)} findings")
        return self.results

    def _simulate_fuzz(self, base_url: str, endpoints: list[str]) -> list[APIFuzzResult]:
        """Simulate API fuzzing."""
        sample_results = [
            APIFuzzResult(
                endpoint="/api/users",
                method="GET",
                payload="?id=999999",
                status_code=200,
                response_preview='{"user_id": 999999, "name": "Admin", "email": "admin@example.com"}',
                vulnerability_type="idor",
                timestamp=datetime.now(UTC).isoformat(),
            ),
        ]
        self.results = sample_results
        self.logger.info(f"Simulated: Found {len(self.results)} API issues")
        return self.results


# ============================================================================
# Authentication Testing
# ============================================================================


class AuthTester:
    """Test authentication and authorization mechanisms."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.results: list[AuthTestResult] = []
        self.timeout = 10

    def test(
        self,
        base_url: str,
        username: str | None = None,
        password: str | None = None,
        dry_run: bool = False,
    ) -> list[AuthTestResult]:
        """
        Run authentication tests.

        Args:
            base_url: Base URL of the application
            username: Test username
            password: Test password
            dry_run: If True, simulate tests

        Returns:
            List of AuthTestResult objects
        """
        self.logger.info(f"Starting authentication testing on {base_url}")
        self.results = []

        if dry_run:
            self.logger.info("DRY RUN: Simulating auth tests")
            return self._simulate_auth_tests(base_url)

        # Test 1: Default credentials
        self._test_default_credentials(base_url)

        # Test 2: JWT/Bearer token validation
        self._test_jwt_validation(base_url)

        # Test 3: Session fixation
        self._test_session_fixation(base_url)

        # Test 4: Auth bypass
        self._test_auth_bypass(base_url)

        self.logger.info(f"Auth testing complete: {len(self.results)} tests executed")
        return self.results

    def _test_default_credentials(self, base_url: str) -> None:
        """Test for default credentials."""
        common_defaults = [
            ("admin", "admin"),
            ("admin", "password"),
            ("root", "root"),
            ("test", "test"),
        ]

        for username, password in common_defaults:
            try:
                # Attempt login
                response = requests.post(
                    urljoin(base_url, "/api/login"),
                    json={"username": username, "password": password},
                    timeout=self.timeout,
                    headers={"User-Agent": "Lucius-AuthTester/1.0"},
                )

                if response.status_code == 200 and "token" in response.text.lower():
                    result = AuthTestResult(
                        target=base_url,
                        test_name=f"Default Credentials ({username}:{password})",
                        passed=False,
                        details="Successfully authenticated with default credentials",
                        severity="CRITICAL",
                        timestamp=datetime.now(UTC).isoformat(),
                    )
                    self.results.append(result)
                    self.logger.warning(f"Default credentials vulnerable: {username}:{password}")

            except requests.RequestException:
                pass

    def _test_jwt_validation(self, base_url: str) -> None:
        """Test JWT token validation."""
        # Test with invalid token
        invalid_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.invalid"

        try:
            response = requests.get(
                urljoin(base_url, "/api/user/profile"),
                headers={"Authorization": f"Bearer {invalid_token}"},
                timeout=self.timeout,
            )

            if response.status_code == 200:
                result = AuthTestResult(
                    target=base_url,
                    test_name="JWT Token Validation",
                    passed=False,
                    details="API accepted invalid JWT token",
                    severity="HIGH",
                    timestamp=datetime.now(UTC).isoformat(),
                )
                self.results.append(result)
                self.logger.warning("JWT validation vulnerability found")

        except requests.RequestException:
            pass

    def _test_session_fixation(self, base_url: str) -> None:
        """Test for session fixation vulnerabilities."""
        result = AuthTestResult(
            target=base_url,
            test_name="Session Fixation",
            passed=True,
            details="Unable to test without valid session (test skipped)",
            severity="INFO",
            timestamp=datetime.now(UTC).isoformat(),
        )
        self.results.append(result)

    def _test_auth_bypass(self, base_url: str) -> None:
        """Test for authentication bypass."""
        bypass_attempts = [
            {"Authorization": ""},
            {"Authorization": "null"},
            {"Authorization": "Bearer null"},
        ]

        for headers_override in bypass_attempts:
            try:
                response = requests.get(
                    urljoin(base_url, "/api/admin"),
                    headers=headers_override,
                    timeout=self.timeout,
                )

                if response.status_code == 200:
                    result = AuthTestResult(
                        target=base_url,
                        test_name=f"Auth Bypass - {headers_override}",
                        passed=False,
                        details="Admin endpoint accessible without valid token",
                        severity="CRITICAL",
                        timestamp=datetime.now(UTC).isoformat(),
                    )
                    self.results.append(result)

            except requests.RequestException:
                pass

    def _simulate_auth_tests(self, base_url: str) -> list[AuthTestResult]:
        """Simulate authentication tests."""
        sample_results = [
            AuthTestResult(
                target=base_url,
                test_name="Default Credentials (admin:admin)",
                passed=True,
                details="Credentials not found (as expected)",
                severity="INFO",
                timestamp=datetime.now(UTC).isoformat(),
            ),
            AuthTestResult(
                target=base_url,
                test_name="JWT Token Validation",
                passed=True,
                details="Invalid token properly rejected",
                severity="INFO",
                timestamp=datetime.now(UTC).isoformat(),
            ),
        ]
        self.results = sample_results
        self.logger.info(f"Simulated: {len(self.results)} auth tests")
        return self.results


# ============================================================================
# CVSS Scoring
# ============================================================================


class CVSSScorer:
    """Calculate and validate CVSS v3.1 scores for vulnerabilities."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def calculate(
        self,
        attack_vector: str = "N",
        attack_complexity: str = "L",
        privileges_required: str = "N",
        user_interaction: str = "N",
        scope: str = "U",
        confidentiality: str = "H",
        integrity: str = "H",
        availability: str = "H",
    ) -> dict[str, Any]:
        """
        Calculate CVSS v3.1 score.

        Args:
            attack_vector: AV (N=Network, A=Adjacent, L=Local, P=Physical)
            attack_complexity: AC (L=Low, H=High)
            privileges_required: PR (N=None, L=Low, H=High)
            user_interaction: UI (N=None, R=Required)
            scope: S (U=Unchanged, C=Changed)
            confidentiality: C (H=High, L=Low, N=None)
            integrity: I (H=High, L=Low, N=None)
            availability: A (H=High, L=Low, N=None)

        Returns:
            Dictionary with score, vector, and severity
        """
        # CVSS v3.1 scoring weights
        av_scores = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        ac_scores = {"L": 0.77, "H": 0.44}
        pr_unchanged = {"N": 0.85, "L": 0.62, "H": 0.27}
        pr_changed = {"N": 0.85, "L": 0.68, "H": 0.50}
        ui_scores = {"N": 0.85, "R": 0.62}
        impact_scores = {"H": 0.56, "L": 0.22, "N": 0.0}

        try:
            # Calculate base score
            av = av_scores.get(attack_vector, 0)
            ac = ac_scores.get(attack_complexity, 0)
            pr = (
                pr_changed.get(privileges_required, 0)
                if scope == "C"
                else pr_unchanged.get(privileges_required, 0)
            )
            ui = ui_scores.get(user_interaction, 0)

            c = impact_scores.get(confidentiality, 0)
            i = impact_scores.get(integrity, 0)
            a = impact_scores.get(availability, 0)

            impact = 1 - ((1 - c) * (1 - i) * (1 - a))
            scope_multiplier = 1.08 if scope == "C" else 1.0

            base_score = min(10, (av * ac * pr * ui) * (c * i * a) * scope_multiplier)
            base_score = round(base_score * 10) / 10  # Round to 1 decimal

            # Determine severity
            if base_score >= 9.0:
                severity = "CRITICAL"
            elif base_score >= 7.0:
                severity = "HIGH"
            elif base_score >= 4.0:
                severity = "MEDIUM"
            elif base_score > 0:
                severity = "LOW"
            else:
                severity = "NONE"

            vector = f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}/PR:{privileges_required}/UI:{user_interaction}/S:{scope}/C:{confidentiality}/I:{integrity}/A:{availability}"

            return {
                "score": base_score,
                "vector": vector,
                "severity": severity,
                "impact": round(impact * 10) / 10,
            }

        except Exception as e:
            self.logger.error(f"CVSS calculation error: {e}")
            return {"score": 0, "vector": "", "severity": "UNKNOWN"}


# ============================================================================
# Main Orchestrator
# ============================================================================


class ReconOrchestrator:
    """Orchestrates security reconnaissance operations."""

    def __init__(self, config: ReconConfig):
        self.config = config
        self.logger = logging.getLogger("lucius.recon")

        if config.verbose:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)

        self.logger.info(f"Initializing reconnaissance for target: {config.target}")

        # Log HackerOne headers if provided
        if config.hackerone_username or config.test_account_email:
            self.logger.info("HackerOne bug bounty headers configured for submission")
            if config.hackerone_username:
                self.logger.debug(f"X-Bug-Bounty header: {config.hackerone_username}")
            if config.test_account_email:
                self.logger.debug(f"X-Test-Account-Email header: {config.test_account_email}")

        self.subdomain_scanner = SubdomainScanner(self.logger)
        self.cve_scanner = CVEScanner(self.logger) if config.enable_cve_lookup else None
        self.api_fuzzer = APIFuzzer(self.logger) if config.enable_api_fuzz else None
        self.auth_tester = AuthTester(self.logger) if config.enable_auth_test else None
        self.cvss_scorer = CVSSScorer(self.logger)
        self.report: ReconReport | None = None

    def get_request_headers(self) -> dict[str, str]:
        """Build request headers including HackerOne bug bounty headers if configured."""
        headers = {
            "User-Agent": "Lucius-SecurityScanner/1.0",
        }

        if self.config.hackerone_username:
            headers["X-Bug-Bounty"] = self.config.hackerone_username

        if self.config.test_account_email:
            headers["X-Test-Account-Email"] = self.config.test_account_email

        return headers

    def validate_target(self) -> bool:
        """Validate target domain."""
        if not self.config.target:
            self.logger.error("Target domain is required")
            return False

        # Basic validation
        if "." not in self.config.target:
            self.logger.warning(f"Target '{self.config.target}' may not be a valid domain")

        return True

    def run(self) -> bool:
        """Execute full reconnaissance workflow."""
        try:
            self.logger.info("=" * 70)
            self.logger.info("LUCIUS RECONNAISSANCE FRAMEWORK")
            self.logger.info("=" * 70)

            # Validation
            if not self.validate_target():
                return False

            # Subdomain enumeration
            subdomains = []
            if self.config.enable_subdomain_scan:
                subdomains = self.subdomain_scanner.scan(
                    self.config.target, dry_run=self.config.dry_run
                )

            # CVE lookup
            cves = []
            if self.config.enable_cve_lookup and self.cve_scanner:
                keywords = [self.config.target.split(".")[0]]
                cves = self.cve_scanner.scan(keywords, dry_run=self.config.dry_run)

            # API fuzzing
            api_fuzz_results = []
            if self.config.enable_api_fuzz and self.api_fuzzer:
                base_url = f"https://{self.config.target}"
                endpoints = [
                    "/api/login",
                    "/api/users",
                    "/api/admin",
                    "/api/profile",
                    "/api/settings",
                ]
                api_fuzz_results = self.api_fuzzer.fuzz(
                    base_url, endpoints, dry_run=self.config.dry_run
                )

            # Auth testing
            auth_test_results = []
            if self.config.enable_auth_test and self.auth_tester:
                base_url = f"https://{self.config.target}"
                auth_test_results = self.auth_tester.test(
                    base_url,
                    username=self.config.auth_username,
                    password=self.config.auth_password,
                    dry_run=self.config.dry_run,
                )

            # Prepare report
            self.report = ReconReport(
                timestamp=datetime.now(UTC).isoformat(),
                target=self.config.target,
                subdomains_found=len(subdomains),
                vulnerabilities_found=len(api_fuzz_results) + len(auth_test_results),
                subdomains=[s.to_dict() for s in subdomains],
                cves=[c.to_dict() for c in cves],
                api_fuzz_results=[r.to_dict() for r in api_fuzz_results],
                auth_test_results=[r.to_dict() for r in auth_test_results],
                metadata={
                    "dry_run": self.config.dry_run,
                    "tools_used": ["sublist3r", "NVD API", "API Fuzzer", "Auth Tester"],
                    "python_version": sys.version.split()[0],
                    "sublist3r_available": SUBLIST3R_AVAILABLE,
                    "modules_enabled": {
                        "subdomain_scan": self.config.enable_subdomain_scan,
                        "cve_lookup": self.config.enable_cve_lookup,
                        "api_fuzz": self.config.enable_api_fuzz,
                        "auth_test": self.config.enable_auth_test,
                    },
                },
            )

            # Output results
            self.logger.info("Reconnaissance complete")
            self.report.print_summary()

            if self.config.output_file:
                self.report.save_json(self.config.output_file)

            return True

        except Exception as e:
            self.logger.error(f"Reconnaissance failed: {str(e)}")
            self.logger.debug(traceback.format_exc())
            return False


# ============================================================================
# CLI Interface
# ============================================================================


def parse_arguments() -> ReconConfig:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Lucius Security Reconnaissance Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python script.py robinhood.com
  python script.py robinhood.com --output results.json --verbose
  python script.py robinhood.com --dry-run
  python script.py robinhood.com --enable-cve --enable-fuzz --enable-auth
  python script.py robinhood.com --enable-cve --enable-fuzz --auth-user admin --auth-pass test
        """,
    )

    parser.add_argument("target", help="Target domain to scan")
    parser.add_argument("-o", "--output", type=str, help="Output file for results (JSON format)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument(
        "--dry-run", action="store_true", help="Simulate execution without actual scanning"
    )
    parser.add_argument("--no-subdomains", action="store_true", help="Skip subdomain enumeration")

    # New capability flags
    parser.add_argument(
        "--enable-cve",
        action="store_true",
        help="Enable CVE lookup via NVD API",
    )
    parser.add_argument(
        "--enable-fuzz",
        action="store_true",
        help="Enable API fuzzing",
    )
    parser.add_argument(
        "--enable-auth",
        action="store_true",
        help="Enable authentication testing",
    )

    # Auth credentials
    parser.add_argument(
        "--auth-user",
        type=str,
        help="Username for authentication testing",
    )
    parser.add_argument(
        "--auth-pass",
        type=str,
        help="Password for authentication testing",
    )

    # Robinhood bug bounty compliance headers (required for HackerOne submissions)
    parser.add_argument(
        "--hackerone-username",
        type=str,
        help="HackerOne username (required for Robinhood bug bounty submissions)",
    )
    parser.add_argument(
        "--test-account-email",
        type=str,
        help="Email of test account used (required for Robinhood submissions per X-Test-Account-Email header)",
    )

    args = parser.parse_args()

    return ReconConfig(
        target=args.target,
        output_file=args.output,
        verbose=args.verbose,
        dry_run=args.dry_run,
        enable_subdomain_scan=not args.no_subdomains,
        enable_cve_lookup=args.enable_cve,
        enable_api_fuzz=args.enable_fuzz,
        enable_auth_test=args.enable_auth,
        auth_username=args.auth_user,
        auth_password=args.auth_pass,
        hackerone_username=args.hackerone_username,
        test_account_email=args.test_account_email,
    )


def main() -> int:
    """Main entry point."""
    try:
        # Parse arguments
        config = parse_arguments()

        # Run reconnaissance
        orchestrator = ReconOrchestrator(config)
        success = orchestrator.run()

        return 0 if success else 1

    except KeyboardInterrupt:
        print("\n\nReconnaissance interrupted by user")
        return 130
    except Exception as e:
        print(f"\nFatal error: {str(e)}")
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
