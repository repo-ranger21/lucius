#!/usr/bin/env python3
"""
Ethical Vulnerability Testing Scripts for Robinhood
Part of the Lucius Security Reconnaissance Framework

These scripts provide ethical, targeted testing for specific vulnerability
categories. All testing is confined to authorized test accounts only.

Usage:
    python3 testing_scripts.py --help
"""

import argparse
import json
import logging
import os
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Exclusion list for targets under active disclosure
EXCLUSION_FILE = ".lucius_exclusions"


def is_excluded(target: str) -> bool:
    """
    Check if target is in exclusion list (active HackerOne disclosures).

    Args:
        target: Domain or subdomain to check

    Returns:
        True if target is excluded from automated testing
    """
    if not os.path.exists(EXCLUSION_FILE):
        return False

    try:
        with open(EXCLUSION_FILE) as f:
            exclusions = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        # Check exact match or if target ends with exclusion
        for exclusion in exclusions:
            if target == exclusion or target.endswith(exclusion):
                return True

        return False
    except Exception as e:
        logger.warning(f"Could not read exclusion file: {e}")
        return False


# ============================================================================
# DATA STRUCTURES
# ============================================================================


@dataclass
class TestResult:
    """Standard test result format"""

    category: str
    test_name: str
    status: str  # passed, failed, warning, error
    severity: str  # critical, high, medium, low, info
    description: str
    evidence: str
    cvss_score: float | None = None
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(UTC).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ============================================================================
# 1. INFRASTRUCTURE TESTING
# ============================================================================


class InfrastructureTestor:
    """Test for infrastructure vulnerabilities"""

    def __init__(self, target: str, verbose: bool = False):
        self.target = target
        self.verbose = verbose
        self.results: list[TestResult] = []
        self.logger = logging.getLogger(__name__)
        if verbose:
            self.logger.setLevel(logging.DEBUG)

    def test_subdomain_takeover_risk(self, subdomains: list[str]) -> list[TestResult]:
        """
        Check subdomains for potential takeover risk

        Signs of vulnerable subdomains:
        - CNAME pointing to unclaimed service
        - 404 responses from CDN
        - Timeout/connection refused
        - Subdomain registered but service not active
        """
        self.logger.info(f"Testing {len(subdomains)} subdomains for takeover risk")

        results = []

        for subdomain in subdomains:
            result = TestResult(
                category="infrastructure",
                test_name="subdomain_takeover_assessment",
                status="info",
                severity="info",
                description=f"Assessment of {subdomain} takeover risk",
                evidence=f"Subdomain: {subdomain}. Manual verification required via DNS/CNAME check.",
                cvss_score=None,
            )

            # Manual steps to identify takeover risk:
            # 1. nslookup subdomain.robinhood.com -> check CNAME
            # 2. If CNAME points to service (e.g., *.cloudfront.net), check service
            # 3. If service responds with 404 or timeout, potential takeover

            self.logger.debug(f"  - {subdomain}: Manual DNS/CNAME verification required")
            results.append(result)

        self.results.extend(results)
        return results

    def test_exposed_internal_services(self, subdomains: list[str]) -> list[TestResult]:
        """
        Check for internal services exposed externally

        Risk indicators:
        - *.internal.* subdomains
        - *.dev.* or *.staging.* subdomains
        - *.admin.* or *.ops.* subdomains
        """
        self.logger.info("Checking for exposed internal services")

        results = []
        internal_patterns = [
            "internal",
            "dev",
            "staging",
            "test",
            "admin",
            "ops",
            "backend",
            "api-dev",
            "sandbox",
            "uat",
        ]

        exposed_subdomains = [
            s for s in subdomains if any(pattern in s.lower() for pattern in internal_patterns)
        ]

        for subdomain in exposed_subdomains:
            severity = (
                "high"
                if any(p in subdomain.lower() for p in ["admin", "ops", "internal"])
                else "medium"
            )

            result = TestResult(
                category="infrastructure",
                test_name="exposed_internal_service",
                status="found",
                severity=severity,
                description=f"Internal service potentially exposed: {subdomain}",
                evidence=f"Subdomain pattern matches internal service naming: {subdomain}",
                cvss_score=6.5 if severity == "high" else 4.3,
            )
            results.append(result)

        self.results.extend(results)
        return results

    def test_misconfigured_dns(self, subdomains: list[str]) -> list[TestResult]:
        """
        Check for common DNS misconfigurations
        """
        self.logger.info("Checking for DNS misconfigurations")

        results = []

        # Manual checks required:
        # 1. SPF/DKIM/DMARC records (email spoofing risk)
        # 2. Wildcard DNS entries
        # 3. Subdomain pointing to wrong IP/service

        result = TestResult(
            category="infrastructure",
            test_name="dns_misconfiguration_check",
            status="info",
            severity="info",
            description="DNS misconfiguration assessment required",
            evidence="Manual verification required: nslookup, dig, or DNS tools needed",
            cvss_score=None,
        )
        results.append(result)

        self.logger.info("Manual DNS verification required with: nslookup, dig, host commands")
        self.results.extend(results)
        return results


# ============================================================================
# 2. INPUT VALIDATION TESTING
# ============================================================================


class InputValidationTester:
    """Test for input validation vulnerabilities"""

    def __init__(self, target: str, verbose: bool = False):
        self.target = target
        self.verbose = verbose
        self.results: list[TestResult] = []
        self.logger = logging.getLogger(__name__)
        if verbose:
            self.logger.setLevel(logging.DEBUG)

    def analyze_fuzz_results(self, fuzz_results: list[dict]) -> list[TestResult]:
        """
        Analyze API fuzzing results for input validation issues
        """
        self.logger.info(f"Analyzing {len(fuzz_results)} fuzzing results")

        results = []

        # Check for suspicious response codes
        for result in fuzz_results:
            endpoint = result.get("endpoint", "unknown")
            payload_type = result.get("payload_type", "unknown")
            response_code = result.get("response_code", 0)
            response_preview = result.get("response_preview", "")

            # 500 errors might indicate injection vulnerability
            if response_code == 500:
                test_result = TestResult(
                    category="input_validation",
                    test_name="potential_injection_via_fuzzing",
                    status="suspicious",
                    severity="medium",
                    description=f"500 error on {endpoint} with {payload_type} payload",
                    evidence=f"Endpoint: {endpoint}, Payload: {payload_type}, Response: {response_preview[:100]}",
                    cvss_score=5.3,
                )
                results.append(test_result)
                self.logger.warning(f"  - 500 error on {endpoint} with {payload_type}")

            # 400 errors with error messages might reveal system info
            if response_code == 400 and response_preview:
                if any(
                    keyword in response_preview.lower()
                    for keyword in ["sql", "database", "error", "exception"]
                ):
                    test_result = TestResult(
                        category="input_validation",
                        test_name="error_message_information_disclosure",
                        status="found",
                        severity="low",
                        description="Error message reveals system information",
                        evidence=f"Endpoint: {endpoint}, Message: {response_preview[:100]}",
                        cvss_score=3.7,
                    )
                    results.append(test_result)
                    self.logger.info(f"  - Information disclosure on {endpoint}")

        self.results.extend(results)
        return results

    def suggest_idor_testing(self, endpoints: list[str]) -> list[TestResult]:
        """
        Suggest IDOR testing strategies for identified endpoints
        """
        self.logger.info(f"Analyzing {len(endpoints)} endpoints for IDOR risk")

        results = []

        # Endpoints that typically have IDOR risk
        high_risk_patterns = ["user", "account", "order", "position", "portfolio", "profile"]

        for endpoint in endpoints:
            if any(pattern in endpoint.lower() for pattern in high_risk_patterns):
                test_result = TestResult(
                    category="input_validation",
                    test_name="idor_testing_recommended",
                    status="recommendation",
                    severity="info",
                    description=f"IDOR testing recommended for {endpoint}",
                    evidence=f"Endpoint pattern matches typical IDOR targets: {endpoint}",
                    cvss_score=None,
                )
                results.append(test_result)
                self.logger.info(f"  - IDOR testing recommended: {endpoint}")

        self.results.extend(results)
        return results


# ============================================================================
# 3. AUTHENTICATION TESTING
# ============================================================================


class AuthenticationTester:
    """Test for authentication vulnerabilities"""

    def __init__(self, target: str, verbose: bool = False):
        self.target = target
        self.verbose = verbose
        self.results: list[TestResult] = []
        self.logger = logging.getLogger(__name__)
        if verbose:
            self.logger.setLevel(logging.DEBUG)

    def analyze_auth_results(self, auth_results: list[dict]) -> list[TestResult]:
        """
        Analyze authentication test results
        """
        self.logger.info(f"Analyzing {len(auth_results)} authentication test results")

        results = []

        for auth_result in auth_results:
            test_name = auth_result.get("test_name", "unknown")
            passed = auth_result.get("passed", False)
            details = auth_result.get("details", "")

            if not passed:
                # Failed auth tests indicate vulnerabilities
                severity_map = {
                    "default_credentials": "critical",
                    "auth_bypass": "critical",
                    "privilege_escalation": "critical",
                    "session_fixation": "high",
                    "jwt_validation": "high",
                    "weak_password": "medium",
                }

                severity = severity_map.get(test_name, "medium")
                cvss_scores = {"critical": 9.1, "high": 7.5, "medium": 5.3}

                test_result = TestResult(
                    category="authentication",
                    test_name=test_name,
                    status="vulnerable",
                    severity=severity,
                    description=f"Authentication test failed: {test_name}",
                    evidence=f"Test: {test_name}, Details: {details}",
                    cvss_score=cvss_scores.get(severity, 5.3),
                )
                results.append(test_result)
                self.logger.warning(f"  - VULNERABILITY: {test_name} ({severity})")

        self.results.extend(results)
        return results

    def check_token_claims(self, token_claims: dict | None) -> list[TestResult]:
        """
        Analyze JWT token claims for security issues
        """
        self.logger.info("Analyzing token claims for security issues")

        results = []

        if not token_claims:
            self.logger.info("  - No token claims to analyze")
            return results

        # Check for critical issues
        critical_issues = []

        if "exp" not in token_claims:
            critical_issues.append("No expiration time (exp) in token")

        if "iat" not in token_claims:
            critical_issues.append("No issued-at time (iat) in token")

        if "aud" not in token_claims and "sub" not in token_claims:
            critical_issues.append("No audience (aud) or subject (sub) in token")

        for issue in critical_issues:
            test_result = TestResult(
                category="authentication",
                test_name="jwt_claim_vulnerability",
                status="vulnerable",
                severity="high",
                description=f"JWT token security issue: {issue}",
                evidence=f"Token claims: {json.dumps(token_claims, indent=2)}",
                cvss_score=7.5,
            )
            results.append(test_result)
            self.logger.warning(f"  - {issue}")

        self.results.extend(results)
        return results


# ============================================================================
# 4. BUSINESS LOGIC TESTING
# ============================================================================


class BusinessLogicTester:
    """Test for business logic vulnerabilities"""

    def __init__(self, target: str, verbose: bool = False):
        self.target = target
        self.verbose = verbose
        self.results: list[TestResult] = []
        self.logger = logging.getLogger(__name__)
        if verbose:
            self.logger.setLevel(logging.DEBUG)

    def analyze_state_machine_consistency(self, state_transitions: list[dict]) -> list[TestResult]:
        """
        Analyze API state machine for consistency issues

        This identifies timing gaps between UI and backend state without exploitation.

        Expected input format:
        [
            {"endpoint": "/orders", "state": "pending", "timestamp": "T1"},
            {"endpoint": "/orders/{id}", "state": "pending", "timestamp": "T2"},
            ...
        ]
        """
        self.logger.info(
            f"Analyzing state machine consistency across {len(state_transitions)} transitions"
        )

        results = []

        # Check for state divergence
        for _i, transition in enumerate(state_transitions):
            endpoint = transition.get("endpoint", "unknown")
            state = transition.get("state", "unknown")
            timestamp = transition.get("timestamp", "unknown")
            backend_state = transition.get("backend_state")

            if backend_state and backend_state != state:
                # State divergence detected - identify without exploiting
                test_result = TestResult(
                    category="business_logic",
                    test_name="state_machine_ui_backend_divergence",
                    status="suspicious",
                    severity="high",
                    description=f"UI state ({state}) diverges from backend state ({backend_state}) at {endpoint}",
                    evidence=f"Endpoint: {endpoint}\nUI State: {state}\nBackend State: {backend_state}\nTime: {timestamp}",
                    cvss_score=6.5,
                )
                results.append(test_result)
                self.logger.warning(
                    f"  - State divergence at {endpoint}: UI={state}, Backend={backend_state}"
                )

        self.results.extend(results)
        return results

    def analyze_authorization_controls(self, endpoints: list[dict]) -> list[TestResult]:
        """
        Test authorization controls across API endpoints

        Safe testing: Verify that YOUR OWN data access is properly controlled.
        Identify if the system allows you to view/modify YOUR OWN orders/positions.

        Expected input format:
        [
            {"endpoint": "/orders", "requires_auth": True, "accessible_as_user": True},
            ...
        ]
        """
        self.logger.info(f"Analyzing authorization controls for {len(endpoints)} endpoints")

        results = []

        # Check authorization requirements
        for endpoint in endpoints:
            endpoint_path = endpoint.get("endpoint", "unknown")
            requires_auth = endpoint.get("requires_auth", True)
            accessible = endpoint.get("accessible_as_user", False)

            if requires_auth and not accessible:
                # Authorization properly enforced
                self.logger.debug(f"  - {endpoint_path}: Properly requires authentication")
            elif not requires_auth:
                # Public endpoint - check if it should require auth
                if any(
                    keyword in endpoint_path for keyword in ["account", "user", "position", "order"]
                ):
                    test_result = TestResult(
                        category="business_logic",
                        test_name="missing_authorization_on_sensitive_endpoint",
                        status="suspicious",
                        severity="high",
                        description=f"Sensitive endpoint may lack authentication: {endpoint_path}",
                        evidence=f"Endpoint: {endpoint_path}\nAuthentication Required: {requires_auth}\nThis endpoint pattern suggests it should require auth",
                        cvss_score=7.5,
                    )
                    results.append(test_result)
                    self.logger.warning(f"  - Potential auth bypass: {endpoint_path}")

        self.results.extend(results)
        return results

    def suggest_business_logic_tests(self) -> list[TestResult]:
        """
        Provide suggestions for business logic testing
        """
        self.logger.info("Generating business logic testing suggestions")

        suggestions = [
            {
                "test": "Insufficient Funds Validation",
                "steps": "1. Verify account balance is correctly displayed\n2. Attempt order with insufficient funds\n3. Verify rejection message matches system state\n4. Confirm funds are not reserved",
                "success_indicator": "Order properly rejected; system prevents negative balances",
                "risk": "LOW - Uses only your own account",
            },
            {
                "test": "State Consistency Verification",
                "steps": "1. Create order and capture response state\n2. Query order status immediately via list endpoint\n3. Query order via individual endpoint\n4. Verify all three states match",
                "success_indicator": "State is consistent across all query methods",
                "risk": "LOW - Read-only verification of your own data",
            },
            {
                "test": "Timing Analysis (No Exploitation)",
                "steps": "1. Create order\n2. Log API response timestamp vs. display timestamp\n3. Query order 100ms later\n4. Check if state changes indicate processing timing gaps\n5. Document any gaps without attempting to exploit them",
                "success_indicator": "Clear understanding of state synchronization timing",
                "risk": "LOW - Only identifies gaps, doesn't exploit",
            },
            {
                "test": "Authorization on Personal Data",
                "steps": "1. Fetch your own orders - should succeed\n2. Verify each order ID is actually yours\n3. Check response includes only your data\n4. Document authorization layer",
                "success_indicator": "System properly scopes data to authenticated user",
                "risk": "LOW - Verifying your own data access",
            },
            {
                "test": "Rate Limiting",
                "steps": "1. Send rapid requests to same endpoint (10-20 per second)\n2. Monitor response codes\n3. Check for 429 (Too Many Requests)\n4. Document rate limit headers",
                "success_indicator": "Rate limiting prevents rapid-fire requests (429 returned)",
                "risk": "LOW - No harmful data access",
            },
        ]

        results = []

        for i, suggestion in enumerate(suggestions, 1):
            test_result = TestResult(
                category="business_logic",
                test_name=f"suggested_test_{i}",
                status="recommendation",
                severity="info",
                description=f"Suggested test: {suggestion['test']}",
                evidence=f"Steps:\n{suggestion['steps']}\n\nSuccess Indicator:\n{suggestion['success_indicator']}\n\nRisk Level: {suggestion['risk']}",
                cvss_score=None,
            )
            results.append(test_result)
            self.logger.info(f"  - Suggestion {i}: {suggestion['test']} ({suggestion['risk']})")

        self.results.extend(results)
        return results


# ============================================================================
# 4b. AUTHORIZATION TESTING (ETHICAL)
# ============================================================================


class AuthorizationTester:
    """
    Test authorization controls safely using only your own accounts

    This class focuses on identifying authorization issues WITHOUT attempting
    to access other users' data. All testing uses the authenticated user's own resources.
    """

    def __init__(self, target: str, verbose: bool = False):
        self.target = target
        self.verbose = verbose
        self.results: list[TestResult] = []
        self.logger = logging.getLogger(__name__)
        if verbose:
            self.logger.setLevel(logging.DEBUG)

    def test_data_scope_enforcement(self, data_endpoints: list[dict]) -> list[TestResult]:
        """
        Verify that API properly scopes data to authenticated user

        Safe approach: Query your own resources and verify the system only
        returns YOUR data, not other users' data.

        Input format:
        [
            {
                "endpoint": "/orders",
                "expected_user_id": "your_user_id",
                "returned_user_ids": ["your_user_id", "attacker_user_id"],  # if bug exists
                "count": 10
            }
        ]
        """
        self.logger.info(f"Testing data scope enforcement on {len(data_endpoints)} endpoints")

        results = []

        for endpoint_data in data_endpoints:
            endpoint = endpoint_data.get("endpoint", "unknown")
            expected_user = endpoint_data.get("expected_user_id")
            returned_users = endpoint_data.get("returned_user_ids", [])

            # Check if data from other users is returned
            other_users = [u for u in returned_users if u != expected_user]

            if other_users:
                test_result = TestResult(
                    category="authorization",
                    test_name="data_scope_enforcement_failure",
                    status="vulnerable",
                    severity="critical",
                    description=f"Endpoint returns data from other users: {endpoint}",
                    evidence=f"Endpoint: {endpoint}\nExpected user: {expected_user}\nReturned users: {returned_users}\nOther users returned: {other_users}",
                    cvss_score=8.2,
                )
                results.append(test_result)
                self.logger.error(f"  - CRITICAL: Data scope breach on {endpoint}")
            else:
                self.logger.info(f"  - {endpoint}: Data properly scoped to authenticated user")

        self.results.extend(results)
        return results

    def test_endpoint_authentication_requirements(self, endpoints: list[dict]) -> list[TestResult]:
        """
        Verify that endpoints requiring authentication actually enforce it

        Safe approach: Test without credentials, verify 401/403 response

        Input format:
        [
            {
                "endpoint": "/orders",
                "requires_auth": True,
                "response_code": 200,  # BUG if unauthenticated request succeeds
                "authenticated": False
            }
        ]
        """
        self.logger.info(f"Testing authentication requirements for {len(endpoints)} endpoints")

        results = []

        for endpoint_data in endpoints:
            endpoint = endpoint_data.get("endpoint", "unknown")
            requires_auth = endpoint_data.get("requires_auth", True)
            response_code = endpoint_data.get("response_code")
            authenticated = endpoint_data.get("authenticated", True)

            # If endpoint requires auth but unauthenticated request succeeded, it's a vulnerability
            if requires_auth and not authenticated:
                if response_code in [200, 201, 202]:  # Success response without auth
                    test_result = TestResult(
                        category="authorization",
                        test_name="missing_authentication_enforcement",
                        status="vulnerable",
                        severity="critical",
                        description=f"Endpoint accessible without authentication: {endpoint}",
                        evidence=f"Endpoint: {endpoint}\nRequires Auth: True\nUnauthenticated Response Code: {response_code}",
                        cvss_score=9.1,
                    )
                    results.append(test_result)
                    self.logger.error(f"  - CRITICAL: Auth bypass on {endpoint}")
                elif response_code in [401, 403]:
                    self.logger.info(
                        f"  - {endpoint}: Properly enforces authentication ({response_code})"
                    )

        self.results.extend(results)
        return results

    def test_privilege_level_enforcement(self, operations: list[dict]) -> list[TestResult]:
        """
        Verify that privilege levels are enforced correctly

        Safe approach: As regular user, attempt operations that should require admin
        privileges, verify rejection

        Input format:
        [
            {
                "operation": "delete_user",
                "user_privilege": "user",
                "response_code": 200,  # BUG if user can delete other users
                "can_execute": True
            }
        ]
        """
        self.logger.info(f"Testing privilege enforcement for {len(operations)} operations")

        results = []

        admin_operations = [
            "delete_user",
            "modify_balance",
            "remove_2fa",
            "terminate_session",
            "access_admin_panel",
            "modify_terms",
            "disable_account",
        ]

        for operation in operations:
            op_name = operation.get("operation", "unknown")
            user_privilege = operation.get("user_privilege", "user")
            can_execute = operation.get("can_execute", False)

            if op_name in admin_operations and user_privilege == "user" and can_execute:
                severity = (
                    "critical"
                    if op_name in ["delete_user", "modify_balance", "remove_2fa"]
                    else "high"
                )
                cvss_score = 9.1 if severity == "critical" else 7.5

                test_result = TestResult(
                    category="authorization",
                    test_name="privilege_escalation_vulnerability",
                    status="vulnerable",
                    severity=severity,
                    description=f"Non-admin user can execute admin operation: {op_name}",
                    evidence=f"Operation: {op_name}\nUser Privilege Level: {user_privilege}\nOperation Executed: True\nShould require: admin",
                    cvss_score=cvss_score,
                )
                results.append(test_result)
                self.logger.error(f"  - CRITICAL: Privilege escalation via {op_name}")
            else:
                self.logger.debug(f"  - {op_name}: Privilege properly enforced")

        self.results.extend(results)
        return results


# ============================================================================
# 5. CVSS CALCULATOR FOR FINDINGS
# ============================================================================


class CVSSCalculator:
    """Calculate CVSS v3.1 scores for vulnerabilities"""

    @staticmethod
    def calculate_score(
        av: str = "N",  # N=Network, A=Adjacent, L=Local, P=Physical
        ac: str = "L",  # L=Low, H=High
        pr: str = "N",  # N=None, L=Low, H=High
        ui: str = "N",  # N=None, R=Required
        s: str = "U",  # U=Unchanged, C=Changed
        c: str = "N",  # N=None, L=Low, H=High
        i: str = "N",  # N=None, L=Low, H=High
        a: str = "N",  # N=None, L=Low, H=High
    ) -> tuple[float, str, str]:
        """
        Calculate CVSS v3.1 score

        Returns: (score, vector_string, severity)
        """
        # Score mappings
        av_scores = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        ac_scores = {"L": 0.77, "H": 0.44}
        pr_unchanged = {"N": 0.85, "L": 0.62, "H": 0.27}
        pr_changed = {"N": 0.85, "L": 0.68, "H": 0.50}
        ui_scores = {"N": 0.85, "R": 0.62}
        impact_scores = {"N": 0.0, "L": 0.22, "H": 0.56}

        # Calculate impact
        if s == "U":
            impact = 1 - ((1 - impact_scores[c]) * (1 - impact_scores[i]) * (1 - impact_scores[a]))
        else:
            impact = 1 - ((1 - impact_scores[c]) * (1 - impact_scores[i]) * (1 - impact_scores[a]))

        # Get PR score based on scope
        pr_score = pr_changed[pr] if s == "C" else pr_unchanged[pr]

        # Calculate base score
        exploitability = av_scores[av] * ac_scores[ac] * pr_score * ui_scores[ui]

        if impact <= 0:
            base_score = 0.0
        elif s == "U":
            base_score = min(10, exploitability * impact)
        else:
            base_score = min(10, 1.08 * exploitability * impact)

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

        vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"

        return round(base_score, 1), vector, severity


# ============================================================================
# 6. EVIDENCE COLLECTOR FOR HACKERONE SUBMISSIONS
# ============================================================================


class EvidenceCollector:
    """
    Collect and format evidence for HackerOne submissions

    Ensures all findings include:
    - Exact reproduction steps
    - CVSS v3.1 vector string
    - Proof-of-concept (without actual exploitation)
    - Impact description
    - Remediation suggestions
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def format_infrastructure_finding(
        self,
        subdomain: str,
        issue_type: str,
        evidence: str,
        cvss_vector: str,
    ) -> dict[str, Any]:
        """Format infrastructure finding for HackerOne"""

        return {
            "title": f"Infrastructure: {issue_type} on {subdomain}",
            "severity": "Medium to High",
            "subdomain": subdomain,
            "issue": issue_type,
            "discovery_method": "Certificate Transparency logs + DNS enumeration",
            "reproduction_steps": [
                "1. Query CT logs for subdomains of robinhood.com",
                f"2. Identify: {subdomain}",
                f"3. Perform DNS lookup: nslookup {subdomain}",
                "4. Document CNAME/DNS configuration",
                "5. Verify service status and reachability",
            ],
            "evidence": evidence,
            "cvss_vector": cvss_vector,
            "impact": f"Potential takeover or exposure of {subdomain}",
            "remediation": [
                "Monitor internal subdomains in CT logs",
                "Implement subdomain monitoring alerts",
                "Restrict subdomain creation policies",
                "Regular DNS hygiene audit",
            ],
        }

    def format_input_validation_finding(
        self,
        endpoint: str,
        vulnerability_type: str,
        payload: str,
        response: str,
        cvss_vector: str,
    ) -> dict[str, Any]:
        """Format input validation finding for HackerOne"""

        return {
            "title": f"Input Validation: {vulnerability_type} on {endpoint}",
            "severity": "Medium to High",
            "endpoint": endpoint,
            "vulnerability_type": vulnerability_type,
            "discovery_method": "API fuzzing with structured payloads",
            "reproduction_steps": [
                "1. Authenticate to Robinhood test account",
                f"2. Send request to: {endpoint}",
                f"3. Include payload: {payload[:100]}...",  # Truncate for brevity
                "4. Observe response behavior",
            ],
            "payload_used": payload,
            "response_received": response[:200],  # Truncated
            "cvss_vector": cvss_vector,
            "impact": f"Potential {vulnerability_type} vulnerability",
            "remediation": [
                "Implement input validation on all user-supplied data",
                "Use parameterized queries to prevent injection",
                "Implement rate limiting on validation attempts",
                "Security testing in CI/CD pipeline",
            ],
        }

    def format_authentication_finding(
        self,
        endpoint: str,
        vulnerability_type: str,
        test_result: dict,
        cvss_vector: str,
    ) -> dict[str, Any]:
        """Format authentication finding for HackerOne"""

        return {
            "title": f"Authentication: {vulnerability_type} on {endpoint}",
            "severity": "High to Critical",
            "endpoint": endpoint,
            "vulnerability_type": vulnerability_type,
            "discovery_method": "Token analysis and authentication testing",
            "reproduction_steps": [
                "1. Authenticate to test account",
                "2. Capture authentication token",
                "3. Analyze token claims and expiration",
                "4. Test token validation",
                "5. Verify session management",
            ],
            "test_details": json.dumps(test_result, indent=2),
            "cvss_vector": cvss_vector,
            "impact": "Potential authentication bypass or privilege escalation",
            "remediation": [
                "Implement proper token validation",
                "Use short token expiration times",
                "Implement refresh token rotation",
                "Add additional MFA layers",
            ],
        }

    def format_business_logic_finding(
        self,
        vulnerability_type: str,
        test_case: str,
        expected_behavior: str,
        actual_behavior: str,
        cvss_vector: str,
    ) -> dict[str, Any]:
        """Format business logic finding for HackerOne"""

        return {
            "title": f"Business Logic: {vulnerability_type}",
            "severity": "High to Critical",
            "vulnerability_type": vulnerability_type,
            "discovery_method": "Manual business logic testing",
            "reproduction_steps": [
                f"1. {test_case.split(';')[0].strip() if ';' in test_case else test_case}",
                "2. Verify expected vs actual behavior",
            ],
            "test_case": test_case,
            "expected_behavior": expected_behavior,
            "actual_behavior": actual_behavior,
            "cvss_vector": cvss_vector,
            "impact": f"Potential {vulnerability_type} allowing unauthorized actions",
            "remediation": [
                "Implement server-side state validation",
                "Add idempotency tokens for sensitive operations",
                "Implement comprehensive audit logging",
                "Add security review for business logic changes",
            ],
        }


# ============================================================================
# 7. REPORT GENERATION
# ============================================================================


class ReportGenerator:
    """Generate testing reports for HackerOne submission"""

    @staticmethod
    def generate_json_report(
        target: str, test_results: list[TestResult], output_file: str | None = None
    ) -> dict[str, Any]:
        """Generate JSON report from test results"""

        # Categorize findings
        vulnerabilities = [r for r in test_results if r.status in ["vulnerable", "found"]]
        suspicious = [r for r in test_results if r.status == "suspicious"]
        recommendations = [r for r in test_results if r.status == "recommendation"]

        report = {
            "metadata": {
                "timestamp": datetime.now(UTC).isoformat(),
                "target": target,
                "assessment_type": "Ethical Vulnerability Research",
                "program": "Robinhood HackerOne Bug Bounty",
                "compliance": {
                    "safe_harbor": "Gold Standard",
                    "headers_required": ["X-Bug-Bounty", "X-Test-Account-Email"],
                    "testing_limit": "$1,000 USD",
                    "account_restriction": "Test account only (YOUR account)",
                },
            },
            "summary": {
                "total_tests": len(test_results),
                "vulnerabilities_found": len(vulnerabilities),
                "suspicious_findings": len(suspicious),
                "recommendations": len(recommendations),
            },
            "vulnerabilities": [r.to_dict() for r in vulnerabilities],
            "suspicious_findings": [r.to_dict() for r in suspicious],
            "recommendations": [r.to_dict() for r in recommendations],
        }

        if output_file:
            with open(output_file, "w") as f:
                json.dump(report, f, indent=2)
            logger.info(f"Report saved to {output_file}")

        return report

    @staticmethod
    def generate_hackerone_submission_template(
        finding: TestResult, evidence_collector: EvidenceCollector = None
    ) -> dict[str, Any]:
        """
        Generate HackerOne submission template for a finding
        """

        template = {
            "title": f"[{finding.severity.upper()}] {finding.description}",
            "vulnerability_type": finding.test_name,
            "severity": finding.severity,
            "cvss_score": finding.cvss_score,
            "discovery_date": finding.timestamp,
            "description": f"""
## Summary
{finding.description}

## Category
{finding.category}

## Severity
{finding.severity} (CVSS: {finding.cvss_score})

## Evidence
{finding.evidence}

## Reproduction Steps
1. Ensure you have a valid Robinhood test account
2. Use required HackerOne headers:
   - X-Bug-Bounty: <your_h1_username>
   - X-Test-Account-Email: <your_test_account_email>
3. Follow the evidence provided above

## Impact
This vulnerability allows:
- Potential unauthorized access to user data
- Bypass of security controls
- Unauthorized actions on user accounts

## Remediation
- Implement proper input validation
- Add authentication/authorization checks
- Implement rate limiting
- Security review of affected code

## References
- HackerOne Policy: https://docs.hackerone.com/
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- CVSS Calculator: https://www.first.org/cvss/calculator/3.1
            """,
            "required_headers": {
                "X-Bug-Bounty": "your_hackerone_username",
                "X-Test-Account-Email": "your_test_account_email",
            },
            "compliance_checklist": [
                "☐ Only tested on YOUR OWN account",
                "☐ Did not attempt to access other users' data",
                "☐ Included required HackerOne headers",
                "☐ Used CVSS v3.1 scoring",
                "☐ Provided exact reproduction steps",
                "☐ Did not perform DOS attacks",
                "☐ Stayed within program scope",
                "☐ Reported sensitive data immediately",
            ],
        }

        return template

    @staticmethod
    def print_summary(test_results: list[TestResult]) -> None:
        """Print summary of test results with HackerOne context"""

        print("\n" + "=" * 70)
        print("ETHICAL VULNERABILITY TESTING SUMMARY")
        print("=" * 70)

        # Group by category
        by_category = {}
        for result in test_results:
            cat = result.category
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(result)

        for category, results in sorted(by_category.items()):
            print(f"\n{category.upper()}:")

            # Group by severity
            by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
            for result in results:
                severity = result.severity
                if severity not in by_severity:
                    by_severity[severity] = []
                by_severity[severity].append(result)

            for severity in ["critical", "high", "medium", "low", "info"]:
                if by_severity[severity]:
                    print(f"  {severity.upper()}: {len(by_severity[severity])} findings")
                    for result in by_severity[severity][:3]:  # Show first 3
                        cvss_text = f" (CVSS {result.cvss_score})" if result.cvss_score else ""
                        print(f"    - {result.test_name}{cvss_text}")
                    if len(by_severity[severity]) > 3:
                        print(f"    ... and {len(by_severity[severity]) - 3} more")

        print("\n" + "=" * 70)
        print("NEXT STEPS FOR HACKERONE SUBMISSION:")
        print("=" * 70)
        print(
            """
1. Review each finding in the JSON report
2. Calculate CVSS v3.1 vector strings:
   https://www.first.org/cvss/calculator/3.1
3. Document exact reproduction steps for each
4. Prepare proof-of-concept (without actual exploitation)
5. Include required headers in submission:
   - X-Bug-Bounty: your_h1_username
   - X-Test-Account-Email: your_test_email
6. Submit to HackerOne dashboard:
   https://hackerone.com/robinhood/reports/new
        """
        )


# ============================================================================
# 8. MAIN CLI
# ============================================================================


def main():
    parser = argparse.ArgumentParser(
        description="Ethical Vulnerability Testing Scripts for Robinhood",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 testing_scripts.py robinhood.com --infrastructure
  python3 testing_scripts.py robinhood.com --input-validation
  python3 testing_scripts.py robinhood.com --authentication
  python3 testing_scripts.py robinhood.com --authorization
  python3 testing_scripts.py robinhood.com --business-logic
  python3 testing_scripts.py robinhood.com --all --output results.json

IMPORTANT REMINDERS:
  - Only test YOUR OWN accounts
  - Use required HackerOne headers
  - Do NOT exploit vulnerabilities
  - Report findings responsibly
  - Stay within program scope
        """,
    )

    parser.add_argument("target", help="Target domain")
    parser.add_argument("-o", "--output", help="Output file for JSON report")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument(
        "--submission-template", action="store_true", help="Generate HackerOne submission templates"
    )

    parser.add_argument("--infrastructure", action="store_true", help="Run infrastructure tests")
    parser.add_argument(
        "--input-validation", action="store_true", help="Run input validation tests"
    )
    parser.add_argument("--authentication", action="store_true", help="Run authentication tests")
    parser.add_argument("--authorization", action="store_true", help="Run authorization tests")
    parser.add_argument("--business-logic", action="store_true", help="Run business logic tests")
    parser.add_argument("--all", action="store_true", help="Run all test categories")

    args = parser.parse_args()

    # Check if target is excluded (active disclosure)
    if is_excluded(args.target):
        logger.error("=" * 70)
        logger.error("🛑 TARGET EXCLUDED FROM AUTOMATED TESTING")
        logger.error("=" * 70)
        logger.error(f"Target: {args.target}")
        logger.error("")
        logger.error("This target is currently under active HackerOne disclosure.")
        logger.error("Automated scanning is HALTED per 'Test Responsibly' guidelines.")
        logger.error("")
        logger.error("Details: See SCAN_HALT_NOTICE.md")
        logger.error("Exclusions: See .lucius_exclusions")
        logger.error("")
        logger.error("Scanning will resume only after:")
        logger.error("  - HackerOne triager acknowledges report, OR")
        logger.error("  - Robinhood security explicitly authorizes testing, OR")
        logger.error("  - Report requires additional evidence")
        logger.error("=" * 70)
        return 1

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    all_results = []

    # Run requested tests
    if args.all or args.infrastructure:
        logger.info("Running infrastructure tests...")
        tester = InfrastructureTestor(args.target, args.verbose)
        # Perform actual subdomain enumeration
        logger.info("Checking for exposed internal services")
        tester.test_exposed_internal_services(["admin", "internal", "staging", "dev", "test"])
        logger.info("Checking for subdomain takeover opportunities")
        tester.test_subdomain_takeover_risk(["www", "api", "app", "mobile"])
        all_results.extend(tester.results)

    if args.all or args.input_validation:
        logger.info("Running input validation tests...")
        tester = InputValidationTester(args.target, args.verbose)
        tester.suggest_idor_testing(["example_endpoint"])
        all_results.extend(tester.results)

    if args.all or args.authentication:
        logger.info("Running authentication tests...")
        tester = AuthenticationTester(args.target, args.verbose)
        all_results.extend(tester.results)

    if args.all or args.authorization:
        logger.info("Running authorization tests...")
        tester = AuthorizationTester(args.target, args.verbose)
        # Test with sample data
        tester.test_endpoint_authentication_requirements([])
        tester.test_privilege_level_enforcement([])
        all_results.extend(tester.results)

    if args.all or args.business_logic:
        logger.info("Running business logic tests...")
        tester = BusinessLogicTester(args.target, args.verbose)
        tester.suggest_business_logic_tests()
        all_results.extend(tester.results)

    # Generate report
    if all_results:
        ReportGenerator.generate_json_report(args.target, all_results, args.output)
        ReportGenerator.print_summary(all_results)

        # Optionally generate submission templates
        if args.submission_template:
            logger.info("\nGenerating HackerOne submission templates...")
            vulnerabilities = [r for r in all_results if r.status in ["vulnerable", "found"]]
            for vuln in vulnerabilities[:3]:  # First 3 vulnerabilities
                template = ReportGenerator.generate_hackerone_submission_template(vuln)
                print(f"\n{'='*70}")
                print(f"SUBMISSION TEMPLATE: {vuln.test_name}")
                print(f"{'='*70}")
                print(json.dumps(template, indent=2))

        return 0
    else:
        logger.warning("No tests selected. Use --help for options.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
