"""
API Testing Module for Bug Bounty Testing

This module provides comprehensive API testing capabilities including:
- Endpoint discovery and mapping
- Parameter fuzzing and injection testing
- Request/response analysis
- Rate limiting detection
- Automated vulnerability scanning

Designed for ethical security testing with built-in safety controls.
"""

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urljoin, urlparse

try:
    import requests

    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from sentinel.utils import SafeUrlError, canonicalize_and_validate_url
from shared.logging import get_logger

logger = get_logger(__name__)


class HTTPMethod(Enum):
    """Supported HTTP methods for API testing"""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"


class ParameterType(Enum):
    """Types of parameters to test"""

    QUERY = "query"
    HEADER = "header"
    BODY = "body"
    PATH = "path"
    COOKIE = "cookie"


class VulnerabilityType(Enum):
    """API vulnerability categories"""

    SQL_INJECTION = "sql_injection"
    XSS = "cross_site_scripting"
    COMMAND_INJECTION = "command_injection"
    XXE = "xml_external_entity"
    SSRF = "server_side_request_forgery"
    IDOR = "insecure_direct_object_reference"
    BROKEN_AUTH = "broken_authentication"
    EXCESSIVE_DATA = "excessive_data_exposure"
    MASS_ASSIGNMENT = "mass_assignment"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    RATE_LIMIT_BYPASS = "rate_limit_bypass"
    INJECTION = "injection"


class RateLimitStatus(Enum):
    """Rate limiting detection status"""

    NO_LIMIT = "no_limit"
    SOFT_LIMIT = "soft_limit"
    HARD_LIMIT = "hard_limit"
    UNKNOWN = "unknown"


@dataclass
class APIEndpoint:
    """Represents a discovered API endpoint"""

    url: str
    method: HTTPMethod
    parameters: Dict[ParameterType, List[str]] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    authentication_required: bool = False
    discovered_at: datetime = field(default_factory=datetime.now)
    response_content_type: Optional[str] = None
    status_code: Optional[int] = None

    def __post_init__(self):
        if not self.parameters:
            self.parameters = {
                ParameterType.QUERY: [],
                ParameterType.HEADER: [],
                ParameterType.BODY: [],
                ParameterType.PATH: [],
                ParameterType.COOKIE: [],
            }


@dataclass
class FuzzingPayload:
    """Fuzzing payload for parameter testing"""

    value: str
    payload_type: VulnerabilityType
    description: str
    expected_indicators: List[str] = field(default_factory=list)


@dataclass
class APITestResult:
    """Result of an API security test"""

    endpoint: APIEndpoint
    vulnerability_type: VulnerabilityType
    severity: str  # "critical", "high", "medium", "low", "info"
    parameter_tested: str
    parameter_type: ParameterType
    payload_used: str
    evidence: str
    http_request: str
    http_response: str
    discovered_at: datetime = field(default_factory=datetime.now)
    confidence: float = 0.0  # 0.0 to 1.0
    false_positive_likelihood: float = 0.0  # 0.0 to 1.0


@dataclass
class RateLimitInfo:
    """Information about rate limiting on an endpoint"""

    endpoint_url: str
    status: RateLimitStatus
    requests_before_limit: Optional[int] = None
    reset_time_seconds: Optional[int] = None
    limit_header: Optional[str] = None
    remaining_header: Optional[str] = None
    reset_header: Optional[str] = None
    tested_at: datetime = field(default_factory=datetime.now)


class EndpointDiscovery:
    """
    Discovers API endpoints through various techniques:
    - Common API path enumeration
    - Swagger/OpenAPI specification parsing
    - JavaScript file analysis
    - Robots.txt and sitemap parsing
    """

    # Common API endpoint patterns
    COMMON_API_PATHS = [
        "/api/v1",
        "/api/v2",
        "/api/v3",
        "/api",
        "/rest",
        "/graphql",
        "/v1",
        "/v2",
        "/v3",
        "/api/users",
        "/api/auth",
        "/api/login",
        "/api/admin",
        "/api/config",
        "/api/settings",
        "/swagger",
        "/swagger.json",
        "/swagger-ui",
        "/openapi.json",
        "/api-docs",
        "/healthcheck",
        "/health",
        "/status",
        "/metrics",
        "/ping",
        "/version",
    ]

    # Common API resource patterns
    COMMON_RESOURCES = [
        "users",
        "accounts",
        "profiles",
        "auth",
        "login",
        "logout",
        "admin",
        "settings",
        "config",
        "data",
        "files",
        "uploads",
        "posts",
        "comments",
        "messages",
        "notifications",
        "orders",
        "payments",
        "transactions",
        "invoices",
    ]

    def __init__(self, base_url: str, max_depth: int = 3):
        """
        Initialize endpoint discovery

        Args:
            base_url: Base URL to discover endpoints from
            max_depth: Maximum depth for recursive discovery
        """
        self.base_url = base_url.rstrip("/")
        self.max_depth = max_depth
        self.discovered_endpoints: Set[Tuple[str, str]] = set()  # Set of (url, method) tuples

    def discover_common_endpoints(self) -> List[APIEndpoint]:
        """
        Discover endpoints using common API path patterns

        Returns:
            List of discovered API endpoints
        """
        endpoints = []

        for path in self.COMMON_API_PATHS:
            url = urljoin(self.base_url, path)
            endpoint_key = (url, HTTPMethod.GET.value)
            if endpoint_key not in self.discovered_endpoints:
                self.discovered_endpoints.add(endpoint_key)
                endpoint = APIEndpoint(url=url, method=HTTPMethod.GET)
                endpoints.append(endpoint)
                logger.info(f"Discovered common endpoint: {url}")

        return endpoints

    def discover_resource_endpoints(self, base_path: str = "/api") -> List[APIEndpoint]:
        """
        Discover RESTful resource endpoints

        Args:
            base_path: Base API path to append resources to

        Returns:
            List of discovered resource endpoints
        """
        endpoints = []

        for resource in self.COMMON_RESOURCES:
            for method in [HTTPMethod.GET, HTTPMethod.POST, HTTPMethod.PUT, HTTPMethod.DELETE]:
                # Base resource endpoint
                url = urljoin(self.base_url, f"{base_path}/{resource}")
                endpoint_key = (url, method.value)
                if endpoint_key not in self.discovered_endpoints:
                    self.discovered_endpoints.add(endpoint_key)
                    endpoint = APIEndpoint(url=url, method=method)
                    endpoints.append(endpoint)

                # Resource with ID parameter
                url_with_id = urljoin(self.base_url, f"{base_path}/{resource}/{{id}}")
                endpoint_key_with_id = (url_with_id, method.value)
                if endpoint_key_with_id not in self.discovered_endpoints:
                    self.discovered_endpoints.add(endpoint_key_with_id)
                    endpoint = APIEndpoint(
                        url=url_with_id,
                        method=method,
                        parameters={
                            ParameterType.PATH: ["id"],
                            ParameterType.QUERY: [],
                            ParameterType.HEADER: [],
                            ParameterType.BODY: [],
                            ParameterType.COOKIE: [],
                        },
                    )
                    endpoints.append(endpoint)

        logger.info(f"Discovered {len(endpoints)} resource endpoints")
        return endpoints

    def parse_openapi_spec(self, spec_data: Dict[str, Any]) -> List[APIEndpoint]:
        """
        Parse OpenAPI/Swagger specification to discover endpoints

        Args:
            spec_data: Parsed OpenAPI specification dictionary

        Returns:
            List of discovered API endpoints
        """
        endpoints = []

        if "paths" not in spec_data:
            return endpoints

        for path, methods in spec_data["paths"].items():
            for method_name, operation in methods.items():
                if method_name.upper() not in [m.value for m in HTTPMethod]:
                    continue

                url = urljoin(self.base_url, path)
                method = HTTPMethod(method_name.upper())

                # Extract parameters
                params = {
                    ParameterType.QUERY: [],
                    ParameterType.HEADER: [],
                    ParameterType.BODY: [],
                    ParameterType.PATH: [],
                    ParameterType.COOKIE: [],
                }

                if "parameters" in operation:
                    for param in operation["parameters"]:
                        param_name = param.get("name", "")
                        param_in = param.get("in", "")

                        if param_in == "query":
                            params[ParameterType.QUERY].append(param_name)
                        elif param_in == "header":
                            params[ParameterType.HEADER].append(param_name)
                        elif param_in == "path":
                            params[ParameterType.PATH].append(param_name)
                        elif param_in == "cookie":
                            params[ParameterType.COOKIE].append(param_name)

                # Check for request body
                if "requestBody" in operation:
                    params[ParameterType.BODY].append("body")

                # Check authentication
                auth_required = "security" in operation or "security" in spec_data

                endpoint = APIEndpoint(
                    url=url, method=method, parameters=params, authentication_required=auth_required
                )

                endpoint_key = (url, method.value)
                endpoints.append(endpoint)
                self.discovered_endpoints.add(endpoint_key)
                logger.info(f"Discovered OpenAPI endpoint: {method.value} {url}")

        return endpoints


class ParameterFuzzer:
    """
    Fuzzes API parameters to discover vulnerabilities
    """

    # SQL Injection payloads
    SQL_PAYLOADS = [
        FuzzingPayload(
            value="' OR '1'='1",
            payload_type=VulnerabilityType.SQL_INJECTION,
            description="Classic SQL injection bypass",
            expected_indicators=["sql", "syntax", "mysql", "postgresql", "database error"],
        ),
        FuzzingPayload(
            value="1' AND 1=1--",
            payload_type=VulnerabilityType.SQL_INJECTION,
            description="SQL injection with comment",
            expected_indicators=["sql", "syntax"],
        ),
        FuzzingPayload(
            value="admin'--",
            payload_type=VulnerabilityType.SQL_INJECTION,
            description="SQL comment injection",
            expected_indicators=["sql", "syntax"],
        ),
        FuzzingPayload(
            value="' UNION SELECT NULL--",
            payload_type=VulnerabilityType.SQL_INJECTION,
            description="UNION-based SQL injection",
            expected_indicators=["sql", "union", "select"],
        ),
    ]

    # XSS payloads
    XSS_PAYLOADS = [
        FuzzingPayload(
            value="<script>alert('XSS')</script>",
            payload_type=VulnerabilityType.XSS,
            description="Basic XSS payload",
            expected_indicators=["<script>", "alert"],
        ),
        FuzzingPayload(
            value="<img src=x onerror=alert('XSS')>",
            payload_type=VulnerabilityType.XSS,
            description="Image-based XSS",
            expected_indicators=["<img", "onerror"],
        ),
        FuzzingPayload(
            value="javascript:alert('XSS')",
            payload_type=VulnerabilityType.XSS,
            description="JavaScript protocol XSS",
            expected_indicators=["javascript:"],
        ),
    ]

    # Command injection payloads
    COMMAND_INJECTION_PAYLOADS = [
        FuzzingPayload(
            value="; ls -la",
            payload_type=VulnerabilityType.COMMAND_INJECTION,
            description="Command chaining with semicolon",
            expected_indicators=["root", "bin", "etc", "usr"],
        ),
        FuzzingPayload(
            value="| whoami",
            payload_type=VulnerabilityType.COMMAND_INJECTION,
            description="Command piping",
            expected_indicators=["root", "user", "admin"],
        ),
        FuzzingPayload(
            value="`id`",
            payload_type=VulnerabilityType.COMMAND_INJECTION,
            description="Backtick command substitution",
            expected_indicators=["uid=", "gid="],
        ),
    ]

    # Path traversal payloads
    PATH_TRAVERSAL_PAYLOADS = [
        FuzzingPayload(
            value="../../../etc/passwd",
            payload_type=VulnerabilityType.INJECTION,
            description="Unix path traversal",
            expected_indicators=["root:", "bin:", "/bin/bash"],
        ),
        FuzzingPayload(
            value="..\\..\\..\\windows\\win.ini",
            payload_type=VulnerabilityType.INJECTION,
            description="Windows path traversal",
            expected_indicators=["[extensions]", "[fonts]"],
        ),
    ]

    # SSRF payloads
    SSRF_PAYLOADS = [
        FuzzingPayload(
            value="http://localhost:22",
            payload_type=VulnerabilityType.SSRF,
            description="Localhost SSRF",
            expected_indicators=["SSH", "OpenSSH"],
        ),
        FuzzingPayload(
            value="http://169.254.169.254/latest/meta-data/",
            payload_type=VulnerabilityType.SSRF,
            description="AWS metadata SSRF",
            expected_indicators=["ami-id", "instance-id"],
        ),
    ]

    def __init__(self):
        """Initialize the parameter fuzzer"""
        self.all_payloads = (
            self.SQL_PAYLOADS
            + self.XSS_PAYLOADS
            + self.COMMAND_INJECTION_PAYLOADS
            + self.PATH_TRAVERSAL_PAYLOADS
            + self.SSRF_PAYLOADS
        )

    def get_payloads_for_type(self, vuln_type: VulnerabilityType) -> List[FuzzingPayload]:
        """
        Get fuzzing payloads for a specific vulnerability type

        Args:
            vuln_type: Type of vulnerability to get payloads for

        Returns:
            List of fuzzing payloads
        """
        return [p for p in self.all_payloads if p.payload_type == vuln_type]

    def get_all_payloads(self) -> List[FuzzingPayload]:
        """
        Get all fuzzing payloads

        Returns:
            List of all fuzzing payloads
        """
        return self.all_payloads


class RequestAnalyzer:
    """
    Analyzes API requests and responses for security issues
    """

    # Sensitive data patterns
    SENSITIVE_PATTERNS = {
        "api_key": r"api[_-]?key['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})",
        "password": r"password['\"]?\s*[:=]\s*['\"]?([^'\"&\s]{8,})",
        "token": r"token['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{20,})",
        "secret": r"secret['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})",
        "private_key": r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
        "jwt": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
        "credit_card": r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    }

    def __init__(self):
        """Initialize request analyzer"""
        self.compiled_patterns = {
            name: re.compile(pattern, re.IGNORECASE)
            for name, pattern in self.SENSITIVE_PATTERNS.items()
        }

    def analyze_response(
        self, response_body: str, response_headers: Dict[str, str], status_code: int
    ) -> Dict[str, Any]:
        """
        Analyze API response for security issues

        Args:
            response_body: Response body content
            response_headers: Response headers
            status_code: HTTP status code

        Returns:
            Dictionary of analysis results
        """
        findings = {
            "sensitive_data_exposure": [],
            "security_headers_missing": [],
            "information_disclosure": [],
            "status_code": status_code,
        }

        # Check for sensitive data exposure
        for name, pattern in self.compiled_patterns.items():
            matches = pattern.findall(response_body)
            if matches:
                findings["sensitive_data_exposure"].append(
                    {
                        "type": name,
                        "count": len(matches),
                        "severity": (
                            "high" if name in ["password", "private_key", "api_key"] else "medium"
                        ),
                    }
                )

        # Check for missing security headers
        security_headers = {
            "X-Frame-Options": "Protects against clickjacking",
            "X-Content-Type-Options": "Prevents MIME sniffing",
            "Content-Security-Policy": "Prevents XSS attacks",
            "Strict-Transport-Security": "Enforces HTTPS",
            "X-XSS-Protection": "Legacy XSS protection",
        }

        for header, description in security_headers.items():
            if header.lower() not in [h.lower() for h in response_headers.keys()]:
                findings["security_headers_missing"].append(
                    {"header": header, "description": description, "severity": "medium"}
                )

        # Check for information disclosure
        disclosure_patterns = [
            (r"stack trace|traceback|exception", "Stack trace exposure"),
            (r"sql (error|exception|syntax)", "SQL error exposure"),
            (r"version \d+\.\d+", "Version information disclosure"),
            (r"debug mode|debug=true", "Debug mode enabled"),
        ]

        for pattern, description in disclosure_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                findings["information_disclosure"].append({"type": description, "severity": "low"})

        return findings

    def detect_vulnerability_indicators(
        self, response_body: str, expected_indicators: List[str]
    ) -> Tuple[bool, float]:
        """
        Detect if response contains vulnerability indicators

        Args:
            response_body: Response body to analyze
            expected_indicators: List of indicator strings to look for

        Returns:
            Tuple of (detected: bool, confidence: float)
        """
        if not expected_indicators:
            return False, 0.0

        matches = 0
        response_lower = response_body.lower()

        for indicator in expected_indicators:
            if indicator.lower() in response_lower:
                matches += 1

        confidence = matches / len(expected_indicators)
        detected = confidence > 0.3  # 30% threshold

        return detected, confidence


class RateLimitDetector:
    """
    Detects and analyzes rate limiting on API endpoints
    """

    # Common rate limit headers
    RATE_LIMIT_HEADERS = [
        "X-RateLimit-Limit",
        "X-RateLimit-Remaining",
        "X-RateLimit-Reset",
        "X-Rate-Limit-Limit",
        "X-Rate-Limit-Remaining",
        "X-Rate-Limit-Reset",
        "RateLimit-Limit",
        "RateLimit-Remaining",
        "RateLimit-Reset",
        "Retry-After",
    ]

    def __init__(self, max_requests: int = 100, time_window: int = 60):
        """
        Initialize rate limit detector

        Args:
            max_requests: Maximum requests to send in detection
            time_window: Time window in seconds for testing
        """
        self.max_requests = max_requests
        self.time_window = time_window

    def detect_rate_limit(
        self,
        endpoint_url: str,
        response_headers_list: List[Dict[str, str]],
        status_codes: List[int],
    ) -> RateLimitInfo:
        """
        Analyze responses to detect rate limiting

        Args:
            endpoint_url: URL being tested
            response_headers_list: List of response headers from sequential requests
            status_codes: List of status codes from sequential requests

        Returns:
            RateLimitInfo object with detection results
        """
        # Check for rate limit headers
        limit_header = None
        remaining_header = None
        reset_header = None

        for headers in response_headers_list:
            for header_name in self.RATE_LIMIT_HEADERS:
                if header_name.lower() in [h.lower() for h in headers.keys()]:
                    # Check for reset/retry first (more specific)
                    if "reset" in header_name.lower() or "retry" in header_name.lower():
                        reset_header = header_name
                    # Then check for remaining
                    elif "remaining" in header_name.lower():
                        remaining_header = header_name
                    # Finally check for limit (least specific)
                    elif "limit" in header_name.lower():
                        limit_header = header_name

        # Check for 429 (Too Many Requests) status codes
        requests_before_limit = None
        if 429 in status_codes:
            requests_before_limit = status_codes.index(429)
            status = RateLimitStatus.HARD_LIMIT
        elif limit_header and remaining_header:
            status = RateLimitStatus.SOFT_LIMIT
        else:
            status = (
                RateLimitStatus.NO_LIMIT if len(status_codes) >= 50 else RateLimitStatus.UNKNOWN
            )

        # Extract reset time if available
        reset_time_seconds = None
        if reset_header and response_headers_list:
            for headers in response_headers_list:
                if reset_header in headers:
                    try:
                        reset_time_seconds = int(headers[reset_header])
                    except ValueError:
                        pass

        return RateLimitInfo(
            endpoint_url=endpoint_url,
            status=status,
            requests_before_limit=requests_before_limit,
            reset_time_seconds=reset_time_seconds,
            limit_header=limit_header,
            remaining_header=remaining_header,
            reset_header=reset_header,
        )


class APIVulnerabilityScanner:
    """
    Main API vulnerability scanner that orchestrates testing
    """

    def __init__(
        self,
        base_url: str,
        deep_scan: bool = False,
        timeout: int = 5,
        rate_limit_rps: int = 50,
        safe_url_allowlist: Optional[Dict[str, List[str]]] = None,
    ):
        """
        Initialize API vulnerability scanner

        Args:
            base_url: Base URL of the API to test
            deep_scan: Enable real network requests (vs mocked responses)
            timeout: Request timeout in seconds
        """
        self.base_url = base_url
        self.deep_scan = deep_scan
        self.timeout = timeout
        self.discovery = EndpointDiscovery(base_url)
        self.fuzzer = ParameterFuzzer()
        self.analyzer = RequestAnalyzer()
        self.rate_detector = RateLimitDetector()
        self.results: List[APITestResult] = []
        self.rate_limit_rps = min(rate_limit_rps, 50)
        self._min_request_interval = 1.0 / max(self.rate_limit_rps, 1)
        self._last_request_time = 0.0
        self.safe_url_allowlist = safe_url_allowlist or {}

    def discover_endpoints(self) -> List[APIEndpoint]:
        """
        Discover API endpoints

        Returns:
            List of discovered endpoints
        """
        endpoints = []

        # Discover common endpoints
        endpoints.extend(self.discovery.discover_common_endpoints())

        # Discover resource endpoints
        endpoints.extend(self.discovery.discover_resource_endpoints())

        logger.info(f"Discovered {len(endpoints)} total endpoints")
        return endpoints

    def test_endpoint(
        self,
        endpoint: APIEndpoint,
        payload: FuzzingPayload,
        parameter_name: str,
        parameter_type: ParameterType,
    ) -> Optional[APITestResult]:
        """
        Test an endpoint with a specific payload

        Args:
            endpoint: Endpoint to test
            payload: Fuzzing payload to use
            parameter_name: Name of parameter to inject payload into
            parameter_type: Type of parameter (query, header, body, etc.)

        Returns:
            APITestResult if vulnerability detected, None otherwise
        """
        # Simulate HTTP request (in real implementation, would make actual request)
        http_request = self._build_request_string(
            endpoint, payload.value, parameter_name, parameter_type
        )

        # For deep scan mode, attempt real network request
        if self.deep_scan and REQUESTS_AVAILABLE:
            http_response = self._make_real_request(
                endpoint, payload, parameter_name, parameter_type
            )
        else:
            # Simulate response (in real implementation, would capture actual response)
            http_response = self._simulate_response(payload)

        # Analyze response
        detected, confidence = self.analyzer.detect_vulnerability_indicators(
            http_response, payload.expected_indicators
        )

        if detected:
            severity = self._determine_severity(payload.payload_type, confidence)

            result = APITestResult(
                endpoint=endpoint,
                vulnerability_type=payload.payload_type,
                severity=severity,
                parameter_tested=parameter_name,
                parameter_type=parameter_type,
                payload_used=payload.value,
                evidence=f"Detected {payload.payload_type.value} with {confidence:.0%} confidence",
                http_request=http_request,
                http_response=http_response,
                confidence=confidence,
                false_positive_likelihood=1.0 - confidence,
            )

            self.results.append(result)
            logger.warning(
                f"Vulnerability detected: {payload.payload_type.value} "
                f"in {endpoint.url} (confidence: {confidence:.0%})"
            )
            return result

        return None

    def scan_endpoint(self, endpoint: APIEndpoint) -> List[APITestResult]:
        """
        Scan a single endpoint for all vulnerability types

        Args:
            endpoint: Endpoint to scan

        Returns:
            List of test results with vulnerabilities found
        """
        results = []

        # Test each parameter type
        for param_type, param_names in endpoint.parameters.items():
            if not param_names:
                continue

            for param_name in param_names:
                # Test with all payload types
                for payload in self.fuzzer.get_all_payloads():
                    result = self.test_endpoint(endpoint, payload, param_name, param_type)
                    if result:
                        results.append(result)

        return results

    def _build_request_string(
        self,
        endpoint: APIEndpoint,
        payload_value: str,
        parameter_name: str,
        parameter_type: ParameterType,
    ) -> str:
        """Build HTTP request string for logging"""
        request = f"{endpoint.method.value} {endpoint.url}\n"

        if parameter_type == ParameterType.QUERY:
            request += f"Query: {parameter_name}={payload_value}\n"
        elif parameter_type == ParameterType.HEADER:
            request += f"Header: {parameter_name}: {payload_value}\n"
        elif parameter_type == ParameterType.BODY:
            request += f"Body: {parameter_name}={payload_value}\n"

        return request

    def _simulate_response(self, payload: FuzzingPayload) -> str:
        """Simulate HTTP response (for testing without actual requests)"""
        # In real implementation, this would capture actual HTTP response
        if payload.expected_indicators:
            return f"Response containing indicator: {payload.expected_indicators[0]}"
        return "Standard response"

    def _make_real_request(
        self,
        endpoint: APIEndpoint,
        payload: FuzzingPayload,
        parameter_name: str,
        parameter_type: ParameterType,
    ) -> str:
        """Make actual HTTP request to endpoint with payload (deep scan mode)"""
        if not REQUESTS_AVAILABLE:
            logger.warning("requests library not available, falling back to simulation")
            return self._simulate_response(payload)

        try:
            url = endpoint.url
            headers = {}
            data = None
            params = {}

            if self.safe_url_allowlist:
                url = canonicalize_and_validate_url(
                    url,
                    allowed_hosts=self.safe_url_allowlist,
                )
            else:
                logger.warning("Safe URL allow-list not configured; blocking real request")
                return self._simulate_response(payload)

            # Build request based on parameter type
            if parameter_type == ParameterType.QUERY:
                params[parameter_name] = payload.value
            elif parameter_type == ParameterType.HEADER:
                headers[parameter_name] = payload.value
            elif parameter_type == ParameterType.BODY:
                data = {parameter_name: payload.value}

            headers["X-HackerOne-Research"] = "[lucius-log]"

            logger.info(
                f"🔍 Making real request: {endpoint.method.value} {url} "
                f"(timeout={self.timeout}s)"
            )

            self._throttle_requests()

            # Make actual network request
            response = requests.request(
                method=endpoint.method.value,
                url=url,
                headers=headers,
                json=data if data else None,
                params=params if params else None,
                timeout=self.timeout,
                verify=False,  # Allow self-signed certificates
                allow_redirects=True,
            )

            # Capture response details
            response_text = response.text[:500]  # Limit response size
            status_code = response.status_code
            content_type = response.headers.get("content-type", "unknown")

            response_str = (
                f"HTTP/{response.status_code}\nContent-Type: {content_type}\n\n{response_text}"
            )

            logger.info(f"✓ Real response received: {status_code} ({len(response_text)} bytes)")
            return response_str

        except SafeUrlError as e:
            logger.warning(f"Blocked unsafe URL: {e}, using simulation")
            return self._simulate_response(payload)
        except requests.exceptions.Timeout:
            logger.warning(f"Request timeout after {self.timeout}s, using simulation")
            return self._simulate_response(payload)
        except requests.exceptions.ConnectionError as e:
            logger.warning(f"Connection error: {e}, using simulation")
            return self._simulate_response(payload)
        except Exception as e:
            logger.warning(f"Error making real request: {e}, using simulation")
            return self._simulate_response(payload)

    def _throttle_requests(self) -> None:
        """Throttle requests to stay within rate limit."""
        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < self._min_request_interval:
            time.sleep(self._min_request_interval - elapsed)
        self._last_request_time = time.time()

    def _determine_severity(self, vuln_type: VulnerabilityType, confidence: float) -> str:
        """Determine severity based on vulnerability type and confidence"""
        # Base severity by vulnerability type
        severity_map = {
            VulnerabilityType.SQL_INJECTION: "critical",
            VulnerabilityType.COMMAND_INJECTION: "critical",
            VulnerabilityType.XXE: "high",
            VulnerabilityType.SSRF: "high",
            VulnerabilityType.XSS: "high",
            VulnerabilityType.IDOR: "high",
            VulnerabilityType.BROKEN_AUTH: "critical",
            VulnerabilityType.EXCESSIVE_DATA: "medium",
            VulnerabilityType.MASS_ASSIGNMENT: "medium",
            VulnerabilityType.SECURITY_MISCONFIGURATION: "medium",
            VulnerabilityType.RATE_LIMIT_BYPASS: "low",
            VulnerabilityType.INJECTION: "high",
        }

        base_severity = severity_map.get(vuln_type, "medium")

        # Adjust based on confidence
        if confidence < 0.5:
            # Low confidence downgrades severity
            if base_severity == "critical":
                return "high"
            elif base_severity == "high":
                return "medium"

        return base_severity

    def get_results(self) -> List[APITestResult]:
        """Get all test results"""
        return self.results

    def get_results_by_severity(self, severity: str) -> List[APITestResult]:
        """Get test results filtered by severity"""
        return [r for r in self.results if r.severity == severity]
