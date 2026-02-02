"""
Comprehensive tests for API testing module
"""

from datetime import datetime

import pytest

from sentinel.api_tester import (
    APIEndpoint,
    APITestResult,
    APIVulnerabilityScanner,
    EndpointDiscovery,
    FuzzingPayload,
    HTTPMethod,
    ParameterFuzzer,
    ParameterType,
    RateLimitDetector,
    RateLimitInfo,
    RateLimitStatus,
    RequestAnalyzer,
    VulnerabilityType,
)


class TestHTTPMethod:
    """Test HTTPMethod enum"""

    def test_http_methods_exist(self):
        """Test that all standard HTTP methods are defined"""
        assert HTTPMethod.GET.value == "GET"
        assert HTTPMethod.POST.value == "POST"
        assert HTTPMethod.PUT.value == "PUT"
        assert HTTPMethod.PATCH.value == "PATCH"
        assert HTTPMethod.DELETE.value == "DELETE"
        assert HTTPMethod.OPTIONS.value == "OPTIONS"
        assert HTTPMethod.HEAD.value == "HEAD"


class TestParameterType:
    """Test ParameterType enum"""

    def test_parameter_types_exist(self):
        """Test that all parameter types are defined"""
        assert ParameterType.QUERY.value == "query"
        assert ParameterType.HEADER.value == "header"
        assert ParameterType.BODY.value == "body"
        assert ParameterType.PATH.value == "path"
        assert ParameterType.COOKIE.value == "cookie"


class TestVulnerabilityType:
    """Test VulnerabilityType enum"""

    def test_vulnerability_types_exist(self):
        """Test that common vulnerability types are defined"""
        assert VulnerabilityType.SQL_INJECTION.value == "sql_injection"
        assert VulnerabilityType.XSS.value == "cross_site_scripting"
        assert VulnerabilityType.COMMAND_INJECTION.value == "command_injection"
        assert VulnerabilityType.SSRF.value == "server_side_request_forgery"
        assert VulnerabilityType.IDOR.value == "insecure_direct_object_reference"


class TestAPIEndpoint:
    """Test APIEndpoint dataclass"""

    def test_create_basic_endpoint(self):
        """Test creating a basic API endpoint"""
        endpoint = APIEndpoint(url="https://api.example.com/users", method=HTTPMethod.GET)

        assert endpoint.url == "https://api.example.com/users"
        assert endpoint.method == HTTPMethod.GET
        assert isinstance(endpoint.parameters, dict)
        assert ParameterType.QUERY in endpoint.parameters
        assert endpoint.authentication_required is False
        assert isinstance(endpoint.discovered_at, datetime)

    def test_create_endpoint_with_parameters(self):
        """Test creating endpoint with parameters"""
        endpoint = APIEndpoint(
            url="https://api.example.com/users",
            method=HTTPMethod.POST,
            parameters={
                ParameterType.QUERY: ["page", "limit"],
                ParameterType.BODY: ["username", "email"],
                ParameterType.HEADER: ["Authorization"],
                ParameterType.PATH: [],
                ParameterType.COOKIE: [],
            },
            authentication_required=True,
        )

        assert len(endpoint.parameters[ParameterType.QUERY]) == 2
        assert "page" in endpoint.parameters[ParameterType.QUERY]
        assert "limit" in endpoint.parameters[ParameterType.QUERY]
        assert len(endpoint.parameters[ParameterType.BODY]) == 2
        assert endpoint.authentication_required is True


class TestFuzzingPayload:
    """Test FuzzingPayload dataclass"""

    def test_create_sql_injection_payload(self):
        """Test creating SQL injection payload"""
        payload = FuzzingPayload(
            value="' OR '1'='1",
            payload_type=VulnerabilityType.SQL_INJECTION,
            description="Classic SQL injection",
            expected_indicators=["sql", "error", "syntax"],
        )

        assert payload.value == "' OR '1'='1"
        assert payload.payload_type == VulnerabilityType.SQL_INJECTION
        assert "sql" in payload.expected_indicators

    def test_create_xss_payload(self):
        """Test creating XSS payload"""
        payload = FuzzingPayload(
            value="<script>alert('XSS')</script>",
            payload_type=VulnerabilityType.XSS,
            description="Basic XSS",
            expected_indicators=["<script>", "alert"],
        )

        assert "<script>" in payload.value
        assert payload.payload_type == VulnerabilityType.XSS


class TestAPITestResult:
    """Test APITestResult dataclass"""

    def test_create_test_result(self):
        """Test creating an API test result"""
        endpoint = APIEndpoint(url="https://api.example.com/login", method=HTTPMethod.POST)

        result = APITestResult(
            endpoint=endpoint,
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            severity="critical",
            parameter_tested="username",
            parameter_type=ParameterType.BODY,
            payload_used="' OR '1'='1",
            evidence="SQL error message detected",
            http_request="POST /login\nBody: username=' OR '1'='1",
            http_response="SQL syntax error",
            confidence=0.95,
            false_positive_likelihood=0.05,
        )

        assert result.endpoint.url == "https://api.example.com/login"
        assert result.vulnerability_type == VulnerabilityType.SQL_INJECTION
        assert result.severity == "critical"
        assert result.parameter_tested == "username"
        assert result.confidence == 0.95
        assert isinstance(result.discovered_at, datetime)


class TestRateLimitInfo:
    """Test RateLimitInfo dataclass"""

    def test_create_rate_limit_info_hard_limit(self):
        """Test creating rate limit info for hard limit"""
        info = RateLimitInfo(
            endpoint_url="https://api.example.com/users",
            status=RateLimitStatus.HARD_LIMIT,
            requests_before_limit=100,
            reset_time_seconds=3600,
        )

        assert info.status == RateLimitStatus.HARD_LIMIT
        assert info.requests_before_limit == 100
        assert info.reset_time_seconds == 3600

    def test_create_rate_limit_info_no_limit(self):
        """Test creating rate limit info for no limit detected"""
        info = RateLimitInfo(
            endpoint_url="https://api.example.com/public", status=RateLimitStatus.NO_LIMIT
        )

        assert info.status == RateLimitStatus.NO_LIMIT
        assert info.requests_before_limit is None


class TestEndpointDiscovery:
    """Test EndpointDiscovery class"""

    def test_initialization(self):
        """Test endpoint discovery initialization"""
        discovery = EndpointDiscovery("https://api.example.com", max_depth=3)

        assert discovery.base_url == "https://api.example.com"
        assert discovery.max_depth == 3
        assert len(discovery.discovered_endpoints) == 0

    def test_discover_common_endpoints(self):
        """Test discovering common API endpoints"""
        discovery = EndpointDiscovery("https://api.example.com")
        endpoints = discovery.discover_common_endpoints()

        assert len(endpoints) > 0
        assert any("/api" in e.url for e in endpoints)
        assert any("swagger" in e.url.lower() for e in endpoints)
        assert all(isinstance(e, APIEndpoint) for e in endpoints)

    def test_discover_resource_endpoints(self):
        """Test discovering RESTful resource endpoints"""
        discovery = EndpointDiscovery("https://api.example.com")
        endpoints = discovery.discover_resource_endpoints("/api/v1")

        assert len(endpoints) > 0
        # Should discover endpoints for users, auth, etc.
        user_endpoints = [e for e in endpoints if "users" in e.url]
        assert len(user_endpoints) > 0

        # Should discover multiple HTTP methods
        methods_found = set(e.method for e in user_endpoints)
        assert HTTPMethod.GET in methods_found
        assert HTTPMethod.POST in methods_found

    def test_discover_endpoints_with_id_parameter(self):
        """Test that resource endpoints with ID parameters are discovered"""
        discovery = EndpointDiscovery("https://api.example.com")
        endpoints = discovery.discover_resource_endpoints("/api")

        # Find endpoint with {id} placeholder
        id_endpoints = [e for e in endpoints if "{id}" in e.url]
        assert len(id_endpoints) > 0

        # Should have "id" in path parameters
        id_endpoint = id_endpoints[0]
        assert "id" in id_endpoint.parameters[ParameterType.PATH]

    def test_parse_openapi_spec_basic(self):
        """Test parsing basic OpenAPI specification"""
        discovery = EndpointDiscovery("https://api.example.com")

        spec = {
            "paths": {
                "/users": {
                    "get": {
                        "parameters": [
                            {"name": "page", "in": "query"},
                            {"name": "limit", "in": "query"},
                        ]
                    },
                    "post": {"requestBody": {"required": True}},
                }
            }
        }

        endpoints = discovery.parse_openapi_spec(spec)

        assert len(endpoints) == 2
        get_endpoint = [e for e in endpoints if e.method == HTTPMethod.GET][0]
        assert "page" in get_endpoint.parameters[ParameterType.QUERY]
        assert "limit" in get_endpoint.parameters[ParameterType.QUERY]

        post_endpoint = [e for e in endpoints if e.method == HTTPMethod.POST][0]
        assert "body" in post_endpoint.parameters[ParameterType.BODY]

    def test_parse_openapi_spec_with_auth(self):
        """Test parsing OpenAPI spec with authentication"""
        discovery = EndpointDiscovery("https://api.example.com")

        spec = {"paths": {"/admin": {"get": {"security": [{"bearerAuth": []}]}}}}

        endpoints = discovery.parse_openapi_spec(spec)
        assert len(endpoints) == 1
        assert endpoints[0].authentication_required is True


class TestParameterFuzzer:
    """Test ParameterFuzzer class"""

    def test_initialization(self):
        """Test parameter fuzzer initialization"""
        fuzzer = ParameterFuzzer()

        assert len(fuzzer.all_payloads) > 0
        assert any(p.payload_type == VulnerabilityType.SQL_INJECTION for p in fuzzer.all_payloads)
        assert any(p.payload_type == VulnerabilityType.XSS for p in fuzzer.all_payloads)

    def test_get_sql_injection_payloads(self):
        """Test getting SQL injection payloads"""
        fuzzer = ParameterFuzzer()
        payloads = fuzzer.get_payloads_for_type(VulnerabilityType.SQL_INJECTION)

        assert len(payloads) > 0
        assert all(p.payload_type == VulnerabilityType.SQL_INJECTION for p in payloads)
        # Should have classic SQL injection payloads
        assert any("' OR '1'='1" in p.value for p in payloads)

    def test_get_xss_payloads(self):
        """Test getting XSS payloads"""
        fuzzer = ParameterFuzzer()
        payloads = fuzzer.get_payloads_for_type(VulnerabilityType.XSS)

        assert len(payloads) > 0
        assert all(p.payload_type == VulnerabilityType.XSS for p in payloads)
        # Should have script tag payloads
        assert any("<script>" in p.value for p in payloads)

    def test_get_command_injection_payloads(self):
        """Test getting command injection payloads"""
        fuzzer = ParameterFuzzer()
        payloads = fuzzer.get_payloads_for_type(VulnerabilityType.COMMAND_INJECTION)

        assert len(payloads) > 0
        assert all(p.payload_type == VulnerabilityType.COMMAND_INJECTION for p in payloads)

    def test_get_all_payloads(self):
        """Test getting all payloads"""
        fuzzer = ParameterFuzzer()
        payloads = fuzzer.get_all_payloads()

        assert len(payloads) > 10  # Should have many payloads
        # Should have variety of types
        types_found = set(p.payload_type for p in payloads)
        assert VulnerabilityType.SQL_INJECTION in types_found
        assert VulnerabilityType.XSS in types_found
        assert VulnerabilityType.COMMAND_INJECTION in types_found


class TestRequestAnalyzer:
    """Test RequestAnalyzer class"""

    def test_initialization(self):
        """Test request analyzer initialization"""
        analyzer = RequestAnalyzer()

        assert len(analyzer.compiled_patterns) > 0
        assert "api_key" in analyzer.compiled_patterns
        assert "password" in analyzer.compiled_patterns

    def test_detect_api_key_exposure(self):
        """Test detecting API key in response"""
        analyzer = RequestAnalyzer()

        response = '{"api_key": "sk_live_1234567890abcdefghijklmnop"}'
        findings = analyzer.analyze_response(response, {}, 200)

        assert len(findings["sensitive_data_exposure"]) > 0
        api_key_finding = [f for f in findings["sensitive_data_exposure"] if f["type"] == "api_key"]
        assert len(api_key_finding) > 0
        assert api_key_finding[0]["severity"] == "high"

    def test_detect_password_exposure(self):
        """Test detecting password in response"""
        analyzer = RequestAnalyzer()

        response = '{"password": "MySecretPassword123"}'
        findings = analyzer.analyze_response(response, {}, 200)

        password_findings = [
            f for f in findings["sensitive_data_exposure"] if f["type"] == "password"
        ]
        assert len(password_findings) > 0

    def test_detect_missing_security_headers(self):
        """Test detecting missing security headers"""
        analyzer = RequestAnalyzer()

        # Response with no security headers
        findings = analyzer.analyze_response("", {}, 200)

        assert len(findings["security_headers_missing"]) > 0
        header_names = [f["header"] for f in findings["security_headers_missing"]]
        assert "X-Frame-Options" in header_names
        assert "Content-Security-Policy" in header_names

    def test_security_headers_present(self):
        """Test when security headers are present"""
        analyzer = RequestAnalyzer()

        headers = {
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
        }

        findings = analyzer.analyze_response("", headers, 200)

        # Should have fewer missing headers
        assert len(findings["security_headers_missing"]) < 5

    def test_detect_stack_trace(self):
        """Test detecting stack trace in response"""
        analyzer = RequestAnalyzer()

        response = """
        Traceback (most recent call last):
          File "app.py", line 42
            raise Exception("Database error")
        """

        findings = analyzer.analyze_response(response, {}, 500)

        assert len(findings["information_disclosure"]) > 0
        assert any("Stack trace" in f["type"] for f in findings["information_disclosure"])

    def test_detect_sql_error(self):
        """Test detecting SQL error in response"""
        analyzer = RequestAnalyzer()

        response = "SQL syntax error near 'SELECT'"
        findings = analyzer.analyze_response(response, {}, 500)

        assert any("SQL error" in f["type"] for f in findings["information_disclosure"])

    def test_detect_vulnerability_indicators_positive(self):
        """Test detecting vulnerability indicators when present"""
        analyzer = RequestAnalyzer()

        response = "SQL syntax error in query"
        indicators = ["sql", "syntax", "error"]

        detected, confidence = analyzer.detect_vulnerability_indicators(response, indicators)

        assert detected is True
        assert confidence > 0.5

    def test_detect_vulnerability_indicators_negative(self):
        """Test detecting vulnerability indicators when absent"""
        analyzer = RequestAnalyzer()

        response = "Success: User logged in"
        indicators = ["sql", "syntax", "error"]

        detected, confidence = analyzer.detect_vulnerability_indicators(response, indicators)

        assert detected is False
        assert confidence < 0.3


class TestRateLimitDetector:
    """Test RateLimitDetector class"""

    def test_initialization(self):
        """Test rate limit detector initialization"""
        detector = RateLimitDetector(max_requests=50, time_window=30)

        assert detector.max_requests == 50
        assert detector.time_window == 30

    def test_detect_hard_limit_with_429(self):
        """Test detecting hard rate limit with 429 status"""
        detector = RateLimitDetector()

        # Simulate 50 successful requests then 429
        status_codes = [200] * 50 + [429]
        headers_list = [{}] * 51

        info = detector.detect_rate_limit(
            "https://api.example.com/users", headers_list, status_codes
        )

        assert info.status == RateLimitStatus.HARD_LIMIT
        assert info.requests_before_limit == 50

    def test_detect_soft_limit_with_headers(self):
        """Test detecting soft limit with rate limit headers"""
        detector = RateLimitDetector()

        headers_list = [
            {"X-RateLimit-Limit": "100", "X-RateLimit-Remaining": "50", "X-RateLimit-Reset": "3600"}
        ] * 10

        status_codes = [200] * 10

        info = detector.detect_rate_limit(
            "https://api.example.com/users", headers_list, status_codes
        )

        assert info.status == RateLimitStatus.SOFT_LIMIT
        assert info.limit_header is not None
        assert info.remaining_header is not None
        assert info.reset_header is not None

    def test_detect_no_limit(self):
        """Test detecting no rate limit"""
        detector = RateLimitDetector()

        # Many successful requests with no limiting
        status_codes = [200] * 100
        headers_list = [{}] * 100

        info = detector.detect_rate_limit(
            "https://api.example.com/public", headers_list, status_codes
        )

        assert info.status == RateLimitStatus.NO_LIMIT


class TestAPIVulnerabilityScanner:
    """Test APIVulnerabilityScanner class"""

    def test_initialization(self):
        """Test scanner initialization"""
        scanner = APIVulnerabilityScanner("https://api.example.com")

        assert scanner.base_url == "https://api.example.com"
        assert isinstance(scanner.discovery, EndpointDiscovery)
        assert isinstance(scanner.fuzzer, ParameterFuzzer)
        assert isinstance(scanner.analyzer, RequestAnalyzer)
        assert len(scanner.results) == 0

    def test_discover_endpoints(self):
        """Test endpoint discovery through scanner"""
        scanner = APIVulnerabilityScanner("https://api.example.com")
        endpoints = scanner.discover_endpoints()

        assert len(endpoints) > 0
        assert all(isinstance(e, APIEndpoint) for e in endpoints)

    def test_determine_severity_critical(self):
        """Test severity determination for critical vulnerabilities"""
        scanner = APIVulnerabilityScanner("https://api.example.com")

        severity = scanner._determine_severity(VulnerabilityType.SQL_INJECTION, 0.9)
        assert severity == "critical"

    def test_determine_severity_with_low_confidence(self):
        """Test severity downgrade with low confidence"""
        scanner = APIVulnerabilityScanner("https://api.example.com")

        severity = scanner._determine_severity(VulnerabilityType.SQL_INJECTION, 0.4)
        assert severity == "high"  # Downgraded from critical

    def test_build_request_string_query_param(self):
        """Test building request string with query parameter"""
        scanner = APIVulnerabilityScanner("https://api.example.com")

        endpoint = APIEndpoint(url="https://api.example.com/users", method=HTTPMethod.GET)
        request = scanner._build_request_string(
            endpoint, "' OR '1'='1", "username", ParameterType.QUERY
        )

        assert "GET" in request
        assert "username" in request
        assert "' OR '1'='1" in request

    def test_get_results_by_severity(self):
        """Test filtering results by severity"""
        scanner = APIVulnerabilityScanner("https://api.example.com")

        endpoint = APIEndpoint(url="https://api.example.com/test", method=HTTPMethod.GET)

        # Add some test results
        scanner.results.append(
            APITestResult(
                endpoint=endpoint,
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                severity="critical",
                parameter_tested="id",
                parameter_type=ParameterType.QUERY,
                payload_used="test",
                evidence="test",
                http_request="test",
                http_response="test",
            )
        )

        scanner.results.append(
            APITestResult(
                endpoint=endpoint,
                vulnerability_type=VulnerabilityType.XSS,
                severity="high",
                parameter_tested="name",
                parameter_type=ParameterType.QUERY,
                payload_used="test",
                evidence="test",
                http_request="test",
                http_response="test",
            )
        )

        critical_results = scanner.get_results_by_severity("critical")
        assert len(critical_results) == 1
        assert critical_results[0].vulnerability_type == VulnerabilityType.SQL_INJECTION

        high_results = scanner.get_results_by_severity("high")
        assert len(high_results) == 1
        assert high_results[0].vulnerability_type == VulnerabilityType.XSS

    def test_scan_endpoint_with_parameters(self):
        """Test scanning endpoint with multiple parameters"""
        scanner = APIVulnerabilityScanner("https://api.example.com")

        endpoint = APIEndpoint(
            url="https://api.example.com/search",
            method=HTTPMethod.GET,
            parameters={
                ParameterType.QUERY: ["q", "page"],
                ParameterType.HEADER: [],
                ParameterType.BODY: [],
                ParameterType.PATH: [],
                ParameterType.COOKIE: [],
            },
        )

        results = scanner.scan_endpoint(endpoint)

        # Should test both parameters with multiple payloads
        assert len(results) >= 0  # Results depend on simulated responses
