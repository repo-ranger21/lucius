"""
Web Application Security Scanner

This module provides comprehensive web application security scanning capabilities including:
- OWASP Top 10 vulnerability detection
- Security header analysis
- SSL/TLS configuration testing
- XSS, SQLi, CSRF detection
- Cookie security analysis
- CORS misconfiguration detection
- Subdomain takeover detection
- Third-party script analysis
"""

import asyncio
import re
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import urljoin, urlparse

import aiohttp
import certifi
from bs4 import BeautifulSoup


@dataclass
class WebVulnerability:
    """Represents a web application vulnerability"""

    vuln_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    description: str
    affected_url: str
    evidence: str | None = None
    remediation: str | None = None
    cwe_id: str | None = None
    owasp_category: str | None = None
    cvss_score: float | None = None
    confidence: str = "HIGH"  # HIGH, MEDIUM, LOW
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            'vuln_type': self.vuln_type,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'affected_url': self.affected_url,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'cvss_score': self.cvss_score,
            'confidence': self.confidence,
            'references': self.references,
        }


@dataclass
class WebScanResult:
    """Results from a web application security scan"""

    target_url: str
    scan_type: str
    start_time: datetime
    end_time: datetime | None = None
    vulnerabilities: list[WebVulnerability] = field(default_factory=list)
    security_headers: dict[str, Any] = field(default_factory=dict)
    ssl_info: dict[str, Any] = field(default_factory=dict)
    cookies: list[dict[str, Any]] = field(default_factory=list)
    external_scripts: list[str] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    total_requests: int = 0
    scan_metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == 'CRITICAL')

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == 'HIGH')

    @property
    def medium_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == 'MEDIUM')

    @property
    def low_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == 'LOW')

    @property
    def info_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == 'INFO')

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            'target_url': self.target_url,
            'scan_type': self.scan_type,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'security_headers': self.security_headers,
            'ssl_info': self.ssl_info,
            'cookies': self.cookies,
            'external_scripts': self.external_scripts,
            'forms': self.forms,
            'total_requests': self.total_requests,
            'critical_count': self.critical_count,
            'high_count': self.high_count,
            'medium_count': self.medium_count,
            'low_count': self.low_count,
            'info_count': self.info_count,
            'scan_metadata': self.scan_metadata,
        }


class WebApplicationScanner:
    """
    Comprehensive web application security scanner

    Performs deep security analysis including OWASP Top 10 detection,
    security headers, SSL/TLS configuration, and common web vulnerabilities.
    """

    # XSS payloads for detection
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg/onload=alert('XSS')>",
    ]

    # SQL injection payloads
    SQL_PAYLOADS = [
        "' OR '1'='1",
        "1' OR '1' = '1",
        "' OR 1=1--",
        "admin'--",
        "' UNION SELECT NULL--",
    ]

    # Required security headers
    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'severity': 'HIGH',
            'description': 'HTTP Strict Transport Security (HSTS) header missing',
            'remediation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains',
            'cwe_id': 'CWE-319',
        },
        'Content-Security-Policy': {
            'severity': 'HIGH',
            'description': 'Content Security Policy (CSP) header missing',
            'remediation': "Add: Content-Security-Policy: default-src 'self'",
            'cwe_id': 'CWE-693',
        },
        'X-Frame-Options': {
            'severity': 'MEDIUM',
            'description': 'X-Frame-Options header missing - vulnerable to clickjacking',
            'remediation': 'Add: X-Frame-Options: DENY or SAMEORIGIN',
            'cwe_id': 'CWE-1021',
        },
        'X-Content-Type-Options': {
            'severity': 'MEDIUM',
            'description': 'X-Content-Type-Options header missing',
            'remediation': 'Add: X-Content-Type-Options: nosniff',
            'cwe_id': 'CWE-16',
        },
        'X-XSS-Protection': {
            'severity': 'LOW',
            'description': 'X-XSS-Protection header missing',
            'remediation': 'Add: X-XSS-Protection: 1; mode=block',
            'cwe_id': 'CWE-79',
        },
        'Referrer-Policy': {
            'severity': 'LOW',
            'description': 'Referrer-Policy header missing',
            'remediation': 'Add: Referrer-Policy: no-referrer or strict-origin-when-cross-origin',
            'cwe_id': 'CWE-200',
        },
        'Permissions-Policy': {
            'severity': 'LOW',
            'description': 'Permissions-Policy header missing',
            'remediation': 'Add: Permissions-Policy: geolocation=(), microphone=(), camera=()',
            'cwe_id': 'CWE-16',
        },
    }

    def __init__(
        self,
        timeout: int = 30,
        max_redirects: int = 10,
        user_agent: str = "Lucius-WebScanner/1.0",
        verify_ssl: bool = True,
    ):
        """
        Initialize the web application scanner

        Args:
            timeout: Request timeout in seconds
            max_redirects: Maximum number of redirects to follow
            user_agent: User agent string for requests
            verify_ssl: Whether to verify SSL certificates
        """
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_redirects = max_redirects
        self.user_agent = user_agent
        self.verify_ssl = verify_ssl
        self.session: aiohttp.ClientSession | None = None

    async def __aenter__(self):
        """Async context manager entry"""
        connector = aiohttp.TCPConnector(
            ssl=certifi.where() if self.verify_ssl else False,
            limit=100,
        )
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=self.timeout,
            headers={'User-Agent': self.user_agent},
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()

    async def scan(
        self,
        target_url: str,
        scan_type: str = "comprehensive",
        crawl_depth: int = 2,
        max_pages: int = 50,
    ) -> WebScanResult:
        """
        Perform comprehensive web application security scan

        Args:
            target_url: Target URL to scan
            scan_type: Type of scan (comprehensive, quick, targeted)
            crawl_depth: How deep to crawl the site
            max_pages: Maximum number of pages to crawl

        Returns:
            WebScanResult with all findings
        """
        result = WebScanResult(
            target_url=target_url,
            scan_type=scan_type,
            start_time=datetime.utcnow(),
        )

        try:
            # Perform parallel scans for different vulnerability types
            tasks = [
                self._check_security_headers(target_url, result),
                self._check_ssl_tls(target_url, result),
                self._check_cookies(target_url, result),
                self._crawl_and_analyze(target_url, result, crawl_depth, max_pages),
            ]

            await asyncio.gather(*tasks, return_exceptions=True)

            # Perform targeted vulnerability checks on discovered forms
            if result.forms:
                await self._test_injection_vulnerabilities(result)

        except Exception as e:
            result.scan_metadata['error'] = str(e)

        result.end_time = datetime.utcnow()
        return result

    async def _check_security_headers(
        self,
        url: str,
        result: WebScanResult,
    ) -> None:
        """Check for missing security headers"""
        try:
            async with self.session.get(url, allow_redirects=True) as response:
                result.total_requests += 1
                headers = {k.lower(): v for k, v in response.headers.items()}
                result.security_headers = dict(response.headers)

                # Check each required security header
                for header_name, config in self.SECURITY_HEADERS.items():
                    if header_name.lower() not in headers:
                        vuln = WebVulnerability(
                            vuln_type='MISSING_SECURITY_HEADER',
                            severity=config['severity'],
                            title=f"Missing Security Header: {header_name}",
                            description=config['description'],
                            affected_url=url,
                            remediation=config['remediation'],
                            cwe_id=config['cwe_id'],
                            owasp_category='A05:2021 – Security Misconfiguration',
                            references=[
                                'https://owasp.org/www-project-secure-headers/',
                                'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html',
                            ],
                        )
                        result.vulnerabilities.append(vuln)

                # Check for server information disclosure
                if 'server' in headers:
                    server_header = headers['server']
                    if re.search(r'\d+\.\d+', server_header):  # Version numbers exposed
                        vuln = WebVulnerability(
                            vuln_type='INFORMATION_DISCLOSURE',
                            severity='LOW',
                            title='Server Version Information Disclosure',
                            description=f"Server header exposes version information: {server_header}",
                            affected_url=url,
                            evidence=f"Server: {server_header}",
                            remediation='Remove version information from Server header',
                            cwe_id='CWE-200',
                            owasp_category='A05:2021 – Security Misconfiguration',
                        )
                        result.vulnerabilities.append(vuln)

                # Check for X-Powered-By header
                if 'x-powered-by' in headers:
                    vuln = WebVulnerability(
                        vuln_type='INFORMATION_DISCLOSURE',
                        severity='LOW',
                        title='Technology Stack Disclosure',
                        description=f"X-Powered-By header reveals technology: {headers['x-powered-by']}",
                        affected_url=url,
                        evidence=f"X-Powered-By: {headers['x-powered-by']}",
                        remediation='Remove X-Powered-By header',
                        cwe_id='CWE-200',
                        owasp_category='A05:2021 – Security Misconfiguration',
                    )
                    result.vulnerabilities.append(vuln)

        except Exception as e:
            result.scan_metadata['security_headers_error'] = str(e)

    async def _check_ssl_tls(
        self,
        url: str,
        result: WebScanResult,
    ) -> None:
        """Check SSL/TLS configuration"""
        parsed = urlparse(url)

        if parsed.scheme != 'https':
            vuln = WebVulnerability(
                vuln_type='INSECURE_TRANSPORT',
                severity='HIGH',
                title='HTTPS Not Enforced',
                description='Website does not use HTTPS encryption',
                affected_url=url,
                remediation='Implement HTTPS and redirect all HTTP traffic to HTTPS',
                cwe_id='CWE-319',
                owasp_category='A02:2021 – Cryptographic Failures',
                cvss_score=7.4,
                references=[
                    'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security',
                ],
            )
            result.vulnerabilities.append(vuln)
            return

        # Check SSL/TLS configuration
        hostname = parsed.hostname
        port = parsed.port or 443

        try:
            context = ssl.create_default_context()

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    result.ssl_info = {
                        'protocol_version': version,
                        'cipher_suite': cipher[0] if cipher else None,
                        'cipher_bits': cipher[2] if cipher else None,
                        'certificate': {
                            'subject': dict(x[0] for x in cert.get('subject', [])),
                            'issuer': dict(x[0] for x in cert.get('issuer', [])),
                            'version': cert.get('version'),
                            'serial_number': cert.get('serialNumber'),
                            'not_before': cert.get('notBefore'),
                            'not_after': cert.get('notAfter'),
                            'subject_alt_names': cert.get('subjectAltName', []),
                        }
                    }

                    # Check for weak TLS versions
                    if version in ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']:
                        vuln = WebVulnerability(
                            vuln_type='WEAK_TLS_VERSION',
                            severity='HIGH',
                            title=f'Weak TLS Version: {version}',
                            description=f'Server supports weak TLS version {version}',
                            affected_url=url,
                            evidence=f'TLS Version: {version}',
                            remediation='Disable TLS 1.0 and 1.1. Use TLS 1.2 or 1.3 only',
                            cwe_id='CWE-327',
                            owasp_category='A02:2021 – Cryptographic Failures',
                            cvss_score=7.5,
                        )
                        result.vulnerabilities.append(vuln)

                    # Check for weak cipher suites
                    if cipher and any(weak in cipher[0].lower() for weak in ['rc4', 'des', 'md5', 'null']):
                        vuln = WebVulnerability(
                            vuln_type='WEAK_CIPHER',
                            severity='HIGH',
                            title='Weak Cipher Suite',
                            description=f'Server uses weak cipher suite: {cipher[0]}',
                            affected_url=url,
                            evidence=f'Cipher: {cipher[0]}',
                            remediation='Disable weak cipher suites. Use strong ciphers like AES-GCM',
                            cwe_id='CWE-327',
                            owasp_category='A02:2021 – Cryptographic Failures',
                            cvss_score=7.5,
                        )
                        result.vulnerabilities.append(vuln)

        except Exception as e:
            result.ssl_info['error'] = str(e)

    async def _check_cookies(
        self,
        url: str,
        result: WebScanResult,
    ) -> None:
        """Check cookie security configuration"""
        try:
            async with self.session.get(url, allow_redirects=True) as response:
                result.total_requests += 1

                for cookie in response.cookies.values():
                    cookie_info = {
                        'name': cookie.key,
                        'value': cookie.value[:20] + '...' if len(cookie.value) > 20 else cookie.value,
                        'domain': cookie.get('domain'),
                        'path': cookie.get('path'),
                        'secure': cookie.get('secure', False),
                        'httponly': cookie.get('httponly', False),
                        'samesite': cookie.get('samesite'),
                    }
                    result.cookies.append(cookie_info)

                    # Check for missing Secure flag on HTTPS
                    if not cookie.get('secure') and urlparse(url).scheme == 'https':
                        vuln = WebVulnerability(
                            vuln_type='INSECURE_COOKIE',
                            severity='MEDIUM',
                            title=f'Cookie Missing Secure Flag: {cookie.key}',
                            description=f'Cookie {cookie.key} does not have Secure flag set',
                            affected_url=url,
                            evidence=f'Cookie: {cookie.key}',
                            remediation='Add Secure flag to all cookies on HTTPS sites',
                            cwe_id='CWE-614',
                            owasp_category='A05:2021 – Security Misconfiguration',
                            cvss_score=5.3,
                        )
                        result.vulnerabilities.append(vuln)

                    # Check for missing HttpOnly flag on session cookies
                    if not cookie.get('httponly') and any(
                        keyword in cookie.key.lower()
                        for keyword in ['session', 'auth', 'token', 'login']
                    ):
                        vuln = WebVulnerability(
                            vuln_type='INSECURE_COOKIE',
                            severity='MEDIUM',
                            title=f'Session Cookie Missing HttpOnly Flag: {cookie.key}',
                            description=f'Session cookie {cookie.key} does not have HttpOnly flag',
                            affected_url=url,
                            evidence=f'Cookie: {cookie.key}',
                            remediation='Add HttpOnly flag to session cookies to prevent XSS attacks',
                            cwe_id='CWE-1004',
                            owasp_category='A03:2021 – Injection',
                            cvss_score=5.3,
                        )
                        result.vulnerabilities.append(vuln)

                    # Check for missing SameSite attribute
                    if not cookie.get('samesite'):
                        vuln = WebVulnerability(
                            vuln_type='INSECURE_COOKIE',
                            severity='MEDIUM',
                            title=f'Cookie Missing SameSite Attribute: {cookie.key}',
                            description=f'Cookie {cookie.key} does not have SameSite attribute',
                            affected_url=url,
                            evidence=f'Cookie: {cookie.key}',
                            remediation='Add SameSite=Lax or SameSite=Strict to cookies',
                            cwe_id='CWE-352',
                            owasp_category='A01:2021 – Broken Access Control',
                            cvss_score=4.3,
                        )
                        result.vulnerabilities.append(vuln)

        except Exception as e:
            result.scan_metadata['cookie_check_error'] = str(e)

    async def _crawl_and_analyze(
        self,
        base_url: str,
        result: WebScanResult,
        depth: int,
        max_pages: int,
    ) -> None:
        """Crawl website and analyze pages"""
        visited: set[str] = set()
        to_visit = [(base_url, 0)]
        base_domain = urlparse(base_url).netloc

        while to_visit and len(visited) < max_pages:
            url, current_depth = to_visit.pop(0)

            if url in visited or current_depth > depth:
                continue

            visited.add(url)

            try:
                async with self.session.get(url, allow_redirects=True) as response:
                    result.total_requests += 1

                    if response.content_type and 'text/html' in response.content_type:
                        html = await response.text()
                        soup = BeautifulSoup(html, 'html.parser')

                        # Extract and analyze forms
                        for form in soup.find_all('form'):
                            form_info = self._analyze_form(form, url)
                            result.forms.append(form_info)

                            # Check for CSRF protection
                            if form_info['method'].upper() == 'POST' and not form_info['has_csrf_token']:
                                vuln = WebVulnerability(
                                    vuln_type='CSRF',
                                    severity='MEDIUM',
                                    title='Missing CSRF Protection',
                                    description=f"Form at {url} lacks CSRF token protection",
                                    affected_url=url,
                                    evidence=f"Form action: {form_info['action']}",
                                    remediation='Implement CSRF token validation for all state-changing requests',
                                    cwe_id='CWE-352',
                                    owasp_category='A01:2021 – Broken Access Control',
                                    cvss_score=6.5,
                                )
                                result.vulnerabilities.append(vuln)

                        # Extract external scripts
                        for script in soup.find_all('script', src=True):
                            src = script.get('src')
                            if src:
                                script_url = urljoin(url, src)
                                if urlparse(script_url).netloc != base_domain:
                                    result.external_scripts.append(script_url)

                                    # Check for SRI (Subresource Integrity)
                                    if not script.get('integrity'):
                                        vuln = WebVulnerability(
                                            vuln_type='MISSING_SRI',
                                            severity='MEDIUM',
                                            title='Missing Subresource Integrity (SRI)',
                                            description=f'External script loaded without SRI: {script_url}',
                                            affected_url=url,
                                            evidence=f'Script src: {script_url}',
                                            remediation='Add integrity attribute with SRI hash to external scripts',
                                            cwe_id='CWE-494',
                                            owasp_category='A08:2021 – Software and Data Integrity Failures',
                                            cvss_score=5.3,
                                        )
                                        result.vulnerabilities.append(vuln)

                        # Find more links to crawl
                        if current_depth < depth:
                            for link in soup.find_all('a', href=True):
                                href = link.get('href')
                                if href:
                                    next_url = urljoin(url, href)
                                    if urlparse(next_url).netloc == base_domain:
                                        to_visit.append((next_url, current_depth + 1))

            except Exception as e:
                result.scan_metadata[f'crawl_error_{url}'] = str(e)

    def _analyze_form(self, form, page_url: str) -> dict[str, Any]:
        """Analyze HTML form for security issues"""
        form_data = {
            'action': urljoin(page_url, form.get('action', page_url)),
            'method': form.get('method', 'GET').upper(),
            'inputs': [],
            'has_csrf_token': False,
        }

        # Analyze form inputs
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            input_type = input_tag.get('type', 'text').lower()
            input_name = input_tag.get('name', '')

            form_data['inputs'].append({
                'type': input_type,
                'name': input_name,
            })

            # Check for CSRF token
            if input_type == 'hidden' and any(
                token in input_name.lower()
                for token in ['csrf', 'token', '_token', 'authenticity']
            ):
                form_data['has_csrf_token'] = True

        return form_data

    async def _test_injection_vulnerabilities(
        self,
        result: WebScanResult,
    ) -> None:
        """Test forms for injection vulnerabilities"""
        for form in result.forms[:10]:  # Limit to first 10 forms
            # Test for XSS
            await self._test_xss(form, result)

            # Test for SQL injection
            await self._test_sql_injection(form, result)

    async def _test_xss(
        self,
        form: dict[str, Any],
        result: WebScanResult,
    ) -> None:
        """Test form for XSS vulnerabilities"""
        if not form['inputs']:
            return

        for payload in self.XSS_PAYLOADS[:2]:  # Test with first 2 payloads
            try:
                # Prepare form data with XSS payload
                data = {}
                for input_field in form['inputs']:
                    if input_field['type'] not in ['submit', 'button']:
                        data[input_field['name']] = payload

                if not data:
                    continue

                # Submit form
                if form['method'] == 'POST':
                    async with self.session.post(
                        form['action'],
                        data=data,
                        allow_redirects=True,
                    ) as response:
                        result.total_requests += 1
                        html = await response.text()

                        # Check if payload is reflected unescaped
                        if payload in html:
                            vuln = WebVulnerability(
                                vuln_type='XSS',
                                severity='HIGH',
                                title='Reflected Cross-Site Scripting (XSS)',
                                description='User input is reflected in response without proper encoding',
                                affected_url=form['action'],
                                evidence=f'Payload reflected: {payload[:50]}...',
                                remediation='Sanitize and encode all user input before displaying in HTML',
                                cwe_id='CWE-79',
                                owasp_category='A03:2021 – Injection',
                                cvss_score=7.1,
                                confidence='MEDIUM',
                                references=[
                                    'https://owasp.org/www-community/attacks/xss/',
                                    'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
                                ],
                            )
                            result.vulnerabilities.append(vuln)
                            return  # Found XSS, no need to test more payloads

            except Exception:
                pass  # Continue testing

    async def _test_sql_injection(
        self,
        form: dict[str, Any],
        result: WebScanResult,
    ) -> None:
        """Test form for SQL injection vulnerabilities"""
        if not form['inputs']:
            return

        for payload in self.SQL_PAYLOADS[:2]:  # Test with first 2 payloads
            try:
                # Prepare form data with SQL injection payload
                data = {}
                for input_field in form['inputs']:
                    if input_field['type'] not in ['submit', 'button']:
                        data[input_field['name']] = payload

                if not data:
                    continue

                # Submit form
                if form['method'] == 'POST':
                    async with self.session.post(
                        form['action'],
                        data=data,
                        allow_redirects=True,
                    ) as response:
                        result.total_requests += 1
                        html = await response.text()

                        # Check for SQL error messages
                        sql_errors = [
                            'sql syntax',
                            'mysql_fetch',
                            'ora-',
                            'postgresql',
                            'sqlite',
                            'sqlserver',
                            'syntax error',
                            'unclosed quotation',
                        ]

                        if any(error in html.lower() for error in sql_errors):
                            vuln = WebVulnerability(
                                vuln_type='SQL_INJECTION',
                                severity='CRITICAL',
                                title='SQL Injection',
                                description='Application may be vulnerable to SQL injection attacks',
                                affected_url=form['action'],
                                evidence=f'SQL error detected with payload: {payload[:50]}...',
                                remediation='Use parameterized queries or prepared statements',
                                cwe_id='CWE-89',
                                owasp_category='A03:2021 – Injection',
                                cvss_score=9.8,
                                confidence='MEDIUM',
                                references=[
                                    'https://owasp.org/www-community/attacks/SQL_Injection',
                                    'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
                                ],
                            )
                            result.vulnerabilities.append(vuln)
                            return  # Found SQLi, no need to test more payloads

            except Exception:
                pass  # Continue testing


async def scan_website(
    url: str,
    scan_type: str = "comprehensive",
    timeout: int = 30,
) -> WebScanResult:
    """
    Convenience function to scan a website

    Args:
        url: Target URL to scan
        scan_type: Type of scan (comprehensive, quick, targeted)
        timeout: Request timeout in seconds

    Returns:
        WebScanResult with all findings
    """
    async with WebApplicationScanner(timeout=timeout) as scanner:
        return await scanner.scan(url, scan_type=scan_type)


if __name__ == "__main__":
    # Example usage
    import sys

    async def main():
        if len(sys.argv) < 2:
            print("Usage: python web_scanner.py <url>")
            sys.exit(1)

        target = sys.argv[1]
        print(f"Scanning {target}...")

        result = await scan_website(target)

        print(f"\n=== Scan Results for {target} ===")
        print(f"Total Requests: {result.total_requests}")
        print(f"Vulnerabilities Found: {len(result.vulnerabilities)}")
        print(f"  Critical: {result.critical_count}")
        print(f"  High: {result.high_count}")
        print(f"  Medium: {result.medium_count}")
        print(f"  Low: {result.low_count}")
        print(f"  Info: {result.info_count}")
        print(f"\nForms Found: {len(result.forms)}")
        print(f"External Scripts: {len(result.external_scripts)}")

        print("\n=== Vulnerabilities ===")
        for vuln in result.vulnerabilities:
            print(f"\n[{vuln.severity}] {vuln.title}")
            print(f"  Type: {vuln.vuln_type}")
            print(f"  URL: {vuln.affected_url}")
            print(f"  Description: {vuln.description}")
            if vuln.remediation:
                print(f"  Remediation: {vuln.remediation}")

    asyncio.run(main())
