"""
Container Image Vulnerability Scanner

This module provides comprehensive container image security scanning:
- OS package vulnerability detection
- Layer-by-layer analysis
- Base image vulnerability assessment
- Configuration and security best practices
- Image size optimization recommendations
- Dockerfile security analysis
"""

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class ContainerVulnerability:
    """Represents a vulnerability found in a container image"""

    vulnerability_id: str  # CVE ID
    package_name: str
    installed_version: str
    fixed_version: str | None
    severity: str
    layer_id: str
    description: str
    cvss_score: float | None = None
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            'vulnerability_id': self.vulnerability_id,
            'package_name': self.package_name,
            'installed_version': self.installed_version,
            'fixed_version': self.fixed_version,
            'severity': self.severity,
            'layer_id': self.layer_id,
            'description': self.description,
            'cvss_score': self.cvss_score,
            'references': self.references,
        }


@dataclass
class ImageLayer:
    """Represents a container image layer"""

    layer_id: str
    size: int
    command: str
    vulnerabilities: list[ContainerVulnerability] = field(default_factory=list)
    packages_added: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            'layer_id': self.layer_id,
            'size': self.size,
            'command': self.command,
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'packages_added': self.packages_added,
            'vulnerability_count': len(self.vulnerabilities),
        }


@dataclass
class ContainerScanResult:
    """Results from container image scan"""

    image_name: str
    image_tag: str
    image_id: str
    scan_time: datetime
    layers: list[ImageLayer] = field(default_factory=list)
    vulnerabilities: list[ContainerVulnerability] = field(default_factory=list)
    os_type: str | None = None
    os_version: str | None = None
    total_size: int = 0
    dockerfile_issues: list[dict[str, Any]] = field(default_factory=list)
    security_score: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

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

    def to_dict(self) -> dict[str, Any]:
        return {
            'image_name': self.image_name,
            'image_tag': self.image_tag,
            'image_id': self.image_id,
            'scan_time': self.scan_time.isoformat(),
            'layers': [layer.to_dict() for layer in self.layers],
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'os_type': self.os_type,
            'os_version': self.os_version,
            'total_size': self.total_size,
            'dockerfile_issues': self.dockerfile_issues,
            'security_score': self.security_score,
            'critical_count': self.critical_count,
            'high_count': self.high_count,
            'medium_count': self.medium_count,
            'low_count': self.low_count,
            'total_vulnerabilities': len(self.vulnerabilities),
            'metadata': self.metadata,
        }


class ContainerScanner:
    """
    Container image security scanner

    Performs comprehensive security analysis of container images including
    vulnerability scanning, configuration review, and best practice validation.
    """

    # Dockerfile best practices
    DOCKERFILE_RULES = [
        {
            'pattern': r'^FROM\s+.*:latest',
            'severity': 'HIGH',
            'title': 'Using :latest tag',
            'description': 'Image uses :latest tag which is not reproducible',
            'remediation': 'Use specific version tags instead of :latest',
        },
        {
            'pattern': r'^\s*RUN.*apt-get\s+install.*--no-install-recommends',
            'severity': 'LOW',
            'title': 'Missing --no-install-recommends',
            'description': 'apt-get install without --no-install-recommends increases image size',
            'remediation': 'Add --no-install-recommends to apt-get install commands',
            'inverse': True,  # Should match when NOT present
        },
        {
            'pattern': r'^\s*USER\s+root',
            'severity': 'HIGH',
            'title': 'Running as root user',
            'description': 'Container runs as root user',
            'remediation': 'Create and use a non-root user',
        },
        {
            'pattern': r'^\s*ADD\s+http',
            'severity': 'MEDIUM',
            'title': 'Using ADD for URLs',
            'description': 'ADD is used to download from URLs (use RUN wget or curl instead)',
            'remediation': 'Use RUN with wget or curl instead of ADD for URLs',
        },
    ]

    def __init__(
        self,
        use_trivy: bool = True,
        use_grype: bool = False,
    ):
        """
        Initialize container scanner

        Args:
            use_trivy: Use Trivy scanner if available
            use_grype: Use Grype scanner if available
        """
        self.use_trivy = use_trivy
        self.use_grype = use_grype

    async def scan_image(
        self,
        image_name: str,
        image_tag: str = "latest",
        dockerfile_path: str | None = None,
    ) -> ContainerScanResult:
        """
        Scan container image for vulnerabilities

        Args:
            image_name: Name of the container image
            image_tag: Image tag
            dockerfile_path: Optional path to Dockerfile for analysis

        Returns:
            ContainerScanResult with findings
        """
        full_image = f"{image_name}:{image_tag}"

        result = ContainerScanResult(
            image_name=image_name,
            image_tag=image_tag,
            image_id="",
            scan_time=datetime.utcnow(),
        )

        # Get image information
        await self._get_image_info(full_image, result)

        # Scan with available tools
        if self.use_trivy and await self._check_tool_available('trivy'):
            await self._scan_with_trivy(full_image, result)
        elif self.use_grype and await self._check_tool_available('grype'):
            await self._scan_with_grype(full_image, result)
        else:
            # Fallback to basic inspection
            await self._basic_image_scan(full_image, result)

        # Analyze Dockerfile if provided
        if dockerfile_path:
            await self._analyze_dockerfile(dockerfile_path, result)

        # Calculate security score
        result.security_score = self._calculate_security_score(result)

        return result

    async def _check_tool_available(self, tool: str) -> bool:
        """Check if scanning tool is available"""
        try:
            process = await asyncio.create_subprocess_exec(
                'which',
                tool,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
            return process.returncode == 0
        except Exception:
            return False

    async def _get_image_info(
        self,
        image: str,
        result: ContainerScanResult,
    ) -> None:
        """Get basic image information using docker inspect"""
        try:
            process = await asyncio.create_subprocess_exec(
                'docker',
                'inspect',
                image,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                data = json.loads(stdout.decode())
                if data:
                    image_data = data[0]
                    result.image_id = image_data.get('Id', '')[:12]
                    result.total_size = image_data.get('Size', 0)

                    # Get OS info from config
                    image_data.get('Config', {})
                    result.metadata['architecture'] = image_data.get('Architecture')
                    result.metadata['created'] = image_data.get('Created')

                    # Get layer information
                    layers = image_data.get('RootFS', {}).get('Layers', [])
                    history = image_data.get('History', [])

                    for _i, (layer_hash, hist) in enumerate(zip(layers, history, strict=False)):
                        layer = ImageLayer(
                            layer_id=layer_hash[:12],
                            size=hist.get('Size', 0),
                            command=hist.get('CreatedBy', ''),
                        )
                        result.layers.append(layer)

        except Exception as e:
            result.metadata['image_info_error'] = str(e)

    async def _scan_with_trivy(
        self,
        image: str,
        result: ContainerScanResult,
    ) -> None:
        """Scan image using Trivy"""
        try:
            process = await asyncio.create_subprocess_exec(
                'trivy',
                'image',
                '--format', 'json',
                '--severity', 'CRITICAL,HIGH,MEDIUM,LOW',
                image,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                data = json.loads(stdout.decode())

                # Parse Trivy results
                for target in data.get('Results', []):
                    target.get('Type', '')
                    vulnerabilities = target.get('Vulnerabilities', [])

                    for vuln in vulnerabilities:
                        container_vuln = ContainerVulnerability(
                            vulnerability_id=vuln.get('VulnerabilityID', ''),
                            package_name=vuln.get('PkgName', ''),
                            installed_version=vuln.get('InstalledVersion', ''),
                            fixed_version=vuln.get('FixedVersion'),
                            severity=vuln.get('Severity', 'UNKNOWN'),
                            layer_id='',  # Trivy doesn't provide layer info in JSON
                            description=vuln.get('Description', ''),
                            cvss_score=self._extract_cvss_score(vuln),
                            references=vuln.get('References', []),
                        )
                        result.vulnerabilities.append(container_vuln)

                # Get OS information
                metadata = data.get('Metadata', {})
                os_info = metadata.get('OS', {})
                result.os_type = os_info.get('Family')
                result.os_version = os_info.get('Name')

        except Exception as e:
            result.metadata['trivy_error'] = str(e)

    async def _scan_with_grype(
        self,
        image: str,
        result: ContainerScanResult,
    ) -> None:
        """Scan image using Grype"""
        try:
            process = await asyncio.create_subprocess_exec(
                'grype',
                image,
                '-o', 'json',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                data = json.loads(stdout.decode())

                # Parse Grype results
                for match in data.get('matches', []):
                    vuln = match.get('vulnerability', {})
                    artifact = match.get('artifact', {})

                    container_vuln = ContainerVulnerability(
                        vulnerability_id=vuln.get('id', ''),
                        package_name=artifact.get('name', ''),
                        installed_version=artifact.get('version', ''),
                        fixed_version=vuln.get('fix', {}).get('versions', [None])[0],
                        severity=vuln.get('severity', 'UNKNOWN'),
                        layer_id='',
                        description=vuln.get('description', ''),
                        references=vuln.get('urls', []),
                    )
                    result.vulnerabilities.append(container_vuln)

                # Get OS information
                distro = data.get('distro', {})
                result.os_type = distro.get('name')
                result.os_version = distro.get('version')

        except Exception as e:
            result.metadata['grype_error'] = str(e)

    def _extract_cvss_score(self, vuln: dict[str, Any]) -> float | None:
        """Extract CVSS score from vulnerability data"""
        # Try to get CVSS score from various fields
        cvss = vuln.get('CVSS', {})

        if isinstance(cvss, dict):
            # Try NVD CVSS first
            nvd_cvss = cvss.get('nvd', {})
            if 'V3Score' in nvd_cvss:
                return nvd_cvss['V3Score']
            if 'V2Score' in nvd_cvss:
                return nvd_cvss['V2Score']

            # Try vendor CVSS
            for vendor_cvss in cvss.values():
                if isinstance(vendor_cvss, dict):
                    if 'V3Score' in vendor_cvss:
                        return vendor_cvss['V3Score']
                    if 'V2Score' in vendor_cvss:
                        return vendor_cvss['V2Score']

        return None

    async def _basic_image_scan(
        self,
        image: str,
        result: ContainerScanResult,
    ) -> None:
        """
        Basic image scan without external tools

        Performs basic security checks using docker commands
        """
        try:
            # Check if image runs as root
            process = await asyncio.create_subprocess_exec(
                'docker',
                'run',
                '--rm',
                '--entrypoint', 'id',
                image,
                '-u',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            if stdout:
                uid = stdout.decode().strip()
                if uid == '0':
                    result.dockerfile_issues.append({
                        'severity': 'HIGH',
                        'title': 'Container runs as root',
                        'description': 'Container is running as root user (UID 0)',
                        'remediation': 'Create and use a non-root user',
                    })

        except Exception as e:
            result.metadata['basic_scan_error'] = str(e)

    async def _analyze_dockerfile(
        self,
        dockerfile_path: str,
        result: ContainerScanResult,
    ) -> None:
        """
        Analyze Dockerfile for security issues

        Args:
            dockerfile_path: Path to Dockerfile
            result: ContainerScanResult to update
        """
        try:
            dockerfile = Path(dockerfile_path)
            if not dockerfile.exists():
                return

            content = dockerfile.read_text()
            content.split('\n')

            # Check for best practice violations
            for rule in self.DOCKERFILE_RULES:
                import re
                pattern = re.compile(rule['pattern'], re.IGNORECASE | re.MULTILINE)

                if rule.get('inverse', False):
                    # Check that pattern does NOT match
                    if not pattern.search(content):
                        result.dockerfile_issues.append({
                            'severity': rule['severity'],
                            'title': rule['title'],
                            'description': rule['description'],
                            'remediation': rule['remediation'],
                        })
                else:
                    # Check that pattern matches
                    matches = pattern.finditer(content)
                    for match in matches:
                        # Find line number
                        line_num = content[:match.start()].count('\n') + 1
                        result.dockerfile_issues.append({
                            'severity': rule['severity'],
                            'title': rule['title'],
                            'description': rule['description'],
                            'remediation': rule['remediation'],
                            'line': line_num,
                        })

            # Check for secrets in Dockerfile
            secret_patterns = [
                (r'(?i)(password|pwd|secret|token|key)\s*=\s*["\']?[^"\'\s]+', 'Hardcoded secret'),
                (r'(?i)AWS_ACCESS_KEY', 'AWS credentials'),
                (r'(?i)PRIVATE_KEY', 'Private key'),
            ]

            for pattern, desc in secret_patterns:
                matches = re.finditer(pattern, content)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    result.dockerfile_issues.append({
                        'severity': 'CRITICAL',
                        'title': f'Potential secret in Dockerfile: {desc}',
                        'description': f'Line {line_num} may contain hardcoded secrets',
                        'remediation': 'Use build-time arguments or environment variables',
                        'line': line_num,
                    })

        except Exception as e:
            result.metadata['dockerfile_analysis_error'] = str(e)

    def _calculate_security_score(
        self,
        result: ContainerScanResult,
    ) -> float:
        """
        Calculate overall security score (0-100)

        Args:
            result: ContainerScanResult

        Returns:
            Security score (higher is better)
        """
        score = 100.0

        # Deduct points for vulnerabilities
        score -= result.critical_count * 15
        score -= result.high_count * 8
        score -= result.medium_count * 3
        score -= result.low_count * 1

        # Deduct points for Dockerfile issues
        for issue in result.dockerfile_issues:
            if issue['severity'] == 'CRITICAL':
                score -= 10
            elif issue['severity'] == 'HIGH':
                score -= 5
            elif issue['severity'] == 'MEDIUM':
                score -= 2
            else:
                score -= 1

        # Deduct points for image size (encourage minimal images)
        size_mb = result.total_size / (1024 * 1024)
        if size_mb > 1000:
            score -= 10
        elif size_mb > 500:
            score -= 5

        return max(0.0, min(100.0, score))


async def scan_container(
    image_name: str,
    image_tag: str = "latest",
    dockerfile_path: str | None = None,
) -> ContainerScanResult:
    """
    Convenience function to scan a container image

    Args:
        image_name: Name of the container image
        image_tag: Image tag
        dockerfile_path: Optional path to Dockerfile

    Returns:
        ContainerScanResult with findings
    """
    scanner = ContainerScanner()
    return await scanner.scan_image(image_name, image_tag, dockerfile_path)


if __name__ == "__main__":
    import sys

    async def main():
        if len(sys.argv) < 2:
            print("Usage: python container_scanner.py <image:tag>")
            sys.exit(1)

        image_parts = sys.argv[1].split(':')
        image_name = image_parts[0]
        image_tag = image_parts[1] if len(image_parts) > 1 else 'latest'

        print(f"Scanning container image: {image_name}:{image_tag}")

        result = await scan_container(image_name, image_tag)

        print("\n=== Container Scan Results ===")
        print(f"Image: {result.image_name}:{result.image_tag}")
        print(f"Image ID: {result.image_id}")
        print(f"Size: {result.total_size / (1024 * 1024):.2f} MB")
        print(f"Security Score: {result.security_score:.1f}/100")
        print("\nVulnerabilities:")
        print(f"  Critical: {result.critical_count}")
        print(f"  High: {result.high_count}")
        print(f"  Medium: {result.medium_count}")
        print(f"  Low: {result.low_count}")
        print(f"\nDockerfile Issues: {len(result.dockerfile_issues)}")

        if result.vulnerabilities:
            print("\n=== Top Vulnerabilities ===")
            for vuln in sorted(
                result.vulnerabilities,
                key=lambda v: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}.get(v.severity, 4)
            )[:10]:
                print(f"\n[{vuln.severity}] {vuln.vulnerability_id}")
                print(f"  Package: {vuln.package_name} {vuln.installed_version}")
                if vuln.fixed_version:
                    print(f"  Fixed in: {vuln.fixed_version}")

    asyncio.run(main())
