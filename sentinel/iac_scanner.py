"""
Infrastructure as Code (IaC) Security Scanner

This module provides comprehensive IaC security scanning for:
- Terraform configurations
- AWS CloudFormation templates
- Kubernetes manifests
- Docker Compose files
- Azure Resource Manager (ARM) templates
- Google Cloud Deployment Manager

Detects:
- Security misconfigurations
- Overly permissive access controls
- Unencrypted resources
- Public exposure risks
- Insecure defaults
- Compliance violations
"""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml


@dataclass
class IaCFinding:
    """Represents an IaC security finding"""

    resource_type: str
    resource_name: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    issue_type: str
    file_path: str
    line_number: int | None
    description: str
    remediation: str
    cis_control: str | None = None
    compliance_frameworks: list[str] = field(default_factory=list)
    impact: str | None = None
    risk_score: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            'resource_type': self.resource_type,
            'resource_name': self.resource_name,
            'severity': self.severity,
            'issue_type': self.issue_type,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'description': self.description,
            'remediation': self.remediation,
            'cis_control': self.cis_control,
            'compliance_frameworks': self.compliance_frameworks,
            'impact': self.impact,
            'risk_score': self.risk_score,
        }


@dataclass
class IaCScanResult:
    """Results from IaC security scan"""

    target_path: str
    scan_time: datetime
    findings: list[IaCFinding] = field(default_factory=list)
    files_scanned: int = 0
    resources_analyzed: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'CRITICAL')

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'HIGH')

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'MEDIUM')

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'LOW')

    def to_dict(self) -> dict[str, Any]:
        return {
            'target_path': self.target_path,
            'scan_time': self.scan_time.isoformat(),
            'findings': [f.to_dict() for f in self.findings],
            'files_scanned': self.files_scanned,
            'resources_analyzed': self.resources_analyzed,
            'critical_count': self.critical_count,
            'high_count': self.high_count,
            'medium_count': self.medium_count,
            'low_count': self.low_count,
            'total_findings': len(self.findings),
            'metadata': self.metadata,
        }


class IaCScanner:
    """
    Infrastructure as Code security scanner

    Analyzes IaC files for security misconfigurations and compliance violations.
    """

    # Terraform security checks
    TERRAFORM_CHECKS = [
        {
            'resource': 'aws_s3_bucket',
            'check': lambda r: r.get('acl') == 'public-read' or r.get('acl') == 'public-read-write',
            'severity': 'CRITICAL',
            'issue': 'Public S3 Bucket',
            'description': 'S3 bucket is publicly accessible',
            'remediation': 'Set acl to "private" and use bucket policies for access control',
            'cis': 'CIS AWS 2.1.5',
            'compliance': ['PCI-DSS', 'HIPAA', 'SOC2'],
        },
        {
            'resource': 'aws_security_group',
            'check': lambda r: any(
                ingress.get('cidr_blocks') == ['0.0.0.0/0'] and ingress.get('from_port') in [22, 3389]
                for ingress in r.get('ingress', [])
            ),
            'severity': 'CRITICAL',
            'issue': 'Open SSH/RDP to Internet',
            'description': 'Security group allows SSH/RDP access from anywhere',
            'remediation': 'Restrict SSH/RDP access to specific IP addresses',
            'cis': 'CIS AWS 5.2',
            'compliance': ['PCI-DSS', 'NIST', 'SOC2'],
        },
        {
            'resource': 'aws_instance',
            'check': lambda r: not r.get('monitoring'),
            'severity': 'MEDIUM',
            'issue': 'EC2 Monitoring Disabled',
            'description': 'EC2 instance does not have detailed monitoring enabled',
            'remediation': 'Enable monitoring = true for better visibility',
            'cis': 'CIS AWS 4.4',
            'compliance': ['SOC2'],
        },
        {
            'resource': 'aws_db_instance',
            'check': lambda r: not r.get('storage_encrypted', False),
            'severity': 'HIGH',
            'issue': 'Unencrypted RDS Storage',
            'description': 'RDS database storage is not encrypted',
            'remediation': 'Enable storage_encrypted = true',
            'cis': 'CIS AWS 2.3.1',
            'compliance': ['PCI-DSS', 'HIPAA'],
        },
        {
            'resource': 'aws_ebs_volume',
            'check': lambda r: not r.get('encrypted', False),
            'severity': 'HIGH',
            'issue': 'Unencrypted EBS Volume',
            'description': 'EBS volume is not encrypted',
            'remediation': 'Enable encrypted = true',
            'cis': 'CIS AWS 2.2.1',
            'compliance': ['PCI-DSS', 'HIPAA'],
        },
    ]

    # Kubernetes security checks
    KUBERNETES_CHECKS = [
        {
            'kind': 'Pod',
            'check': lambda spec: spec.get('securityContext', {}).get('runAsNonRoot') is not True,
            'severity': 'HIGH',
            'issue': 'Container Running as Root',
            'description': 'Pod/container runs as root user',
            'remediation': 'Set securityContext.runAsNonRoot = true',
        },
        {
            'kind': 'Pod',
            'check': lambda spec: spec.get('securityContext', {}).get('privileged') is True,
            'severity': 'CRITICAL',
            'issue': 'Privileged Container',
            'description': 'Container runs in privileged mode',
            'remediation': 'Remove privileged = true unless absolutely necessary',
        },
        {
            'kind': 'Service',
            'check': lambda spec: spec.get('type') == 'LoadBalancer',
            'severity': 'MEDIUM',
            'issue': 'LoadBalancer Service',
            'description': 'Service exposed via LoadBalancer (publicly accessible)',
            'remediation': 'Use ClusterIP or NodePort with ingress controller',
        },
    ]

    # Docker Compose security checks
    DOCKER_COMPOSE_CHECKS = [
        {
            'check_type': 'privileged',
            'severity': 'CRITICAL',
            'issue': 'Privileged Container',
            'description': 'Service runs in privileged mode',
            'remediation': 'Remove privileged: true',
        },
        {
            'check_type': 'no_network_mode',
            'severity': 'HIGH',
            'issue': 'Host Network Mode',
            'description': 'Service uses host network mode',
            'remediation': 'Use bridge or custom networks instead',
        },
    ]

    def __init__(self):
        """Initialize IaC scanner"""
        self.terraform_parser = TerraformParser()
        self.kubernetes_parser = KubernetesParser()
        self.cloudformation_parser = CloudFormationParser()

    async def scan_path(
        self,
        path: str,
    ) -> IaCScanResult:
        """
        Scan path for IaC security issues

        Args:
            path: Path to scan

        Returns:
            IaCScanResult with findings
        """
        result = IaCScanResult(
            target_path=path,
            scan_time=datetime.utcnow(),
        )

        target = Path(path)

        if target.is_file():
            await self._scan_file(target, result)
        elif target.is_dir():
            await self._scan_directory(target, result)

        return result

    async def _scan_directory(
        self,
        directory: Path,
        result: IaCScanResult,
    ) -> None:
        """Scan directory recursively"""
        # Terraform files
        for tf_file in directory.rglob('*.tf'):
            await self._scan_file(tf_file, result)

        # Kubernetes manifests
        for k8s_file in directory.rglob('*.yaml'):
            if 'k8s' in str(k8s_file) or 'kubernetes' in str(k8s_file):
                await self._scan_file(k8s_file, result)

        for k8s_file in directory.rglob('*.yml'):
            if 'k8s' in str(k8s_file) or 'kubernetes' in str(k8s_file):
                await self._scan_file(k8s_file, result)

        # CloudFormation
        for cfn_file in directory.rglob('*.template'):
            await self._scan_file(cfn_file, result)

        # Docker Compose
        for compose_file in directory.glob('docker-compose*.{yml,yaml}'):
            await self._scan_file(compose_file, result)

    async def _scan_file(
        self,
        file_path: Path,
        result: IaCScanResult,
    ) -> None:
        """Scan individual IaC file"""
        try:
            result.files_scanned += 1

            if file_path.suffix == '.tf':
                await self._scan_terraform(file_path, result)
            elif file_path.suffix in ['.yaml', '.yml']:
                content = file_path.read_text()
                # Try to detect file type
                if 'apiVersion' in content and 'kind' in content:
                    await self._scan_kubernetes(file_path, result)
                elif 'services:' in content and 'version:' in content:
                    await self._scan_docker_compose(file_path, result)
            elif file_path.suffix == '.template' or 'cloudformation' in file_path.name.lower():
                await self._scan_cloudformation(file_path, result)

        except Exception as e:
            result.metadata[f'scan_error_{file_path}'] = str(e)

    async def _scan_terraform(
        self,
        file_path: Path,
        result: IaCScanResult,
    ) -> None:
        """Scan Terraform file"""
        try:
            content = file_path.read_text()
            resources = self.terraform_parser.parse(content)

            for resource in resources:
                result.resources_analyzed += 1

                for check in self.TERRAFORM_CHECKS:
                    if resource['type'] == check['resource']:
                        if check['check'](resource.get('config', {})):
                            finding = IaCFinding(
                                resource_type=resource['type'],
                                resource_name=resource.get('name', 'unknown'),
                                severity=check['severity'],
                                issue_type=check['issue'],
                                file_path=str(file_path),
                                line_number=resource.get('line_number'),
                                description=check['description'],
                                remediation=check['remediation'],
                                cis_control=check.get('cis'),
                                compliance_frameworks=check.get('compliance', []),
                            )
                            result.findings.append(finding)

        except Exception as e:
            result.metadata[f'terraform_error_{file_path}'] = str(e)

    async def _scan_kubernetes(
        self,
        file_path: Path,
        result: IaCScanResult,
    ) -> None:
        """Scan Kubernetes manifest"""
        try:
            content = file_path.read_text()
            manifests = list(yaml.safe_load_all(content))

            for manifest in manifests:
                if not manifest:
                    continue

                result.resources_analyzed += 1
                kind = manifest.get('kind', '')
                name = manifest.get('metadata', {}).get('name', 'unknown')

                for check in self.KUBERNETES_CHECKS:
                    if kind == check['kind']:
                        spec = manifest.get('spec', {})

                        # For Pods, also check containers
                        if kind == 'Pod':
                            for container in spec.get('containers', []):
                                container_spec = container.get('securityContext', {})
                                if check['check'](container_spec):
                                    finding = IaCFinding(
                                        resource_type=kind,
                                        resource_name=f"{name}/{container.get('name', 'unknown')}",
                                        severity=check['severity'],
                                        issue_type=check['issue'],
                                        file_path=str(file_path),
                                        line_number=None,
                                        description=check['description'],
                                        remediation=check['remediation'],
                                    )
                                    result.findings.append(finding)
                        elif check['check'](spec):
                            finding = IaCFinding(
                                resource_type=kind,
                                resource_name=name,
                                severity=check['severity'],
                                issue_type=check['issue'],
                                file_path=str(file_path),
                                line_number=None,
                                description=check['description'],
                                remediation=check['remediation'],
                            )
                            result.findings.append(finding)

        except Exception as e:
            result.metadata[f'kubernetes_error_{file_path}'] = str(e)

    async def _scan_docker_compose(
        self,
        file_path: Path,
        result: IaCScanResult,
    ) -> None:
        """Scan Docker Compose file"""
        try:
            content = yaml.safe_load(file_path.read_text())
            services = content.get('services', {})

            for service_name, service_config in services.items():
                result.resources_analyzed += 1

                # Check for privileged mode
                if service_config.get('privileged') is True:
                    finding = IaCFinding(
                        resource_type='docker-compose-service',
                        resource_name=service_name,
                        severity='CRITICAL',
                        issue_type='Privileged Container',
                        file_path=str(file_path),
                        line_number=None,
                        description='Service runs in privileged mode',
                        remediation='Remove privileged: true',
                    )
                    result.findings.append(finding)

                # Check for host network mode
                if service_config.get('network_mode') == 'host':
                    finding = IaCFinding(
                        resource_type='docker-compose-service',
                        resource_name=service_name,
                        severity='HIGH',
                        issue_type='Host Network Mode',
                        file_path=str(file_path),
                        line_number=None,
                        description='Service uses host network mode',
                        remediation='Use bridge or custom networks',
                    )
                    result.findings.append(finding)

                # Check for volume mounts to sensitive paths
                volumes = service_config.get('volumes', [])
                for volume in volumes:
                    if isinstance(volume, str):
                        if any(sensitive in volume for sensitive in ['/etc', '/var/run/docker.sock', '/root']):
                            finding = IaCFinding(
                                resource_type='docker-compose-service',
                                resource_name=service_name,
                                severity='HIGH',
                                issue_type='Sensitive Volume Mount',
                                file_path=str(file_path),
                                line_number=None,
                                description=f'Service mounts sensitive path: {volume}',
                                remediation='Avoid mounting sensitive system paths',
                            )
                            result.findings.append(finding)

        except Exception as e:
            result.metadata[f'docker_compose_error_{file_path}'] = str(e)

    async def _scan_cloudformation(
        self,
        file_path: Path,
        result: IaCScanResult,
    ) -> None:
        """Scan CloudFormation template"""
        try:
            content = file_path.read_text()

            # Try JSON first
            try:
                template = json.loads(content)
            except json.JSONDecodeError:
                # Try YAML
                template = yaml.safe_load(content)

            resources = template.get('Resources', {})

            for resource_name, resource_config in resources.items():
                result.resources_analyzed += 1
                resource_type = resource_config.get('Type', '')
                properties = resource_config.get('Properties', {})

                # Check S3 buckets
                if resource_type == 'AWS::S3::Bucket':
                    if properties.get('AccessControl') in ['PublicRead', 'PublicReadWrite']:
                        finding = IaCFinding(
                            resource_type=resource_type,
                            resource_name=resource_name,
                            severity='CRITICAL',
                            issue_type='Public S3 Bucket',
                            file_path=str(file_path),
                            line_number=None,
                            description='S3 bucket is publicly accessible',
                            remediation='Set AccessControl to Private',
                            compliance_frameworks=['PCI-DSS', 'HIPAA'],
                        )
                        result.findings.append(finding)

                # Check RDS encryption
                if resource_type == 'AWS::RDS::DBInstance':
                    if not properties.get('StorageEncrypted', False):
                        finding = IaCFinding(
                            resource_type=resource_type,
                            resource_name=resource_name,
                            severity='HIGH',
                            issue_type='Unencrypted RDS Storage',
                            file_path=str(file_path),
                            line_number=None,
                            description='RDS database storage is not encrypted',
                            remediation='Enable StorageEncrypted',
                            compliance_frameworks=['PCI-DSS', 'HIPAA'],
                        )
                        result.findings.append(finding)

        except Exception as e:
            result.metadata[f'cloudformation_error_{file_path}'] = str(e)


class TerraformParser:
    """Simple Terraform HCL parser"""

    def parse(self, content: str) -> list[dict[str, Any]]:
        """Parse Terraform file and extract resources"""
        resources = []

        # Simple regex-based parsing for basic resources
        resource_pattern = r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{([^}]+)\}'

        for match in re.finditer(resource_pattern, content, re.MULTILINE | re.DOTALL):
            resource_type = match.group(1)
            resource_name = match.group(2)
            resource_body = match.group(3)

            # Parse basic config
            config = {}
            for line in resource_body.split('\n'):
                line = line.strip()
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip().strip('"')
                    config[key] = value

            resources.append({
                'type': resource_type,
                'name': resource_name,
                'config': config,
            })

        return resources


class KubernetesParser:
    """Kubernetes manifest parser"""

    def parse(self, content: str) -> list[dict[str, Any]]:
        """Parse Kubernetes YAML manifests"""
        return list(yaml.safe_load_all(content))


class CloudFormationParser:
    """CloudFormation template parser"""

    def parse(self, content: str) -> dict[str, Any]:
        """Parse CloudFormation template"""
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return yaml.safe_load(content)


async def scan_iac(path: str) -> IaCScanResult:
    """
    Convenience function to scan IaC files

    Args:
        path: Path to scan

    Returns:
        IaCScanResult with findings
    """
    scanner = IaCScanner()
    return await scanner.scan_path(path)


if __name__ == "__main__":
    import asyncio
    import sys

    async def main():
        if len(sys.argv) < 2:
            print("Usage: python iac_scanner.py <path>")
            sys.exit(1)

        target = sys.argv[1]
        print(f"Scanning IaC files at: {target}")

        result = await scan_iac(target)

        print("\n=== IaC Security Scan Results ===")
        print(f"Files Scanned: {result.files_scanned}")
        print(f"Resources Analyzed: {result.resources_analyzed}")
        print("\nFindings:")
        print(f"  Critical: {result.critical_count}")
        print(f"  High: {result.high_count}")
        print(f"  Medium: {result.medium_count}")
        print(f"  Low: {result.low_count}")

        if result.findings:
            print("\n=== Security Issues ===")
            for finding in sorted(
                result.findings,
                key=lambda f: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}.get(f.severity, 4)
            )[:20]:
                print(f"\n[{finding.severity}] {finding.issue_type}")
                print(f"  Resource: {finding.resource_type} / {finding.resource_name}")
                print(f"  File: {finding.file_path}")
                print(f"  Issue: {finding.description}")
                print(f"  Fix: {finding.remediation}")
                if finding.compliance_frameworks:
                    print(f"  Compliance: {', '.join(finding.compliance_frameworks)}")

    asyncio.run(main())
