"""
Secrets Detection Scanner

This module provides comprehensive secrets and credential scanning:
- API keys and tokens detection
- AWS, GCP, Azure credentials
- Private keys and certificates
- Database connection strings
- OAuth tokens and secrets
- Generic secret patterns
- Entropy-based detection
- Git history scanning
"""

import asyncio
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class SecretFinding:
    """Represents a discovered secret"""

    secret_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    file_path: str
    line_number: int
    matched_string: str  # Redacted version
    pattern_name: str
    entropy: float | None = None
    commit_hash: str | None = None
    commit_author: str | None = None
    commit_date: str | None = None
    remediation: str | None = None
    confidence: str = "HIGH"  # HIGH, MEDIUM, LOW

    def to_dict(self) -> dict[str, Any]:
        return {
            'secret_type': self.secret_type,
            'severity': self.severity,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'matched_string': self.matched_string,
            'pattern_name': self.pattern_name,
            'entropy': self.entropy,
            'commit_hash': self.commit_hash,
            'commit_author': self.commit_author,
            'commit_date': self.commit_date,
            'remediation': self.remediation,
            'confidence': self.confidence,
        }


@dataclass
class SecretScanResult:
    """Results from secrets scan"""

    target_path: str
    scan_type: str  # filesystem, git_history
    scan_time: datetime
    findings: list[SecretFinding] = field(default_factory=list)
    files_scanned: int = 0
    commits_scanned: int = 0
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
            'scan_type': self.scan_type,
            'scan_time': self.scan_time.isoformat(),
            'findings': [f.to_dict() for f in self.findings],
            'files_scanned': self.files_scanned,
            'commits_scanned': self.commits_scanned,
            'critical_count': self.critical_count,
            'high_count': self.high_count,
            'medium_count': self.medium_count,
            'low_count': self.low_count,
            'total_findings': len(self.findings),
            'metadata': self.metadata,
        }


class SecretsScanner:
    """
    Comprehensive secrets detection scanner

    Scans code repositories, files, and git history for exposed secrets,
    API keys, credentials, and other sensitive information.
    """

    # Secret patterns with metadata
    SECRET_PATTERNS = [
        # AWS
        {
            'name': 'AWS Access Key ID',
            'pattern': r'(?i)(?:aws|amazon)(?:_|-)?(?:access|account)?(?:_|-)?key(?:_|-)?(?:id)?["\']?\s*[:=]\s*["\']?(AKIA[0-9A-Z]{16})',
            'type': 'aws_access_key',
            'severity': 'CRITICAL',
            'remediation': 'Rotate AWS credentials immediately. Use AWS IAM roles or AWS Secrets Manager.',
        },
        {
            'name': 'AWS Secret Access Key',
            'pattern': r'(?i)(?:aws|amazon)(?:_|-)?secret(?:_|-)?(?:access)?(?:_|-)?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})',
            'type': 'aws_secret_key',
            'severity': 'CRITICAL',
            'remediation': 'Rotate AWS credentials immediately. Use AWS Secrets Manager.',
        },
        # GitHub
        {
            'name': 'GitHub Personal Access Token',
            'pattern': r'ghp_[0-9a-zA-Z]{36}',
            'type': 'github_token',
            'severity': 'CRITICAL',
            'remediation': 'Revoke GitHub token and create new one. Use GitHub Secrets for CI/CD.',
        },
        {
            'name': 'GitHub OAuth Token',
            'pattern': r'gho_[0-9a-zA-Z]{36}',
            'type': 'github_oauth',
            'severity': 'CRITICAL',
            'remediation': 'Revoke GitHub OAuth token immediately.',
        },
        {
            'name': 'GitHub App Token',
            'pattern': r'(?:ghu|ghs)_[0-9a-zA-Z]{36}',
            'type': 'github_app_token',
            'severity': 'CRITICAL',
            'remediation': 'Revoke GitHub App token immediately.',
        },
        # Google Cloud
        {
            'name': 'Google API Key',
            'pattern': r'AIza[0-9A-Za-z_-]{35}',
            'type': 'google_api_key',
            'severity': 'HIGH',
            'remediation': 'Revoke API key. Use Google Cloud Secret Manager.',
        },
        {
            'name': 'Google OAuth Token',
            'pattern': r'ya29\.[0-9A-Za-z_-]+',
            'type': 'google_oauth',
            'severity': 'CRITICAL',
            'remediation': 'Revoke OAuth token immediately.',
        },
        # Slack
        {
            'name': 'Slack Token',
            'pattern': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24,32}',
            'type': 'slack_token',
            'severity': 'HIGH',
            'remediation': 'Revoke Slack token. Use environment variables.',
        },
        {
            'name': 'Slack Webhook',
            'pattern': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
            'type': 'slack_webhook',
            'severity': 'MEDIUM',
            'remediation': 'Rotate Slack webhook URL.',
        },
        # Generic Secrets
        {
            'name': 'Generic API Key',
            'pattern': r'(?i)(?:api|app)(?:_|-)?key["\']?\s*[:=]\s*["\']?([0-9a-zA-Z_-]{32,})',
            'type': 'generic_api_key',
            'severity': 'HIGH',
            'remediation': 'Remove hardcoded API key. Use environment variables or secret management.',
        },
        {
            'name': 'Generic Secret',
            'pattern': r'(?i)(?:secret|password|passwd|pwd|token)["\']?\s*[:=]\s*["\']?([^\s"\']{12,})',
            'type': 'generic_secret',
            'severity': 'HIGH',
            'remediation': 'Remove hardcoded secret. Use environment variables.',
        },
        # Private Keys
        {
            'name': 'RSA Private Key',
            'pattern': r'-----BEGIN RSA PRIVATE KEY-----',
            'type': 'rsa_private_key',
            'severity': 'CRITICAL',
            'remediation': 'Remove private key. Never commit private keys to version control.',
        },
        {
            'name': 'SSH Private Key',
            'pattern': r'-----BEGIN OPENSSH PRIVATE KEY-----',
            'type': 'ssh_private_key',
            'severity': 'CRITICAL',
            'remediation': 'Remove SSH private key immediately.',
        },
        {
            'name': 'PGP Private Key',
            'pattern': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
            'type': 'pgp_private_key',
            'severity': 'CRITICAL',
            'remediation': 'Remove PGP private key immediately.',
        },
        # Database
        {
            'name': 'Database Connection String',
            'pattern': r'(?i)(?:mysql|postgres|postgresql|mongodb)://[^\s"\']+',
            'type': 'database_connection',
            'severity': 'HIGH',
            'remediation': 'Remove connection string. Use environment variables.',
        },
        {
            'name': 'JDBC Connection String',
            'pattern': r'jdbc:[^\s"\']+',
            'type': 'jdbc_connection',
            'severity': 'MEDIUM',
            'remediation': 'Remove JDBC connection string. Use configuration files.',
        },
        # JWT
        {
            'name': 'JSON Web Token',
            'pattern': r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
            'type': 'jwt_token',
            'severity': 'MEDIUM',
            'remediation': 'Remove hardcoded JWT. Use secure token storage.',
        },
        # Stripe
        {
            'name': 'Stripe API Key',
            'pattern': r'(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}',
            'type': 'stripe_api_key',
            'severity': 'CRITICAL',
            'remediation': 'Revoke Stripe key immediately. Use environment variables.',
        },
        # Twilio
        {
            'name': 'Twilio API Key',
            'pattern': r'SK[0-9a-fA-F]{32}',
            'type': 'twilio_api_key',
            'severity': 'HIGH',
            'remediation': 'Revoke Twilio API key. Use environment variables.',
        },
        # SendGrid
        {
            'name': 'SendGrid API Key',
            'pattern': r'SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}',
            'type': 'sendgrid_api_key',
            'severity': 'HIGH',
            'remediation': 'Revoke SendGrid API key. Use environment variables.',
        },
        # MailChimp
        {
            'name': 'MailChimp API Key',
            'pattern': r'[0-9a-f]{32}-us[0-9]{1,2}',
            'type': 'mailchimp_api_key',
            'severity': 'HIGH',
            'remediation': 'Revoke MailChimp API key immediately.',
        },
        # PayPal
        {
            'name': 'PayPal Braintree Access Token',
            'pattern': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
            'type': 'paypal_token',
            'severity': 'CRITICAL',
            'remediation': 'Revoke PayPal token immediately.',
        },
        # Cloudinary
        {
            'name': 'Cloudinary URL',
            'pattern': r'cloudinary://[0-9]+:[0-9A-Za-z_-]+@[a-z]+',
            'type': 'cloudinary_url',
            'severity': 'MEDIUM',
            'remediation': 'Remove Cloudinary URL. Use environment variables.',
        },
        # Firebase
        {
            'name': 'Firebase URL',
            'pattern': r'.*firebaseio\.com',
            'type': 'firebase_url',
            'severity': 'LOW',
            'remediation': 'Review Firebase security rules.',
        },
        # Heroku
        {
            'name': 'Heroku API Key',
            'pattern': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
            'type': 'heroku_api_key',
            'severity': 'HIGH',
            'remediation': 'Revoke Heroku API key. Use Heroku CLI for authentication.',
        },
    ]

    # Files to ignore
    IGNORE_PATTERNS = [
        r'\.git/',
        r'node_modules/',
        r'vendor/',
        r'\.pyc$',
        r'\.lock$',
        r'\.min\.js$',
        r'\.map$',
        r'package-lock\.json$',
        r'yarn\.lock$',
        r'poetry\.lock$',
    ]

    # File extensions to scan
    SCANNABLE_EXTENSIONS = {
        '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb', '.php',
        '.sh', '.bash', '.zsh', '.env', '.yml', '.yaml', '.json', '.xml',
        '.config', '.conf', '.ini', '.properties', '.tf', '.tfvars', '.rs',
        '.c', '.cpp', '.h', '.cs', '.swift', '.kt', '.scala', '.sql', '.txt',
        '.md', '.rst',
    }

    def __init__(
        self,
        entropy_threshold: float = 4.5,
        scan_git_history: bool = False,
        max_commits: int = 100,
    ):
        """
        Initialize secrets scanner

        Args:
            entropy_threshold: Minimum Shannon entropy for high-entropy string detection
            scan_git_history: Whether to scan git commit history
            max_commits: Maximum number of commits to scan in history
        """
        self.entropy_threshold = entropy_threshold
        self.scan_git_history = scan_git_history
        self.max_commits = max_commits

        # Compile patterns
        self.compiled_patterns = []
        for pattern_def in self.SECRET_PATTERNS:
            self.compiled_patterns.append({
                **pattern_def,
                'regex': re.compile(pattern_def['pattern']),
            })

    async def scan_path(
        self,
        path: str,
        scan_type: str = "filesystem",
    ) -> SecretScanResult:
        """
        Scan path for secrets

        Args:
            path: Path to scan (file or directory)
            scan_type: Type of scan (filesystem, git_history)

        Returns:
            SecretScanResult with findings
        """
        result = SecretScanResult(
            target_path=path,
            scan_type=scan_type,
            scan_time=datetime.utcnow(),
        )

        target_path = Path(path)

        if target_path.is_file():
            await self._scan_file(target_path, result)
        elif target_path.is_dir():
            await self._scan_directory(target_path, result)

        # Scan git history if enabled
        if self.scan_git_history and (target_path / '.git').exists():
            await self._scan_git_history(target_path, result)

        return result

    async def _scan_directory(
        self,
        directory: Path,
        result: SecretScanResult,
    ) -> None:
        """Scan directory recursively"""
        for file_path in directory.rglob('*'):
            if file_path.is_file():
                # Check if file should be scanned
                if self._should_scan_file(file_path):
                    await self._scan_file(file_path, result)

    def _should_scan_file(
        self,
        file_path: Path,
    ) -> bool:
        """Check if file should be scanned"""
        # Check ignore patterns
        file_str = str(file_path)
        for ignore_pattern in self.IGNORE_PATTERNS:
            if re.search(ignore_pattern, file_str):
                return False

        # Check extension
        return file_path.suffix in self.SCANNABLE_EXTENSIONS or file_path.name.startswith('.')

    async def _scan_file(
        self,
        file_path: Path,
        result: SecretScanResult,
    ) -> None:
        """Scan individual file for secrets"""
        try:
            content = file_path.read_text(errors='ignore')
            lines = content.split('\n')

            result.files_scanned += 1

            for line_num, line in enumerate(lines, start=1):
                # Check against all patterns
                for pattern_def in self.compiled_patterns:
                    matches = pattern_def['regex'].finditer(line)

                    for match in matches:
                        # Extract the secret value (first group if exists, otherwise full match)
                        secret_value = match.group(1) if match.groups() else match.group(0)

                        # Calculate entropy
                        entropy = self._calculate_entropy(secret_value)

                        # Redact the secret for display
                        redacted = self._redact_secret(secret_value)

                        finding = SecretFinding(
                            secret_type=pattern_def['type'],
                            severity=pattern_def['severity'],
                            file_path=str(file_path),
                            line_number=line_num,
                            matched_string=redacted,
                            pattern_name=pattern_def['name'],
                            entropy=entropy,
                            remediation=pattern_def['remediation'],
                            confidence='HIGH',
                        )

                        result.findings.append(finding)

                # Also check for high-entropy strings
                high_entropy_findings = self._detect_high_entropy_secrets(
                    line,
                    str(file_path),
                    line_num,
                )
                result.findings.extend(high_entropy_findings)

        except Exception as e:
            result.metadata[f'scan_error_{file_path}'] = str(e)

    def _calculate_entropy(
        self,
        string: str,
    ) -> float:
        """
        Calculate Shannon entropy of a string

        Args:
            string: Input string

        Returns:
            Shannon entropy value
        """
        if not string:
            return 0.0

        # Count character frequencies
        char_freq = Counter(string)
        length = len(string)

        # Calculate Shannon entropy
        entropy = 0.0
        for count in char_freq.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def _detect_high_entropy_secrets(
        self,
        line: str,
        file_path: str,
        line_number: int,
    ) -> list[SecretFinding]:
        """Detect high-entropy strings that may be secrets"""
        findings = []

        # Pattern for variable assignments with high-entropy values
        assignment_pattern = r'[\w_]+\s*[:=]\s*["\']([A-Za-z0-9+/=_-]{20,})["\']'

        for match in re.finditer(assignment_pattern, line):
            value = match.group(1)
            entropy = self._calculate_entropy(value)

            if entropy >= self.entropy_threshold:
                # Skip if it matches known patterns (to avoid duplicates)
                is_duplicate = False
                for pattern_def in self.compiled_patterns:
                    if pattern_def['regex'].search(value):
                        is_duplicate = True
                        break

                if not is_duplicate:
                    redacted = self._redact_secret(value)

                    finding = SecretFinding(
                        secret_type='high_entropy_string',
                        severity='MEDIUM',
                        file_path=file_path,
                        line_number=line_number,
                        matched_string=redacted,
                        pattern_name='High Entropy String',
                        entropy=entropy,
                        remediation='Review this high-entropy string. It may be a secret.',
                        confidence='MEDIUM',
                    )

                    findings.append(finding)

        return findings

    def _redact_secret(
        self,
        secret: str,
    ) -> str:
        """Redact secret for safe display"""
        if len(secret) <= 8:
            return '*' * len(secret)

        # Show first 4 and last 4 characters
        return f"{secret[:4]}{'*' * (len(secret) - 8)}{secret[-4:]}"

    async def _scan_git_history(
        self,
        repo_path: Path,
        result: SecretScanResult,
    ) -> None:
        """Scan git commit history for secrets"""
        try:
            # Get git log
            process = await asyncio.create_subprocess_exec(
                'git',
                'log',
                '--all',
                '--pretty=format:%H|%an|%ai',
                f'-{self.max_commits}',
                cwd=repo_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                result.metadata['git_history_error'] = stderr.decode()
                return

            commits = stdout.decode().strip().split('\n')
            result.commits_scanned = len(commits)

            for commit_line in commits:
                parts = commit_line.split('|')
                if len(parts) < 3:
                    continue

                commit_hash, author, date = parts[0], parts[1], parts[2]

                # Get commit diff
                diff_process = await asyncio.create_subprocess_exec(
                    'git',
                    'show',
                    commit_hash,
                    cwd=repo_path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                diff_stdout, _ = await diff_process.communicate()

                if diff_process.returncode == 0:
                    diff_content = diff_stdout.decode(errors='ignore')
                    lines = diff_content.split('\n')

                    for line_num, line in enumerate(lines, start=1):
                        # Only scan added lines
                        if line.startswith('+') and not line.startswith('+++'):
                            for pattern_def in self.compiled_patterns:
                                matches = pattern_def['regex'].finditer(line)

                                for match in matches:
                                    secret_value = match.group(1) if match.groups() else match.group(0)
                                    entropy = self._calculate_entropy(secret_value)
                                    redacted = self._redact_secret(secret_value)

                                    finding = SecretFinding(
                                        secret_type=pattern_def['type'],
                                        severity=pattern_def['severity'],
                                        file_path='git_history',
                                        line_number=line_num,
                                        matched_string=redacted,
                                        pattern_name=pattern_def['name'],
                                        entropy=entropy,
                                        commit_hash=commit_hash[:8],
                                        commit_author=author,
                                        commit_date=date,
                                        remediation=f"{pattern_def['remediation']} Found in commit history.",
                                        confidence='HIGH',
                                    )

                                    result.findings.append(finding)

        except Exception as e:
            result.metadata['git_history_scan_error'] = str(e)


async def scan_for_secrets(
    path: str,
    scan_git_history: bool = False,
) -> SecretScanResult:
    """
    Convenience function to scan for secrets

    Args:
        path: Path to scan
        scan_git_history: Whether to scan git history

    Returns:
        SecretScanResult with findings
    """
    scanner = SecretsScanner(scan_git_history=scan_git_history)
    return await scanner.scan_path(path)


if __name__ == "__main__":
    import sys

    async def main():
        if len(sys.argv) < 2:
            print("Usage: python secrets_scanner.py <path> [--git-history]")
            sys.exit(1)

        scan_path = sys.argv[1]
        scan_git = '--git-history' in sys.argv

        print(f"Scanning for secrets in: {scan_path}")
        if scan_git:
            print("Including git history scan")

        result = await scan_for_secrets(scan_path, scan_git_history=scan_git)

        print("\n=== Secrets Scan Results ===")
        print(f"Files Scanned: {result.files_scanned}")
        if result.commits_scanned:
            print(f"Commits Scanned: {result.commits_scanned}")
        print("\nFindings:")
        print(f"  Critical: {result.critical_count}")
        print(f"  High: {result.high_count}")
        print(f"  Medium: {result.medium_count}")
        print(f"  Low: {result.low_count}")

        if result.findings:
            print("\n=== Discovered Secrets ===")
            for finding in sorted(
                result.findings,
                key=lambda f: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}.get(f.severity, 4)
            )[:20]:
                print(f"\n[{finding.severity}] {finding.pattern_name}")
                print(f"  File: {finding.file_path}:{finding.line_number}")
                print(f"  Type: {finding.secret_type}")
                print(f"  Value: {finding.matched_string}")
                if finding.commit_hash:
                    print(f"  Commit: {finding.commit_hash} by {finding.commit_author}")
                print(f"  Remediation: {finding.remediation}")

    asyncio.run(main())
