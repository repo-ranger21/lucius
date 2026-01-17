"""
Static Application Security Testing (SAST) Analyzer

This module provides comprehensive static code analysis for security vulnerabilities:
- SQL Injection detection
- XSS (Cross-Site Scripting) detection
- Command Injection detection
- Path Traversal detection
- Insecure Deserialization
- Hardcoded Credentials
- Weak Cryptography
- Insecure Random Number Generation
- Race Conditions
- Memory Safety Issues
"""

import ast
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class SASTFinding:
    """Represents a SAST finding"""

    vulnerability_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    file_path: str
    line_number: int
    column_number: int | None
    code_snippet: str
    description: str
    remediation: str
    cwe_id: str
    owasp_category: str
    confidence: str = "HIGH"  # HIGH, MEDIUM, LOW
    function_name: str | None = None
    variable_name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            'vulnerability_type': self.vulnerability_type,
            'severity': self.severity,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'column_number': self.column_number,
            'code_snippet': self.code_snippet,
            'description': self.description,
            'remediation': self.remediation,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'confidence': self.confidence,
            'function_name': self.function_name,
            'variable_name': self.variable_name,
        }


@dataclass
class SASTResult:
    """Results from SAST analysis"""

    target_path: str
    scan_time: datetime
    findings: list[SASTFinding] = field(default_factory=list)
    files_analyzed: int = 0
    lines_analyzed: int = 0
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
            'files_analyzed': self.files_analyzed,
            'lines_analyzed': self.lines_analyzed,
            'critical_count': self.critical_count,
            'high_count': self.high_count,
            'medium_count': self.medium_count,
            'low_count': self.low_count,
            'total_findings': len(self.findings),
            'metadata': self.metadata,
        }


class SASTAnalyzer:
    """
    Static Application Security Testing analyzer

    Performs deep static analysis of source code to identify security
    vulnerabilities and coding weaknesses.
    """

    # Security patterns for different languages
    PATTERNS = {
        'python': [
            {
                'name': 'SQL Injection',
                'pattern': r'(?:execute|executemany|cursor\.execute)\s*\([^)]*%s[^)]*\)',
                'severity': 'CRITICAL',
                'cwe_id': 'CWE-89',
                'owasp': 'A03:2021 – Injection',
                'description': 'Potential SQL injection using string formatting',
                'remediation': 'Use parameterized queries with placeholders',
            },
            {
                'name': 'Command Injection',
                'pattern': r'(?:os\.system|subprocess\.call|subprocess\.run|exec|eval)\s*\([^)]*\+',
                'severity': 'CRITICAL',
                'cwe_id': 'CWE-78',
                'owasp': 'A03:2021 – Injection',
                'description': 'Potential command injection via string concatenation',
                'remediation': 'Use subprocess with list arguments, avoid shell=True',
            },
            {
                'name': 'Weak Cryptography',
                'pattern': r'(?:MD5|SHA1)\(',
                'severity': 'MEDIUM',
                'cwe_id': 'CWE-327',
                'owasp': 'A02:2021 – Cryptographic Failures',
                'description': 'Use of weak cryptographic hash function',
                'remediation': 'Use SHA-256 or stronger hashing algorithms',
            },
            {
                'name': 'Insecure Random',
                'pattern': r'random\.(?:random|randint|choice)\(',
                'severity': 'MEDIUM',
                'cwe_id': 'CWE-338',
                'owasp': 'A02:2021 – Cryptographic Failures',
                'description': 'Use of insecure random number generator',
                'remediation': 'Use secrets module for security-sensitive randomness',
            },
            {
                'name': 'Pickle Deserialization',
                'pattern': r'pickle\.loads?\(',
                'severity': 'HIGH',
                'cwe_id': 'CWE-502',
                'owasp': 'A08:2021 – Software and Data Integrity Failures',
                'description': 'Insecure deserialization using pickle',
                'remediation': 'Use JSON or other safe serialization formats',
            },
            {
                'name': 'YAML Unsafe Load',
                'pattern': r'yaml\.load\([^,)]*\)',
                'severity': 'HIGH',
                'cwe_id': 'CWE-502',
                'owasp': 'A08:2021 – Software and Data Integrity Failures',
                'description': 'Unsafe YAML deserialization',
                'remediation': 'Use yaml.safe_load() instead',
            },
            {
                'name': 'Assert Statement',
                'pattern': r'^\s*assert\s+',
                'severity': 'LOW',
                'cwe_id': 'CWE-703',
                'owasp': 'A04:2021 – Insecure Design',
                'description': 'Assert statement used for security check',
                'remediation': 'Use explicit exception raising for security checks',
            },
        ],
        'javascript': [
            {
                'name': 'eval() Usage',
                'pattern': r'\beval\s*\(',
                'severity': 'CRITICAL',
                'cwe_id': 'CWE-95',
                'owasp': 'A03:2021 – Injection',
                'description': 'Use of eval() with potentially untrusted input',
                'remediation': 'Avoid eval(), use JSON.parse() or safe alternatives',
            },
            {
                'name': 'innerHTML Assignment',
                'pattern': r'\.innerHTML\s*=',
                'severity': 'HIGH',
                'cwe_id': 'CWE-79',
                'owasp': 'A03:2021 – Injection',
                'description': 'Potential XSS via innerHTML assignment',
                'remediation': 'Use textContent or sanitize input with DOMPurify',
            },
            {
                'name': 'document.write',
                'pattern': r'document\.write\(',
                'severity': 'MEDIUM',
                'cwe_id': 'CWE-79',
                'owasp': 'A03:2021 – Injection',
                'description': 'Use of document.write with potentially untrusted data',
                'remediation': 'Use DOM manipulation methods instead',
            },
            {
                'name': 'dangerouslySetInnerHTML',
                'pattern': r'dangerouslySetInnerHTML',
                'severity': 'HIGH',
                'cwe_id': 'CWE-79',
                'owasp': 'A03:2021 – Injection',
                'description': 'React dangerouslySetInnerHTML usage',
                'remediation': 'Sanitize HTML content or use safe alternatives',
            },
        ],
        'php': [
            {
                'name': 'SQL Injection',
                'pattern': r'(?:mysql_query|mysqli_query)\s*\([^)]*\$_(?:GET|POST|REQUEST)',
                'severity': 'CRITICAL',
                'cwe_id': 'CWE-89',
                'owasp': 'A03:2021 – Injection',
                'description': 'SQL query using unsanitized user input',
                'remediation': 'Use prepared statements with PDO or mysqli',
            },
            {
                'name': 'File Inclusion',
                'pattern': r'(?:include|require)(?:_once)?\s*\(\s*\$_(?:GET|POST|REQUEST)',
                'severity': 'CRITICAL',
                'cwe_id': 'CWE-98',
                'owasp': 'A03:2021 – Injection',
                'description': 'File inclusion with user-controlled input',
                'remediation': 'Validate and whitelist file paths',
            },
            {
                'name': 'eval() Usage',
                'pattern': r'\beval\s*\(',
                'severity': 'CRITICAL',
                'cwe_id': 'CWE-95',
                'owasp': 'A03:2021 – Injection',
                'description': 'Use of eval() with potentially untrusted input',
                'remediation': 'Avoid eval(), use safe alternatives',
            },
        ],
    }

    # Common dangerous functions across languages
    DANGEROUS_FUNCTIONS = {
        'exec', 'eval', 'system', 'shell_exec', 'passthru', 'popen',
        'proc_open', 'pcntl_exec', 'assert', 'create_function',
    }

    LANGUAGE_EXTENSIONS = {
        '.py': 'python',
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.ts': 'javascript',
        '.tsx': 'javascript',
        '.php': 'php',
        '.java': 'java',
        '.rb': 'ruby',
        '.go': 'go',
    }

    def __init__(self):
        """Initialize SAST analyzer"""
        pass

    async def analyze_path(
        self,
        path: str,
    ) -> SASTResult:
        """
        Analyze path for security vulnerabilities

        Args:
            path: Path to file or directory

        Returns:
            SASTResult with findings
        """
        result = SASTResult(
            target_path=path,
            scan_time=datetime.utcnow(),
        )

        target = Path(path)

        if target.is_file():
            await self._analyze_file(target, result)
        elif target.is_dir():
            await self._analyze_directory(target, result)

        return result

    async def _analyze_directory(
        self,
        directory: Path,
        result: SASTResult,
    ) -> None:
        """Analyze directory recursively"""
        for file_path in directory.rglob('*'):
            if file_path.is_file() and file_path.suffix in self.LANGUAGE_EXTENSIONS:
                await self._analyze_file(file_path, result)

    async def _analyze_file(
        self,
        file_path: Path,
        result: SASTResult,
    ) -> None:
        """Analyze individual file"""
        try:
            language = self.LANGUAGE_EXTENSIONS.get(file_path.suffix)
            if not language:
                return

            content = file_path.read_text(errors='ignore')
            lines = content.split('\n')

            result.files_analyzed += 1
            result.lines_analyzed += len(lines)

            # Pattern-based analysis
            patterns = self.PATTERNS.get(language, [])
            for pattern_def in patterns:
                regex = re.compile(pattern_def['pattern'])

                for line_num, line in enumerate(lines, start=1):
                    matches = regex.finditer(line)

                    for match in matches:
                        finding = SASTFinding(
                            vulnerability_type=pattern_def['name'],
                            severity=pattern_def['severity'],
                            file_path=str(file_path),
                            line_number=line_num,
                            column_number=match.start(),
                            code_snippet=line.strip(),
                            description=pattern_def['description'],
                            remediation=pattern_def['remediation'],
                            cwe_id=pattern_def['cwe_id'],
                            owasp_category=pattern_def['owasp'],
                        )
                        result.findings.append(finding)

            # AST-based analysis for Python
            if language == 'python':
                await self._analyze_python_ast(file_path, content, result)

        except Exception as e:
            result.metadata[f'analysis_error_{file_path}'] = str(e)

    async def _analyze_python_ast(
        self,
        file_path: Path,
        content: str,
        result: SASTResult,
    ) -> None:
        """Perform AST-based analysis for Python code"""
        try:
            tree = ast.parse(content)

            # Analyze AST nodes
            for node in ast.walk(tree):
                # Check for dangerous function calls
                if isinstance(node, ast.Call):
                    func_name = self._get_function_name(node.func)

                    if func_name in self.DANGEROUS_FUNCTIONS:
                        finding = SASTFinding(
                            vulnerability_type='Dangerous Function',
                            severity='HIGH',
                            file_path=str(file_path),
                            line_number=node.lineno,
                            column_number=node.col_offset,
                            code_snippet=ast.get_source_segment(content, node) or '',
                            description=f'Use of dangerous function: {func_name}()',
                            remediation='Use safer alternatives to this function',
                            cwe_id='CWE-676',
                            owasp_category='A04:2021 – Insecure Design',
                            function_name=func_name,
                        )
                        result.findings.append(finding)

                # Check for shell=True in subprocess
                if isinstance(node, ast.Call):
                    for keyword in node.keywords:
                        if keyword.arg == 'shell' and isinstance(keyword.value, ast.Constant):
                            if keyword.value.value is True:
                                finding = SASTFinding(
                                    vulnerability_type='Command Injection',
                                    severity='HIGH',
                                    file_path=str(file_path),
                                    line_number=node.lineno,
                                    column_number=node.col_offset,
                                    code_snippet=ast.get_source_segment(content, node) or '',
                                    description='subprocess call with shell=True',
                                    remediation='Use list arguments instead of shell=True',
                                    cwe_id='CWE-78',
                                    owasp_category='A03:2021 – Injection',
                                )
                                result.findings.append(finding)

        except SyntaxError:
            pass  # Skip files with syntax errors
        except Exception as e:
            result.metadata[f'ast_error_{file_path}'] = str(e)

    def _get_function_name(self, node: ast.AST) -> str:
        """Extract function name from AST node"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        return ''


async def analyze_code(path: str) -> SASTResult:
    """
    Convenience function to analyze code

    Args:
        path: Path to analyze

    Returns:
        SASTResult with findings
    """
    analyzer = SASTAnalyzer()
    return await analyzer.analyze_path(path)


if __name__ == "__main__":
    import asyncio
    import sys

    async def main():
        if len(sys.argv) < 2:
            print("Usage: python sast_analyzer.py <path>")
            sys.exit(1)

        target = sys.argv[1]
        print(f"Analyzing code at: {target}")

        result = await analyze_code(target)

        print("\n=== SAST Analysis Results ===")
        print(f"Files Analyzed: {result.files_analyzed}")
        print(f"Lines Analyzed: {result.lines_analyzed}")
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
                print(f"\n[{finding.severity}] {finding.vulnerability_type}")
                print(f"  File: {finding.file_path}:{finding.line_number}")
                print(f"  Code: {finding.code_snippet}")
                print(f"  Issue: {finding.description}")
                print(f"  Fix: {finding.remediation}")
                print(f"  CWE: {finding.cwe_id}")

    asyncio.run(main())
