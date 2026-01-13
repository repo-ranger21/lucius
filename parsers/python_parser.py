"""
Python language parser for vulnerability scanning.

Identifies common security vulnerabilities in Python code such as:
- SQL injection risks
- Command injection risks
- Insecure deserialization
- Hard-coded credentials
- And more
"""

from pathlib import Path
from typing import Dict, List, Any
import re

from . import BaseParser


class PythonParser(BaseParser):
    """Parser for Python source code."""
    
    def __init__(self):
        super().__init__()
        # Patterns for common vulnerabilities
        self.patterns = {
            'sql_injection': [
                r'execute\([^)]*%[^)]*\)',  # String formatting in SQL
                r'executemany\([^)]*%[^)]*\)',
                r'\.format\([^)]*\).*execute',
            ],
            'command_injection': [
                r'os\.system\([^)]*\+',  # Concatenation in os.system
                r'subprocess\.(call|run|Popen).*shell=True',
            ],
            'hardcoded_credentials': [
                r'password\s*=\s*["\'][^"\']+["\']',
                r'api_key\s*=\s*["\'][^"\']+["\']',
                r'secret\s*=\s*["\'][^"\']+["\']',
            ],
            'insecure_deserialization': [
                r'pickle\.loads',
                r'yaml\.load\([^,)]*\)(?!\s*,\s*Loader\s*=\s*yaml\.SafeLoader)',  # Without SafeLoader
            ],
        }
    
    def parse(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        Parse a Python file for vulnerabilities.
        
        Args:
            file_path: Path to the Python file
            
        Returns:
            List of vulnerability findings
        """
        vulnerabilities = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
                
                for vuln_type, patterns in self.patterns.items():
                    for pattern in patterns:
                        for line_num, line in enumerate(lines, 1):
                            if re.search(pattern, line, re.IGNORECASE):
                                vulnerabilities.append({
                                    'type': vuln_type,
                                    'file': str(file_path),
                                    'line': line_num,
                                    'code': line.strip(),
                                    'severity': self._get_severity(vuln_type),
                                })
        except Exception as e:
            print(f"Error parsing {file_path}: {e}")
        
        return vulnerabilities
    
    def get_supported_extensions(self) -> List[str]:
        """Return Python file extensions."""
        return ['.py', '.pyw']
    
    def _get_severity(self, vuln_type: str) -> str:
        """Determine severity level for a vulnerability type."""
        severity_map = {
            'sql_injection': 'high',
            'command_injection': 'high',
            'hardcoded_credentials': 'medium',
            'insecure_deserialization': 'high',
        }
        return severity_map.get(vuln_type, 'medium')


__all__ = ['PythonParser']
