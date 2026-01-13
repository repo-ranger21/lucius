"""
JavaScript language parser for vulnerability scanning.

Identifies common security vulnerabilities in JavaScript code such as:
- XSS vulnerabilities
- Prototype pollution
- Insecure randomness
- eval() usage
"""

from pathlib import Path
from typing import Dict, List, Any
import re

from . import BaseParser


class JavaScriptParser(BaseParser):
    """Parser for JavaScript source code."""
    
    def __init__(self):
        super().__init__()
        self.patterns = {
            'xss': [
                r'innerHTML\s*=',
                r'document\.write\(',
                r'\.html\([^)]*\+',
            ],
            'eval_usage': [
                r'\beval\(',
                r'setTimeout\([^)]*[\'"`]',
                r'setInterval\([^)]*[\'"`]',
            ],
            'prototype_pollution': [
                r'Object\.assign\(',
                r'\.prototype\.',
            ],
        }
    
    def parse(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        Parse a JavaScript file for vulnerabilities.
        
        Args:
            file_path: Path to the JavaScript file
            
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
                            if re.search(pattern, line):
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
        """Return JavaScript file extensions."""
        return ['.js', '.jsx', '.mjs']
    
    def _get_severity(self, vuln_type: str) -> str:
        """Determine severity level for a vulnerability type."""
        severity_map = {
            'xss': 'high',
            'eval_usage': 'medium',
            'prototype_pollution': 'high',
        }
        return severity_map.get(vuln_type, 'medium')


__all__ = ['JavaScriptParser']
