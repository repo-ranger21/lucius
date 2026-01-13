"""
Python parser for detecting security vulnerabilities in Python code.
"""

import re
from pathlib import Path
from typing import List, Dict, Any


class PythonParser:
    """Parser for analyzing Python source code for security vulnerabilities."""
    
    def __init__(self):
        """Initialize the Python parser with vulnerability patterns."""
        self.vulnerability_patterns = {
            "sql_injection": {
                "pattern": r'(execute|cursor\.execute|query)\s*\([^)]*(\+|%|\.format\(|f["\'])(?!["\'])',
                "severity": "high",
                "description": "Potential SQL injection vulnerability"
            },
            "command_injection": {
                "pattern": r'os\.system\s*\(|subprocess\.call\s*\([^)]*shell\s*=\s*True',
                "severity": "critical",
                "description": "Potential command injection vulnerability"
            },
            "hardcoded_password": {
                "pattern": r'(password|passwd|pwd|pass)\s*=\s*["\'][^"\']{3,}["\']',
                "severity": "high",
                "description": "Hardcoded password detected"
            },
            "eval_usage": {
                "pattern": r'\beval\s*\(',
                "severity": "critical",
                "description": "Use of eval() function - code injection risk"
            },
            "pickle_usage": {
                "pattern": r'pickle\.loads?\s*\(',
                "severity": "medium",
                "description": "Pickle deserialization - potential code execution"
            },
            "weak_crypto": {
                "pattern": r'hashlib\.(md5|sha1)\s*\(',
                "severity": "medium",
                "description": "Use of weak cryptographic hash function"
            },
            "debug_mode": {
                "pattern": r'DEBUG\s*=\s*True',
                "severity": "low",
                "description": "Debug mode enabled - potential information disclosure"
            }
        }
    
    def parse(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        Parse a Python file and detect security vulnerabilities.
        
        Args:
            file_path: Path to the Python file to analyze
            
        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
                
            for vuln_type, vuln_config in self.vulnerability_patterns.items():
                pattern = vuln_config["pattern"]
                
                for line_num, line in enumerate(lines, start=1):
                    if re.search(pattern, line, re.IGNORECASE):
                        vulnerabilities.append({
                            "type": vuln_type,
                            "file": str(file_path),
                            "line": line_num,
                            "severity": vuln_config["severity"],
                            "description": vuln_config["description"],
                            "code_snippet": line.strip()
                        })
        
        except Exception as e:
            print(f"Error parsing {file_path}: {e}")
        
        return vulnerabilities
