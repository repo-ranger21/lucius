"""
JavaScript/TypeScript parser for detecting security vulnerabilities.
"""

import re
from pathlib import Path
from typing import List, Dict, Any


class JavaScriptParser:
    """Parser for analyzing JavaScript/TypeScript code for security vulnerabilities."""
    
    def __init__(self):
        """Initialize the JavaScript parser with vulnerability patterns."""
        self.vulnerability_patterns = {
            "eval_usage": {
                "pattern": r'\beval\s*\(',
                "severity": "critical",
                "description": "Use of eval() - code injection risk"
            },
            "innerhtml": {
                "pattern": r'\.innerHTML\s*=',
                "severity": "high",
                "description": "Direct innerHTML assignment - XSS vulnerability"
            },
            "document_write": {
                "pattern": r'document\.write\s*\(',
                "severity": "medium",
                "description": "Use of document.write - potential XSS"
            },
            "console_log": {
                "pattern": r'console\.(log|debug|info)\s*\(',
                "severity": "low",
                "description": "Console statements in production code"
            },
            "unsafe_redirect": {
                "pattern": r'window\.location\s*=|location\.href\s*=',
                "severity": "medium",
                "description": "Unsafe redirect - potential open redirect vulnerability"
            },
            "local_storage": {
                "pattern": r'localStorage\.(setItem|getItem)',
                "severity": "low",
                "description": "Use of localStorage - ensure no sensitive data stored"
            },
            "sql_injection": {
                "pattern": r'query\s*\([^)]*\+',
                "severity": "high",
                "description": "Potential SQL injection in database query"
            },
            "weak_random": {
                "pattern": r'Math\.random\s*\(',
                "severity": "medium",
                "description": "Use of Math.random() - not cryptographically secure"
            }
        }
    
    def parse(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        Parse a JavaScript/TypeScript file and detect security vulnerabilities.
        
        Args:
            file_path: Path to the JS/TS file to analyze
            
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
                    # Skip comments
                    if line.strip().startswith('//') or line.strip().startswith('*'):
                        continue
                        
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
