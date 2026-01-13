"""
Report generators for vulnerability scan results.

This package contains various report formatters that can output
vulnerability scan results in different formats (JSON, HTML, text, etc.).
"""

from typing import Dict, List, Any
from abc import ABC, abstractmethod


class BaseReportGenerator(ABC):
    """Base class for report generators."""
    
    def __init__(self):
        self.vulnerabilities = []
    
    @abstractmethod
    def generate(self, vulnerabilities: List[Dict[str, Any]], output_path: str = None) -> str:
        """
        Generate a report from the vulnerability data.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            output_path: Optional path to write the report to
            
        Returns:
            The generated report as a string
        """
        pass
    
    def _count_by_severity(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count vulnerabilities by severity level."""
        counts = {'high': 0, 'medium': 0, 'low': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low')
            counts[severity] = counts.get(severity, 0) + 1
        return counts


__all__ = ['BaseReportGenerator']
