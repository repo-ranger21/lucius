"""
Text report generator.

Outputs vulnerability scan results in a human-readable text format.
"""

from typing import Dict, List, Any
from datetime import datetime

from . import BaseReportGenerator


class TextReportGenerator(BaseReportGenerator):
    """Generates reports in plain text format."""
    
    def generate(self, vulnerabilities: List[Dict[str, Any]], output_path: str = None) -> str:
        """
        Generate a text report.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            output_path: Optional path to write the report to
            
        Returns:
            The generated text report as a string
        """
        lines = []
        lines.append("=" * 80)
        lines.append("LUCIUS SENTINEL - VULNERABILITY SCAN REPORT")
        lines.append("=" * 80)
        lines.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        
        # Summary
        severity_counts = self._count_by_severity(vulnerabilities)
        lines.append("SUMMARY")
        lines.append("-" * 80)
        lines.append(f"Total Vulnerabilities: {len(vulnerabilities)}")
        lines.append(f"  High Severity:   {severity_counts.get('high', 0)}")
        lines.append(f"  Medium Severity: {severity_counts.get('medium', 0)}")
        lines.append(f"  Low Severity:    {severity_counts.get('low', 0)}")
        lines.append("")
        
        # Detailed findings
        if vulnerabilities:
            lines.append("DETAILED FINDINGS")
            lines.append("-" * 80)
            
            for i, vuln in enumerate(vulnerabilities, 1):
                lines.append(f"\n[{i}] {vuln.get('type', 'unknown').upper()}")
                lines.append(f"    Severity: {vuln.get('severity', 'unknown').upper()}")
                lines.append(f"    File: {vuln.get('file', 'unknown')}")
                lines.append(f"    Line: {vuln.get('line', 'unknown')}")
                lines.append(f"    Code: {vuln.get('code', 'N/A')}")
        else:
            lines.append("No vulnerabilities found.")
        
        lines.append("")
        lines.append("=" * 80)
        
        text_output = "\n".join(lines)
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(text_output)
        
        return text_output


__all__ = ['TextReportGenerator']
