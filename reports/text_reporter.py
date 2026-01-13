"""
Text report generator for vulnerability scan results.
"""

from typing import Dict, Any


class TextReporter:
    """Reporter that outputs scan results in plain text format."""
    
    def generate(self, results: Dict[str, Any]) -> str:
        """
        Generate a plain text report from scan results.
        
        Args:
            results: Dictionary containing scan results
            
        Returns:
            Text-formatted string
        """
        summary = results.get("summary", {})
        vulnerabilities = results.get("vulnerabilities", [])
        
        # Sort vulnerabilities by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: severity_order.get(v.get("severity", "info").lower(), 4)
        )
        
        lines = []
        lines.append("=" * 80)
        lines.append("LUCIUS SENTINEL - SECURITY SCAN REPORT")
        lines.append("=" * 80)
        lines.append("")
        lines.append(f"Target:     {results.get('target', 'N/A')}")
        lines.append(f"Scan Type:  {results.get('scan_type', 'N/A')}")
        lines.append("")
        
        lines.append("-" * 80)
        lines.append("SUMMARY")
        lines.append("-" * 80)
        lines.append(f"Files Scanned:  {summary.get('files_scanned', 0)} / {summary.get('total_files', 0)}")
        lines.append("")
        lines.append(f"Critical:  {summary.get('critical', 0)}")
        lines.append(f"High:      {summary.get('high', 0)}")
        lines.append(f"Medium:    {summary.get('medium', 0)}")
        lines.append(f"Low:       {summary.get('low', 0)}")
        lines.append(f"Info:      {summary.get('info', 0)}")
        lines.append("")
        
        if not sorted_vulns:
            lines.append("-" * 80)
            lines.append("No vulnerabilities detected. ✅")
            lines.append("-" * 80)
        else:
            lines.append("-" * 80)
            lines.append(f"VULNERABILITIES ({len(sorted_vulns)} found)")
            lines.append("-" * 80)
            lines.append("")
            
            for i, vuln in enumerate(sorted_vulns, 1):
                severity = vuln.get("severity", "info").upper()
                lines.append(f"[{i}] {vuln.get('description', 'Unknown vulnerability')}")
                lines.append(f"    Severity: {severity}")
                lines.append(f"    Type:     {vuln.get('type', 'N/A')}")
                lines.append(f"    File:     {vuln.get('file', 'N/A')}")
                lines.append(f"    Line:     {vuln.get('line', 'N/A')}")
                lines.append(f"    Code:     {vuln.get('code_snippet', '')}")
                lines.append("")
        
        lines.append("=" * 80)
        
        return "\n".join(lines)
