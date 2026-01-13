"""
HTML report generator.

Outputs vulnerability scan results in HTML format for web viewing.
"""

from typing import Dict, List, Any
from datetime import datetime

from . import BaseReportGenerator


class HTMLReportGenerator(BaseReportGenerator):
    """Generates reports in HTML format."""
    
    def generate(self, vulnerabilities: List[Dict[str, Any]], output_path: str = None) -> str:
        """
        Generate an HTML report.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            output_path: Optional path to write the report to
            
        Returns:
            The generated HTML report as a string
        """
        severity_counts = self._count_by_severity(vulnerabilities)
        
        html_parts = []
        html_parts.append('<!DOCTYPE html>')
        html_parts.append('<html lang="en">')
        html_parts.append('<head>')
        html_parts.append('    <meta charset="UTF-8">')
        html_parts.append('    <meta name="viewport" content="width=device-width, initial-scale=1.0">')
        html_parts.append('    <title>Lucius Sentinel - Vulnerability Report</title>')
        html_parts.append('    <style>')
        html_parts.append('        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }')
        html_parts.append('        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }')
        html_parts.append('        h1 { color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }')
        html_parts.append('        .summary { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; }')
        html_parts.append('        .vulnerability { border-left: 4px solid #ddd; padding: 15px; margin: 15px 0; background-color: #fff; }')
        html_parts.append('        .vulnerability.high { border-left-color: #dc3545; }')
        html_parts.append('        .vulnerability.medium { border-left-color: #ffc107; }')
        html_parts.append('        .vulnerability.low { border-left-color: #28a745; }')
        html_parts.append('        .severity { display: inline-block; padding: 3px 10px; border-radius: 3px; font-weight: bold; font-size: 12px; }')
        html_parts.append('        .severity.high { background-color: #dc3545; color: white; }')
        html_parts.append('        .severity.medium { background-color: #ffc107; color: black; }')
        html_parts.append('        .severity.low { background-color: #28a745; color: white; }')
        html_parts.append('        code { background-color: #f4f4f4; padding: 2px 5px; border-radius: 3px; font-family: monospace; }')
        html_parts.append('        .meta { color: #666; font-size: 14px; }')
        html_parts.append('    </style>')
        html_parts.append('</head>')
        html_parts.append('<body>')
        html_parts.append('    <div class="container">')
        html_parts.append('        <h1>Lucius Sentinel - Vulnerability Scan Report</h1>')
        html_parts.append(f'        <p class="meta">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>')
        
        # Summary section
        html_parts.append('        <div class="summary">')
        html_parts.append('            <h2>Summary</h2>')
        html_parts.append(f'            <p><strong>Total Vulnerabilities:</strong> {len(vulnerabilities)}</p>')
        html_parts.append(f'            <p><span class="severity high">High: {severity_counts.get("high", 0)}</span> ')
        html_parts.append(f'            <span class="severity medium">Medium: {severity_counts.get("medium", 0)}</span> ')
        html_parts.append(f'            <span class="severity low">Low: {severity_counts.get("low", 0)}</span></p>')
        html_parts.append('        </div>')
        
        # Detailed findings
        html_parts.append('        <h2>Detailed Findings</h2>')
        
        if vulnerabilities:
            for i, vuln in enumerate(vulnerabilities, 1):
                severity = vuln.get('severity', 'low')
                html_parts.append(f'        <div class="vulnerability {severity}">')
                html_parts.append(f'            <h3>[{i}] {vuln.get("type", "unknown").replace("_", " ").title()}</h3>')
                html_parts.append(f'            <p><span class="severity {severity}">{severity.upper()}</span></p>')
                html_parts.append(f'            <p class="meta"><strong>File:</strong> {vuln.get("file", "unknown")}</p>')
                html_parts.append(f'            <p class="meta"><strong>Line:</strong> {vuln.get("line", "unknown")}</p>')
                html_parts.append(f'            <p><strong>Code:</strong> <code>{vuln.get("code", "N/A")}</code></p>')
                html_parts.append('        </div>')
        else:
            html_parts.append('        <p>No vulnerabilities found.</p>')
        
        html_parts.append('    </div>')
        html_parts.append('</body>')
        html_parts.append('</html>')
        
        html_output = '\n'.join(html_parts)
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_output)
        
        return html_output


__all__ = ['HTMLReportGenerator']
