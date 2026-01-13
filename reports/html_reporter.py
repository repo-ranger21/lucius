"""
HTML report generator for vulnerability scan results.
"""

import html
from typing import Dict, Any
from datetime import datetime


class HTMLReporter:
    """Reporter that outputs scan results in HTML format."""
    
    def generate(self, results: Dict[str, Any]) -> str:
        """
        Generate an HTML report from scan results.
        
        Args:
            results: Dictionary containing scan results
            
        Returns:
            HTML-formatted string
        """
        summary = results.get("summary", {})
        vulnerabilities = results.get("vulnerabilities", [])
        
        # Sort vulnerabilities by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: severity_order.get(v.get("severity", "info").lower(), 4)
        )
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Lucius Sentinel - Security Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .summary-box {{
            padding: 15px;
            border-radius: 6px;
            text-align: center;
        }}
        .critical {{ background-color: #e74c3c; color: white; }}
        .high {{ background-color: #e67e22; color: white; }}
        .medium {{ background-color: #f39c12; color: white; }}
        .low {{ background-color: #3498db; color: white; }}
        .info {{ background-color: #95a5a6; color: white; }}
        .summary-box h3 {{
            margin: 0;
            font-size: 32px;
        }}
        .summary-box p {{
            margin: 5px 0 0 0;
            font-size: 14px;
        }}
        .vulnerability {{
            border: 1px solid #ddd;
            border-left: 4px solid #3498db;
            margin: 15px 0;
            padding: 15px;
            border-radius: 4px;
            background-color: #f9f9f9;
        }}
        .vulnerability.critical {{
            border-left-color: #e74c3c;
        }}
        .vulnerability.high {{
            border-left-color: #e67e22;
        }}
        .vulnerability.medium {{
            border-left-color: #f39c12;
        }}
        .vulnerability.low {{
            border-left-color: #3498db;
        }}
        .vulnerability h3 {{
            margin-top: 0;
            color: #2c3e50;
        }}
        .vulnerability .severity {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 3px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .code-snippet {{
            background-color: #2c3e50;
            color: #ecf0f1;
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            margin-top: 10px;
        }}
        .meta {{
            color: #7f8c8d;
            font-size: 14px;
            margin-top: 10px;
        }}
        .timestamp {{
            text-align: right;
            color: #95a5a6;
            font-size: 12px;
            margin-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Lucius Sentinel Security Report</h1>
        
        <p><strong>Target:</strong> {results.get('target', 'N/A')}</p>
        <p><strong>Scan Type:</strong> {results.get('scan_type', 'N/A')}</p>
        
        <h2>Summary</h2>
        <div class="summary">
            <div class="summary-box critical">
                <h3>{summary.get('critical', 0)}</h3>
                <p>Critical</p>
            </div>
            <div class="summary-box high">
                <h3>{summary.get('high', 0)}</h3>
                <p>High</p>
            </div>
            <div class="summary-box medium">
                <h3>{summary.get('medium', 0)}</h3>
                <p>Medium</p>
            </div>
            <div class="summary-box low">
                <h3>{summary.get('low', 0)}</h3>
                <p>Low</p>
            </div>
            <div class="summary-box info">
                <h3>{summary.get('info', 0)}</h3>
                <p>Info</p>
            </div>
        </div>
        
        <p><strong>Files Scanned:</strong> {summary.get('files_scanned', 0)} / {summary.get('total_files', 0)}</p>
        
        <h2>Vulnerabilities</h2>
"""
        
        if not sorted_vulns:
            html_content += "<p>No vulnerabilities detected. ✅</p>"
        else:
            for vuln in sorted_vulns:
                severity = html.escape(vuln.get("severity", "info").lower())
                description = html.escape(vuln.get('description', 'Unknown vulnerability'))
                vuln_type = html.escape(vuln.get('type', 'N/A'))
                file_path = html.escape(vuln.get('file', 'N/A'))
                line = html.escape(str(vuln.get('line', 'N/A')))
                code_snippet = html.escape(vuln.get('code_snippet', ''))
                
                html_content += f"""
        <div class="vulnerability {severity}">
            <h3>{description}</h3>
            <span class="severity {severity}">{severity}</span>
            <p><strong>Type:</strong> {vuln_type}</p>
            <div class="meta">
                <p><strong>File:</strong> {file_path}</p>
                <p><strong>Line:</strong> {line}</p>
            </div>
            <div class="code-snippet">
                <code>{code_snippet}</code>
            </div>
        </div>
"""
        
        html_content += f"""
        <div class="timestamp">
            Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </div>
    </div>
</body>
</html>
"""
        return html_content
