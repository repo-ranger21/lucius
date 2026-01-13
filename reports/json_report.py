"""
JSON report generator.

Outputs vulnerability scan results in JSON format for easy parsing
and integration with other tools.
"""

import json
from typing import Dict, List, Any
from datetime import datetime

from . import BaseReportGenerator


class JSONReportGenerator(BaseReportGenerator):
    """Generates reports in JSON format."""
    
    def generate(self, vulnerabilities: List[Dict[str, Any]], output_path: str = None) -> str:
        """
        Generate a JSON report.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            output_path: Optional path to write the report to
            
        Returns:
            The generated JSON report as a string
        """
        report_data = {
            'scan_date': datetime.now().isoformat(),
            'summary': {
                'total_vulnerabilities': len(vulnerabilities),
                'by_severity': self._count_by_severity(vulnerabilities),
            },
            'vulnerabilities': vulnerabilities,
        }
        
        json_output = json.dumps(report_data, indent=2)
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(json_output)
        
        return json_output


__all__ = ['JSONReportGenerator']
