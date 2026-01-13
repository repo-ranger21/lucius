"""
JSON report generator for vulnerability scan results.
"""

import json
from typing import Dict, Any


class JSONReporter:
    """Reporter that outputs scan results in JSON format."""
    
    def generate(self, results: Dict[str, Any]) -> str:
        """
        Generate a JSON report from scan results.
        
        Args:
            results: Dictionary containing scan results
            
        Returns:
            JSON-formatted string
        """
        return json.dumps(results, indent=2, sort_keys=True)
