"""
Report generators for vulnerability scan results.

This package contains different report formatters that can output scan results
in various formats (JSON, HTML, text, etc.).
"""

from .json_reporter import JSONReporter
from .html_reporter import HTMLReporter
from .text_reporter import TextReporter


# Mapping of format names to reporter classes
REPORTER_MAP = {
    "json": JSONReporter,
    "html": HTMLReporter,
    "text": TextReporter,
}


def generate_report(results, format_type="text"):
    """
    Generate a report from scan results in the specified format.
    
    Args:
        results: Dictionary containing scan results
        format_type: Output format type (json, html, text)
        
    Returns:
        Formatted report as a string
    """
    reporter_class = REPORTER_MAP.get(format_type.lower(), TextReporter)
    reporter = reporter_class()
    return reporter.generate(results)


__all__ = [
    "generate_report",
    "JSONReporter",
    "HTMLReporter",
    "TextReporter",
]
