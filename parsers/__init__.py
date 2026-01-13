"""
Language-specific parsers for vulnerability detection.

This package contains parsers for different programming languages that can
identify security vulnerabilities in source code.
"""

from typing import Optional
from pathlib import Path

from .python_parser import PythonParser
from .javascript_parser import JavaScriptParser


# Mapping of file extensions to parser classes
PARSER_MAP = {
    ".py": PythonParser,
    ".js": JavaScriptParser,
    ".jsx": JavaScriptParser,
    ".ts": JavaScriptParser,
    ".tsx": JavaScriptParser,
}


def get_parser(file_extension: str):
    """
    Get the appropriate parser for a given file extension.
    
    Args:
        file_extension: File extension (e.g., '.py', '.js')
        
    Returns:
        Parser instance or None if no parser available for the extension
    """
    parser_class = PARSER_MAP.get(file_extension.lower())
    if parser_class:
        return parser_class()
    return None


__all__ = [
    "get_parser",
    "PythonParser",
    "JavaScriptParser",
]
