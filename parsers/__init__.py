"""
Language-specific parsers for vulnerability scanning.

This package contains parsers for various programming languages that
extract and analyze code patterns to identify potential security vulnerabilities.
"""

from pathlib import Path
from typing import Dict, List, Any
from abc import ABC, abstractmethod


class BaseParser(ABC):
    """Base class for language-specific parsers."""
    
    def __init__(self):
        self.vulnerabilities = []
    
    @abstractmethod
    def parse(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        Parse a file and return a list of vulnerabilities found.
        
        Args:
            file_path: Path to the file to parse
            
        Returns:
            List of vulnerability dictionaries
        """
        raise NotImplementedError("Subclasses must implement parse()")
    
    @abstractmethod
    def get_supported_extensions(self) -> List[str]:
        """
        Get the list of file extensions this parser supports.
        
        Returns:
            List of file extensions (e.g., ['.py', '.pyw'])
        """
        raise NotImplementedError("Subclasses must implement get_supported_extensions()")


__all__ = ['BaseParser']
