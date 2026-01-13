#!/usr/bin/env python3
"""
Lucius Sentinel - Main Vulnerability Scanner

A comprehensive security vulnerability scanner that analyzes code across multiple
programming languages to identify potential security issues.
"""

import argparse
import sys
from pathlib import Path
from typing import List, Dict, Any

from parsers import get_parser
from reports import generate_report


class LuciusSentinel:
    """Main vulnerability scanner class."""
    
    def __init__(self, target_path: str, scan_type: str = "full"):
        """
        Initialize the Lucius Sentinel scanner.
        
        Args:
            target_path: Path to the target file or directory to scan
            scan_type: Type of scan to perform (full, quick, deep)
        """
        self.target_path = Path(target_path)
        self.scan_type = scan_type
        
    def scan(self) -> Dict[str, Any]:
        """
        Perform vulnerability scan on the target.
        
        Returns:
            Dictionary containing scan results and vulnerabilities found
        """
        if not self.target_path.exists():
            raise FileNotFoundError(f"Target path not found: {self.target_path}")
        
        results = {
            "target": str(self.target_path),
            "scan_type": self.scan_type,
            "vulnerabilities": [],
            "summary": {
                "total_files": 0,
                "files_scanned": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            }
        }
        
        if self.target_path.is_file():
            self._scan_file(self.target_path, results)
        elif self.target_path.is_dir():
            self._scan_directory(self.target_path, results)
        
        return results
    
    def _scan_file(self, file_path: Path, results: Dict[str, Any]):
        """
        Scan a single file for vulnerabilities.
        
        Args:
            file_path: Path to the file to scan
            results: Results dictionary to update
        """
        results["summary"]["total_files"] += 1
        
        # Get appropriate parser based on file extension
        parser = get_parser(file_path.suffix)
        if parser is None:
            return
        
        try:
            vulnerabilities = parser.parse(file_path)
            results["vulnerabilities"].extend(vulnerabilities)
            results["summary"]["files_scanned"] += 1
            
            # Update severity counts
            for vuln in vulnerabilities:
                severity = vuln.get("severity", "info").lower()
                if severity in results["summary"]:
                    results["summary"][severity] += 1
                    
        except Exception as e:
            print(f"Error scanning {file_path}: {e}", file=sys.stderr)
    
    def _scan_directory(self, dir_path: Path, results: Dict[str, Any]):
        """
        Recursively scan a directory for vulnerabilities.
        
        Args:
            dir_path: Path to the directory to scan
            results: Results dictionary to update
        """
        for item in dir_path.rglob("*"):
            if item.is_file() and not self._should_skip(item):
                self._scan_file(item, results)
    
    def _should_skip(self, file_path: Path) -> bool:
        """
        Determine if a file should be skipped during scanning.
        
        Args:
            file_path: Path to check
            
        Returns:
            True if file should be skipped, False otherwise
        """
        skip_patterns = [
            ".git", "__pycache__", "node_modules", ".venv", "venv",
            ".pytest_cache", ".mypy_cache", ".tox", "dist", "build"
        ]
        
        return any(pattern in str(file_path) for pattern in skip_patterns)


def main():
    """Main entry point for the Lucius Sentinel scanner."""
    parser = argparse.ArgumentParser(
        description="Lucius Sentinel - Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/project
  %(prog)s /path/to/file.py --format json
  %(prog)s . --scan-type deep --output report.html
        """
    )
    
    parser.add_argument(
        "target",
        help="Target file or directory to scan"
    )
    
    parser.add_argument(
        "--scan-type",
        choices=["quick", "full", "deep"],
        default="full",
        help="Type of scan to perform (default: full)"
    )
    
    parser.add_argument(
        "--format",
        choices=["json", "html", "text"],
        default="text",
        help="Output format (default: text)"
    )
    
    parser.add_argument(
        "--output",
        "-o",
        help="Output file path (default: stdout)"
    )
    
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    try:
        # Initialize and run scanner
        sentinel = LuciusSentinel(args.target, args.scan_type)
        
        if args.verbose:
            print(f"Starting {args.scan_type} scan of {args.target}...")
        
        results = sentinel.scan()
        
        # Generate report
        report = generate_report(results, args.format)
        
        # Output results
        if args.output:
            with open(args.output, "w") as f:
                f.write(report)
            if args.verbose:
                print(f"Report saved to {args.output}")
        else:
            print(report)
        
        # Exit with appropriate code
        total_vulns = sum([
            results["summary"]["critical"],
            results["summary"]["high"],
            results["summary"]["medium"],
            results["summary"]["low"]
        ])
        
        sys.exit(1 if total_vulns > 0 else 0)
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
