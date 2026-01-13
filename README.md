# Lucius Sentinel 🛡️

A comprehensive security vulnerability scanner that analyzes code across multiple programming languages to identify potential security issues.

## Overview

Lucius Sentinel is a static code analysis tool designed to detect common security vulnerabilities in your codebase. It supports multiple programming languages and provides detailed reports in various formats.

## Features

- 🔍 **Multi-language support**: Python, JavaScript/TypeScript, and more
- 🎯 **Comprehensive vulnerability detection**: SQL injection, XSS, command injection, and more
- 📊 **Multiple report formats**: JSON, HTML, and plain text
- ⚡ **Fast scanning**: Efficient directory traversal and pattern matching
- 🎨 **Beautiful HTML reports**: Visual representation of security findings
- 🔧 **Configurable scan types**: Quick, full, and deep scans

## Installation

Clone the repository:

```bash
git clone https://github.com/repo-ranger21/lucius.git
cd lucius
```

Make the scanner executable:

```bash
chmod +x lucius_sentinel.py
```

## Usage

### Basic Scan

Scan a single file:

```bash
python lucius_sentinel.py /path/to/file.py
```

Scan a directory:

```bash
python lucius_sentinel.py /path/to/project
```

### Scan Options

```bash
# Perform a quick scan
python lucius_sentinel.py /path/to/project --scan-type quick

# Perform a deep scan
python lucius_sentinel.py /path/to/project --scan-type deep

# Generate JSON report
python lucius_sentinel.py /path/to/project --format json

# Generate HTML report and save to file
python lucius_sentinel.py /path/to/project --format html --output report.html

# Verbose output
python lucius_sentinel.py /path/to/project --verbose
```

### Command-Line Options

- `target`: Target file or directory to scan (required)
- `--scan-type`: Type of scan (`quick`, `full`, `deep`) - default: `full`
- `--format`: Output format (`json`, `html`, `text`) - default: `text`
- `--output`, `-o`: Output file path (default: stdout)
- `--verbose`, `-v`: Enable verbose output

## Architecture

### Project Structure

```
lucius/
├── lucius_sentinel.py    # Main scanner entry point
├── parsers/              # Language-specific parsers
│   ├── __init__.py
│   ├── python_parser.py
│   └── javascript_parser.py
├── reports/              # Report generators
│   ├── __init__.py
│   ├── json_reporter.py
│   ├── html_reporter.py
│   └── text_reporter.py
└── README.md             # This file
```

### Components

#### Main Scanner (`lucius_sentinel.py`)
The main entry point that orchestrates the scanning process:
- Parses command-line arguments
- Manages file/directory traversal
- Coordinates parsers and report generators
- Handles scan results aggregation

#### Parsers (`parsers/`)
Language-specific modules that analyze source code:
- **PythonParser**: Detects Python-specific vulnerabilities
  - SQL injection
  - Command injection
  - Hardcoded credentials
  - Use of `eval()` and `pickle`
  - Weak cryptographic functions
  
- **JavaScriptParser**: Detects JavaScript/TypeScript vulnerabilities
  - XSS via `innerHTML`
  - Use of `eval()`
  - Unsafe redirects
  - Weak random number generation
  - SQL injection patterns

#### Report Generators (`reports/`)
Format scan results for different outputs:
- **JSONReporter**: Machine-readable JSON format
- **HTMLReporter**: Rich, visual HTML reports
- **TextReporter**: Human-readable plain text

## Supported Vulnerabilities

### Critical Severity
- Command injection
- Code injection (`eval()` usage)

### High Severity
- SQL injection
- XSS vulnerabilities
- Hardcoded credentials

### Medium Severity
- Weak cryptographic functions
- Unsafe pickle deserialization
- Weak random number generation

### Low Severity
- Debug mode enabled
- Console statements in production
- Use of localStorage

## Examples

### Example 1: Scan Python Project

```bash
python lucius_sentinel.py ./my_python_app --format html --output security_report.html
```

### Example 2: Quick Scan with JSON Output

```bash
python lucius_sentinel.py ./src --scan-type quick --format json > scan_results.json
```

### Example 3: Deep Scan with Verbose Output

```bash
python lucius_sentinel.py . --scan-type deep --verbose
```

## Exit Codes

- `0`: No vulnerabilities found
- `1`: Vulnerabilities detected or error occurred

## Contributing

Contributions are welcome! To add support for a new language:

1. Create a new parser in `parsers/` (e.g., `java_parser.py`)
2. Implement the parser class with a `parse()` method
3. Register the parser in `parsers/__init__.py`

## License

See the [LICENSE](LICENSE) file for details.

## Security

If you discover a security vulnerability in Lucius Sentinel itself, please report it responsibly by opening a security advisory on GitHub.

## Roadmap

- [ ] Add support for more languages (Java, Go, Ruby, PHP)
- [ ] Implement custom rule configuration
- [ ] Add severity level filtering
- [ ] Integrate with CI/CD pipelines
- [ ] Add fix suggestions for detected vulnerabilities
- [ ] Support for SARIF output format

---

**Note**: Lucius Sentinel is a static analysis tool and may produce false positives. Always review findings in context and perform manual security audits for critical applications.
