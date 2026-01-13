# Lucius Sentinel

A comprehensive vulnerability scanner that analyzes code for security issues across multiple programming languages.

## Overview

Lucius Sentinel is designed to help developers identify common security vulnerabilities in their codebases. It supports multiple programming languages and provides detailed reports in various formats.

## Features

- **Multi-language Support**: Scan Python, JavaScript, and more
- **Multiple Report Formats**: Generate reports in JSON, HTML, or plain text
- **Extensible Architecture**: Easy to add new parsers and report generators
- **Pattern-based Detection**: Uses regex patterns to identify common vulnerabilities

## Installation

Clone the repository:

```bash
git clone https://github.com/repo-ranger21/lucius.git
cd lucius
```

## Usage

Run the scanner on a file or directory:

```bash
python lucius_sentinel.py <target> [options]
```

### Options

- `-o, --output FILE`: Specify output file for the report
- `-f, --format FORMAT`: Choose report format (json, html, text) - default: text
- `-v, --verbose`: Enable verbose output

### Examples

Scan a single file:
```bash
python lucius_sentinel.py /path/to/file.py
```

Scan a directory with HTML output:
```bash
python lucius_sentinel.py /path/to/project -f html -o report.html
```

## Project Structure

```
lucius_sentinel.py        # Main scanner
parsers/                  # Language-specific parsers
  ├── __init__.py
  ├── python_parser.py    # Python vulnerability patterns
  └── javascript_parser.py # JavaScript vulnerability patterns
reports/                  # Report generators
  ├── __init__.py
  ├── json_report.py      # JSON format
  ├── html_report.py      # HTML format
  └── text_report.py      # Plain text format
README.md                 # Public documentation
```

## Supported Vulnerabilities

### Python
- SQL Injection
- Command Injection
- Hard-coded Credentials
- Insecure Deserialization

### JavaScript
- Cross-Site Scripting (XSS)
- eval() Usage
- Prototype Pollution

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

See the LICENSE file for details.
