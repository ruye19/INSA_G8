# EthioScan - Web Vulnerability Scanner

EthioScan is a lightweight Python CLI vulnerability scanner that crawls, fuzzes, scans, and reports findings in HTML/JSON format. It's designed for authorized security testing with built-in safety mechanisms.

## ⚠️ IMPORTANT SAFETY NOTICE

**EthioScan is designed for authorized testing only. Always ensure you have explicit permission before scanning any target.**

- **Never scan systems you don't own or don't have explicit permission to test**
- **Use conservative payloads - no destructive operations**
- **Respect rate limits and implement polite delays**
- **Mask sensitive data in logs and reports**
- **Follow responsible disclosure practices**

## Features

- **Async Web Crawler**: Fast, concurrent crawling with depth control
- **Security Payloads**: Comprehensive payload sets for SQLi, XSS, IDOR, and more
- **Intelligent Fuzzing**: Automated test case generation from discovered forms and parameters
- **Allowlist Enforcement**: Only scan domains in allowlist.txt or with explicit confirmation
- **Non-destructive Testing**: Conservative payloads, no RCE attempts by default
- **Rate Limiting**: Default concurrency=5 with polite delays
- **Multiple Report Formats**: HTML and JSON output
- **SQLite History**: Optional result storage
- **Rich CLI Interface**: Beautiful terminal output with progress indicators
- **Robust Error Handling**: Retry logic with exponential backoff

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd ethioscan
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Quick Start

### Basic Usage
```bash
python cli.py --url https://example.com
```

### Advanced Usage
```bash
# Scan with custom depth and JSON report
python cli.py --url https://example.com --depth 3 --report json --out scan_results.json

# Scan with history enabled
python cli.py --url https://example.com --history

# Scan unauthorized domain (requires explicit confirmation)
python cli.py --url https://unauthorized-site.com --confirm-allow I_HAVE_PERMISSION
```

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--url` | Target URL to scan (required) | - |
| `--depth` | Crawling depth | 2 |
| `--report` | Report format (html/json) | html |
| `--out` | Output file path | report.html |
| `--concurrency` | Concurrency level | 5 |
| `--history` | Store results in SQLite | False |
| `--confirm-allow` | Bypass allowlist confirmation | - |

## Allowlist Configuration

EthioScan enforces an allowlist for security. To scan a domain:

1. **Add to allowlist.txt** (recommended):
```
# Add your authorized domains
your-domain.com
test.example.com
```

2. **Use explicit confirmation** (emergency only):
```bash
python cli.py --url https://domain.com --confirm-allow I_HAVE_PERMISSION
```

## Crawler Behavior

The EthioScan crawler discovers web pages, forms, and parameters through intelligent web crawling:

### Discovery Process
- **Pages**: Extracts all `<a href>` links and normalizes them to absolute URLs
- **Forms**: Identifies `<form>` elements with action URLs, methods, and input fields
- **Parameters**: Extracts query parameters from discovered URLs
- **Depth Control**: Respects the `--depth` parameter for crawling scope

### URL Processing
- Normalizes relative URLs to absolute URLs
- Skips non-HTTP schemes (mailto, tel, javascript, etc.)
- Preserves query parameters and fragments
- Deduplicates discovered URLs

### Politeness & Safety
- **Rate Limiting**: Configurable concurrency with semaphore control
- **Delays**: Polite delays between requests (default 0.2s)
- **Retries**: Exponential backoff on failures (up to 2 retries)
- **Timeouts**: 10-second timeout per request
- **User Agent**: Identifies as "EthioScan/1.0 (Ethiopian Security Scanner)"

### Output Format
```json
{
  "pages": ["https://example.com/", "https://example.com/about"],
  "forms": [
    {"url":"https://example.com/contact","action":"/submit","method":"post","inputs":["name","email"]}
  ],
  "params": [
    {"url":"https://example.com/search?q=test","params":["q"]}
  ]
}
```

## Fuzzer & Payloads

EthioScan includes a comprehensive fuzzing engine that generates security test cases from discovered forms and parameters:

### Payload Categories
- **SQL Injection**: Safe SQLi payloads for database testing
- **Cross-Site Scripting (XSS)**: Reflected XSS detection payloads
- **IDOR (Insecure Direct Object Reference)**: Numeric parameter manipulation
- **Command Injection**: Safe command injection tests
- **LDAP Injection**: Directory service injection tests
- **NoSQL Injection**: Document database injection tests
- **Directory Traversal**: Lab-only file system access tests

### Safety Profiles
- **Safe Profile** (default): Non-destructive payloads only
- **Lab Profile**: Includes traversal payloads for controlled environments
- **All Profile**: Complete payload set

### Test Case Generation
The fuzzer automatically generates test cases by:
- Injecting payloads into discovered URL parameters
- Filling form inputs with security test payloads
- Preserving other parameters with benign values
- Generating curl commands for manual reproduction

### Lab-Only Protection
Potentially destructive payloads (like directory traversal) are marked as `lab_only` and require explicit opt-in via `--lab-test` flag. This ensures safe operation in production environments.

## Safety Features

### Allowlist Enforcement
- Only domains in `allowlist.txt` can be scanned without confirmation
- Explicit confirmation required for unauthorized domains
- Clear error messages for blocked attempts

### Non-destructive Testing
- Conservative payloads only
- No destructive operations or RCE attempts
- Safe fuzzing techniques

### Rate Limiting & Politeness
- Default concurrency limit of 5
- Exponential backoff on failures
- Respectful delays between requests

### Data Protection
- No logging of credentials or secrets
- Sensitive data masking in reports
- Secure handling of scan results

## Project Structure

```
ethioscan/
├── cli.py              # Main CLI interface
├── crawler.py          # Web crawling functionality
├── scanner.py          # Vulnerability scanning
├── fuzzer.py           # Payload fuzzing
├── reporter.py         # Report generation
├── database.py         # SQLite database operations
├── utils.py            # Utility functions and orchestrator
├── payloads.py         # Security test payloads
├── allowlist.txt       # Authorized domains list
├── requirements.txt    # Python dependencies
├── README.md           # This file
├── templates/
│   └── report_template.html
└── tests/
    ├── test_utils.py
    └── test_scanner.py
```

## Legal and Ethical Use

EthioScan is provided for educational and authorized testing purposes only. Users are responsible for:

- **Obtaining explicit permission** before scanning any target
- **Complying with local laws** and regulations
- **Following responsible disclosure** practices
- **Not causing harm** to systems or data
- **Respecting privacy** and confidentiality

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For questions, issues, or contributions, please:
- Open an issue on GitHub
- Check the documentation
- Review the safety guidelines

## Disclaimer

The authors and contributors of EthioScan are not responsible for any misuse of this tool. Users must ensure they have proper authorization before conducting any security testing activities.
