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

- **Allowlist Enforcement**: Only scan domains in allowlist.txt or with explicit confirmation
- **Non-destructive Testing**: Conservative payloads, no RCE attempts
- **Rate Limiting**: Default concurrency=5 with polite delays
- **Multiple Report Formats**: HTML and JSON output
- **SQLite History**: Optional result storage
- **Rich CLI Interface**: Beautiful terminal output with progress indicators

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
