# EthioScan - Complete File Summary

## Project Overview
**EthioScan** is a web vulnerability scanner that automatically discovers and tests security flaws in web applications through crawling, fuzzing, and vulnerability detection.

---

## Core Files

### 1. **cli.py** - Command Line Interface
**Purpose**: Entry point for the scanner with safety controls

**Key Functions**:
- `print_banner()` - Displays EthioScan banner
- `load_allowlist()` - Loads authorized domains from allowlist.txt
- `check_allowlist()` - Validates target is authorized before scanning
- `main()` - Parses arguments and starts scan

**Command Line Arguments**:
- `--url` - Target URL (required)
- `--depth` - Crawl depth (default: 2)
- `--report` - Output format (html/json)
- `--out` - Output file path
- `--concurrency` - Parallel requests (default: 5)
- `--history` - Save to SQLite database
- `--confirm-allow` - Bypass allowlist with "I_HAVE_PERMISSION"

**Safety Features**:
- Checks allowlist.txt before scanning
- Requires explicit confirmation for non-allowlisted domains
- Prevents unauthorized scanning

---

### 2. **crawler.py** - Web Crawler
**Purpose**: Discovers pages, forms, and parameters on target website

**Key Components**:
- `Crawler` class - Async crawler with connection pooling
- `crawl()` - Main async crawling function
- `crawl_sync()` - Synchronous fallback using requests
- `normalize_url()` - Converts relative URLs to absolute
- `extract_query_params()` - Extracts parameter names from URLs
- `fetch_page()` - Fetches page with retry logic
- `parse_html()` - Extracts links, forms, and parameters from HTML

**What It Discovers**:
- All pages on the website
- HTML forms (action, method, input fields)
- URL parameters (e.g., ?id=123&page=2)

**Features**:
- Breadth-first search (BFS) algorithm
- Concurrent requests with semaphore control
- Exponential backoff on failures
- Polite delays between requests (0.2s default)
- Deduplication of results

**Output**: Dictionary with `pages`, `forms`, `params` lists

---

### 3. **payloads.py** - Attack Payloads
**Purpose**: Provides security test payloads for different vulnerability types

**Payload Categories**:

**SQL Injection (sqli)**:
- `' OR '1'='1` - Basic authentication bypass
- `' OR 1=1--` - Comment-based injection
- `' UNION SELECT NULL--` - Union-based injection
- `'; DROP TABLE test--` - Destructive test (safe version)

**XSS (Cross-Site Scripting)**:
- `<script>alert(1)</script>` - Basic XSS
- `<img src=x onerror=alert(1)>` - Image-based XSS
- `<svg onload=alert(1)>` - SVG-based XSS
- `javascript:alert(1)` - JavaScript protocol

**Directory Traversal**:
- `../../../../etc/passwd` - Unix path traversal
- `..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts` - Windows traversal
- URL-encoded variants

**IDOR (Insecure Direct Object Reference)**:
- Adjacent values (+1, -1)
- Large values (999999, 0)
- Negative values (-1, -999999)

**Command Injection**:
- `; ls` - Semicolon separator
- `| whoami` - Pipe operator
- `$(whoami)` - Command substitution

**LDAP/NoSQL Injection**:
- `*` - Wildcard injection
- `*)(uid=*` - LDAP filter bypass

**Key Functions**:
- `get_payloads(profile)` - Returns payloads for "safe", "lab", or "all" profiles
- `is_lab_only_payload()` - Checks if payload is potentially destructive
- `get_payload_categories()` - Lists available categories
- `get_payload_count()` - Counts payloads per category

---

### 4. **fuzzer.py** - Test Case Generator
**Purpose**: Creates and executes test cases by injecting payloads

**Key Functions**:

**Test Generation**:
- `generate_tests_from_params()` - Creates tests for URL parameters
- `generate_tests_from_forms()` - Creates tests for form inputs
- `_build_test_url()` - Injects payload into URL
- `_is_numeric_param()` - Detects numeric parameters for IDOR tests

**Test Execution**:
- `submit_test_case()` - Async HTTP request submission
- `submit_test_case_sync()` - Synchronous fallback
- `quick_precheck()` - Fast preliminary vulnerability check

**Utilities**:
- `generate_curl_command()` - Converts test to curl command
- `get_test_case_summary()` - Statistics on generated tests

**Test Case Structure**:
```python
{
    "id": "uuid",
    "method": "GET/POST",
    "url": "http://example.com?id=payload",
    "param": "id",
    "payload": {"payload": "' OR '1'='1", "note": "..."},
    "origin": "param/form",
    "meta": {"category": "sqli", "lab_only": False}
}
```

**Features**:
- Limits payloads per parameter (max 3 by default)
- Handles GET and POST requests
- Builds form data with benign values for non-target fields
- Async execution with timeout handling
- Error detection in responses

---

### 5. **scanner.py** - Vulnerability Detection
**Purpose**: Analyzes HTTP responses to detect security vulnerabilities

**Scanner Class**:
- `__init__(fast)` - Initialize with detection rules
- `analyze_response()` - Main analysis function
- `detect_sqli()` - SQL injection detection
- `detect_xss()` - XSS detection
- `detect_error_keywords()` - General error detection
- `_detect_anomalies()` - Unusual behavior detection

**Detection Methods**:

**SQL Injection**:
- Searches for database error keywords: "mysql", "syntax error", "postgresql", "oracle", "sqlite"
- Detects error messages: "database error", "sql error", "query failed"

**XSS (Cross-Site Scripting)**:
- Checks for reflected payloads in response
- Detects dangerous HTML patterns: `<script>`, `<img>`, `<svg>`, `<iframe>`
- Validates payload contains XSS indicators before flagging

**Error Detection**:
- Finds error keywords: "error", "exception", "warning", "fatal"
- Detects HTTP errors: "internal server error", "bad request"

**Anomaly Detection**:
- Unusual status codes (500, 502, 503, 504)
- Very slow responses (>10 seconds)
- Debug/test headers

**Finding Structure**:
```python
{
    "id": "uuid",
    "category": "sqli/xss/error/anomaly",
    "severity": "critical/high/medium/low",
    "param": "parameter_name",
    "url": "http://...",
    "payload": {...},
    "evidence": "response snippet",
    "status": 200,
    "response_time": 0.5,
    "timestamp": "2025-10-11T08:30:32"
}
```

---

### 6. **reporter.py** - Report Generation
**Purpose**: Creates HTML reports from scan findings

**Key Function**:
- `generate_report(findings_file, output_file)` - Generates HTML from JSON

**Features**:
- Uses Jinja2 templates for HTML generation
- Color-coded severity levels:
  - Red: Critical/High
  - Orange: Medium
  - Green: Low
  - Gray: Unknown
- Includes scan metadata (target, time, depth)
- Displays findings table with evidence
- Auto-escapes HTML for security

**Template Location**: `templates/report_template.html`

**Usage**:
```bash
python -m ethioscan.reporter findings.json report.html
```

---

### 7. **database.py** & **db.py** - Data Storage
**Purpose**: SQLite database for storing scan history

**Database Schema**:

**scans table**:
- id (PRIMARY KEY)
- target_url
- scan_time
- depth
- concurrency
- max_tests
- lab_mode
- total_findings

**findings table**:
- id (PRIMARY KEY)
- scan_id (FOREIGN KEY)
- url
- param
- payload
- category
- severity
- evidence

**Key Functions**:
- `initialize_db()` - Creates tables if not exist
- `save_scan(scan_info)` - Saves scan metadata, returns scan_id
- `save_findings(scan_id, findings)` - Saves vulnerability findings

**Note**: `database.py` is deprecated, use `db.py` instead

---

### 8. **run_scan.py** - Main Orchestrator
**Purpose**: End-to-end vulnerability scanning orchestrator

**EthioScanOrchestrator Class**:

**Main Methods**:
- `check_allowlist()` - Validates target authorization
- `run_crawler()` - Executes crawler phase
- `generate_test_cases()` - Creates test cases from crawler results
- `run_tests()` - Executes tests and collects findings
- `save_findings()` - Saves results to JSON
- `create_summary()` - Creates text summary
- `print_final_summary()` - Displays results to console
- `run()` - Main execution flow

**Workflow**:
1. Check allowlist authorization
2. Crawl target website
3. Generate test cases from discovered attack surface
4. Execute tests with concurrency control
5. Analyze responses for vulnerabilities
6. Save findings to JSON
7. Optionally save to database
8. Optionally generate HTML report
9. Display summary

**Features**:
- Progress bars with Rich library
- Async execution with semaphore control
- Error handling and graceful failures
- Keyboard interrupt handling
- Configurable test limits
- Lab mode for destructive payloads

**Command Line Arguments**:
- `--url` - Target URL (required)
- `--depth` - Crawl depth (default: 2)
- `--concurrency` - Parallel requests (default: 5)
- `--max-tests` - Max test cases (default: 200)
- `--out` - Output JSON file
- `--lab` - Enable lab-only payloads
- `--confirm-allow` - Authorization bypass
- `--report-html` - Generate HTML report
- `--save-db` - Save to SQLite database

**Usage**:
```bash
python -m ethioscan.run_scan --url https://example.com
python -m ethioscan.run_scan --url https://example.com --depth 3 --max-tests 100
python -m ethioscan.run_scan --url https://example.com --lab --report-html report.html
```

---

### 9. **utils.py** - Utility Functions
**Purpose**: Helper functions and orchestrator (simplified version)

**Key Function**:
- `run_scan(args)` - Simplified orchestrator that runs crawler only

**Features**:
- Tries async crawler first
- Falls back to sync crawler on failure
- Displays discovered pages/forms/params
- Note: This is a basic version; `run_scan.py` is the full implementation

---

### 10. **__init__.py** - Package Initialization
**Purpose**: Makes ethioscan a Python package

**Exports**:
- `crawl` - Crawler function
- `Scanner` - Scanner class
- `get_payloads` - Payload function

**Package Info**:
- Version: 1.0.0
- Author: EthioScan Team

---

## Supporting Files

### **allowlist.txt**
**Purpose**: Authorized domains for scanning

**Format**:
```
example.com
testsite.local
localhost
127.0.0.1
```

**Usage**: Add domains you have permission to scan

---

### **requirements.txt**
**Purpose**: Python dependencies

**Dependencies**:
- `requests>=2.31.0` - HTTP requests (sync)
- `aiohttp>=3.8.0` - Async HTTP requests
- `beautifulsoup4>=4.12.0` - HTML parsing
- `jinja2>=3.1.0` - Template engine
- `rich>=13.0.0` - Beautiful CLI output
- `pytest>=7.0.0` - Testing framework
- `pytest-asyncio>=0.21.0` - Async testing

**Installation**:
```bash
pip install -r requirements.txt
```

---

## Test Files

### **tests/test_crawler.py**
Tests for crawler functionality (URL normalization, parsing, etc.)

### **tests/test_fuzzer.py**
Tests for fuzzer (test generation, payload injection, etc.)

### **tests/test_scanner.py**
Tests for scanner (vulnerability detection logic)

### **tests/test_utils.py**
Tests for utility functions

---

## Complete Workflow

### **Step 1: User Runs Scan**
```bash
python -m ethioscan.run_scan --url https://example.com --depth 2
```

### **Step 2: Allowlist Check**
- Validates domain is in `allowlist.txt`
- Requires confirmation if not authorized

### **Step 3: Crawling**
- Discovers all pages, forms, and parameters
- Uses BFS with configurable depth
- Respects rate limits

### **Step 4: Test Generation**
- Loads payloads based on profile (safe/lab)
- Generates test cases for each parameter/form
- Limits tests to avoid overload

### **Step 5: Test Execution**
- Submits test cases with async HTTP requests
- Uses concurrency control (semaphore)
- Handles timeouts and errors

### **Step 6: Vulnerability Detection**
- Analyzes each response for security issues
- Detects SQL injection, XSS, errors, anomalies
- Creates findings with evidence

### **Step 7: Reporting**
- Saves findings to JSON
- Creates text summary
- Optionally generates HTML report
- Optionally saves to SQLite database

### **Step 8: Results Display**
- Shows findings by severity
- Displays top vulnerabilities
- Provides file paths for reports

---

## Key Features

✅ **Ethical & Safe**: Allowlist prevents unauthorized scanning  
✅ **Fast**: Async/concurrent requests for speed  
✅ **Comprehensive**: Tests 6+ vulnerability types  
✅ **Professional**: Beautiful HTML reports with Jinja2  
✅ **Modular**: Clean architecture with separate components  
✅ **Production-Ready**: Error handling, retries, rate limiting  
✅ **Configurable**: Multiple profiles and options  
✅ **Persistent**: SQLite database for scan history  
✅ **Tested**: Unit tests for core functionality  

---

## Technologies Used

- **Python 3.x** - Core language
- **aiohttp** - Async HTTP client
- **requests** - Sync HTTP client (fallback)
- **BeautifulSoup4** - HTML parsing
- **Jinja2** - Template engine for reports
- **Rich** - Beautiful CLI output with colors/progress bars
- **SQLite** - Embedded database
- **pytest** - Testing framework

---

## Demo Script

### **1. Show Banner & Safety**
```bash
python -m ethioscan.run_scan --url https://example.com
```
- Shows EthioScan banner
- Checks allowlist
- Displays configuration

### **2. Crawling Phase**
- Watch as it discovers pages
- Shows count of forms and parameters found

### **3. Test Generation**
- Displays number of test cases generated
- Shows payload categories being used

### **4. Scanning Phase**
- Progress bar shows test execution
- Real-time vulnerability alerts

### **5. Results**
- Opens `examples/sample_findings.json` to show raw data
- Opens HTML report to show professional presentation
- Shows summary with severity breakdown

---

## Security Notice

⚠️ **EthioScan is for authorized testing only**  
- Always get explicit permission before scanning
- Use safe payloads on production systems
- Respect rate limits and server resources
- Add targets to allowlist.txt only if authorized
- Lab mode should only be used in controlled environments

---

## Project Structure

```
ethioscan/
├── __init__.py           # Package initialization
├── cli.py                # Command line interface
├── crawler.py            # Web crawler
├── payloads.py           # Attack payloads
├── fuzzer.py             # Test case generator
├── scanner.py            # Vulnerability detector
├── reporter.py           # HTML report generator
├── database.py           # Database (deprecated)
├── db.py                 # Database (current)
├── run_scan.py           # Main orchestrator
├── utils.py              # Utility functions
├── allowlist.txt         # Authorized domains
├── requirements.txt      # Dependencies
├── templates/            # Jinja2 templates
│   └── report_template.html
├── tests/                # Unit tests
│   ├── test_crawler.py
│   ├── test_fuzzer.py
│   ├── test_scanner.py
│   └── test_utils.py
└── examples/             # Sample outputs
    ├── sample_findings.json
    └── sample_summary.txt
```

---

## Summary

**EthioScan** is a complete vulnerability scanning solution that:
1. **Discovers** attack surfaces through intelligent crawling
2. **Tests** for vulnerabilities using proven payloads
3. **Detects** security issues through response analysis
4. **Reports** findings in professional formats
5. **Stores** scan history for tracking over time

All while maintaining **ethical standards** through allowlist controls and safe-by-default payloads.
