"""
EthioScan Scanner - Vulnerability detection and analysis (improved classification)
"""

import re
import uuid
from datetime import datetime
from typing import Dict, Optional, Any


class Scanner:
    """
    Vulnerability scanner for analyzing HTTP responses and detecting security issues.
    """

    def __init__(self, fast: bool = False):
        self.fast = fast

        # SQL error keywords / DB engine signatures
        self.sqli_keywords = [
            "syntax error", "mysql", "ora-00933", "postgres", "sqlstate",
            "sql syntax", "database error", "sql error", "query failed",
            "mysql_fetch", "postgresql", "oracle", "sqlite", "mssql",
            "sql server", "access denied", "invalid query", "sql exception",
            "database connection", "sql command", "sqlite3", "mysqli",
            "pg_query", "oci_parse", "sqlite_error", "mssql_query"
        ]

        # XSS detection patterns (compiled)
        self.xss_patterns = [
            re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL),
            re.compile(r"<img[^>]*onerror[^>]*>", re.IGNORECASE),
            re.compile(r"<svg[^>]*onload[^>]*>", re.IGNORECASE),
            re.compile(r"<iframe[^>]*src=['\"][^'\"]*javascript:", re.IGNORECASE),
            re.compile(r"<body[^>]*onload[^>]*>", re.IGNORECASE),
            re.compile(r"javascript:", re.IGNORECASE),
            re.compile(r"on\w+\s*=", re.IGNORECASE),
        ]

        # General error keywords (lowercase checks)
        self.error_keywords = [
            "error", "exception", "warning", "fatal", "critical",
            "failed", "failure", "invalid", "unauthorized", "forbidden",
            "not found", "internal server error", "bad request",
            "service unavailable", "timeout", "connection refused"
        ]

        # Command injection heuristics: shell messages / exec function names
        self.cmd_injection_indicators = [
            re.compile(r"command not found", re.IGNORECASE),
            re.compile(r"permission denied", re.IGNORECASE),
            re.compile(r"sh:\s*\d+:", re.IGNORECASE),
            re.compile(r"exec\(", re.IGNORECASE),
            re.compile(r"shell_exec", re.IGNORECASE),
            re.compile(r"root@|uid=\d+|www-data", re.IGNORECASE),
        ]

        # Common trace signatures (for info disclosure)
        self.trace_signatures = [
            "traceback (most recent call last)",
            "exception in thread",
            "at org.",
            "java.lang.",
            "file \"",
            "stack trace"
        ]

    # -------------------------
    # Public analysis function
    # -------------------------
    def analyze_response(self, test_case: Dict[str, Any], response: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Analyze a test case + response and return a finding dict if something suspicious is detected.
        """
        if not response or not response.get("body"):
            return None

        body = (response.get("body") or "").lower()
        headers = response.get("headers") or {}

        # --- FIX: normalize payload safely ---
        raw_payload = test_case.get("payload", "")
        if isinstance(raw_payload, dict):
            payload_str = str(raw_payload.get("payload", raw_payload))
        else:
            payload_str = str(raw_payload)
        payload_str = payload_str.lower()

        # DEBUG
        print("[DEBUG] URL:", test_case.get("url"),
              "status:", response.get("status"),
              "payload:", payload_str[:50],
              "body-snippet:", body[:120])

        # Priority: XSS -> SQLi -> CMD -> Info Disclosure -> Errors -> Anomalies
        if self.detect_xss(body, payload_str):
            return self._create_finding(test_case, response,
                                        category="Cross-Site Scripting (XSS)",
                                        severity="high",
                                        evidence=self._extract_evidence(body, payload_str))

        if self.detect_sqli(body, payload_str):
            db_error_found = any(k in body for k in ["sqlstate", "syntax error", "mysql", "postgres", "ora-", "sqlite"])
            severity = "critical" if db_error_found else "high"
            return self._create_finding(test_case, response,
                                        category="SQL Injection",
                                        severity=severity,
                                        evidence=self._extract_evidence(body, payload_str))

        if self.detect_command_injection(body, payload_str):
            return self._create_finding(test_case, response,
                                        category="Command Injection",
                                        severity="high",
                                        evidence=self._extract_evidence(body, payload_str))

        if self.detect_info_disclosure(body, headers):
            return self._create_finding(test_case, response,
                                        category="Information Disclosure",
                                        severity="medium",
                                        evidence=self._extract_evidence(body, payload_str))

        if self.detect_error_keywords(body):
            return self._create_finding(test_case, response,
                                        category="Error Response",
                                        severity="medium",
                                        evidence=self._extract_evidence(body, payload_str))

        if self._detect_anomalies(response, payload_str):
            return self._create_finding(test_case, response,
                                        category="Anomalous Response",
                                        severity="low",
                                        evidence=self._extract_evidence(body, payload_str))

        return None

    # -------------------------
    # Detection helpers
    # -------------------------
    def detect_sqli(self, body: str, payload_str: str = "") -> bool:
        if any(kw in body for kw in self.sqli_keywords):
            return True
        tautologies = ["' or '1'='1", '" or "1"="1', " or 1=1"]
        return any(t in payload_str and payload_str in body for t in tautologies)

    def detect_xss(self, body: str, payload_str: str = "") -> bool:
        if any(patt.search(body) for patt in self.xss_patterns):
            return True
        return self._is_xss_payload(payload_str) and payload_str in body

    def detect_command_injection(self, body: str, payload_str: str = "") -> bool:
        return any(patt.search(body) for patt in self.cmd_injection_indicators)

    def detect_info_disclosure(self, body: str, headers: Dict[str, Any]) -> bool:
        if any(sig in body for sig in self.trace_signatures):
            return True
        server = (headers.get("server") or "").lower()
        return server and any(s in server for s in ["apache", "nginx", "werkzeug"]) and self.detect_error_keywords(body)

    def detect_error_keywords(self, body: str) -> bool:
        return any(kw in body for kw in self.error_keywords)

    def _detect_anomalies(self, response: Dict[str, Any], payload_str: str = "") -> bool:
        if response.get("status") in (500, 502, 503, 504):
            return True
        elapsed = response.get("elapsed", 0)
        return isinstance(elapsed, (int, float)) and elapsed > 10

    # -------------------------
    # Utility helpers
    # -------------------------
    def _is_xss_payload(self, payload_str: str) -> bool:
        indicators = ["<script", "<img", "<svg", "<iframe", "javascript:", "onerror", "onload"]
        return any(ind in payload_str for ind in indicators)

    def _extract_evidence(self, body: str, payload_str: str, max_length: int = 300) -> str:
        if payload_str and payload_str in body:
            start = body.find(payload_str)
            return body[max(0, start-80): start+len(payload_str)+80]
        return body[:max_length]

    def _create_finding(self, test_case: Dict[str, Any], response: Dict[str, Any],
                        category: str, severity: str, evidence: str) -> Dict[str, Any]:
        return {
            "id": test_case.get("id", str(uuid.uuid4())),
            "category": category,
            "url": test_case.get("url", ""),
            "param": test_case.get("param", ""),
            "method": test_case.get("method", ""),
            "payload": test_case.get("payload", ""),
            "status": response.get("status", 0),
            "evidence": evidence,
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
"""
EthioScan Scanner - Vulnerability detection and analysis (improved classification)
"""

import re
import uuid
from datetime import datetime
from typing import Dict, Optional, Any


class Scanner:
    """
    Vulnerability scanner for analyzing HTTP responses and detecting security issues.
    """

    def __init__(self, fast: bool = False):
        self.fast = fast

        # SQL error keywords / DB engine signatures
        self.sqli_keywords = [
            "syntax error", "mysql", "ora-00933", "postgres", "sqlstate",
            "sql syntax", "database error", "sql error", "query failed",
            "mysql_fetch", "postgresql", "oracle", "sqlite", "mssql",
            "sql server", "access denied", "invalid query", "sql exception",
            "database connection", "sql command", "sqlite3", "mysqli",
            "pg_query", "oci_parse", "sqlite_error", "mssql_query"
        ]

        # XSS detection patterns (compiled)
        self.xss_patterns = [
            re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL),
            re.compile(r"<img[^>]*onerror[^>]*>", re.IGNORECASE),
            re.compile(r"<svg[^>]*onload[^>]*>", re.IGNORECASE),
            re.compile(r"<iframe[^>]*src=['\"][^'\"]*javascript:", re.IGNORECASE),
            re.compile(r"<body[^>]*onload[^>]*>", re.IGNORECASE),
            re.compile(r"javascript:", re.IGNORECASE),
            re.compile(r"on\w+\s*=", re.IGNORECASE),
        ]

        # General error keywords (lowercase checks)
        self.error_keywords = [
            "error", "exception", "warning", "fatal", "critical",
            "failed", "failure", "invalid", "unauthorized", "forbidden",
            "not found", "internal server error", "bad request",
            "service unavailable", "timeout", "connection refused"
        ]

        # Command injection heuristics: shell messages / exec function names
        self.cmd_injection_indicators = [
            re.compile(r"command not found", re.IGNORECASE),
            re.compile(r"permission denied", re.IGNORECASE),
            re.compile(r"sh:\s*\d+:", re.IGNORECASE),
            re.compile(r"exec\(", re.IGNORECASE),
            re.compile(r"shell_exec", re.IGNORECASE),
            re.compile(r"root@|uid=\d+|www-data", re.IGNORECASE),
        ]

        # Common trace signatures (for info disclosure)
        self.trace_signatures = [
            "traceback (most recent call last)",
            "exception in thread",
            "at org.",
            "java.lang.",
            "file \"",
            "stack trace"
        ]

    # -------------------------
    # Public analysis function
    # -------------------------
    def analyze_response(self, test_case: Dict[str, Any], response: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Analyze a test case + response and return a finding dict if something suspicious is detected.
        """
        if not response or not response.get("body"):
            return None

        body = (response.get("body") or "").lower()
        headers = response.get("headers") or {}

        # --- FIX: normalize payload safely ---
        raw_payload = test_case.get("payload", "")
        if isinstance(raw_payload, dict):
            payload_str = str(raw_payload.get("payload", raw_payload))
        else:
            payload_str = str(raw_payload)
        payload_str = payload_str.lower()

        # DEBUG
        print("[DEBUG] URL:", test_case.get("url"),
              "status:", response.get("status"),
              "payload:", payload_str[:50],
              "body-snippet:", body[:120])

        # Priority: XSS -> SQLi -> CMD -> Info Disclosure -> Errors -> Anomalies
        if self.detect_xss(body, payload_str):
            return self._create_finding(test_case, response,
                                        category="Cross-Site Scripting (XSS)",
                                        severity="high",
                                        evidence=self._extract_evidence(body, payload_str))

        if self.detect_sqli(body, payload_str):
            db_error_found = any(k in body for k in ["sqlstate", "syntax error", "mysql", "postgres", "ora-", "sqlite"])
            severity = "critical" if db_error_found else "high"
            return self._create_finding(test_case, response,
                                        category="SQL Injection",
                                        severity=severity,
                                        evidence=self._extract_evidence(body, payload_str))

        if self.detect_command_injection(body, payload_str):
            return self._create_finding(test_case, response,
                                        category="Command Injection",
                                        severity="high",
                                        evidence=self._extract_evidence(body, payload_str))

        if self.detect_info_disclosure(body, headers):
            return self._create_finding(test_case, response,
                                        category="Information Disclosure",
                                        severity="medium",
                                        evidence=self._extract_evidence(body, payload_str))

        if self.detect_error_keywords(body):
            return self._create_finding(test_case, response,
                                        category="Error Response",
                                        severity="medium",
                                        evidence=self._extract_evidence(body, payload_str))

        if self._detect_anomalies(response, payload_str):
            return self._create_finding(test_case, response,
                                        category="Anomalous Response",
                                        severity="low",
                                        evidence=self._extract_evidence(body, payload_str))

        return None

    # -------------------------
    # Detection helpers
    # -------------------------
    def detect_sqli(self, body: str, payload_str: str = "") -> bool:
        if any(kw in body for kw in self.sqli_keywords):
            return True
        tautologies = ["' or '1'='1", '" or "1"="1', " or 1=1"]
        return any(t in payload_str and payload_str in body for t in tautologies)

    def detect_xss(self, body: str, payload_str: str = "") -> bool:
        if any(patt.search(body) for patt in self.xss_patterns):
            return True
        return self._is_xss_payload(payload_str) and payload_str in body

    def detect_command_injection(self, body: str, payload_str: str = "") -> bool:
        return any(patt.search(body) for patt in self.cmd_injection_indicators)

    def detect_info_disclosure(self, body: str, headers: Dict[str, Any]) -> bool:
        if any(sig in body for sig in self.trace_signatures):
            return True
        server = (headers.get("server") or "").lower()
        return server and any(s in server for s in ["apache", "nginx", "werkzeug"]) and self.detect_error_keywords(body)

    def detect_error_keywords(self, body: str) -> bool:
        return any(kw in body for kw in self.error_keywords)

    def _detect_anomalies(self, response: Dict[str, Any], payload_str: str = "") -> bool:
        if response.get("status") in (500, 502, 503, 504):
            return True
        elapsed = response.get("elapsed", 0)
        return isinstance(elapsed, (int, float)) and elapsed > 10

    # -------------------------
    # Utility helpers
    # -------------------------
    def _is_xss_payload(self, payload_str: str) -> bool:
        indicators = ["<script", "<img", "<svg", "<iframe", "javascript:", "onerror", "onload"]
        return any(ind in payload_str for ind in indicators)

    def _extract_evidence(self, body: str, payload_str: str, max_length: int = 300) -> str:
        if payload_str and payload_str in body:
            start = body.find(payload_str)
            return body[max(0, start-80): start+len(payload_str)+80]
        return body[:max_length]

    def _create_finding(self, test_case: Dict[str, Any], response: Dict[str, Any],
                        category: str, severity: str, evidence: str) -> Dict[str, Any]:
        return {
            "id": test_case.get("id", str(uuid.uuid4())),
            "category": category,
            "url": test_case.get("url", ""),
            "param": test_case.get("param", ""),
            "method": test_case.get("method", ""),
            "payload": test_case.get("payload", ""),
            "status": response.get("status", 0),
            "evidence": evidence,
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
