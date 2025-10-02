"""
EthioScan Scanner - Vulnerability detection and analysis
"""

import re
import uuid
from typing import Dict, List, Optional, Any


class Scanner:
    """
    Vulnerability scanner for analyzing HTTP responses and detecting security issues.
    """
    
    def __init__(self, fast: bool = False):
        """
        Initialize the scanner.
        
        Args:
            fast: If True, skips heavy checks for faster scanning
        """
        self.fast = fast
        
        # Database error keywords for SQL injection detection
        self.sqli_keywords = [
            "syntax error", "mysql", "ora-00933", "postgres", "sqlstate",
            "sql syntax", "database error", "sql error", "query failed",
            "mysql_fetch", "postgresql", "oracle", "sqlite", "mssql",
            "sql server", "access denied", "invalid query", "sql exception",
            "database connection", "sql command", "sqlite3", "mysqli",
            "pg_query", "oci_parse", "sqlite_error", "mssql_query"
        ]
        
        # XSS payload patterns for reflected XSS detection
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"<img[^>]*onerror[^>]*>",
            r"<svg[^>]*onload[^>]*>",
            r"<iframe[^>]*src[^>]*javascript:",
            r"<body[^>]*onload[^>]*>",
            r"<input[^>]*onfocus[^>]*>",
            r"<select[^>]*onfocus[^>]*>",
            r"javascript:",
            r"onclick\s*=",
            r"onmouseover\s*=",
            r"onerror\s*=",
            r"onload\s*="
        ]
        
        # Error keywords for general error detection
        self.error_keywords = [
            "error", "exception", "warning", "fatal", "critical",
            "failed", "failure", "invalid", "unauthorized", "forbidden",
            "not found", "internal server error", "bad request",
            "service unavailable", "timeout", "connection refused"
        ]
    
    def analyze_response(self, test_case: Dict, response: Dict) -> Optional[Dict]:
        """
        Analyze a test case and response to detect vulnerabilities.
        
        Args:
            test_case: Test case dictionary from fuzzer
            response: Response dictionary with status, headers, body, etc.
            
        Returns:
            Finding dictionary if vulnerability detected, None otherwise
        """
        if not response or not response.get("body"):
            return None
        
        response_body = response["body"].lower()
        payload = test_case.get("payload", {})
        
        # Extract payload string for reflection checking
        payload_str = ""
        if isinstance(payload, dict) and "payload" in payload:
            payload_str = payload["payload"].lower()
        elif isinstance(payload, str):
            payload_str = payload.lower()
        
        # Check for SQL injection
        if self.detect_sqli(response_body):
            return self._create_finding(
                test_case, response, "sqli", "high",
                self._extract_evidence(response_body, payload_str)
            )
        
        # Check for XSS
        if self.detect_xss(response_body, payload_str):
            return self._create_finding(
                test_case, response, "xss", "high",
                self._extract_evidence(response_body, payload_str)
            )
        
        # Check for general errors
        if self.detect_error_keywords(response_body):
            return self._create_finding(
                test_case, response, "error", "medium",
                self._extract_evidence(response_body, payload_str)
            )
        
        # Check for other anomalies
        if self._detect_anomalies(response, payload_str):
            return self._create_finding(
                test_case, response, "anomaly", "low",
                self._extract_evidence(response_body, payload_str)
            )
        
        return None
    
    def detect_sqli(self, response_body: str) -> bool:
        """
        Detect SQL injection vulnerabilities in response body.
        
        Args:
            response_body: Lowercase response body text
            
        Returns:
            True if SQL injection indicators found
        """
        for keyword in self.sqli_keywords:
            if keyword in response_body:
                return True
        return False
    
    def detect_xss(self, response_body: str, payload_str: str = "") -> bool:
        """
        Detect XSS vulnerabilities in response body.
        
        Args:
            response_body: Lowercase response body text
            payload_str: Lowercase payload string for reflection checking
            
        Returns:
            True if XSS indicators found
        """
        # Check for XSS patterns first (more reliable)
        for pattern in self.xss_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                return True
        
        # Check for payload reflection only if payload contains XSS indicators
        if payload_str and self._is_xss_payload(payload_str):
            if payload_str in response_body:
                return True
        
        return False
    
    def _is_xss_payload(self, payload_str: str) -> bool:
        """
        Check if a payload string contains XSS indicators.
        
        Args:
            payload_str: Payload string to check
            
        Returns:
            True if payload contains XSS indicators
        """
        xss_indicators = [
            "<script", "<img", "<svg", "<iframe", "<body", "<input", "<select",
            "javascript:", "onclick", "onmouseover", "onerror", "onload", "onfocus"
        ]
        
        payload_lower = payload_str.lower()
        return any(indicator in payload_lower for indicator in xss_indicators)
    
    def detect_error_keywords(self, response_body: str) -> bool:
        """
        Detect general error keywords in response body.
        
        Args:
            response_body: Lowercase response body text
            
        Returns:
            True if error keywords found
        """
        for keyword in self.error_keywords:
            if keyword in response_body:
                return True
        return False
    
    def _detect_anomalies(self, response: Dict, payload_str: str) -> bool:
        """
        Detect other anomalies that might indicate vulnerabilities.
        
        Args:
            response: Response dictionary
            payload_str: Payload string for checking
            
        Returns:
            True if anomalies detected
        """
        # Check for unusual status codes
        status = response.get("status", 0)
        if status in [500, 502, 503, 504]:
            return True
        
        # Check for unusual response times (if available)
        elapsed = response.get("elapsed", 0)
        if elapsed > 10:  # Very slow response might indicate processing issues
            return True
        
        # Check for unusual headers
        headers = response.get("headers", {})
        if "server" in headers:
            server = headers["server"].lower()
            if any(keyword in server for keyword in ["error", "debug", "test"]):
                return True
        
        return False
    
    def _create_finding(self, test_case: Dict, response: Dict, category: str, 
                       severity: str, evidence: str) -> Dict:
        """
        Create a vulnerability finding dictionary.
        
        Args:
            test_case: Original test case
            response: HTTP response
            category: Vulnerability category
            severity: Severity level
            evidence: Evidence snippet
            
        Returns:
            Finding dictionary
        """
        return {
            "id": test_case.get("id", str(uuid.uuid4())),
            "category": category,
            "param": test_case.get("param", ""),
            "url": test_case.get("url", ""),
            "method": test_case.get("method", ""),
            "payload": test_case.get("payload", {}),
            "status": response.get("status", 0),
            "evidence": evidence,
            "severity": severity,
            "final_url": response.get("final_url", ""),
            "response_time": response.get("elapsed", 0),
            "timestamp": self._get_timestamp()
        }
    
    def _extract_evidence(self, response_body: str, payload_str: str, max_length: int = 500) -> str:
        """
        Extract evidence snippet from response body.
        
        Args:
            response_body: Response body text
            payload_str: Payload string to highlight
            max_length: Maximum evidence length
            
        Returns:
            Evidence snippet
        """
        if not response_body:
            return ""
        
        # If payload is reflected, try to extract context around it
        if payload_str and payload_str in response_body:
            start = response_body.find(payload_str)
            if start != -1:
                # Extract context around the payload
                context_start = max(0, start - 100)
                context_end = min(len(response_body), start + len(payload_str) + 100)
                evidence = response_body[context_start:context_end]
                
                # Truncate if too long
                if len(evidence) > max_length:
                    evidence = evidence[:max_length] + "..."
                
                return evidence
        
        # Otherwise, return beginning of response
        if len(response_body) > max_length:
            return response_body[:max_length] + "..."
        
        return response_body
    
    def _get_timestamp(self) -> str:
        """
        Get current timestamp string.
        
        Returns:
            ISO timestamp string
        """
        from datetime import datetime
        return datetime.now().isoformat()
    
    def get_detection_stats(self) -> Dict[str, int]:
        """
        Get detection statistics.
        
        Returns:
            Dictionary with detection counts
        """
        return {
            "sqli_keywords": len(self.sqli_keywords),
            "xss_patterns": len(self.xss_patterns),
            "error_keywords": len(self.error_keywords),
            "fast_mode": self.fast
        }