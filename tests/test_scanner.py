"""
Tests for EthioScan Scanner
"""

import pytest
import uuid
from scanner import Scanner


class TestScanner:
    """Test Scanner class functionality"""
    
    def test_scanner_initialization(self):
        """Test scanner initialization"""
        scanner = Scanner()
        assert scanner.fast == False
        
        scanner_fast = Scanner(fast=True)
        assert scanner_fast.fast == True
        
        # Check that detection keywords are loaded
        stats = scanner.get_detection_stats()
        assert stats["sqli_keywords"] > 0
        assert stats["xss_patterns"] > 0
        assert stats["error_keywords"] > 0
    
    def test_detect_sqli_positive(self):
        """Test SQL injection detection with positive cases"""
        scanner = Scanner()
        
        # Test various SQL error patterns
        test_cases = [
            "mysql syntax error in query",
            "postgresql database error",
            "ora-00933: command not properly ended",
            "sqlite3.OperationalError: near",
            "mssql server error",
            "database connection failed",
            "invalid sql command",
            "sql exception occurred"
        ]
        
        for test_case in test_cases:
            assert scanner.detect_sqli(test_case.lower()) == True
    
    def test_detect_sqli_negative(self):
        """Test SQL injection detection with negative cases"""
        scanner = Scanner()
        
        # Test non-SQL content
        test_cases = [
            "welcome to our website",
            "login successful",
            "page not found",
            "contact us for more information",
            "javascript:alert('hello')",
            "normal html content"
        ]
        
        for test_case in test_cases:
            assert scanner.detect_sqli(test_case.lower()) == False
    
    def test_detect_xss_positive(self):
        """Test XSS detection with positive cases"""
        scanner = Scanner()
        
        # Test XSS patterns
        test_cases = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<iframe src=javascript:alert(1)></iframe>",
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "javascript:alert(1)",
            "onclick=alert(1)"
        ]
        
        for test_case in test_cases:
            assert scanner.detect_xss(test_case.lower()) == True
    
    def test_detect_xss_payload_reflection(self):
        """Test XSS detection with payload reflection"""
        scanner = Scanner()
        
        response_body = "welcome <script>alert(1)</script> to our site"
        payload_str = "<script>alert(1)</script>"
        
        assert scanner.detect_xss(response_body.lower(), payload_str.lower()) == True
    
    def test_detect_xss_negative(self):
        """Test XSS detection with negative cases"""
        scanner = Scanner()
        
        # Test non-XSS content
        test_cases = [
            "welcome to our website",
            "login successful",
            "contact us for more information",
            "normal html content",
            "mysql syntax error",
            "database connection failed"
        ]
        
        for test_case in test_cases:
            assert scanner.detect_xss(test_case.lower()) == False
    
    def test_detect_error_keywords_positive(self):
        """Test error keyword detection with positive cases"""
        scanner = Scanner()
        
        test_cases = [
            "internal server error",
            "unauthorized access",
            "forbidden request",
            "service unavailable",
            "connection timeout",
            "bad request format",
            "critical system failure"
        ]
        
        for test_case in test_cases:
            assert scanner.detect_error_keywords(test_case.lower()) == True
    
    def test_detect_error_keywords_negative(self):
        """Test error keyword detection with negative cases"""
        scanner = Scanner()
        
        test_cases = [
            "welcome to our website",
            "login successful",
            "page loaded successfully",
            "contact us for more information",
            "normal operation"
        ]
        
        for test_case in test_cases:
            assert scanner.detect_error_keywords(test_case.lower()) == False
    
    def test_analyze_response_sqli_detection(self):
        """Test analyze_response with SQL injection detection"""
        scanner = Scanner()
        
        test_case = {
            "id": str(uuid.uuid4()),
            "method": "GET",
            "url": "https://example.com/search?q=test",
            "param": "q",
            "payload": {"payload": "' OR 1=1--", "note": "SQLi test"},
            "origin": "param",
            "meta": {"category": "sqli", "lab_only": False},
            "crawl_ref": {}
        }
        
        response = {
            "status": 200,
            "headers": {"content-type": "text/html"},
            "body": "mysql syntax error in query at line 1",
            "final_url": "https://example.com/search?q=test",
            "elapsed": 0.5
        }
        
        finding = scanner.analyze_response(test_case, response)
        
        assert finding is not None
        assert finding["category"] == "sqli"
        assert finding["severity"] == "high"
        assert finding["param"] == "q"
        assert finding["url"] == "https://example.com/search?q=test"
        assert finding["method"] == "GET"
        assert finding["status"] == 200
        assert "mysql syntax error" in finding["evidence"]
    
    def test_analyze_response_xss_detection(self):
        """Test analyze_response with XSS detection"""
        scanner = Scanner()
        
        test_case = {
            "id": str(uuid.uuid4()),
            "method": "GET",
            "url": "https://example.com/search?q=test",
            "param": "q",
            "payload": {"payload": "<script>alert(1)</script>", "note": "XSS test"},
            "origin": "param",
            "meta": {"category": "xss", "lab_only": False},
            "crawl_ref": {}
        }
        
        response = {
            "status": 200,
            "headers": {"content-type": "text/html"},
            "body": "Search results for: <script>alert(1)</script>",
            "final_url": "https://example.com/search?q=test",
            "elapsed": 0.3
        }
        
        finding = scanner.analyze_response(test_case, response)
        
        assert finding is not None
        assert finding["category"] == "xss"
        assert finding["severity"] == "high"
        assert finding["param"] == "q"
        assert finding["url"] == "https://example.com/search?q=test"
        assert finding["method"] == "GET"
        assert finding["status"] == 200
        assert "<script>alert(1)</script>" in finding["evidence"]
    
    def test_analyze_response_error_detection(self):
        """Test analyze_response with error detection"""
        scanner = Scanner()
        
        test_case = {
            "id": str(uuid.uuid4()),
            "method": "POST",
            "url": "https://example.com/submit",
            "param": "data",
            "payload": {"payload": "test", "note": "test"},
            "origin": "form",
            "meta": {"category": "sqli", "lab_only": False},
            "crawl_ref": {}
        }
        
        response = {
            "status": 500,
            "headers": {"content-type": "text/html"},
            "body": "internal server error occurred",
            "final_url": "https://example.com/submit",
            "elapsed": 2.0
        }
        
        finding = scanner.analyze_response(test_case, response)
        
        assert finding is not None
        assert finding["category"] == "error"
        assert finding["severity"] == "medium"
        assert finding["status"] == 500
        assert "internal server error" in finding["evidence"]
    
    def test_analyze_response_no_vulnerability(self):
        """Test analyze_response with no vulnerability detected"""
        scanner = Scanner()
        
        test_case = {
            "id": str(uuid.uuid4()),
            "method": "GET",
            "url": "https://example.com/search?q=test",
            "param": "q",
            "payload": {"payload": "normal search", "note": "test"},
            "origin": "param",
            "meta": {"category": "sqli", "lab_only": False},
            "crawl_ref": {}
        }
        
        response = {
            "status": 200,
            "headers": {"content-type": "text/html"},
            "body": "Search results for: normal search",
            "final_url": "https://example.com/search?q=test",
            "elapsed": 0.2
        }
        
        finding = scanner.analyze_response(test_case, response)
        
        assert finding is None
    
    def test_analyze_response_empty_response(self):
        """Test analyze_response with empty response"""
        scanner = Scanner()
        
        test_case = {
            "id": str(uuid.uuid4()),
            "method": "GET",
            "url": "https://example.com/test",
            "param": "q",
            "payload": {"payload": "test", "note": "test"},
            "origin": "param",
            "meta": {"category": "sqli", "lab_only": False},
            "crawl_ref": {}
        }
        
        response = {
            "status": 200,
            "headers": {},
            "body": "",
            "final_url": "https://example.com/test",
            "elapsed": 0.1
        }
        
        finding = scanner.analyze_response(test_case, response)
        
        assert finding is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
