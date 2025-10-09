"""
EthioScan - Ethiopian Security Scanner
A vulnerability scanning tool for authorized security testing.
"""

__version__ = "1.0.0"
__author__ = "EthioScan Team"

# Import main components for easy access
from ethioscan.crawler import crawl
from ethioscan.scanner import Scanner
from ethioscan.payloads import get_payloads

__all__ = [
    "crawl",
    "Scanner",
    "get_payloads",
]
