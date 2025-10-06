"""
EthioScan Utils (Deprecated)

This module previously contained an orchestrator function for scanning.
It is now deprecated. Please use `run_scan.py` instead.
"""

import sys

def run_scan(*args, **kwargs):
    sys.stderr.write(
        "[!] The `utils.run_scan` orchestrator is deprecated.\n"
        "    Please use `run_scan.py` as the main entry point.\n"
    )
    raise RuntimeError("Deprecated: use run_scan.py instead of utils.py")
