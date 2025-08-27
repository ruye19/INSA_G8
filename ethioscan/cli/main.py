import argparse
from ethioscan.scanning.network_scan import run_network_scan
from ethioscan.reporting.report_generator import generate_report

def main():
    parser = argparse.ArgumentParser(
        prog="ethioscan",
        description="EthioScan - Security Scanning & Reporting Tool"
    )
    parser.add_argument("--scan", action="store_true", help="Run a network scan")
    parser.add_argument("--report", action="store_true", help="Generate report after scan")
    
    args = parser.parse_args()

    if args.scan:
        print("[*] Running network scan...")
        results = run_network_scan()
        print("[+] Scan complete:", results)

    if args.report:
        print("[*] Generating report...")
        generate_report()
        print("[+] Report saved.")
