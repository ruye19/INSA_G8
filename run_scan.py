"""
EthioScan Run Scan - End-to-end vulnerability scanning orchestrator
Advanced-only mode.
"""

import argparse
import asyncio
import json
import os
import sys
import time
from typing import Dict, List, Any
from urllib.parse import urlparse

# EthioScan modules
from crawler import crawl
from payloads import get_payloads
from fuzzer import (
    generate_tests_from_params,
    generate_tests_from_forms,
    submit_test_case,
)
from scanner import Scanner
from reporter import save_report

# ---------------------------
# DB: add imports (SQLite now, Postgres-ready later)
# ---------------------------
try:
    from ethioscan_db import (
        init_db,
        start_scan,
        save_findings as db_save_findings,  # avoid name clash with method below
        finish_scan,
    )
except Exception:  # if module missing, keep scanner working
    init_db = lambda: None
    start_scan = lambda *a, **k: None
    db_save_findings = lambda *a, **k: None
    finish_scan = lambda *a, **k: None
# ---------------------------

from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
)

console = Console()


class EthioScanOrchestrator:
    """Main orchestrator for running complete EthioScan vulnerability assessments."""

    def __init__(self, args):
        self.args = args
        self.scanner = Scanner(fast=False)
        self.findings: List[Dict[str, Any]] = []
        self.tests_executed: int = 0
        # ---------------------------
        # DB: track current scan id
        # ---------------------------
        self.scan_id: Any = None

    # ---------------------------
    # Utilities
    # ---------------------------
    @staticmethod
    def _to_text(value: Any) -> str:
        """Robustly stringify any value for pattern checks."""
        try:
            if isinstance(value, (dict, list, tuple)):
                return json.dumps(value, ensure_ascii=False)
            return "" if value is None else str(value)
        except Exception:
            return str(value)

    def classify_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assign severity and normalize category based on payload/response.
        Defensive against any payload type (str/dict/etc).
        """
        category = self._to_text(finding.get("category", "error")).lower()
        payload_txt = self._to_text(finding.get("payload", "")).lower()

        # Defaults
        final_cat = "Error Response" if "error" in category else "Anomalous Response"
        severity = "medium" if final_cat == "Error Response" else "low"

        # Category heuristics
        if "sqli" in category or "' or" in payload_txt or "union select" in payload_txt:
            final_cat, severity = "SQL Injection", "high"
        elif "xss" in category or "<script" in payload_txt or "onerror=" in payload_txt or "onload=" in payload_txt:
            final_cat, severity = "Cross-Site Scripting (XSS)", "high"
        elif "command" in category or any(tok in payload_txt for tok in ["; ", "&&", " |", "| ", "`", "$("]):
            final_cat, severity = "Command Injection", "high"
        elif "ldap" in category:
            final_cat, severity = "LDAP Injection", "high"
        elif "nosql" in category:
            final_cat, severity = "NoSQL Injection", "high"
        elif "idor" in category:
            final_cat, severity = "IDOR", "medium"
        elif "info" in category:
            final_cat, severity = "Information Disclosure", "medium"

        finding["category"] = final_cat
        finding["severity"] = severity
        return finding

    # ---------------------------
    # Allowlist
    # ---------------------------
    def check_allowlist(self) -> bool:
        """Check domain against allowlist or explicit confirmation."""
        parsed_url = urlparse(self.args.url)
        domain = parsed_url.netloc.lower().split(":")[0]

        allowlist_file = os.path.join(os.path.dirname(__file__), "allowlist.txt")
        allowed = set()
        try:
            with open(allowlist_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        allowed.add(line.lower())
        except FileNotFoundError:
            console.print(
                "[yellow]Warning: allowlist.txt not found. All domains will require confirmation.[/yellow]"
            )

        if domain in allowed:
            console.print(f"[green]Domain '{domain}' is in allowlist.[/green]")
            return True

        if getattr(self.args, "confirm_allow", None) == "I_HAVE_PERMISSION":
            console.print(f"[yellow]Warning: Scanning {domain} with explicit confirmation.[/yellow]")
            return True

        console.print(f"[red]Error: Domain '{domain}' is not in the allowlist.[/red]")
        console.print("[yellow]To scan this domain, you must either:[/yellow]")
        console.print("1. Add it to allowlist.txt")
        console.print("2. Use --confirm-allow I_HAVE_PERMISSION (only if you have explicit permission)")
        console.print("\n[bold red]EthioScan will not scan unauthorized targets.[/bold red]")
        return False

    # ---------------------------
    # Crawl
    # ---------------------------
    async def run_crawler(self) -> Dict[str, Any]:
        """Run async crawler."""
        console.print(f"[blue]Starting crawler on {self.args.url}[/blue]")
        console.print(f"[blue]Depth: {self.args.depth}, Concurrency: {self.args.concurrency}[/blue]")

        crawl_results = await crawl(
            start_url=self.args.url,
            depth=self.args.depth,
            concurrency=self.args.concurrency,
            delay=0.2,
        )

        console.print(f"[green]Crawling completed![/green]")
        console.print(f"[blue]Discovered:[/blue]")
        console.print(f"  - {len(crawl_results['pages'])} pages")
        console.print(f"  - {len(crawl_results['forms'])} forms")
        console.print(f"  - {len(crawl_results['params'])} parameterized URLs")
        return crawl_results

    # ---------------------------
    # Test generation
    # ---------------------------
    def generate_test_cases(self, crawl_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate test cases using fuzzer and payload profiles."""
        console.print("[blue]Generating test cases...[/blue]")

        profile = "lab" if self.args.lab else "safe"
        payloads = get_payloads(profile)

        console.print(f"[blue]Using payload profile: {profile}[/blue]")
        console.print(f"[blue]Payload categories: {list(payloads.keys())}[/blue]")

        param_tests = list(
            generate_tests_from_params(
                crawl_results["params"], payloads, max_per_param=2
            )
        )
        form_tests = list(
            generate_tests_from_forms(
                crawl_results["forms"], payloads, max_samples=2
            )
        )

        all_tests = param_tests + form_tests

        if not self.args.lab:
            filtered = [t for t in all_tests if not t.get("meta", {}).get("lab_only")]
            if len(filtered) != len(all_tests):
                console.print(f"[yellow]Filtered out {len(all_tests) - len(filtered)} lab-only tests[/yellow]")
            all_tests = filtered

        if len(all_tests) > self.args.max_tests:
            console.print(f"[yellow]Limiting tests from {len(all_tests)} to {self.args.max_tests}[/yellow]")
            all_tests = all_tests[: self.args.max_tests]

        console.print(f"[green]Generated {len(all_tests)} test cases[/green]")
        console.print(f"[blue]  - {len(param_tests)} parameter tests[/blue]")
        console.print(f"[blue]  - {len(form_tests)} form tests[/blue]")
        return all_tests

    # ---------------------------
    # Execute tests
    # ---------------------------
    async def run_tests(self, test_cases: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Run tests concurrently and analyze responses."""
        console.print(f"[blue]Executing {len(test_cases)} test cases...[/blue]")

        findings: List[Dict[str, Any]] = []
        sem = asyncio.Semaphore(self.args.concurrency)

        async def execute(test_case: Dict[str, Any]) -> None:
            async with sem:
                try:
                    import aiohttp

                    async with aiohttp.ClientSession(
                        timeout=aiohttp.ClientTimeout(total=10),
                        headers={
                            "User-Agent": "EthioScan/1.0 (Ethiopian Security Scanner)"
                        },
                    ) as session:
                        resp = await submit_test_case(session, test_case, timeout=10)

                        # Analyze
                        finding = self.scanner.analyze_response(test_case, resp)
                        if finding:
                            finding = self.classify_finding(finding)
                            findings.append(finding)
                            console.print(
                                f"[red]Vulnerability found: {finding['category']} "
                                f"(Severity: {finding['severity'].capitalize()}) "
                                f"in {finding.get('param','')}[/red]"
                            )
                except Exception as e:
                    console.print(f"[yellow]Test case failed: {e}[/yellow]")
                finally:
                    self.tests_executed += 1

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Executing tests...", total=len(test_cases))
            pending = [execute(tc) for tc in test_cases]

            done = 0
            for coro in asyncio.as_completed(pending):
                await coro
                done += 1
                progress.update(task, completed=done)

        console.print(f"[green]Test execution completed![/green]")
        console.print(f"[blue]Found {len(findings)} vulnerabilities[/blue]")
        return findings

    # ---------------------------
    # Reporting / Persistence
    # ---------------------------

    def save_findings(self, findings: List[Dict[str, Any]]) -> None:
        """Save raw findings JSON to --out when report=json, or sidecar JSON otherwise."""
        # ------------------------------
        # ADDED: Normalize output path to examples/
        # ------------------------------
        base_out_name = os.path.basename(self.args.out or "report.html")
        normalized_out = os.path.join("examples", base_out_name)
        os.makedirs("examples", exist_ok=True)
        # ensure downstream steps (print + save_report) see the normalized path
        self.args.out = normalized_out
        # ------------------------------

        target_out = self.args.out
        out_dir = os.path.dirname(target_out)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)

        data = {
            "scan_info": {
                "target_url": self.args.url,
                "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "depth": self.args.depth,
                "concurrency": self.args.concurrency,
                "max_tests": self.args.max_tests,
                "lab_mode": self.args.lab,
                "tests_executed": self.tests_executed,
                "total_findings": len(findings),
            },
            "findings": findings,
        }

        # If user asked for JSON report, write it directly to --out
        # Otherwise, write a sidecar JSON next to the HTML for convenience.
        json_path = target_out if self.args.report == "json" else (
            os.path.splitext(target_out)[0] + ".json"
        )
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        console.print(f"[green]Findings saved to {json_path}[/green]")

    def create_summary(self, findings: List[Dict[str, Any]]) -> None:
        """Create a concise text summary."""
        console.print("[blue]Creating summary...[/blue]")

        severities, categories = {}, {}
        for f in findings:
            sev = f.get("severity", "unknown")
            cat = f.get("category", "unknown")
            severities[sev] = severities.get(sev, 0) + 1
            categories[cat] = categories.get(cat, 0) + 1

        lines = [
            "EthioScan Vulnerability Assessment Summary",
            "=" * 50,
            f"Target URL: {self.args.url}",
            f"Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Tests Executed: {self.tests_executed}",
            f"Total Findings: {len(findings)}",
            "",
            "Findings by Severity:",
            "-" * 20,
        ]
        for sev in ["critical", "high", "medium", "low"]:
            lines.append(f"{sev.capitalize()}: {severities.get(sev, 0)}")

        lines.extend(["", "Findings by Category:", "-" * 20])
        for cat, cnt in sorted(categories.items()):
            lines.append(f"{cat.upper()}: {cnt}")

        if findings:
            lines.extend(["", "Top (up to 5) Findings:", "-" * 20])
            for i, f in enumerate(findings[:5], 1):
                lines.append(
                    f"{i}. {f['category']} - {f['severity']} - {f.get('param','')} - {f.get('url','')}"
                )

        os.makedirs("examples", exist_ok=True)
        summary_file = "examples/sample_summary.txt"
        with open(summary_file, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))

        console.print(f"[green]Summary saved to {summary_file}[/green]")

    def print_final_summary(self, findings: List[Dict[str, Any]]) -> None:
        """Console summary."""
        console.print("\n[bold green]EthioScan Assessment Complete![/bold green]")
        console.print("=" * 50)
        console.print(f"Target: {self.args.url}")
        console.print(f"Tests Executed: {self.tests_executed}")
        console.print(f"Total Findings: {len(findings)}")

        if findings:
            console.print("\n[bold]Findings by Severity:[/bold]")
            severities = {}
            for f in findings:
                s = f.get("severity", "unknown")
                severities[s] = severities.get(s, 0) + 1
            for sev in ["critical", "high", "medium", "low"]:
                c = severities.get(sev, 0)
                if c:
                    color = "red" if sev in ("critical", "high") else ("yellow" if sev == "medium" else "blue")
                    console.print(f"  [{color}]{sev.capitalize()}: {c}[/{color}]")
        else:
            console.print("\n[green]No vulnerabilities found![/green]")

        console.print(f"\n[blue]Results saved to:[/blue]")
        console.print(f"  - {self.args.out}")
        console.print(f"  - examples/sample_summary.txt")

    # ---------------------------
    # Main Orchestration
    # ---------------------------
    async def run(self) -> None:
        start = time.time()
        try:
            if not self.check_allowlist():
                sys.exit(1)

            # ---------------------------
            # DB: init and register this scan
            # ---------------------------
            init_db()
            self.scan_id = start_scan({
                "target_url": self.args.url,
                "depth": self.args.depth,
                "concurrency": self.args.concurrency,
                "max_tests": self.args.max_tests,
                "lab_mode": self.args.lab,
            })
            # ---------------------------

            crawl_results = await self.run_crawler()
            test_cases = self.generate_test_cases(crawl_results)

            if not test_cases:
                console.print("[yellow]No test cases generated. Nothing to scan.[/yellow]")
                self.save_findings([])
                self.create_summary([])
                # ---------------------------
                # DB: finalize even when empty
                # ---------------------------
                try:
                    report_html_path = self.args.out if self.args.report == "html" else None
                    report_json_path = (
                        os.path.splitext(self.args.out)[0] + ".json"
                        if self.args.report == "html"
                        else self.args.out
                    )
                    finish_scan(
                        self.scan_id,
                        {"total": 0, "tests_executed": self.tests_executed},
                        {"html": report_html_path, "json": report_json_path},
                    )
                except Exception:
                    pass
                # ---------------------------
                self.print_final_summary([])
                return

            findings = await self.run_tests(test_cases)

            # Save raw findings (json or sidecar)
            self.save_findings(findings)

            # ---------------------------
            # DB: store findings rows
            # ---------------------------
            try:
                db_save_findings(self.scan_id, findings)
            except Exception:
                # keep scanning/reporting even if DB write fails
                pass
            # ---------------------------

            # Create summary
            self.create_summary(findings)

            # Generate pretty report (HTML/JSON) using reporter
            meta = {
                "target": self.args.url,
                "depth": self.args.depth,
                "concurrency": self.args.concurrency,
                "report_format": self.args.report,
            }
            # Pass tests_run = self.tests_executed for accuracy
            save_report(meta, findings, self.args.report, self.args.out, tests_run=self.tests_executed)
            console.print(f"[green]Detailed report saved to {self.args.out}[/green]")

            # ---------------------------
            # DB: finalize scan with summary + report paths
            # ---------------------------
            try:
                summary = {"total": len(findings), "tests_executed": self.tests_executed}
                report_html_path = self.args.out if self.args.report == "html" else None
                report_json_path = (
                    os.path.splitext(self.args.out)[0] + ".json"
                    if self.args.report == "html"
                    else self.args.out
                )
                finish_scan(self.scan_id, summary, {"html": report_html_path, "json": report_json_path})
            except Exception:
                pass
            # ---------------------------

            console.print(f"\n[blue]Total scan time: {time.time() - start:.1f} seconds[/blue]")
            self.print_final_summary(findings)

        except KeyboardInterrupt:
            console.print("\n[yellow]Scan interrupted by user[/yellow]")
            sys.exit(1)
        except Exception as e:
            console.print(f"\n[red]Scan failed: {e}[/red]")
            sys.exit(1)


# ---------------------------
# CLI glue (advanced-only)
# ---------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="EthioScan - End-to-end vulnerability scanner (advanced-only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_scan.py --url http://localhost:8000/test_page.html
  python run_scan.py --url https://example.com --depth 3 --max-tests 100
  python run_scan.py --url https://example.com --lab --confirm-allow I_HAVE_PERMISSION

Safety Notice:
  EthioScan is designed for authorized testing only. Always ensure you have
  explicit permission before scanning any target.
        """,
    )

    parser.add_argument("--url", required=True, help="Target URL to scan (required)")
    parser.add_argument("--depth", type=int, default=2, help="Crawling depth (default: 2)")
    parser.add_argument("--concurrency", type=int, default=5, help="Concurrency level (default: 5)")
    parser.add_argument("--max-tests", type=int, default=200, help="Maximum number of tests (default: 200)")
    parser.add_argument("--out", default="examples/report.html", help="Output report path (html/json).")
    parser.add_argument("--report", choices=["html", "json"], default="html", help="Report format (default: html)")
    parser.add_argument("--lab", action="store_true", help="Enable lab-only payloads (potentially destructive)")
    parser.add_argument("--confirm-allow", help="Bypass allowlist (use: I_HAVE_PERMISSION)")
    return parser.parse_args()


async def main():
    args = parse_args()
    console.print("\n[bold blue]EthioScan Vulnerability Scanner[/bold blue]")
    console.print("[italic]Ethiopian Security Scanner - End-to-End Assessment[/italic]")
    console.print("=" * 60)

    orchestrator = EthioScanOrchestrator(args)
    await orchestrator.run()


if __name__ == "__main__":
    asyncio.run(main())
