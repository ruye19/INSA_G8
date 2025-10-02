"""
EthioScan Run Scan - End-to-end vulnerability scanning orchestrator
"""

import argparse
import asyncio
import json
import os
import sys
import time
from typing import Dict, List, Any
from urllib.parse import urlparse

# Import EthioScan modules
from crawler import crawl
from payloads import get_payloads
from fuzzer import generate_tests_from_params, generate_tests_from_forms, submit_test_case
from scanner import Scanner
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

console = Console()


class EthioScanOrchestrator:
    """
    Main orchestrator for running complete EthioScan vulnerability assessments.
    """
    
    def __init__(self, args):
        """
        Initialize the orchestrator with command line arguments.
        
        Args:
            args: Parsed command line arguments
        """
        self.args = args
        self.scanner = Scanner(fast=False)
        self.findings = []
        
    def check_allowlist(self) -> bool:
        """
        Check if the target URL is in the allowlist or user has provided confirmation.
        
        Returns:
            True if allowed, False otherwise
        """
        parsed_url = urlparse(self.args.url)
        domain = parsed_url.netloc.lower()
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Check allowlist file
        allowlist_file = os.path.join(os.path.dirname(__file__), 'allowlist.txt')
        allowed_domains = set()
        
        try:
            with open(allowlist_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        allowed_domains.add(line.lower())
        except FileNotFoundError:
            console.print("[yellow]Warning: allowlist.txt not found. All domains will require confirmation.[/yellow]")
        
        # Check if domain is allowed
        if domain in allowed_domains:
            console.print(f"[green]Domain '{domain}' is in allowlist.[/green]")
            return True
        
        # Check for explicit confirmation
        if self.args.confirm_allow == "I_HAVE_PERMISSION":
            console.print(f"[yellow]Warning: Scanning {domain} with explicit confirmation.[/yellow]")
            return True
        
        # Domain not allowed
        console.print(f"[red]Error: Domain '{domain}' is not in the allowlist.[/red]")
        console.print("[yellow]To scan this domain, you must either:[/yellow]")
        console.print("1. Add it to allowlist.txt")
        console.print("2. Use --confirm-allow I_HAVE_PERMISSION (only if you have explicit permission)")
        console.print("\n[bold red]EthioScan will not scan unauthorized targets.[/bold red]")
        return False
    
    async def run_crawler(self) -> Dict[str, Any]:
        """
        Run the crawler to discover pages, forms, and parameters.
        
        Returns:
            Crawler results dictionary
        """
        console.print(f"[blue]Starting crawler on {self.args.url}[/blue]")
        console.print(f"[blue]Depth: {self.args.depth}, Concurrency: {self.args.concurrency}[/blue]")
        
        try:
            crawl_results = await crawl(
                start_url=self.args.url,
                depth=self.args.depth,
                concurrency=self.args.concurrency,
                delay=0.2
            )
            
            console.print(f"[green]Crawling completed![/green]")
            console.print(f"[blue]Discovered:[/blue]")
            console.print(f"  - {len(crawl_results['pages'])} pages")
            console.print(f"  - {len(crawl_results['forms'])} forms")
            console.print(f"  - {len(crawl_results['params'])} parameterized URLs")
            
            return crawl_results
            
        except Exception as e:
            console.print(f"[red]Crawler error: {e}[/red]")
            raise
    
    def generate_test_cases(self, crawl_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate test cases from crawler results using the fuzzer.
        
        Args:
            crawl_results: Results from the crawler
            
        Returns:
            List of test case dictionaries
        """
        console.print("[blue]Generating test cases...[/blue]")
        
        # Get payloads based on lab mode
        profile = "lab" if self.args.lab else "safe"
        payloads = get_payloads(profile)
        
        console.print(f"[blue]Using payload profile: {profile}[/blue]")
        console.print(f"[blue]Payload categories: {list(payloads.keys())}[/blue]")
        
        # Generate test cases from parameters
        param_tests = list(generate_tests_from_params(
            crawl_results["params"], 
            payloads, 
            max_per_param=2
        ))
        
        # Generate test cases from forms
        form_tests = list(generate_tests_from_forms(
            crawl_results["forms"], 
            payloads, 
            max_samples=2
        ))
        
        # Combine and limit tests
        all_tests = param_tests + form_tests
        
        # Filter out lab-only tests if not in lab mode
        if not self.args.lab:
            filtered_tests = [test for test in all_tests if not test["meta"]["lab_only"]]
            console.print(f"[yellow]Filtered out {len(all_tests) - len(filtered_tests)} lab-only tests[/yellow]")
            all_tests = filtered_tests
        
        # Limit total number of tests
        if len(all_tests) > self.args.max_tests:
            console.print(f"[yellow]Limiting tests from {len(all_tests)} to {self.args.max_tests}[/yellow]")
            all_tests = all_tests[:self.args.max_tests]
        
        console.print(f"[green]Generated {len(all_tests)} test cases[/green]")
        console.print(f"[blue]  - {len(param_tests)} parameter tests[/blue]")
        console.print(f"[blue]  - {len(form_tests)} form tests[/blue]")
        
        return all_tests
    
    async def run_tests(self, test_cases: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Execute test cases and collect findings.
        
        Args:
            test_cases: List of test case dictionaries
            
        Returns:
            List of vulnerability findings
        """
        console.print(f"[blue]Executing {len(test_cases)} test cases...[/blue]")
        
        findings = []
        semaphore = asyncio.Semaphore(self.args.concurrency)
        
        async def execute_test_case(test_case):
            """Execute a single test case."""
            async with semaphore:
                try:
                    # Import aiohttp here to avoid import issues
                    import aiohttp
                    
                    async with aiohttp.ClientSession(
                        timeout=aiohttp.ClientTimeout(total=10),
                        headers={'User-Agent': 'EthioScan/1.0 (Ethiopian Security Scanner)'}
                    ) as session:
                        # Submit test case
                        response = await submit_test_case(session, test_case, timeout=10)
                        
                        # Analyze response with scanner
                        finding = self.scanner.analyze_response(test_case, response)
                        
                        if finding:
                            findings.append(finding)
                            console.print(f"[red]Vulnerability found: {finding['category']} in {finding['param']}[/red]")
                        
                except Exception as e:
                    console.print(f"[yellow]Test case failed: {e}[/yellow]")
        
        # Execute all test cases with progress bar
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Executing tests...", total=len(test_cases))
            
            # Create tasks
            tasks = [execute_test_case(test_case) for test_case in test_cases]
            
            # Execute with progress updates
            completed = 0
            for coro in asyncio.as_completed(tasks):
                await coro
                completed += 1
                progress.update(task, completed=completed)
        
        console.print(f"[green]Test execution completed![/green]")
        console.print(f"[blue]Found {len(findings)} vulnerabilities[/blue]")
        
        return findings
    
    def save_findings(self, findings: List[Dict[str, Any]]) -> None:
        """
        Save findings to JSON file.
        
        Args:
            findings: List of vulnerability findings
        """
        console.print(f"[blue]Saving findings to {self.args.out}[/blue]")
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(self.args.out), exist_ok=True)
        
        # Create findings data structure
        findings_data = {
            "scan_info": {
                "target_url": self.args.url,
                "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "depth": self.args.depth,
                "concurrency": self.args.concurrency,
                "max_tests": self.args.max_tests,
                "lab_mode": self.args.lab,
                "total_findings": len(findings)
            },
            "findings": findings
        }
        
        # Write JSON file
        with open(self.args.out, 'w', encoding='utf-8') as f:
            json.dump(findings_data, f, indent=2, ensure_ascii=False)
        
        console.print(f"[green]Findings saved to {self.args.out}[/green]")
    
    def create_summary(self, findings: List[Dict[str, Any]]) -> None:
        """
        Create a human-readable summary of findings.
        
        Args:
            findings: List of vulnerability findings
        """
        console.print("[blue]Creating summary...[/blue]")
        
        # Count findings by severity and category
        severity_counts = {}
        category_counts = {}
        
        for finding in findings:
            severity = finding.get("severity", "unknown")
            category = finding.get("category", "unknown")
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            category_counts[category] = category_counts.get(category, 0) + 1
        
        # Create summary text
        summary_lines = [
            "EthioScan Vulnerability Assessment Summary",
            "=" * 50,
            f"Target URL: {self.args.url}",
            f"Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Total Findings: {len(findings)}",
            "",
            "Findings by Severity:",
            "-" * 20
        ]
        
        for severity in ["critical", "high", "medium", "low"]:
            count = severity_counts.get(severity, 0)
            summary_lines.append(f"{severity.capitalize()}: {count}")
        
        summary_lines.extend([
            "",
            "Findings by Category:",
            "-" * 20
        ])
        
        for category, count in sorted(category_counts.items()):
            summary_lines.append(f"{category.upper()}: {count}")
        
        if findings:
            summary_lines.extend([
                "",
                "Top Vulnerabilities:",
                "-" * 20
            ])
            
            # Show top 5 findings
            for i, finding in enumerate(findings[:5], 1):
                summary_lines.append(
                    f"{i}. {finding['category'].upper()} - {finding['severity']} - {finding['param']} - {finding['url']}"
                )
        
        summary_text = "\n".join(summary_lines)
        
        # Save summary
        summary_file = "examples/sample_summary.txt"
        os.makedirs("examples", exist_ok=True)
        
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write(summary_text)
        
        console.print(f"[green]Summary saved to {summary_file}[/green]")
    
    def print_final_summary(self, findings: List[Dict[str, Any]]) -> None:
        """
        Print final summary to console.
        
        Args:
            findings: List of vulnerability findings
        """
        console.print("\n[bold green]EthioScan Assessment Complete![/bold green]")
        console.print("=" * 50)
        console.print(f"Target: {self.args.url}")
        console.print(f"Total Findings: {len(findings)}")
        
        if findings:
            severity_counts = {}
            for finding in findings:
                severity = finding.get("severity", "unknown")
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            console.print("\n[bold]Findings by Severity:[/bold]")
            for severity in ["critical", "high", "medium", "low"]:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    color = "red" if severity in ["critical", "high"] else "yellow" if severity == "medium" else "blue"
                    console.print(f"  [{color}]{severity.capitalize()}: {count}[/{color}]")
        else:
            console.print("\n[green]No vulnerabilities found![/green]")
        
        console.print(f"\n[blue]Results saved to:[/blue]")
        console.print(f"  - {self.args.out}")
        console.print(f"  - examples/sample_summary.txt")
    
    async def run(self) -> None:
        """
        Run the complete EthioScan assessment.
        """
        start_time = time.time()
        
        try:
            # Check allowlist
            if not self.check_allowlist():
                sys.exit(1)
            
            # Run crawler
            crawl_results = await self.run_crawler()
            
            # Generate test cases
            test_cases = self.generate_test_cases(crawl_results)
            
            if not test_cases:
                console.print("[yellow]No test cases generated. Nothing to scan.[/yellow]")
                self.save_findings([])
                self.create_summary([])
                self.print_final_summary([])
                return
            
            # Run tests
            findings = await self.run_tests(test_cases)
            
            # Save results
            self.save_findings(findings)
            self.create_summary(findings)
            
            # Print final summary
            elapsed = time.time() - start_time
            console.print(f"\n[blue]Total scan time: {elapsed:.1f} seconds[/blue]")
            self.print_final_summary(findings)
            
        except KeyboardInterrupt:
            console.print("\n[yellow]Scan interrupted by user[/yellow]")
            sys.exit(1)
        except Exception as e:
            console.print(f"\n[red]Scan failed: {e}[/red]")
            sys.exit(1)


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="EthioScan - End-to-end vulnerability scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m ethioscan.run_scan --url https://example.com
  python -m ethioscan.run_scan --url https://example.com --depth 3 --max-tests 100
  python -m ethioscan.run_scan --url https://example.com --lab --confirm-allow I_HAVE_PERMISSION

Safety Notice:
  EthioScan is designed for authorized testing only. Always ensure you have
  explicit permission before scanning any target.
        """
    )
    
    parser.add_argument(
        '--url',
        required=True,
        help='Target URL to scan (required)'
    )
    
    parser.add_argument(
        '--depth',
        type=int,
        default=2,
        help='Crawling depth (default: 2)'
    )
    
    parser.add_argument(
        '--concurrency',
        type=int,
        default=5,
        help='Concurrency level (default: 5)'
    )
    
    parser.add_argument(
        '--max-tests',
        type=int,
        default=200,
        help='Maximum number of test cases to generate (default: 200)'
    )
    
    parser.add_argument(
        '--out',
        default='examples/sample_findings.json',
        help='Output JSON file path (default: examples/sample_findings.json)'
    )
    
    parser.add_argument(
        '--lab',
        action='store_true',
        help='Enable lab-only payloads (potentially destructive)'
    )
    
    parser.add_argument(
        '--confirm-allow',
        help='Confirmation string to bypass allowlist (use: I_HAVE_PERMISSION)'
    )
    
    return parser.parse_args()


async def main():
    """Main entry point."""
    args = parse_args()
    
    # Print banner
    console.print("\n[bold blue]EthioScan Vulnerability Scanner[/bold blue]")
    console.print("[italic]Ethiopian Security Scanner - End-to-End Assessment[/italic]")
    console.print("=" * 60)
    
    # Create and run orchestrator
    orchestrator = EthioScanOrchestrator(args)
    await orchestrator.run()


if __name__ == '__main__':
    asyncio.run(main())
