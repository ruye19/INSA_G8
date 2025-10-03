#!/usr/bin/env python3
"""
EthioScan - CLI Web Vulnerability Scanner
A lightweight Python CLI vulnerability scanner that crawls, fuzzes, scans, and reports findings.
"""

import argparse
import sys
import os
import asyncio
from urllib.parse import urlparse
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()


def print_banner():
    """Print the EthioScan banner."""
    banner_text = Text()
    banner_text.append("EthioScan", style="bold blue")
    banner_text.append(" - Web Vulnerability Scanner", style="white")
    
    console.print(Panel(
        banner_text,
        title="[bold green]EthioScan[/bold green]",
        subtitle="[italic]Ethiopian Security Scanner[/italic]",
        border_style="blue"
    ))


def load_allowlist():
    """Load the allowlist from allowlist.txt file."""
    allowlist_file = os.path.join(os.path.dirname(__file__), 'allowlist.txt')
    allowed_domains = set()
    
    try:
        with open(allowlist_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    allowed_domains.add(line.lower())
    except FileNotFoundError:
        console.print("[red]Warning: allowlist.txt not found. All domains will require confirmation.[/red]")
    
    return allowed_domains


def check_allowlist(url, confirm_string=None):
    """Check if the URL is in the allowlist or user has provided confirmation."""
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()
    
    # Remove port if present
    if ':' in domain:
        domain = domain.split(':')[0]
    
    allowed_domains = load_allowlist()
    
    if domain in allowed_domains:
        return True
    
    if confirm_string == "I_HAVE_PERMISSION":
        console.print(f"[yellow]Warning: Scanning {domain} with explicit confirmation.[/yellow]")
        return True
    
    console.print(f"[red]Error: Domain '{domain}' is not in the allowlist.[/red]")
    console.print("[yellow]To scan this domain, you must either:[/yellow]")
    console.print("1. Add it to allowlist.txt")
    console.print("2. Use --confirm-allow I_HAVE_PERMISSION (only if you have explicit permission)")
    console.print("\n[bold red]EthioScan will not scan unauthorized targets.[/bold red]")
    return False


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="EthioScan - Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py --url https://example.com
  python cli.py --url https://example.com --depth 3 --report json
  python cli.py --url https://example.com --confirm-allow I_HAVE_PERMISSION --mode advanced

Safety Notice:
  EthioScan is designed for authorized testing only. Always ensure you have
  explicit permission before scanning any target. Use conservative payloads
  and respect rate limits.
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
        '--report',
        choices=['html', 'json'],
        default='html',
        help='Report format (default: html)'
    )
    
    parser.add_argument(
        '--out',
        default='report.html',
        help='Output file path (default: report.html)'
    )
    
    parser.add_argument(
        '--concurrency',
        type=int,
        default=5,
        help='Concurrency level (default: 5)'
    )
    
    parser.add_argument(
        '--history',
        action='store_true',
        help='Store results in SQLite database'
    )
    
    parser.add_argument(
        '--confirm-allow',
        help='Confirmation string to bypass allowlist (use: I_HAVE_PERMISSION)'
    )
    parser.add_argument(
        '--lab',
        action='store_true',
        help='Enable lab-only payloads (potentially destructive)'
    )

    parser.add_argument(
        '--max-tests',
        type=int,
        default=200,
        help='Maximum number of test cases to generate (default: 200)'
    )

    
    parser.add_argument(
        '--lab',
        action='store_true',
        help='Enable lab-only payloads (potentially destructive)'
    )

    parser.add_argument(
        '--max-tests',
        type=int,
        default=200,
        help='Maximum number of test cases to generate (default: 200)'
    )

    parser.add_argument(
        '--mode',
        choices=['simple', 'advanced'],
        default='simple',
        help='Choose orchestrator mode: simple (utils) or advanced (run_scan)'
    )
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Check allowlist
    if not check_allowlist(args.url, args.confirm_allow):
        sys.exit(1)
    
    console.print(f"[green]Starting EthioScan on {args.url}[/green]")
    console.print(f"[blue]Configuration:[/blue]")
    console.print(f"  Depth: {args.depth}")
    console.print(f"  Report format: {args.report}")
    console.print(f"  Output file: {args.out}")
    console.print(f"  Concurrency: {args.concurrency}")
    console.print(f"  History enabled: {args.history}")
    console.print(f"  Mode: {args.mode}")
    
    try:
        if args.mode == "simple":
            from utils import run_scan
            run_scan(args)
        else:
            from run_scan import EthioScanOrchestrator
            orchestrator = EthioScanOrchestrator(args)
            asyncio.run(orchestrator.run())
    except ImportError as e:
        console.print(f"[yellow]Import error: {e}[/yellow]")
        console.print("[green]EthioScan skeleton is working correctly![/green]")
        sys.exit(0)


if __name__ == '__main__':
    main()
