"""
EthioScan Utils - Orchestrator and utility functions
"""

import asyncio
from rich.console import Console
import aiohttp

from crawler import crawl, crawl_sync
from fuzzer import generate_tests_from_params, generate_tests_from_forms, submit_test_case, get_test_case_summary
from scanner import Scanner
from payloads import get_payloads
from reporter import save_report


console = Console()



def run_scan(args):
    """
    Main orchestrator function that coordinates the scanning process.
    
    Args:
        args: Parsed command line arguments
    """
    console.print("[blue]EthioScan orchestrator called[/blue]")
    console.print(f"[green]Target: {args.url}[/green]")
    console.print(f"[green]Depth: {args.depth}[/green]")
    console.print(f"[green]Report format: {args.report}[/green]")
    console.print(f"[green]Output file: {args.out}[/green]")
    console.print(f"[green]Concurrency: {args.concurrency}[/green]")
    console.print(f"[green]History enabled: {args.history}[/green]")
    
    try:
        # Step 1: Crawl
        crawl_results = asyncio.run(crawl(
            start_url=args.url,
            depth=args.depth,
            concurrency=args.concurrency,
            delay=0.2
        ))
        
        console.print("[green]Crawling completed successfully![/green]")
        console.print(f"[blue]Discovered:[/blue]")
        console.print(f"  - {len(crawl_results['pages'])} pages")
        console.print(f"  - {len(crawl_results['forms'])} forms")
        console.print(f"  - {len(crawl_results['params'])} parameterized URLs")
        
        # Step 2: Generate test cases from crawl output
        payloads = get_payloads(profile="safe")
        test_cases = list(generate_tests_from_params(crawl_results["params"], payloads))
        test_cases += list(generate_tests_from_forms(crawl_results["forms"], payloads))
        
        summary = get_test_case_summary(test_cases)
        console.print(f"[blue]Generated {summary['total']} test cases[/blue]")
        
        # Step 3: Run fuzzer + scanner
        scanner = Scanner()
        findings = []
        
        async def run_tests():
            async with aiohttp.ClientSession(headers={"User-Agent": "EthioScan/1.0"}) as session:
                for test in test_cases:
                    response = await submit_test_case(session, test)
                    finding = scanner.analyze_response(test, response)
                    if finding:
                        findings.append(finding)
        
        asyncio.run(run_tests())
        
        console.print(f"[red]Detected {len(findings)} findings[/red]")

        
        # Step 4: Reporting
        meta = {
            "target": args.url,
            "depth": args.depth,
            "concurrency": args.concurrency,
            "report_format": args.report,
                }
        save_report(meta, findings, args.report, args.out, tests_run=len(findings))
        console.print(f"[green]Report generated at {args.out}[/green]")


        
    except Exception as e:
        console.print(f"[red]Error during scanning: {e}[/red]")
        console.print("[yellow]Falling back to synchronous crawler...[/yellow]")
        
        try:
            crawl_results = crawl_sync(
                start_url=args.url,
                depth=args.depth,
                concurrency=args.concurrency,
                delay=0.2
            )
            
            console.print("[green]Synchronous crawling completed successfully![/green]")
        except Exception as e2:
            console.print(f"[red]Both async and sync crawling failed: {e2}[/red]")
            return
