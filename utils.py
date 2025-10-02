"""
EthioScan Utils - Orchestrator and utility functions
"""

import asyncio
from rich.console import Console
from crawler import crawl, crawl_sync

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
    
    # Run the crawler
    try:
        # Try async crawler first
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
        
        # TODO: Implement actual scanning logic
        # This will be implemented in subsequent steps
        console.print("[yellow]Scanning logic will be implemented in the next steps[/yellow]")
        
    except Exception as e:
        console.print(f"[red]Error during crawling: {e}[/red]")
        console.print("[yellow]Falling back to synchronous crawler...[/yellow]")
        
        try:
            crawl_results = crawl_sync(
                start_url=args.url,
                depth=args.depth,
                concurrency=args.concurrency,
                delay=0.2
            )
            
            console.print("[green]Synchronous crawling completed successfully![/green]")
            console.print(f"[blue]Discovered:[/blue]")
            console.print(f"  - {len(crawl_results['pages'])} pages")
            console.print(f"  - {len(crawl_results['forms'])} forms")
            console.print(f"  - {len(crawl_results['params'])} parameterized URLs")
            
        except Exception as e2:
            console.print(f"[red]Both async and sync crawling failed: {e2}[/red]")
            return
