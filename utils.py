"""
EthioScan Utils - Orchestrator and utility functions
"""

from rich.console import Console

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
    
    # TODO: Implement actual scanning logic
    # This will be implemented in subsequent steps
    console.print("[yellow]Scanning logic will be implemented in the next steps[/yellow]")
