"""
Async orchestrator — the heart of ReconAI.

Receives a validated Target, dispatches all available agents concurrently,
collects findings into a ReconResult, then passes it to the AI analyzer.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskID, TextColumn, TimeElapsedColumn
from rich.table import Table

from reconai.agents.dns_recon import DNSReconAgent
from reconai.agents.port_scanner import PortScannerAgent
from reconai.core.target import Target
from reconai.types.findings import ReconResult, Severity

console = Console()


# Registry — add new agents here as you build them
AGENTS = [
    DNSReconAgent(),
    PortScannerAgent(),
    # WHOISAgent(),         # Phase 2
    # WebTechAgent(),       # Phase 2
    # ShodanAgent(),        # Phase 2 (needs API key)
    # ScreenshotAgent(),    # Phase 2
]


async def run_recon(target: Target, use_ai: bool = True) -> ReconResult:
    """
    Main entry point for a recon run.

    1. Dispatch all agents concurrently
    2. Collect findings
    3. Run AI analysis (optional)
    4. Return complete ReconResult
    """
    result = ReconResult(target=str(target))

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )

    with progress:
        tasks: dict[str, TaskID] = {}
        for agent in AGENTS:
            tasks[agent.name] = progress.add_task(
                f"[cyan]{agent.name}[/cyan] — {agent.description}",
                total=None,
            )

        async def run_and_update(agent) -> None:
            elapsed = await agent.execute(target, result)
            count = len([f for f in result.findings if f.agent == agent.name])
            progress.update(
                tasks[agent.name],
                description=f"[green]{agent.name}[/green] — {count} findings ({elapsed:.1f}s)",
                completed=1,
                total=1,
            )

        await asyncio.gather(*[run_and_update(a) for a in AGENTS])

    result.completed_at = datetime.now(timezone.utc)

    if use_ai and result.findings:
        from reconai.core.ai_analyzer import analyze_with_ai
        console.print("\n[purple]Running AI analysis...[/purple]")
        await analyze_with_ai(result)

    return result


def print_summary(result: ReconResult) -> None:
    """Print a Rich summary table of findings to stdout."""
    table = Table(title=f"ReconAI — {result.target}", show_header=True, header_style="bold")
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Agent", width=14)
    table.add_column("Finding", width=45)
    table.add_column("Type", width=12)

    for f in result.sorted_findings():
        sev_color = {
            Severity.CRITICAL: "red",
            Severity.HIGH: "dark_orange",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "cyan",
            Severity.INFO: "bright_black",
        }[f.severity]

        table.add_row(
            f"[{sev_color}]{f.severity.value.upper()}[/{sev_color}]",
            f.agent,
            f.title[:45],
            f.type.value,
        )

    console.print(table)

    if result.duration_seconds:
        console.print(
            f"\n[bright_black]Completed in {result.duration_seconds:.1f}s — "
            f"{len(result.findings)} findings — "
            f"{result.critical_count} critical, {result.high_count} high[/bright_black]"
        )

    if result.ai_analysis:
        console.print(
            Panel(result.ai_analysis, title="[purple]AI Analysis[/purple]", border_style="purple")
        )
