"""
ReconAI CLI — entrypoint.

Usage:
    reconai scan 10.10.11.21
    reconai scan target.htb --no-ai
    reconai scan 192.168.1.1 --force-scope --output report.json
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel

load_dotenv()

app = typer.Typer(
    name="reconai",
    help="AI-powered recon orchestrator for authorized penetration testing.",
    add_completion=False,
)
console = Console()


def _banner() -> None:
    console.print(
        Panel(
            "[bold red]ReconAI[/bold red]  [bright_black]v0.1.0[/bright_black]\n"
            "[bright_black]Authorized penetration testing reconnaissance only.[/bright_black]",
            border_style="bright_black",
            padding=(0, 2),
        )
    )


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target: IP, domain, or CIDR (e.g. 10.10.11.21, target.htb)"),
    force_scope: bool = typer.Option(
        False,
        "--force-scope",
        help="Bypass scope check. Only use with WRITTEN AUTHORIZATION.",
    ),
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip Claude AI analysis."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Save JSON report to file."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress banner and progress."),
) -> None:
    """Run a full recon scan against the target."""
    if not quiet:
        _banner()

    from reconai.core.target import ScopeError, Target
    from reconai.core.orchestrator import print_summary, run_recon

    parsed = Target.parse(target)

    try:
        parsed.validate_scope(force=force_scope)
    except ScopeError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1)

    if not quiet:
        scope_note = "[green]in scope[/green]" if parsed.is_in_default_scope() else "[yellow]force-scope active[/yellow]"
        console.print(f"[bright_black]Target:[/bright_black] [bold]{parsed.host}[/bold]  {scope_note}\n")

    result = asyncio.run(run_recon(parsed, use_ai=not no_ai))

    if not quiet:
        print_summary(result)

    if output:
        output.write_text(json.dumps(result.to_dict(), indent=2, default=str))
        console.print(f"\n[green]Report saved → {output}[/green]")


@app.command()
def agents() -> None:
    """List all available recon agents."""
    from reconai.core.orchestrator import AGENTS
    from rich.table import Table

    table = Table(title="Available agents", show_header=True)
    table.add_column("Agent", style="bold")
    table.add_column("Description")
    table.add_column("Status")

    for agent in AGENTS:
        table.add_row(agent.name, agent.description, "[green]active[/green]")

    console.print(table)


if __name__ == "__main__":
    app()
