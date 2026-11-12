"""
SAIFE CLI — Command Line Interface
====================================
The main entry point for running SAIFE security scans.

Commands:
    saife scan     → Run a security scan against a target
    saife quick    → Quick scan (single category)
    saife attacks  → List all available attack categories
    saife score    → Show scoring guide
    saife history  → Show past scan history
    saife eval     → Run evaluation suite
    saife mcp      → Start the MCP server (stdio or HTTP)

Usage:
    python main.py scan --target http://localhost:9001
    python main.py quick --target http://localhost:9001 --category prompt_injection
    python main.py history
    python main.py mcp --transport stdio
    python main.py mcp --transport http --port 8080
"""
import asyncio
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text
from rich import box

sys.path.insert(0, str(Path(__file__).parent))

from engine.orchestrator import (
    run_full_scan, run_single_scan,
    FullScanReport, AgentStatus,
)
from data.attack_prompts import ALL_ATTACKS, TOTAL_ATTACKS, CATEGORIES
from nodes.scorer import SEVERITY_WEIGHTS
from nodes.memory_store import get_memory


console = Console()


# ── Banner ────────────────────────────────────────────────────────

BANNER = """
[bold red]╔═══════════════════════════════════════════════════╗[/bold red]
[bold red]║[/bold red]  [bold white]🛡️  SAIFE — Secure AI Framework for Everyone[/bold white]     [bold red]║[/bold red]
[bold red]║[/bold red]  [dim]AI Security Scanner · OWASP LLM Top 10[/dim]         [bold red]║[/bold red]
[bold red]║[/bold red]  [dim]Capstone Project · AI Engineering Upskilling[/dim]    [bold red]║[/bold red]
[bold red]╚═══════════════════════════════════════════════════╝[/bold red]
"""


# ── Main CLI Group ────────────────────────────────────────────────

@click.group()
def cli():
    """SAIFE — AI Security Scanner CLI"""
    pass


# ── Command: scan ─────────────────────────────────────────────────

@cli.command()
@click.option("--target", "-t", required=True, help="Target chatbot URL")
@click.option(
    "--category", "-c", default=None,
    help="Specific category to scan (default: all)"
)
@click.option(
    "--concurrent", default=3,
    help="Max parallel agents (default: 3)"
)
def scan(target: str, category: str | None, concurrent: int):
    """Run a full security scan against a target."""
    console.print(BANNER)
    console.print(f"[bold]Target:[/bold] {target}")

    if category:
        if category not in CATEGORIES:
            console.print(f"[red]Unknown category: {category}[/red]")
            console.print(f"Valid: {', '.join(CATEGORIES)}")
            return
        console.print(f"[bold]Category:[/bold] {category}")
        categories = [category]
    else:
        console.print(f"[bold]Categories:[/bold] All {len(CATEGORIES)}")
        categories = None

    console.print()

    # Progress callback for live updates
    def on_progress(cat: str, status: AgentStatus, message: str):
        icon = {
            AgentStatus.PENDING: "⏳",
            AgentStatus.RUNNING: "🔄",
            AgentStatus.COMPLETE: "✅",
            AgentStatus.FAILED: "❌",
            AgentStatus.RETRYING: "🔁",
            AgentStatus.SKIPPED: "⏭️",
        }.get(status, "❓")
        console.print(f"  {icon} [bold]{cat}[/bold]: {message}")

    # Run the scan
    console.print("[bold yellow]Starting scan...[/bold yellow]")
    console.print()

    report: FullScanReport = asyncio.run(
        run_full_scan(
            target,
            categories=categories,
            max_concurrent=concurrent,
            on_progress=on_progress,
        )
    )

    # Display results
    console.print()
    _display_report(report)


# ── Command: quick ────────────────────────────────────────────────

@cli.command()
@click.option("--target", "-t", required=True, help="Target chatbot URL")
@click.option(
    "--category", "-c", required=True,
    type=click.Choice(CATEGORIES),
    help="Category to scan"
)
def quick(target: str, category: str):
    """Quick scan — single category only."""
    console.print(BANNER)
    console.print(f"[bold]Quick Scan:[/bold] {category} → {target}")
    console.print()

    report = asyncio.run(run_single_scan(target, category))
    _display_report(report)


# ── Command: attacks ──────────────────────────────────────────────

@cli.command()
def attacks():
    """List all attack categories and prompts."""
    console.print(BANNER)

    table = Table(
        title="SAIFE Attack Library",
        box=box.ROUNDED,
        show_lines=True,
    )
    table.add_column("#", style="bold", width=4)
    table.add_column("Category", style="bold cyan", width=20)
    table.add_column("Attacks", style="green", width=8)
    table.add_column("OWASP", style="yellow", width=12)

    owasp_map = {
        "prompt_injection": "LLM01",
        "jailbreak": "LLM01",
        "data_extraction": "LLM02/07",
        "output_handling": "LLM05/06",
        "rag_poisoning": "LLM08",
        "availability": "LLM10",
    }

    for i, (cat, prompts) in enumerate(ALL_ATTACKS.items(), 1):
        table.add_row(
            str(i), cat, str(len(prompts)), owasp_map.get(cat, "—")
        )

    console.print(table)
    console.print(f"\n[bold]Total: {TOTAL_ATTACKS} attacks across {len(CATEGORIES)} categories[/bold]")


# ── Command: score ────────────────────────────────────────────────

@cli.command()
def score():
    """Show the scoring guide."""
    console.print(BANNER)

    table = Table(title="Scoring Guide", box=box.ROUNDED)
    table.add_column("Grade", style="bold", width=8)
    table.add_column("Score Range", width=12)
    table.add_column("Meaning", width=40)

    table.add_row("[green]A[/green]", "90-100", "Excellent — minimal vulnerabilities")
    table.add_row("[blue]B[/blue]", "75-89", "Good — minor issues only")
    table.add_row("[yellow]C[/yellow]", "50-74", "Fair — needs improvement")
    table.add_row("[red]D[/red]", "25-49", "Poor — significant vulnerabilities")
    table.add_row("[bold red]F[/bold red]", "0-24", "Failing — critically vulnerable")

    console.print(table)

    console.print("\n[bold]Severity Deductions:[/bold]")
    for sev, points in SEVERITY_WEIGHTS.items():
        console.print(f"  • {sev}: -{points} points per finding")


# ── Report Display ────────────────────────────────────────────────

def _display_report(report: FullScanReport):
    """Display a scan report with Rich formatting."""

    # Errors (non-fatal)
    if report.errors:
        for err in report.errors:
            console.print(f"[dim red]  ⚠ {err}[/dim red]")
        if not report.score:
            return
        console.print()

    # ── Score Panel ───────────────────────────────────────────────
    if report.score:
        grade_color = {
            "A": "green", "B": "blue", "C": "yellow",
            "D": "red", "F": "bold red",
        }.get(report.score.grade, "white")

        score_text = Text()
        score_text.append(f"\n  Score: {report.score.score}/100 ", style="bold")
        score_text.append(f"({report.score.grade})", style=f"bold {grade_color}")
        score_text.append(f"\n  {report.score.summary}\n")

        console.print(Panel(
            score_text,
            title="🛡️ Security Score",
            border_style=grade_color,
            box=box.DOUBLE,
        ))

    # ── Collect all findings (from analysis OR raw scanner results) ─
    all_findings = []

    # Prefer analysis agent findings (AI-enriched)
    if report.analysis and report.analysis.findings:
        for f in report.analysis.findings:
            all_findings.append({
                "title": f.title,
                "severity": f.severity,
                "owasp": getattr(f, "owasp_id", "—"),
                "recommendation": f.recommendation,
                "evidence": getattr(f, "evidence", ""),
                "attack": getattr(f, "attack_used", ""),
                "response": getattr(f, "target_response", ""),
            })
    else:
        # Fallback: use raw findings from scanner results
        for cat, result in report.category_results.items():
            for f in result.findings:
                all_findings.append({
                    "title": f.title,
                    "severity": f.severity,
                    "owasp": _category_to_owasp(f.category or cat),
                    "recommendation": f.recommendation,
                    "evidence": f.evidence,
                    "attack": f.attack_used,
                    "response": f.target_response,
                })

    # ── Findings Table ────────────────────────────────────────────
    if all_findings:
        table = Table(
            title=f"🔍 Vulnerabilities Found ({len(all_findings)})",
            box=box.ROUNDED,
            show_lines=True,
        )
        table.add_column("#", width=4)
        table.add_column("Severity", width=10)
        table.add_column("OWASP", width=10)
        table.add_column("Title", width=28)
        table.add_column("Evidence", width=35)

        severity_colors = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }

        for i, f in enumerate(all_findings, 1):
            color = severity_colors.get(f["severity"].lower(), "white")
            evidence = f["evidence"][:60] + "..." if len(f["evidence"]) > 60 else f["evidence"]
            table.add_row(
                str(i),
                f"[{color}]{f['severity'].upper()}[/{color}]",
                f["owasp"],
                f["title"],
                evidence,
            )

        console.print(table)

        # ── Recommendations ───────────────────────────────────────
        seen_recs = set()
        recs = []
        for f in all_findings:
            if f["recommendation"] and f["recommendation"] not in seen_recs:
                seen_recs.add(f["recommendation"])
                recs.append(f"• {f['recommendation']}")

        if recs:
            console.print(Panel(
                "\n".join(recs[:5]),
                title="💡 Top Recommendations",
                border_style="cyan",
            ))

    # ── Per-Category Summary ──────────────────────────────────────
    if report.category_results:
        cat_table = Table(
            title="📊 Category Breakdown",
            box=box.SIMPLE,
        )
        cat_table.add_column("Category", style="cyan", width=20)
        cat_table.add_column("Attacks Sent", width=12)
        cat_table.add_column("Blocked", style="green", width=10)
        cat_table.add_column("Successful", style="red", width=12)
        cat_table.add_column("Findings", style="bold", width=10)

        for cat, result in report.category_results.items():
            cat_table.add_row(
                cat,
                str(result.total_attacks_sent),
                str(result.attacks_blocked),
                str(result.attacks_successful),
                str(len(result.findings)),
            )

        console.print(cat_table)

    # ── OWASP Context (from Knowledge Agent RAG) ──────────────────
    if report.owasp_context:
        for ctx in report.owasp_context:
            if ctx.answer and ctx.answer != "No relevant OWASP guidance found.":
                source_line = f"\n[dim]Source: {ctx.source_snippet[:80]}...[/dim]" if ctx.source_snippet else ""
                owasp_line = f" [{ctx.owasp_id}]" if ctx.owasp_id != "—" else ""
                console.print(Panel(
                    f"{ctx.answer[:300]}{source_line}",
                    title=f"📖 OWASP Guidance{owasp_line} (confidence: {ctx.confidence:.0%})",
                    border_style="yellow",
                ))

    # ── Executive Summary (if analysis agent succeeded) ───────────
    if report.analysis and report.analysis.executive_summary:
        console.print(Panel(
            report.analysis.executive_summary,
            title="📋 Executive Summary",
            border_style="cyan",
        ))
    elif not all_findings:
        console.print("[bold green]✅ No vulnerabilities found! Target appears secure.[/bold green]")

    # ── Duration ──────────────────────────────────────────────────
    if report.scan_duration_seconds:
        console.print(
            f"\n[dim]Scan completed in {report.scan_duration_seconds:.1f} seconds[/dim]"
        )



# ── History Command ───────────────────────────────────────────────

@cli.command()
@click.option("--target", default=None, help="Filter by target URL")
@click.option("--limit", default=10, help="Number of records to show")
def history(target: str | None, limit: int):
    """Show past scan history from persistent memory."""
    console.print(BANNER)

    memory = get_memory()
    records = memory.get_history(target_url=target, limit=limit)

    if not records:
        console.print("[dim]No scan history found. Run a scan first![/dim]")
        return

    # Stats overview
    stats = memory.get_stats()
    console.print(Panel(
        f"Total Scans: [bold]{stats['total_scans']}[/bold]  |  "
        f"Average Score: [bold]{stats['average_score']}[/bold]  |  "
        f"Conversations: [bold]{stats['total_conversations']}[/bold]",
        title="📊 Memory Stats",
        border_style="cyan",
    ))

    # History table
    table = Table(
        title="📜 Scan History",
        box=box.ROUNDED,
        show_lines=True,
    )
    table.add_column("#", style="dim", width=3)
    table.add_column("Date", style="dim", width=16)
    table.add_column("Target", min_width=20)
    table.add_column("Categories", min_width=12)
    table.add_column("Score", justify="center", width=8)
    table.add_column("Grade", justify="center", width=6)
    table.add_column("Findings", justify="center", width=8)

    grade_colors = {
        "A": "green", "B": "yellow", "C": "orange3",
        "D": "red", "F": "bold red",
    }

    for i, rec in enumerate(records, 1):
        dt = rec.datetime.strftime("%Y-%m-%d %H:%M")
        color = grade_colors.get(rec.grade, "white")
        table.add_row(
            str(i),
            dt,
            rec.target_url,
            rec.categories,
            str(rec.score),
            f"[{color}]{rec.grade}[/{color}]",
            str(rec.findings_count),
        )

    console.print(table)


# ── Eval Command ──────────────────────────────────────────────────

@cli.command()
@click.option(
    "--suite", "-s", default="all",
    type=click.Choice(["all", "scanner", "rag"]),
    help="Which eval suite to run",
)
def eval(suite: str):
    """Run the evaluation suite (LLMJudge + custom evaluators)."""
    console.print(BANNER)
    console.print("[bold cyan]Running SAIFE Evaluation Suite...[/bold cyan]\n")

    if suite in ("all", "scanner"):
        console.print("[bold]━━━ Scanner Evals ━━━[/bold]")
        from evals.scanner_evals import main as run_scanner_evals
        run_scanner_evals()
        console.print()

    if suite in ("all", "rag"):
        console.print("[bold]━━━ RAG Faithfulness Evals ━━━[/bold]")
        from evals.rag_evals import main as run_rag_evals
        run_rag_evals()
        console.print()

    console.print("[bold green]✅ Evaluation complete![/bold green]")

def _category_to_owasp(category: str) -> str:
    """Map category name to OWASP LLM Top 10 ID."""
    return {
        "prompt_injection": "LLM01",
        "jailbreak": "LLM01",
        "data_extraction": "LLM02/07",
        "output_handling": "LLM05/06",
        "rag_poisoning": "LLM08",
        "availability": "LLM10",
    }.get(category, "—")


# ── MCP Server Command ────────────────────────────────────────────

@cli.command()
@click.option(
    "--transport", "-t",
    type=click.Choice(["stdio", "http"]),
    default="stdio",
    help="Transport type: stdio (Claude Desktop) or http (remote)",
)
@click.option("--port", "-p", default=8080, help="Port for HTTP transport (default: 8080)")
@click.option("--host", default="0.0.0.0", help="Host for HTTP transport")
def mcp(transport: str, port: int, host: str):
    """Start the SAIFE MCP server for Claude Desktop or remote access.

    \b
    Transports:
      stdio  → For Claude Desktop (default)
      http   → For remote/network access

    \b
    Examples:
      python main.py mcp                           # stdio (Claude Desktop)
      python main.py mcp --transport http          # HTTP on port 8080
      python main.py mcp --transport http --port 9090
    """
    from mcp_server.server import mcp as saife_mcp

    if transport == "stdio":
        console.print("[bold cyan]Starting SAIFE MCP Server (stdio)...[/bold cyan]")
        console.print("[dim]Connect via Claude Desktop using claude_desktop_config.json[/dim]")
        saife_mcp.run(transport="stdio")
    else:
        console.print(BANNER)
        console.print(f"[bold cyan]Starting SAIFE MCP Server (HTTP) on {host}:{port}[/bold cyan]")
        console.print(f"[dim]Client URL: http://{host}:{port}/mcp[/dim]")
        console.print("[dim]Press Ctrl+C to stop[/dim]\n")
        saife_mcp.run(transport="streamable-http", host=host, port=port)


# ── Entry Point ───────────────────────────────────────────────────

if __name__ == "__main__":
    cli()
