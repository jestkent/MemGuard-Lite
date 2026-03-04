"""Terminal UI module.

Renders the startup banner and process table using rich,
with color-coded memory usage indicators.
"""

import logging

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from .collector import ProcessRecord, SystemOverview

logger = logging.getLogger(__name__)

console = Console()

# Memory thresholds (MB)
_RED_THRESHOLD = 500.0
_YELLOW_THRESHOLD = 100.0


def _memory_style(rss_mb: float) -> str:
    """Return a rich style string based on memory usage."""
    if rss_mb >= _RED_THRESHOLD:
        return "bold red"
    elif rss_mb >= _YELLOW_THRESHOLD:
        return "bold yellow"
    return "green"


def _threat_level_style(threat_level: str) -> str:
    """Return color style for threat level labels."""
    if threat_level == "MALICIOUS":
        return "bold red"
    if threat_level == "SUSPICIOUS":
        return "bold yellow"
    return "green"


def _memory_flag_style(memory_flag: str) -> str:
    """Return color style for memory anomaly labels."""
    if memory_flag == "ANOMALOUS":
        return "bold magenta"
    return "white"


def show_banner() -> None:
    """Display the MemGuard startup banner."""
    banner = Text("MemGuard — Read-Only Forensic Mode", style="bold cyan")
    console.print(Panel(banner, expand=False, border_style="bright_blue"))
    console.print()


def show_system_overview(overview: SystemOverview) -> None:
    """Render RAM and CPU telemetry above the process table."""
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column(style="bold cyan")
    table.add_column(style="white")

    table.add_row("Total RAM", f"{overview['total_ram_mb']:,.2f} MB")
    table.add_row("Used RAM", f"{overview['used_ram_mb']:,.2f} MB")
    table.add_row("Free RAM", f"{overview['free_ram_mb']:,.2f} MB")
    table.add_row("CPU %", f"{overview['cpu_percent']:.1f}%")

    console.print(Panel(table, title="System Overview", border_style="bright_blue", expand=False))
    console.print()


def show_process_table(processes: list[ProcessRecord], limit: int = 25, memory_enabled: bool = False) -> None:
    """Render a rich table of the top N processes sorted by memory.

    Args:
        processes: Pre-sorted list of ProcessRecord (descending RSS).
        limit: Number of rows to display (default 25).
    """
    table = Table(
        title=f"Top {limit} Processes by Memory Usage",
        title_style="bold white",
        show_lines=False,
        header_style="bold bright_white on dark_blue",
        row_styles=["", "dim"],
    )

    table.add_column("PID", justify="right", style="cyan", no_wrap=True)
    table.add_column("PPID", justify="right", style="dim")
    table.add_column("Name", style="bold")
    table.add_column("User", style="magenta")
    table.add_column("RSS (MB)", justify="right")
    table.add_column("CPU %", justify="right", style="blue")
    table.add_column("Threat Score", justify="right", style="bright_cyan")
    table.add_column("Threat Level", justify="center")
    if memory_enabled:
        table.add_column("Mem Flag", justify="center")
        table.add_column("Mem Score", justify="right", style="bright_magenta")
    table.add_column("Executable Path", max_width=50, overflow="ellipsis")
    table.add_column("Start Time", style="dim")

    for proc in processes[:limit]:
        mem_style = _memory_style(proc["rss_mb"])
        threat_score = int(proc.get("threat_score", 0))
        threat_level = str(proc.get("threat_level", "SAFE"))
        threat_style = _threat_level_style(threat_level)
        row = [
            str(proc["pid"]),
            str(proc["ppid"]),
            proc["name"],
            proc["user"],
            f"[{mem_style}]{proc['rss_mb']:,.2f}[/{mem_style}]",
            f"{proc['cpu_percent']:.1f}",
            str(threat_score),
            f"[{threat_style}]{threat_level}[/{threat_style}]",
        ]

        if memory_enabled:
            memory_flag = str(proc.get("memory_flag", "-"))
            memory_score = proc.get("memory_anomaly_score", "-")
            memory_style = _memory_flag_style(memory_flag)
            row.append(f"[{memory_style}]{memory_flag}[/{memory_style}]")
            row.append(str(memory_score))

        row.extend([
            proc["exe"],
            proc["start_time"],
        ])

        table.add_row(*row)

    console.print(table)
    console.print(
        f"\n  [dim]Showing {min(limit, len(processes))} of {len(processes)} total processes[/dim]\n"
    )


def show_threat_alerts(processes: list[ProcessRecord]) -> None:
    """Render a secondary panel with suspicious/malicious process alerts."""
    alerts = [
        process
        for process in processes
        if process.get("threat_level") in {"SUSPICIOUS", "MALICIOUS"}
    ]

    if not alerts:
        console.print(Panel("[green]No SUSPICIOUS or MALICIOUS processes detected.[/green]", title="Threat Alerts", border_style="green"))
        console.print()
        return

    alert_table = Table(show_lines=False, header_style="bold bright_white on dark_red")
    alert_table.add_column("PID", justify="right", style="cyan", no_wrap=True)
    alert_table.add_column("Name", style="bold")
    alert_table.add_column("Threat", justify="center")
    alert_table.add_column("Triggered Rules", overflow="fold", max_width=80)

    for process in alerts:
        threat_level = str(process.get("threat_level", "SAFE"))
        threat_style = _threat_level_style(threat_level)
        rules = process.get("triggered_rules") or []
        rules_text = ", ".join(rules) if rules else "-"
        alert_table.add_row(
            str(process.get("pid", 0)),
            str(process.get("name", "N/A")),
            f"[{threat_style}]{threat_level}[/{threat_style}]",
            rules_text,
        )

    console.print(Panel(alert_table, title="Threat Alerts", border_style="red"))
    console.print()


def show_virustotal_findings(processes: list[ProcessRecord], limit: int = 10) -> None:
    """Render a panel summarizing VirusTotal enrichment results."""
    vt_rows = [
        process
        for process in processes
        if isinstance(process.get("vt_malicious"), int)
    ]

    if not vt_rows:
        console.print(
            Panel(
                "[yellow]No VirusTotal data in this run.[/yellow]\n"
                "[dim]Possible reasons: VT disabled, missing API key, API rate limit, or file hashes not found.[/dim]",
                title="VirusTotal Findings",
                border_style="yellow",
            )
        )
        console.print()
        return

    vt_rows.sort(key=lambda p: int(p.get("vt_malicious", 0) or 0), reverse=True)

    vt_table = Table(show_lines=False, header_style="bold bright_white on dark_green")
    vt_table.add_column("PID", justify="right", style="cyan", no_wrap=True)
    vt_table.add_column("Name", style="bold")
    vt_table.add_column("VT M", justify="right", style="red")
    vt_table.add_column("VT S", justify="right", style="yellow")
    vt_table.add_column("VT H", justify="right", style="green")

    for process in vt_rows[:limit]:
        vt_table.add_row(
            str(process.get("pid", 0)),
            str(process.get("name", "N/A")),
            str(int(process.get("vt_malicious", 0) or 0)),
            str(int(process.get("vt_suspicious", 0) or 0)),
            str(int(process.get("vt_harmless", 0) or 0)),
        )

    console.print(Panel(vt_table, title="VirusTotal Findings", border_style="green"))
    console.print(f"[dim]VT enriched processes: {len(vt_rows)}[/dim]\n")
