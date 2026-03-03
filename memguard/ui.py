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


def show_process_table(processes: list[ProcessRecord], limit: int = 25) -> None:
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
    table.add_column("Executable Path", max_width=50, overflow="ellipsis")
    table.add_column("Start Time", style="dim")

    for proc in processes[:limit]:
        mem_style = _memory_style(proc["rss_mb"])
        table.add_row(
            str(proc["pid"]),
            str(proc["ppid"]),
            proc["name"],
            proc["user"],
            f"[{mem_style}]{proc['rss_mb']:,.2f}[/{mem_style}]",
            f"{proc['cpu_percent']:.1f}",
            proc["exe"],
            proc["start_time"],
        )

    console.print(table)
    console.print(
        f"\n  [dim]Showing {min(limit, len(processes))} of {len(processes)} total processes[/dim]\n"
    )
