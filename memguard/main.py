"""MemGuard — Process Intelligence Engine (Layer 1).

Read-only forensic mode: enumerates processes, displays a
color-coded table, and exports CSV/JSON reports.
No process modification or termination is performed.
"""

import logging
import sys

from .collector import collect_processes, collect_system_overview
from .exporter import export_csv, export_json
from .ui import show_banner, show_process_table, show_system_overview, console

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


def main() -> None:
    """Entry point for MemGuard CLI."""
    show_banner()

    # ── Collect ──────────────────────────────────────────────
    console.print("[bold]Scanning processes…[/bold]")
    overview = collect_system_overview()
    processes = collect_processes()

    if not processes:
        console.print("[red]No processes collected. Exiting.[/red]")
        sys.exit(1)

    # ── Display ──────────────────────────────────────────────
    show_system_overview(overview)
    show_process_table(processes, limit=25)

    # ── Export ───────────────────────────────────────────────
    csv_path = export_csv(processes)
    json_path = export_json(processes)

    console.print(f"[green]✓[/green] CSV  → {csv_path}")
    console.print(f"[green]✓[/green] JSON → {json_path}")
    console.print("\n[dim]Read-only mode — no processes were modified.[/dim]")


if __name__ == "__main__":
    main()
