"""MemGuard — Process Intelligence Engine (Layer 1).

Read-only forensic mode: enumerates processes, displays a
color-coded table, and exports CSV/JSON reports.
No process modification or termination is performed.
"""

import logging
import argparse
import sys

from .collector import collect_processes, collect_system_overview
from .exporter import export_csv, export_json
from .hasher import attach_sha256, load_blocklist
from .scorer import score_processes
from .threat_intel import enrich_with_virustotal
from .ui import (
    show_banner,
    show_process_table,
    show_system_overview,
    show_threat_alerts,
    show_virustotal_findings,
    console,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


def _build_parser() -> argparse.ArgumentParser:
    """Build CLI parser for MemGuard options."""
    parser = argparse.ArgumentParser(description="MemGuard — Read-Only Forensic Mode")
    parser.add_argument(
        "--vt",
        action="store_true",
        default=False,
        help="Enable optional VirusTotal enrichment (requires VT_API_KEY).",
    )
    parser.add_argument(
        "--vt-max-requests",
        type=int,
        default=8,
        help="Maximum number of unique SHA256 hashes to query from VirusTotal.",
    )
    parser.add_argument(
        "--vt-min-score",
        type=int,
        default=20,
        help="Only query VirusTotal for processes with threat_score >= this value.",
    )
    parser.add_argument(
        "--vt-suspicious-only",
        action="store_true",
        default=False,
        help="Shortcut for VT on only SUSPICIOUS/MALICIOUS processes (threat_score >= 21).",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    """Entry point for MemGuard CLI."""
    args = _build_parser().parse_args(argv)
    show_banner()
    blocklist_hashes = load_blocklist()

    # ── Collect ──────────────────────────────────────────────
    console.print("[bold]Scanning processes…[/bold]")
    overview = collect_system_overview()
    processes = collect_processes()
    processes = attach_sha256(processes)
    processes = score_processes(processes, blocklist_hashes=blocklist_hashes)
    vt_min_score = 21 if args.vt_suspicious_only else args.vt_min_score
    processes = enrich_with_virustotal(
        processes,
        enabled=args.vt,
        max_requests=args.vt_max_requests,
        min_threat_score=vt_min_score,
    )
    processes = score_processes(processes, blocklist_hashes=blocklist_hashes)

    if not processes:
        console.print("[red]No processes collected. Exiting.[/red]")
        sys.exit(1)

    # ── Display ──────────────────────────────────────────────
    show_system_overview(overview)
    show_process_table(processes, limit=25)
    show_threat_alerts(processes)
    show_virustotal_findings(processes)

    # ── Export ───────────────────────────────────────────────
    csv_path = export_csv(processes)
    json_path = export_json(processes)

    console.print(f"[green]✓[/green] CSV  → {csv_path}")
    console.print(f"[green]✓[/green] JSON → {json_path}")
    console.print("\n[dim]Read-only mode — no processes were modified.[/dim]")


if __name__ == "__main__":
    main()
