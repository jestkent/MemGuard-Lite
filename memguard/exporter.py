"""Export module for process data.

Exports collected process data to CSV and JSON formats
using pandas for structured serialization.
"""

import json
import logging
from pathlib import Path

import pandas as pd

from .collector import ProcessRecord
from .port_inspector import PortRecord

logger = logging.getLogger(__name__)

COLUMNS = [
    "pid", "ppid", "name", "exe", "user",
    "rss_mb", "cpu_percent", "cmdline", "start_time", "sha256",
    "vt_malicious", "vt_suspicious", "vt_harmless",
    "vms_mb", "num_memory_maps", "private_writable_regions", "executable_writable_regions",
    "memory_anomaly_score", "memory_flag",
    "threat_score", "threat_level", "triggered_rules",
]


def _clean_export_strings(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize string fields to avoid newline characters in exported data."""
    text_columns = [
        "name", "exe", "user", "cmdline", "start_time", "sha256", "threat_level", "memory_flag"
    ]
    for column in text_columns:
        if column in df.columns:
            df[column] = (
                df[column]
                .fillna("N/A")
                .astype(str)
                .str.replace(r"[\r\n\t]+", " ", regex=True)
                .str.replace(r"\s+", " ", regex=True)
                .str.strip()
            )
    return df


def _to_dataframe(processes: list[ProcessRecord]) -> pd.DataFrame:
    """Convert a list of ProcessRecord dictionaries to a pandas DataFrame."""
    records = list(processes)
    df = pd.DataFrame(records, columns=COLUMNS)
    return _clean_export_strings(df)


def _normalize_rules(value: object) -> str:
    if isinstance(value, list):
        return ", ".join(str(item) for item in value) if value else "-"
    return "-" if value in (None, "") else str(value)


def _build_summary(processes: list[ProcessRecord]) -> dict[str, int]:
    suspicious = sum(process.get("threat_level") == "SUSPICIOUS" for process in processes)
    high = sum(process.get("threat_level") == "HIGH" for process in processes)
    vt_enriched = sum(isinstance(process.get("vt_malicious"), int) for process in processes)
    anomalous_memory = sum(process.get("memory_flag") == "ANOMALOUS" for process in processes)
    return {
        "total": len(processes),
        "suspicious": suspicious,
        "high": high,
        "vt_enriched": vt_enriched,
        "anomalous_memory": anomalous_memory,
    }


def export_full_report(
    processes: list[ProcessRecord],
    overview: dict[str, float] | None = None,
    path: str = "memguard_full_report.md",
    scan_options: dict[str, object] | None = None,
    generated_at: str | None = None,
    active_filters: dict[str, object] | None = None,
) -> Path:
    """Export an AI-friendly markdown report with the full scan dataset embedded.

    Args:
        processes: Full process list from the last scan.
        overview: System overview collected during the scan.
        path: Output file path.
        scan_options: Scan settings used for the run.
        generated_at: Human-readable scan timestamp.
        active_filters: Current GUI filter state for context.

    Returns:
        Path to the written markdown report.
    """
    dest = Path(path)
    df = _to_dataframe(processes)
    records = df.to_dict(orient="records")
    summary = _build_summary(processes)
    suspicious_rows = sorted(
        records,
        key=lambda process: int(process.get("threat_score", 0) or 0),
        reverse=True,
    )[:20]

    lines = [
        "# MemGuard Full Report",
        "",
        "This report is formatted for direct upload to an AI assistant for review.",
        "",
        "## Scan Metadata",
        "",
        f"- Generated At: {generated_at or 'N/A'}",
    ]

    if overview:
        lines.extend(
            [
                f"- Total RAM MB: {float(overview.get('total_ram_mb', 0.0) or 0.0):,.2f}",
                f"- Used RAM MB: {float(overview.get('used_ram_mb', 0.0) or 0.0):,.2f}",
                f"- Free RAM MB: {float(overview.get('free_ram_mb', 0.0) or 0.0):,.2f}",
                f"- CPU Percent: {float(overview.get('cpu_percent', 0.0) or 0.0):.1f}",
            ]
        )

    if scan_options:
        lines.extend(["", "## Scan Settings", ""])
        lines.extend(f"- {key}: {value}" for key, value in scan_options.items())

    if active_filters:
        lines.extend(["", "## Current GUI Filter State", ""])
        lines.extend(f"- {key}: {value}" for key, value in active_filters.items())

    lines.extend(
        [
            "",
            "## Summary",
            "",
            f"- Total Processes: {summary['total']}",
            f"- Suspicious: {summary['suspicious']}",
            f"- High: {summary['high']}",
            f"- VirusTotal Enriched: {summary['vt_enriched']}",
            f"- Memory Anomalies: {summary['anomalous_memory']}",
            "",
            "## Top Risk Findings",
            "",
        ]
    )

    if suspicious_rows:
        for process in suspicious_rows:
            lines.extend(
                [
                    f"### PID {process.get('pid', 'N/A')} - {process.get('name', 'N/A')}",
                    f"- Threat: {process.get('threat_level', 'SAFE')} (score {process.get('threat_score', 0)})",
                    f"- Executable: {process.get('exe', 'N/A')}",
                    f"- User: {process.get('user', 'N/A')}",
                    f"- SHA256: {process.get('sha256', 'N/A')}",
                    f"- Memory Flag: {process.get('memory_flag', '-')}",
                    f"- VT (M/S/H): {process.get('vt_malicious', 0)}/{process.get('vt_suspicious', 0)}/{process.get('vt_harmless', 0)}",
                    f"- Triggered Rules: {_normalize_rules(process.get('triggered_rules'))}",
                    f"- Command Line: {process.get('cmdline', 'N/A')}",
                    "",
                ]
            )
    else:
        lines.extend(["No process rows were available in this report.", ""])

    lines.extend(
        [
            "## Full Dataset JSON",
            "",
            "```json",
            json.dumps(records, indent=2),
            "```",
            "",
        ]
    )

    dest.write_text("\n".join(lines), encoding="utf-8")
    logger.info("Exported full report with %d processes to %s", len(processes), dest)
    return dest


def export_ports_report(
    ports: list[PortRecord],
    path: str = "memguard_ports_report.md",
    generated_at: str | None = None,
) -> Path:
    """Export a markdown report of port scan results.

    Args:
        ports: Port records from the last scan.
        path: Output file path.
        generated_at: Human-readable scan timestamp.

    Returns:
        Path to the written markdown report.
    """
    dest = Path(path)

    high = sum(p["risk_level"] == "HIGH" for p in ports)
    medium = sum(p["risk_level"] == "MEDIUM" for p in ports)
    low = sum(p["risk_level"] == "LOW" for p in ports)
    safe = sum(p["risk_level"] == "SAFE" for p in ports)

    sorted_ports = sorted(ports, key=lambda p: p["risk_score"], reverse=True)

    lines = [
        "# MemGuard Ports Report",
        "",
        "## Scan Metadata",
        "",
        f"- Generated At: {generated_at or 'N/A'}",
        "",
        "## Summary",
        "",
        f"- Total Ports: {len(ports)}",
        f"- High Risk: {high}",
        f"- Medium Risk: {medium}",
        f"- Low Risk: {low}",
        f"- Safe: {safe}",
        "",
        "## Port Details",
        "",
    ]

    if sorted_ports:
        for port in sorted_ports:
            rules_text = ", ".join(port["triggered_rules"]) if port["triggered_rules"] else "-"
            lines.extend([
                f"### Port {port['port']} / {port['protocol']} — {port['risk_level']} (score {port['risk_score']})",
                f"- State: {port['state']}",
                f"- Process: {port['process_name']} (PID {port['pid'] or 'N/A'})",
                f"- Local Address: {port['local_addr']}",
                f"- Remote Address: {port['remote_addr']}",
                f"- Triggered Rules: {rules_text}",
                "",
            ])
    else:
        lines.extend(["No port records available.", ""])

    lines.extend([
        "## Full Dataset JSON",
        "",
        "```json",
        json.dumps(sorted_ports, indent=2),
        "```",
        "",
    ])

    dest.write_text("\n".join(lines), encoding="utf-8")
    logger.info("Exported ports report with %d ports to %s", len(ports), dest)
    return dest


_PORT_COLUMNS = [
    "port", "protocol", "state", "local_addr", "remote_addr",
    "pid", "process_name", "risk_level", "risk_score", "triggered_rules",
]


def export_ports_csv(ports: list[PortRecord], path: str = "ports.csv") -> Path:
    """Export port records to CSV.

    Returns:
        Path to the written file.
    """
    dest = Path(path)
    df = pd.DataFrame(ports, columns=_PORT_COLUMNS)
    df["triggered_rules"] = df["triggered_rules"].apply(
        lambda r: ", ".join(r) if isinstance(r, list) else (str(r) if r else "-")
    )
    df.to_csv(dest, index=False)
    logger.info("Exported %d ports to %s", len(ports), dest)
    return dest


def export_ports_json(ports: list[PortRecord], path: str = "ports.json") -> Path:
    """Export port records to JSON.

    Returns:
        Path to the written file.
    """
    dest = Path(path)
    df = pd.DataFrame(ports, columns=_PORT_COLUMNS)
    df["triggered_rules"] = df["triggered_rules"].apply(
        lambda r: ", ".join(r) if isinstance(r, list) else (str(r) if r else "-")
    )
    df.to_json(dest, orient="records", indent=2)
    logger.info("Exported %d ports to %s", len(ports), dest)
    return dest


def export_csv(processes: list[ProcessRecord], path: str = "processes.csv") -> Path:
    """Export process list to CSV.

    Args:
        processes: Collected process data.
        path: Output file path.

    Returns:
        Path to the written file.
    """
    dest = Path(path)
    df = _to_dataframe(processes)
    df.to_csv(dest, index=False)
    logger.info("Exported %d processes to %s", len(processes), dest)
    return dest


def export_json(processes: list[ProcessRecord], path: str = "processes.json") -> Path:
    """Export process list to JSON.

    Args:
        processes: Collected process data.
        path: Output file path.

    Returns:
        Path to the written file.
    """
    dest = Path(path)
    df = _to_dataframe(processes)
    df.to_json(dest, orient="records", indent=2)
    logger.info("Exported %d processes to %s", len(processes), dest)
    return dest
