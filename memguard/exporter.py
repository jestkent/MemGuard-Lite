"""Export module for process data.

Exports collected process data to CSV and JSON formats
using pandas for structured serialization.
"""

import logging
from pathlib import Path

import pandas as pd

from .collector import ProcessRecord

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
