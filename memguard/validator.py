"""Read-only validation utilities for suspicious process entries."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import time
from typing import TypedDict

import psutil

from .collector import ProcessRecord


class ValidationReport(TypedDict):
    """Validation result model for a selected process record."""

    timestamp: str
    pid: int
    ppid: int
    name: str
    exe: str
    process_running: bool
    parent_running: bool | None
    file_exists: bool
    path_is_temp: bool
    sha256_expected: str | None
    sha256_actual: str | None
    sha256_match: bool | None
    signature_status: str
    signature_subject: str


def _compute_sha256(file_path: Path) -> str | None:
    digest = hashlib.sha256()
    try:
        with file_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def _is_temp_path(path_value: str) -> bool:
    normalized = path_value.replace("/", "\\").lower()
    return any(
        marker in normalized
        for marker in (
            "\\temp\\",
            "appdata\\local\\temp",
            "\\windows\\temp\\",
        )
    )


def _powershell_escape_single_quotes(value: str) -> str:
    return value.replace("'", "''")


def _get_windows_signature(path_value: str) -> tuple[str, str]:
    if os.name != "nt":
        return "UNAVAILABLE", "N/A"

    escaped_path = _powershell_escape_single_quotes(path_value)
    script = (
        f"$s = Get-AuthenticodeSignature -LiteralPath '{escaped_path}'; "
        "$subj = if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { 'N/A' }; "
        "Write-Output ($s.Status.ToString() + '|' + $subj)"
    )

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
    except Exception:
        return "UNAVAILABLE", "N/A"

    output = (result.stdout or "").strip()
    if not output:
        return "UNAVAILABLE", "N/A"

    status, _, subject = output.partition("|")
    return status.strip() or "UNAVAILABLE", subject.strip() or "N/A"


def validate_process_record(process: ProcessRecord) -> ValidationReport:
    """Perform read-only validation checks on a selected process row."""
    pid = int(process.get("pid", 0) or 0)
    ppid = int(process.get("ppid", 0) or 0)
    name = str(process.get("name", "N/A") or "N/A")
    exe = str(process.get("exe", "N/A") or "N/A")

    file_path = Path(exe) if exe and exe.lower() != "n/a" else None
    file_exists = bool(file_path and file_path.exists())

    expected_hash_raw = process.get("sha256")
    expected_hash = str(expected_hash_raw).lower() if expected_hash_raw else None
    actual_hash = _compute_sha256(file_path) if file_exists and file_path else None
    hash_match = None
    if expected_hash and actual_hash:
        hash_match = expected_hash == actual_hash.lower()

    signature_status, signature_subject = (
        _get_windows_signature(exe) if file_exists else ("UNAVAILABLE", "N/A")
    )

    return {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "pid": pid,
        "ppid": ppid,
        "name": name,
        "exe": exe,
        "process_running": psutil.pid_exists(pid) if pid > 0 else False,
        "parent_running": psutil.pid_exists(ppid) if ppid > 0 else None,
        "file_exists": file_exists,
        "path_is_temp": _is_temp_path(exe),
        "sha256_expected": expected_hash,
        "sha256_actual": actual_hash,
        "sha256_match": hash_match,
        "signature_status": signature_status,
        "signature_subject": signature_subject,
    }


def format_validation_report(report: ValidationReport) -> str:
    """Format validation results for GUI display."""
    parent_state = (
        "N/A" if report["parent_running"] is None else str(report["parent_running"])
    )
    hash_match = report["sha256_match"]
    hash_match_text = "N/A" if hash_match is None else str(hash_match)

    lines = [
        "Validation",
        f"Checked At: {report['timestamp']}",
        f"PID Running: {report['process_running']}",
        f"Parent Running: {parent_state}",
        f"Executable Exists: {report['file_exists']}",
        f"Path In Temp: {report['path_is_temp']}",
        f"SHA256 Match: {hash_match_text}",
        f"Signature Status: {report['signature_status']}",
        f"Signer Subject: {report['signature_subject']}",
    ]

    if report["sha256_expected"]:
        lines.append(f"Expected SHA256: {report['sha256_expected']}")
    if report["sha256_actual"]:
        lines.append(f"Actual SHA256: {report['sha256_actual']}")

    return "\n".join(lines)
