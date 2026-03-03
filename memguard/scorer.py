"""Heuristic threat scoring engine for MemGuard.

Layer 2 scoring is read-only and enriches process records with:
- threat_score
- threat_level
- triggered_rules
"""

from __future__ import annotations

import ctypes
import logging
import os
from ctypes import wintypes
from typing import Final

import psutil

from .collector import ProcessRecord

logger = logging.getLogger(__name__)

_TEMP_PATH_PATTERNS: Final[tuple[str, ...]] = (
    "appdata\\local\\temp",
    "\\temp\\",
    "/tmp",
    "/var/tmp",
)

_CMDLINE_PATTERNS: Final[tuple[str, ...]] = (
    "powershell -enc",
    "base64",
    "cmd.exe /c",
)

_ELEVATED_USERS: Final[set[str]] = {
    "system",
    "root",
    "nt authority\\system",
}

_USER_SPACE_PATTERNS: Final[tuple[str, ...]] = (
    "c:\\users\\",
    "/home/",
)


def _classify_score(score: int) -> str:
    """Map numeric score to threat level."""
    if score >= 50:
        return "MALICIOUS"
    if score >= 21:
        return "SUSPICIOUS"
    return "SAFE"


def _is_windows_token_elevated(pid: int) -> bool:
    """Best-effort Windows token elevation check for a process PID."""
    if os.name != "nt" or pid <= 0:
        return False

    process_query_limited_information = 0x1000
    token_query = 0x0008
    token_elevation_class = 20

    class TokenElevation(ctypes.Structure):
        _fields_ = [("TokenIsElevated", wintypes.DWORD)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    process_handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
    if not process_handle:
        return False

    try:
        token_handle = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(process_handle, token_query, ctypes.byref(token_handle)):
            return False

        try:
            elevation = TokenElevation()
            return_length = wintypes.DWORD(0)
            ok = advapi32.GetTokenInformation(
                token_handle,
                token_elevation_class,
                ctypes.byref(elevation),
                ctypes.sizeof(elevation),
                ctypes.byref(return_length),
            )
            if not ok:
                return False
            return bool(elevation.TokenIsElevated)
        finally:
            kernel32.CloseHandle(token_handle)
    finally:
        kernel32.CloseHandle(process_handle)


def _is_process_elevated(pid: int, user: str) -> bool:
    """Detect elevated execution context while minimizing false positives."""
    normalized = user.strip().lower()
    if not normalized or normalized == "n/a":
        return False

    if normalized in _ELEVATED_USERS:
        return True

    if os.name != "nt":
        return normalized == "root"

    return _is_windows_token_elevated(pid)


def _has_ephemeral_listening_port(pid: int) -> bool:
    """Check if a process has any listening inet connection on port > 49152.

    Returns False on permission/process errors to keep scoring resilient.
    """
    try:
        proc = psutil.Process(pid)
        connections = proc.connections(kind="inet")
        for conn in connections:
            if conn.status == psutil.CONN_LISTEN and conn.laddr and conn.laddr.port > 49152:
                return True
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        return False
    except Exception as exc:
        logger.debug("Network inspection failed for PID %s: %s", pid, exc)
        return False

    return False


def score_process(process: ProcessRecord, blocklist_hashes: set[str] | None = None) -> ProcessRecord:
    """Apply heuristic rules and return an enriched process record."""
    score = 0
    triggered_rules: list[str] = []

    exe = (process.get("exe") or "").lower()
    cmdline = (process.get("cmdline") or "").lower()
    user = process.get("user") or ""
    sha256_hash = (process.get("sha256") or "").lower()
    vt_malicious = int(process.get("vt_malicious", 0) or 0)

    if exe and exe != "n/a" and any(pattern in exe for pattern in _TEMP_PATH_PATTERNS):
        score += 30
        triggered_rules.append("temp_executable_path")

    if cmdline and cmdline != "n/a" and any(pattern in cmdline for pattern in _CMDLINE_PATTERNS):
        score += 20
        triggered_rules.append("suspicious_commandline")

    pid = process.get("pid", 0)

    if (
        exe
        and exe != "n/a"
        and _is_process_elevated(pid, user)
        and any(path in exe for path in _USER_SPACE_PATTERNS)
    ):
        score += 15
        triggered_rules.append("elevated_user_running_from_user_space")

    if pid and _has_ephemeral_listening_port(pid):
        score += 25
        triggered_rules.append("listening_ephemeral_port")

    if blocklist_hashes and sha256_hash and sha256_hash in blocklist_hashes:
        score += 70
        triggered_rules.append("Matched local blocklist")

    if vt_malicious >= 5:
        score += 50
        triggered_rules.append("VirusTotal malicious detections >= 5")

    enriched = dict(process)
    enriched["threat_score"] = score
    enriched["threat_level"] = _classify_score(score)
    enriched["triggered_rules"] = triggered_rules
    return enriched


def score_processes(processes: list[ProcessRecord], blocklist_hashes: set[str] | None = None) -> list[ProcessRecord]:
    """Score all processes while preserving input ordering."""
    return [score_process(process, blocklist_hashes=blocklist_hashes) for process in processes]
