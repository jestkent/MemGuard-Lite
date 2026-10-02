"""Process data collection module.

Enumerates running processes and collects forensic metadata
using psutil. Read-only — no process modification allowed.
"""

import logging
import os
import re
import time
from datetime import datetime
from typing import NotRequired, TypedDict

import psutil

logger = logging.getLogger(__name__)

_SENSITIVE_ARG_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"(?i)(--(?:access-?token|api[-_]?key|auth[-_]?token|password|passwd|secret|client-secret|token)\s*=\s*)([^\s]+)"
    ),
    re.compile(
        r"(?i)(--(?:access-?token|api[-_]?key|auth[-_]?token|password|passwd|secret|client-secret|token)\s+)([^\s]+)"
    ),
    re.compile(r"(?i)(--vscode-window-config=)([^\s]+)"),
)


class ProcessRecord(TypedDict):
    """Internal process data model used across MemGuard layers."""

    pid: int
    ppid: int
    name: str
    exe: str
    user: str
    rss_mb: float
    cpu_percent: float
    cmdline: str
    start_time: str
    sha256: NotRequired[str]
    vt_malicious: NotRequired[int]
    vt_suspicious: NotRequired[int]
    vt_harmless: NotRequired[int]
    vms_mb: NotRequired[float]
    num_memory_maps: NotRequired[int]
    private_writable_regions: NotRequired[int]
    executable_writable_regions: NotRequired[int]
    memory_anomaly_score: NotRequired[int]
    memory_flag: NotRequired[str]
    threat_score: NotRequired[int]
    threat_level: NotRequired[str]
    triggered_rules: NotRequired[list[str]]
    access_denied_fields: NotRequired[list[str]]
    data_confidence: NotRequired[str]


class SystemOverview(TypedDict):
    """System-level telemetry shown above the process table."""

    total_ram_mb: float
    used_ram_mb: float
    free_ram_mb: float
    cpu_percent: float


def _sanitize_text(value: str) -> str:
    """Remove newlines/tabs from text fields to keep exports parse-safe."""
    normalized = " ".join(value.replace("\r", " ").replace("\n", " ").replace("\t", " ").split())
    redacted = normalized
    for pattern in _SENSITIVE_ARG_PATTERNS:
        redacted = pattern.sub(r"\1[REDACTED]", redacted)
    return redacted


def is_elevated() -> bool:
    """True when the current process holds an elevated (admin) token.

    Without elevation, Windows denies cmdline/exe reads on SYSTEM-owned
    processes, which silently removes evidence from scoring.
    """
    if os.name != "nt":
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _probe_denied_fields(proc: "psutil.Process", info: dict) -> list[str]:
    """Return the names of fields Windows refused to disclose.

    psutil.process_iter() substitutes None for an AccessDenied attribute, so a
    denied field and a genuinely empty one are indistinguishable in `info`.
    Re-reading the missing ones tells the two apart — the distinction matters
    because missing evidence must not be scored as absent evidence.
    """
    denied: list[str] = []
    probes = (("cmdline", proc.cmdline), ("exe", proc.exe), ("user", proc.username))
    for field, getter in probes:
        key = "username" if field == "user" else field
        if info.get(key):
            continue
        try:
            getter()
        except psutil.AccessDenied:
            denied.append(field)
        except Exception:
            continue
    return denied


def collect_system_overview() -> SystemOverview:
    """Collect total/used/free RAM and current CPU usage percentage."""
    memory = psutil.virtual_memory()
    return {
        "total_ram_mb": round(memory.total / (1024 * 1024), 2),
        "used_ram_mb": round(memory.used / (1024 * 1024), 2),
        "free_ram_mb": round(memory.available / (1024 * 1024), 2),
        "cpu_percent": round(psutil.cpu_percent(interval=0.5), 1),
    }


def collect_processes() -> list[ProcessRecord]:
    """Enumerate all running processes and collect metadata.

    Returns:
        List of ProcessRecord sorted by RSS memory descending.
    """
    attrs = [
        "pid", "ppid", "name", "exe", "username",
        "memory_info", "cmdline", "create_time",
    ]

    processes: list[ProcessRecord] = []

    process_objects = list(psutil.process_iter(attrs=attrs))

    for proc in process_objects:
        try:
            proc.cpu_percent(interval=None)
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            continue

    time.sleep(0.2)

    for proc in process_objects:
        try:
            info = proc.info  # type: ignore[attr-defined]

            # PID / PPID
            pid: int = info.get("pid", 0)
            ppid: int = info.get("ppid", 0)

            # Name & executable
            name: str = info.get("name") or "N/A"
            exe: str = _sanitize_text(info.get("exe") or "N/A")

            # Username
            user: str = _sanitize_text(info.get("username") or "N/A")

            # RSS memory in MB
            mem = info.get("memory_info")
            rss_mb: float = round(mem.rss / (1024 * 1024), 2) if mem else 0.0

            # CPU usage
            cpu_percent: float = round(proc.cpu_percent(interval=None), 1)

            # Command line
            cmdline_list = info.get("cmdline")
            cmdline: str = _sanitize_text(" ".join(cmdline_list) if cmdline_list else "N/A")

            # Start time
            create_time = info.get("create_time")
            if create_time:
                start_time = datetime.fromtimestamp(create_time).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            else:
                start_time = "N/A"

            denied_fields = _probe_denied_fields(proc, info)

            processes.append(
                {
                    "pid": pid,
                    "ppid": ppid,
                    "name": name,
                    "exe": exe,
                    "user": user,
                    "rss_mb": rss_mb,
                    "cpu_percent": cpu_percent,
                    "cmdline": cmdline,
                    "start_time": start_time,
                    "access_denied_fields": denied_fields,
                    "data_confidence": "PARTIAL" if denied_fields else "FULL",
                }
            )

        except psutil.NoSuchProcess:
            logger.debug("Process disappeared during collection (PID %s)", proc.pid)
        except psutil.AccessDenied:
            logger.debug("Access denied for PID %s", proc.pid)
        except psutil.ZombieProcess:
            logger.debug("Zombie process skipped (PID %s)", proc.pid)
        except Exception as exc:
            logger.warning("Unexpected error collecting PID %s: %s", proc.pid, exc)

    # Sort by RSS memory descending
    processes.sort(key=lambda p: p["rss_mb"], reverse=True)
    logger.info("Collected %d processes", len(processes))
    return processes
