"""Experimental memory metadata inspection for high-risk processes.

This module is read-only and inspects process memory metadata via psutil:
- memory_info() for RSS/VMS
- memory_maps(grouped=False) for region attributes
"""

from __future__ import annotations

import logging

import psutil

from .collector import ProcessRecord

logger = logging.getLogger(__name__)

_MB = 1024 * 1024


def _is_anonymous_path(path: str) -> bool:
    """Return True when a memory map path is empty or anonymous."""
    normalized = (path or "").strip().lower()
    if not normalized:
        return True
    if normalized in {"[anon]", "[anonymous]", "anonymous"}:
        return True
    return normalized.startswith("[") and normalized.endswith("]")


def _inspect_process_memory(process: ProcessRecord) -> None:
    """Attach memory metadata and anomaly flags to a single process record."""
    pid = int(process.get("pid", 0) or 0)

    vms_mb = 0.0
    rss_mb = 0.0
    num_memory_maps = 0
    private_writable_regions = 0
    executable_writable_regions = 0

    try:
        ps_process = psutil.Process(pid)
        mem_info = ps_process.memory_info()
        vms_mb = round(float(getattr(mem_info, "vms", 0)) / _MB, 2)
        rss_mb = round(float(getattr(mem_info, "rss", 0)) / _MB, 2)

        try:
            maps = ps_process.memory_maps(grouped=False)
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, AttributeError, NotImplementedError, OSError):
            maps = []

        num_memory_maps = len(maps)

        for region in maps:
            perms = str(getattr(region, "perms", "") or "").lower()
            path = str(getattr(region, "path", "") or "")

            if "rw" in perms and _is_anonymous_path(path):
                private_writable_regions += 1

            if "rwx" in perms or "wx" in perms:
                executable_writable_regions += 1

    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        logger.debug("Memory inspection unavailable for PID %s", pid)
    except Exception as exc:
        logger.debug("Memory inspection failed for PID %s: %s", pid, exc)

    memory_anomaly_score = 0
    if executable_writable_regions > 0:
        memory_anomaly_score += 20
    if private_writable_regions > 100:
        memory_anomaly_score += 15
    if vms_mb > 2000 and rss_mb < 200:
        memory_anomaly_score += 15

    process["vms_mb"] = vms_mb
    process["num_memory_maps"] = num_memory_maps
    process["private_writable_regions"] = private_writable_regions
    process["executable_writable_regions"] = executable_writable_regions
    process["memory_anomaly_score"] = memory_anomaly_score
    process["memory_flag"] = "ANOMALOUS" if memory_anomaly_score >= 20 else "NORMAL"


def inspect_memory(
    processes: list[ProcessRecord],
    min_threat_score: int = 30,
    max_processes: int = 10,
) -> list[ProcessRecord]:
    """Inspect memory metadata for top risky processes.

    Only inspects up to ``max_processes`` processes with
    ``threat_score >= min_threat_score`` ordered by highest threat score.
    """
    if max_processes <= 0:
        return processes

    candidates = [
        process
        for process in processes
        if int(process.get("threat_score", 0) or 0) >= min_threat_score
    ]

    candidates.sort(key=lambda process: int(process.get("threat_score", 0) or 0), reverse=True)

    for process in candidates[:max_processes]:
        _inspect_process_memory(process)

    return processes
