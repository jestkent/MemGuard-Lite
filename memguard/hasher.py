"""Executable hashing and local blocklist loading for MemGuard.

Layer 3 artifact checks are read-only and resilient to file access failures.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

from .collector import ProcessRecord

logger = logging.getLogger(__name__)


def load_blocklist(path: str = "data/blocklist.txt") -> set[str]:
    """Load local SHA256 blocklist once and return hashes as a lowercase set."""
    blocklist_path = Path(path)
    try:
        lines = blocklist_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        logger.warning("Unable to read blocklist file %s: %s", blocklist_path, exc)
        return set()

    hashes = {
        line.strip().lower()
        for line in lines
        if line.strip() and not line.strip().startswith("#")
    }
    logger.info("Loaded %d blocklist hash entries from %s", len(hashes), blocklist_path)
    return hashes


def _compute_sha256(file_path: str) -> str | None:
    """Compute SHA256 hash for a file path, returning None on read errors."""
    digest = hashlib.sha256()
    try:
        with open(file_path, "rb") as file_handle:
            for chunk in iter(lambda: file_handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None

    return digest.hexdigest()


def attach_sha256(processes: list[ProcessRecord]) -> list[ProcessRecord]:
    """Attach executable SHA256 to each process using an in-memory path cache."""
    hash_cache: dict[str, str | None] = {}
    enriched_processes: list[ProcessRecord] = []

    for process in processes:
        enriched = dict(process)
        exe_path = process.get("exe", "")

        if not exe_path or exe_path.lower() == "n/a":
            enriched_processes.append(enriched)
            continue

        if exe_path not in hash_cache:
            hash_cache[exe_path] = _compute_sha256(exe_path)

        sha256_value = hash_cache[exe_path]
        if sha256_value:
            enriched["sha256"] = sha256_value

        enriched_processes.append(enriched)

    return enriched_processes
