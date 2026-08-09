"""Persistent scan history log for MemGuard.

Append-only JSONL of HIGH/SUSPICIOUS findings across scans. Lets the
analyst spot persistent threats — same exe + hash repeatedly flagging
across scans is a stronger signal than a single hit.

Read-only safety model: writes only to a local file, never to network.
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections import Counter
from pathlib import Path
from typing import Iterator

from .attack_map import map_rules_to_techniques
from .collector import ProcessRecord

logger = logging.getLogger(__name__)

DEFAULT_HISTORY_PATH = Path("memguard_history.jsonl")
_PERSISTENCE_THRESHOLD = 3


def _resolve_history_path(path: str | os.PathLike[str] | None = None) -> Path:
    return Path(path) if path else DEFAULT_HISTORY_PATH


def append_scan_findings(
    processes: list[ProcessRecord],
    path: str | os.PathLike[str] | None = None,
    scan_timestamp: str | None = None,
) -> int:
    """Append HIGH/SUSPICIOUS findings from a scan to the history log.

    Returns the number of records written.
    """
    dest = _resolve_history_path(path)
    timestamp = scan_timestamp or time.strftime("%Y-%m-%d %H:%M:%S")
    written = 0

    try:
        with dest.open("a", encoding="utf-8") as handle:
            for process in processes:
                level = str(process.get("threat_level", "SAFE")).upper()
                if level not in ("HIGH", "SUSPICIOUS"):
                    continue

                rules = process.get("triggered_rules") or []
                if not isinstance(rules, list):
                    rules = [str(rules)]

                techniques = map_rules_to_techniques(rules)
                record = {
                    "timestamp": timestamp,
                    "pid": int(process.get("pid", 0) or 0),
                    "name": str(process.get("name", "N/A") or "N/A"),
                    "exe": str(process.get("exe", "N/A") or "N/A"),
                    "user": str(process.get("user", "N/A") or "N/A"),
                    "sha256": str(process.get("sha256", "") or ""),
                    "threat_score": int(process.get("threat_score", 0) or 0),
                    "threat_level": level,
                    "triggered_rules": [str(r) for r in rules],
                    "attack_techniques": [
                        {"id": tid, "name": name} for tid, name in techniques
                    ],
                }
                handle.write(json.dumps(record) + "\n")
                written += 1
    except OSError as exc:
        logger.warning("Could not append scan history to %s: %s", dest, exc)
        return 0

    logger.info("Appended %d findings to %s", written, dest)
    return written


def _iter_history(path: Path) -> Iterator[dict]:
    if not path.exists():
        return
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
    except OSError as exc:
        logger.warning("Could not read history %s: %s", path, exc)


def find_persistent_threats(
    path: str | os.PathLike[str] | None = None,
    threshold: int = _PERSISTENCE_THRESHOLD,
) -> list[dict[str, object]]:
    """Return findings that have appeared in the log >= threshold times.

    Identity is (sha256 if present else exe). Returns sorted by occurrence
    count descending.
    """
    dest = _resolve_history_path(path)
    counts: Counter[str] = Counter()
    last_seen: dict[str, dict[str, object]] = {}

    for record in _iter_history(dest):
        identity = str(record.get("sha256") or record.get("exe") or "").lower()
        if not identity or identity == "n/a":
            continue
        counts[identity] += 1
        last_seen[identity] = record

    persistent: list[dict[str, object]] = []
    for identity, count in counts.most_common():
        if count < threshold:
            break
        record = dict(last_seen.get(identity, {}))
        record["occurrences"] = count
        persistent.append(record)
    return persistent
