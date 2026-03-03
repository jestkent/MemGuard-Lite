"""Optional VirusTotal enrichment for MemGuard.

Queries VT v3 by SHA256 in read-only mode and enriches process records with:
- vt_malicious
- vt_suspicious
- vt_harmless
"""

from __future__ import annotations

import logging
import os
import time

import requests

from .collector import ProcessRecord

logger = logging.getLogger(__name__)

_VT_URL_TEMPLATE = "https://www.virustotal.com/api/v3/files/{sha256}"
_VT_TIMEOUT_SECONDS = 5
_VT_SLEEP_SECONDS = 15
_VT_MAX_REQUESTS_DEFAULT = 8


def _get_vt_api_key() -> str | None:
    """Get VT API key from process env, with Windows user-env fallback."""
    api_key = os.getenv("VT_API_KEY")
    if api_key:
        return api_key

    if os.name != "nt":
        return None

    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment") as key:
            value, _ = winreg.QueryValueEx(key, "VT_API_KEY")
            if isinstance(value, str) and value.strip():
                return value.strip()
    except OSError:
        return None
    except Exception:
        return None

    return None


def _extract_stats(payload: dict) -> tuple[int, int, int]:
    """Extract VT last_analysis_stats safely from response payload."""
    stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    return malicious, suspicious, harmless


def enrich_with_virustotal(
    processes: list[ProcessRecord],
    enabled: bool = False,
    max_requests: int | None = None,
    min_threat_score: int = 20,
) -> list[ProcessRecord]:
    """Optionally enrich process records with VirusTotal counts.

    Behavior:
    - If disabled, returns input unchanged.
    - If VT_API_KEY is missing, logs warning and returns input unchanged.
    - Uses in-memory SHA256 cache to avoid duplicate queries per run.
    - Queries only when process threat_score >= 20 OR hash not previously queried.
    - Handles 404/429/network errors without crashing.
    """
    if not enabled:
        return processes

    api_key = _get_vt_api_key()
    if not api_key:
        logger.warning("--vt requested but VT_API_KEY is not set. Continuing without VirusTotal enrichment.")
        return processes

    headers = {"x-apikey": api_key}
    cache: dict[str, tuple[int, int, int] | None] = {}
    enriched_list: list[ProcessRecord] = []
    made_request = False

    if max_requests is None:
        max_requests_raw = os.getenv("VT_MAX_REQUESTS", str(_VT_MAX_REQUESTS_DEFAULT)).strip()
        try:
            max_requests = max(1, int(max_requests_raw))
        except ValueError:
            max_requests = _VT_MAX_REQUESTS_DEFAULT
    else:
        max_requests = max(1, int(max_requests))

    hash_priority: dict[str, int] = {}
    for process in processes:
        sha256_hash = (process.get("sha256") or "").strip().lower()
        if not sha256_hash:
            continue
        threat_score = int(process.get("threat_score", 0) or 0)
        if threat_score < min_threat_score:
            continue
        if sha256_hash not in hash_priority or threat_score > hash_priority[sha256_hash]:
            hash_priority[sha256_hash] = threat_score

    if not hash_priority:
        logger.info("VirusTotal enrichment skipped: no hashes met threat score threshold >= %d.", min_threat_score)
        return processes

    ordered_hashes = [
        sha
        for sha, _ in sorted(hash_priority.items(), key=lambda item: item[1], reverse=True)
    ]

    queried = 0
    for sha256_hash in ordered_hashes:
        if queried >= max_requests:
            logger.info("VirusTotal query cap reached (%d). Remaining hashes skipped for this run.", max_requests)
            break

        if made_request:
            time.sleep(_VT_SLEEP_SECONDS)

        try:
            response = requests.get(
                _VT_URL_TEMPLATE.format(sha256=sha256_hash),
                headers=headers,
                timeout=_VT_TIMEOUT_SECONDS,
            )
        except requests.RequestException as exc:
            logger.warning("VirusTotal request failed for hash %s: %s", sha256_hash[:12], exc)
            cache[sha256_hash] = None
            made_request = True
            queried += 1
            continue

        made_request = True
        queried += 1

        if response.status_code == 200:
            cache[sha256_hash] = _extract_stats(response.json())
        elif response.status_code == 404:
            cache[sha256_hash] = None
        elif response.status_code == 429:
            logger.warning("VirusTotal rate limit reached (HTTP 429). Continuing without additional VT data.")
            cache[sha256_hash] = None
            break
        else:
            logger.warning("VirusTotal API returned HTTP %s for hash %s", response.status_code, sha256_hash[:12])
            cache[sha256_hash] = None

    for process in processes:
        enriched = dict(process)
        sha256_hash = (process.get("sha256") or "").strip().lower()

        if not sha256_hash:
            enriched_list.append(enriched)
            continue

        if sha256_hash in cache and cache[sha256_hash] is not None:
            malicious, suspicious, harmless = cache[sha256_hash]
            enriched["vt_malicious"] = malicious
            enriched["vt_suspicious"] = suspicious
            enriched["vt_harmless"] = harmless

        enriched_list.append(enriched)

    return enriched_list
