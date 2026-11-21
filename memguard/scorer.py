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
from functools import lru_cache
from typing import Final

import psutil

from .collector import ProcessRecord
from memguard import cmdline_rules, masquerade
from memguard.port_inspector import is_loopback_address
from memguard.system_whitelist import is_system_process

logger = logging.getLogger(__name__)

# Resolved once: MemGuard's own PID, excluded from scoring (see score_process).
_OWN_PID: Final[int] = os.getpid()

# Points per rule - the single source of truth. about.py reads this table to
# build the in-app documentation, so the docs cannot drift from the scorer.
# suspicious_commandline's value is the base weight; high-confidence
# behaviours score more (see cmdline_rules.TAGS).
RULE_POINTS: Final[dict[str, int]] = {
    "temp_executable_path": 30,
    "suspicious_commandline": 20,
    "elevated_user_running_from_user_space": 15,
    "listening_ephemeral_port": 25,
    "suspicious_parent_child": 35,
    "unexpected_parent": 40,
    "system_binary_wrong_location": 40,
    "process_name_lookalike": 30,
    "microsoft_name_wrong_signer": 40,
    "duplicate_singleton_process": 30,
    "unsigned_or_invalid_signature": 20,
    "blocklist_match": 70,
    "virustotal_malicious": 50,
    "unverifiable_data": 0,
    "parent_unverifiable": 0,
    "memguard_self": 0,
}

# Score thresholds for the threat levels.
LEVEL_THRESHOLDS: Final[dict[str, int]] = {"HIGH": 40, "SUSPICIOUS": 15}

_TEMP_PATH_PATTERNS: Final[tuple[str, ...]] = (
    "appdata\\local\\temp",
    "\\temp\\",
    "/tmp",
    "/var/tmp",
)

# Command-line detection lives in cmdline_rules.py: it normalises evasive
# spellings (-e/-ec/-EncodedCommand, carets, backticks, Unicode dashes) and
# matches behaviour, not tool names. The former plain-substring list fired on
# every "cmd.exe /c" and bare rundll32/regsvr32 call while missing trivial
# variants such as "powershell -e".

# Suspicious parent → child name pairs (both lowercase).
# Left = parent process name, right = child process name.
_SUSPICIOUS_PARENT_CHILD: Final[tuple[tuple[str, str], ...]] = (
    ("winword.exe", "cmd.exe"),
    ("winword.exe", "powershell.exe"),
    ("winword.exe", "wscript.exe"),
    ("winword.exe", "cscript.exe"),
    ("winword.exe", "mshta.exe"),
    ("excel.exe", "cmd.exe"),
    ("excel.exe", "powershell.exe"),
    ("excel.exe", "wscript.exe"),
    ("excel.exe", "mshta.exe"),
    ("powerpnt.exe", "cmd.exe"),
    ("powerpnt.exe", "powershell.exe"),
    ("outlook.exe", "cmd.exe"),
    ("outlook.exe", "powershell.exe"),
    ("outlook.exe", "wscript.exe"),
    ("explorer.exe", "powershell.exe"),
    ("explorer.exe", "wscript.exe"),
    ("explorer.exe", "mshta.exe"),
    ("iexplore.exe", "cmd.exe"),
    ("iexplore.exe", "powershell.exe"),
    ("chrome.exe", "cmd.exe"),
    ("chrome.exe", "powershell.exe"),
    ("msedge.exe", "cmd.exe"),
    ("msedge.exe", "powershell.exe"),
    ("wmiprvse.exe", "cmd.exe"),
    ("wmiprvse.exe", "powershell.exe"),
    ("mshta.exe", "powershell.exe"),
    ("mshta.exe", "cmd.exe"),
    ("wscript.exe", "powershell.exe"),
    ("wscript.exe", "cmd.exe"),
    ("cscript.exe", "powershell.exe"),
    ("cscript.exe", "cmd.exe"),
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
    if score >= LEVEL_THRESHOLDS["HIGH"]:
        return "HIGH"
    if score >= LEVEL_THRESHOLDS["SUSPICIOUS"]:
        return "SUSPICIOUS"
    return "SAFE"


def _safe_int(value: object) -> int:
    """int() that never raises: a malformed PID scores as 0, not a crash."""
    try:
        return int(value or 0)  # type: ignore[call-overload]
    except (TypeError, ValueError):
        return 0


def _ascii(text: object) -> str:
    """Make a rule label ASCII-safe.

    triggered_rules are printed to the console; a non-encodable character
    (e.g. a Cyrillic homoglyph in a lookalike process name) would abort the
    CLI on a cp1252 console before the export step. backslashreplace keeps
    the evidence visible ("sv\\u0441host.exe") instead of dropping it.
    """
    return str(text).encode("ascii", "backslashreplace").decode("ascii")


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


def _get_ephemeral_listening_addresses(pid: int) -> set[str]:
    """Return inet listening addresses where local port is > 49152.

    Returns an empty set on permission/process errors to keep scoring resilient.
    """
    try:
        proc = psutil.Process(pid)
        connections = proc.connections(kind="inet")
        addresses: set[str] = set()
        for conn in connections:
            if conn.status == psutil.CONN_LISTEN and conn.laddr and conn.laddr.port > 49152:
                ip = getattr(conn.laddr, "ip", None)
                if ip:
                    addresses.add(str(ip))
                elif isinstance(conn.laddr, tuple) and conn.laddr:
                    addresses.add(str(conn.laddr[0]))
        return addresses
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        return set()
    except Exception as exc:
        logger.debug("Network inspection failed for PID %s: %s", pid, exc)
        return set()


def _has_ephemeral_listening_port(pid: int) -> bool:
    """Check if a process has any listening inet connection on port > 49152."""
    return bool(_get_ephemeral_listening_addresses(pid))


def _get_parent_name(ppid: int) -> str | None:
    """Return lowercase parent process name, or None on any error.

    Kept for backwards compatibility. Scoring uses _resolve_parent(), which
    also guards against PID reuse.
    """
    if ppid <= 0:
        return None
    try:
        return psutil.Process(ppid).name().lower()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


def _resolve_parent(pid: int, ppid: int) -> tuple[str | None, str]:
    """Return (lowercase parent name, status) for a process.

    status is one of:
      "ok"      - parent found and verified older than the child.
      "gone"    - no live process holds that PID (parent exited).
      "reused"  - a process holds the PID but started AFTER the child, so it
                  is a newer process that inherited a recycled PID, not the
                  real parent. Windows recycles PIDs quickly; without this
                  check the child is blamed on (or cleared by) a stranger.
      "unknown" - the parent could not be read.
    Only "ok" yields a name; every other status returns None so callers can
    never evaluate a parent relationship on unverified data.
    """
    if ppid <= 0:
        return None, "gone"
    try:
        parent = psutil.Process(ppid)
        parent_name = parent.name().lower()
        parent_created = parent.create_time()
    except psutil.NoSuchProcess:
        return None, "gone"
    except (psutil.AccessDenied, psutil.ZombieProcess):
        return None, "unknown"
    except Exception as exc:  # pragma: no cover - platform/runtime safety
        logger.debug("Parent lookup failed for PPID %s: %s", ppid, exc)
        return None, "unknown"

    try:
        child_created = psutil.Process(pid).create_time() if pid > 0 else None
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        child_created = None
    except Exception:  # pragma: no cover - platform/runtime safety
        child_created = None

    if child_created is not None and parent_created > child_created:
        return None, "reused"
    return parent_name, "ok"


def _is_suspicious_parent_child(parent_name: str | None, child_name: str) -> bool:
    if not parent_name:
        return False
    child_lower = child_name.lower()
    return (parent_name, child_lower) in _SUSPICIOUS_PARENT_CHILD


@lru_cache(maxsize=8192)
def _signature_info_cached(exe: str, fingerprint: tuple[float, int]) -> tuple[str, str]:
    """Cached Authenticode (status, signer subject) for one binary.

    `fingerprint` is (mtime, size) and is part of the cache key, so a binary
    replaced on disk is re-checked rather than served stale.
    """
    return _signature_info_uncached(exe)


def _get_signature_info(exe: str) -> tuple[str, str]:
    """Return (status, signer_subject) for an executable; ("", "") if unknown.

    Each check spawns a PowerShell process (~0.3s), and a host runs many
    processes off the same binary — 414 checks over 145 unique paths on a
    typical scan, scored twice per run. Results are cached per binary so the
    cost is paid once per unique executable instead of once per process.
    The signer is read in the SAME PowerShell call as the status, so the
    wrong-signer rule adds no extra process launches.
    """
    if os.name != "nt" or not exe or exe.lower() == "n/a":
        return "", ""
    try:
        stat = os.stat(exe)
    except OSError:
        # Unreadable or missing: fall through uncached, preserving prior behavior.
        return _signature_info_uncached(exe)
    return _signature_info_cached(exe, (stat.st_mtime, stat.st_size))


def _check_signature_unsigned(exe: str) -> bool:
    """Return True when exe exists and has no valid Authenticode signature."""
    status, _signer = _get_signature_info(exe)
    return status not in ("Valid", "")


# Field separator unlikely to appear in a certificate subject.
_SIG_SEPARATOR: Final[str] = "|#|"


def _signature_info_uncached(exe: str) -> tuple[str, str]:
    """Run PowerShell Get-AuthenticodeSignature — Windows only. Silent on error."""
    if os.name != "nt" or not exe or exe.lower() == "n/a":
        return "", ""
    import subprocess
    escaped = exe.replace("'", "''")
    script = (
        f"$s = Get-AuthenticodeSignature -LiteralPath '{escaped}'; "
        f"$s.Status.ToString() + '{_SIG_SEPARATOR}' + "
        "$(if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { '' })"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            timeout=6,
            check=False,
        )
        output = (result.stdout or "").strip()
        status, _, signer = output.partition(_SIG_SEPARATOR)
        return status.strip(), signer.strip()
    except Exception:
        return "", ""


def _signer_common_name(subject: str) -> str:
    """Extract CN=... from a certificate subject for a short, readable label."""
    for key, value in masquerade.parse_subject(subject):
        if key == "CN":
            return value.strip('"').strip()[:60]
    return (subject or "").strip()[:60]


def score_process(
    process: ProcessRecord,
    blocklist_hashes: set[str] | None = None,
    singleton_counts: dict[str, int] | None = None,
) -> ProcessRecord:
    """Apply heuristic rules and return an enriched process record.

    Args:
        process: Record from collector.py (optionally hashed / enriched).
        blocklist_hashes: Optional local SHA256 blocklist.
        singleton_counts: Optional {lowercase name: instance count} for the
            whole scan, supplied by score_processes(). Needed by the
            duplicate_singleton_process rule, which cannot be judged from one
            record alone. Omitted -> that rule is skipped, never guessed.
    """
    # MemGuard never scores itself. Relaunched as Administrator its interpreter
    # still lives in user space (…/AppData/…/python.exe), which fires
    # elevated_user_running_from_user_space on EVERY elevated scan and writes
    # the false finding to the append-only history, where it would reach the
    # persistent-threat threshold after three scans. The row is still listed,
    # labelled, so the exclusion stays visible rather than hidden.
    if _safe_int(process.get("pid")) == _OWN_PID:
        enriched = dict(process)
        enriched["threat_score"] = 0
        enriched["threat_level"] = _classify_score(0)
        enriched["triggered_rules"] = ["memguard_self (own process, not scored)"]
        enriched["data_confidence"] = process.get("data_confidence", "FULL")
        return enriched

    score = 0
    triggered_rules: list[str] = []

    # str() guards: collector always supplies text, but the scorer must not
    # crash on a malformed record (found by the fuzz stress test).
    exe = str(process.get("exe") or "").lower()
    cmdline = str(process.get("cmdline") or "").lower()
    user = str(process.get("user") or "")
    sha256_hash = str(process.get("sha256") or "").lower()
    vt_malicious = _safe_int(process.get("vt_malicious"))
    memory_anomaly_score = _safe_int(process.get("memory_anomaly_score"))
    memory_flag = str(process.get("memory_flag", "") or "").upper()

    exe_known = bool(exe) and exe != "n/a"
    raw_exe = str(process.get("exe") or "")
    name = str(process.get("name") or "")
    lname = name.lower()
    pid = _safe_int(process.get("pid"))
    ppid = _safe_int(process.get("ppid"))

    if exe_known and any(pattern in exe for pattern in _TEMP_PATH_PATTERNS):
        score += RULE_POINTS["temp_executable_path"]
        triggered_rules.append("temp_executable_path")

    if cmdline and cmdline != "n/a":
        cmd_tags = cmdline_rules.match_cmdline(str(process.get("cmdline") or ""))
        if cmd_tags:
            score += cmdline_rules.score_tags(cmd_tags)
            triggered_rules.append(f"suspicious_commandline ({', '.join(cmd_tags)})")

    if (
        exe_known
        and _is_process_elevated(pid, user)
        and any(path in exe for path in _USER_SPACE_PATTERNS)
    ):
        score += RULE_POINTS["elevated_user_running_from_user_space"]
        triggered_rules.append("elevated_user_running_from_user_space")

    if pid:
        ephemeral_addresses = _get_ephemeral_listening_addresses(pid)
        if ephemeral_addresses:
            rule_score = RULE_POINTS["listening_ephemeral_port"]
            rule_label = "listening_ephemeral_port"

            if is_system_process(name, raw_exe):
                rule_score = 5
                rule_label = "listening_ephemeral_port (system_adjusted)"
                logger.debug("Adjusted score for PID %s due to system whitelist", pid)

            if all(is_loopback_address(address) for address in ephemeral_addresses):
                rule_score = max(0, rule_score - 10)
                rule_label = "listening_ephemeral_port (loopback_only)"
                logger.debug("Reduced score for PID %s due to loopback port", pid)

            score += max(0, rule_score)
            triggered_rules.append(rule_label)

    # ── Process identity (masquerading) ──────────────────────────────────
    if exe_known and masquerade.is_in_expected_location(name, raw_exe) is False:
        score += RULE_POINTS["system_binary_wrong_location"]
        triggered_rules.append(f"system_binary_wrong_location ({_ascii(lname)})")

    imitated = masquerade.find_lookalike(name)
    if imitated:
        score += RULE_POINTS["process_name_lookalike"]
        triggered_rules.append(f"process_name_lookalike ({_ascii(lname)} ~ {imitated})")

    if singleton_counts and lname in masquerade.SINGLETON_PROCESSES:
        count = singleton_counts.get(lname, 0)
        # How many copies sit in the genuine folder. When exactly one does,
        # that copy is the real one and only the impostors are flagged; when
        # several do (an attacker with admin rights wrote to System32) they
        # cannot be told apart, so all of them are flagged. Found by live
        # stress test: a fake lsass.exe made the REAL lsass score SUSPICIOUS.
        genuine_here = masquerade.is_in_expected_location(name, raw_exe) is True
        genuine_total = singleton_counts.get(f"{lname}#genuine", 0)
        if count > 1 and (not genuine_here or genuine_total != 1):
            score += RULE_POINTS["duplicate_singleton_process"]
            triggered_rules.append(f"duplicate_singleton_process ({lname} x{count})")

    # ── Parent relationship ──────────────────────────────────────────────
    parent_name, parent_status = _resolve_parent(pid, ppid)
    if parent_status == "reused":
        # The PID now belongs to a newer process, so the real parent is
        # unknown. Recorded (0 points) rather than silently judged on a
        # stranger's name, which could both cause and hide a finding.
        triggered_rules.append(f"parent_unverifiable (ppid {ppid} reused)")

    if _is_suspicious_parent_child(parent_name, name):
        score += RULE_POINTS["suspicious_parent_child"]
        triggered_rules.append(f"suspicious_parent_child ({_ascii(parent_name)} -> {_ascii(lname)})")

    expected_parents = masquerade.unexpected_parent(name, parent_name)
    if expected_parents:
        score += RULE_POINTS["unexpected_parent"]
        triggered_rules.append(
            f"unexpected_parent ({_ascii(parent_name)} -> {_ascii(lname)}; "
            f"expected {' or '.join(sorted(expected_parents))})"
        )

    # ── Code signing ─────────────────────────────────────────────────────
    if exe_known:
        sig_status, signer = _get_signature_info(exe)
        if sig_status not in ("Valid", ""):
            score += RULE_POINTS["unsigned_or_invalid_signature"]
            triggered_rules.append("unsigned_or_invalid_signature")
        elif (
            sig_status == "Valid"
            and signer
            and lname in masquerade.ALL_PROTECTED_NAMES
            and not masquerade.is_microsoft_signer(signer)
        ):
            score += RULE_POINTS["microsoft_name_wrong_signer"]
            triggered_rules.append(
                f"microsoft_name_wrong_signer ({_ascii(lname)} signed by {_ascii(_signer_common_name(signer))})"
            )

    if blocklist_hashes and sha256_hash and sha256_hash in blocklist_hashes:
        score += RULE_POINTS["blocklist_match"]
        triggered_rules.append("Matched local blocklist")

    if vt_malicious >= 5:
        score += RULE_POINTS["virustotal_malicious"]
        triggered_rules.append("VirusTotal malicious detections >= 5")

    if memory_anomaly_score > 0:
        score += memory_anomaly_score

    if memory_flag == "ANOMALOUS":
        triggered_rules.append("Memory anomaly detected")

    # Evidence that could not be read is recorded, never scored. Adding points
    # for a denied field would punish ordinary SYSTEM processes; adding none
    # and staying silent would let an unassessed process read as cleared. The
    # rule is informational and carries 0 points on purpose.
    denied_fields = process.get("access_denied_fields") or []
    if denied_fields:
        triggered_rules.append(
            f"unverifiable_data ({', '.join(sorted(denied_fields))})"
        )

    enriched = dict(process)
    enriched["threat_score"] = score
    enriched["threat_level"] = _classify_score(score)
    enriched["triggered_rules"] = triggered_rules
    enriched["data_confidence"] = "PARTIAL" if denied_fields else "FULL"
    return enriched


def score_processes(
    processes: list[ProcessRecord],
    blocklist_hashes: set[str] | None = None,
    progress_cb=None,
) -> list[ProcessRecord]:
    """Score all processes while preserving input ordering.

    Args:
        processes: Records to score.
        blocklist_hashes: Optional local SHA256 blocklist.
        progress_cb: Optional callable(done, total). Signature verification
            dominates this step on a cold cache, so a caller driving a
            progress bar needs to see movement during it.
    """
    total = len(processes)

    # Whole-scan context for rules that cannot be judged from one record:
    # "<name>" = instance count, "<name>#genuine" = instances in the real folder.
    singleton_counts: dict[str, int] = {}
    for process in processes:
        lname = str(process.get("name") or "").lower()
        if lname in masquerade.SINGLETON_PROCESSES:
            singleton_counts[lname] = singleton_counts.get(lname, 0) + 1
            if masquerade.is_in_expected_location(lname, str(process.get("exe") or "")) is True:
                key = f"{lname}#genuine"
                singleton_counts[key] = singleton_counts.get(key, 0) + 1

    scored: list[ProcessRecord] = []
    for index, process in enumerate(processes, start=1):
        scored.append(score_process(
            process,
            blocklist_hashes=blocklist_hashes,
            singleton_counts=singleton_counts,
        ))
        if progress_cb and (index % 10 == 0 or index == total):
            progress_cb(index, total)
    return scored
