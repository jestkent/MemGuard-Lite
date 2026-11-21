"""Command-line detection rules for MemGuard.

Read-only string analysis of a process command line. Nothing here touches a
process; it only classifies text that collector.py already captured.

Why this module exists
----------------------
The original rule was a list of plain substrings ("powershell -enc",
"cmd.exe /c", ...). Substring matching fails in both directions:

* Evasion (false negatives). Windows tools accept many spellings of the same
  argument, so an attacker only has to pick one the list does not contain:
  ``-e`` / ``-ec`` / ``-EncodedCommand`` / ``/enc`` instead of ``-enc``,
  ``pwsh`` instead of ``powershell``, ``p^ower^shell`` (cmd ignores carets),
  ``Down`loadString`` (PowerShell ignores backticks), ``'Down'+'loadString'``
  (string concatenation), or a Unicode en dash in place of ``-``.
* Noise (false positives). ``rundll32`` and ``regsvr32`` are used constantly
  by Windows itself, and ``cmd /c`` is how Node, VS Code and most build tools
  launch every child process. A rule that fires on all of them trains the
  analyst to ignore it.

The fix is two steps: normalise the text so equivalent spellings collapse to
one form, then match on *behaviour* (what the tool is being asked to do)
rather than on the tool's name alone.

Every match produces a named tag (for example ``encoded_powershell``) so the
finding stays explainable: the analyst sees exactly which behaviour fired.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True)
class CmdlineTag:
    """One detectable command-line behaviour."""

    name: str
    weight: int
    technique_id: str
    technique_name: str
    summary: str


# Weights: 20 = suspicious on its own (matches the historical rule weight).
#          40 = high-confidence attack behaviour; crosses the HIGH threshold
#               by itself because there is almost no benign reason for it.
_W_SUSPICIOUS: Final[int] = 20
_W_HIGH: Final[int] = 40

TAGS: Final[dict[str, CmdlineTag]] = {
    tag.name: tag
    for tag in (
        CmdlineTag("encoded_powershell", _W_SUSPICIOUS, "T1059.001", "PowerShell",
                   "PowerShell was given a base64-encoded script, hiding what it runs."),
        CmdlineTag("powershell_download_cradle", _W_SUSPICIOUS, "T1105", "Ingress Tool Transfer",
                   "PowerShell downloads content from the network (often then executes it)."),
        CmdlineTag("powershell_base64_decode", _W_SUSPICIOUS, "T1140", "Deobfuscate/Decode Files or Information",
                   "PowerShell decodes base64 at run time, a common way to unpack a hidden payload."),
        CmdlineTag("base64_reference", _W_SUSPICIOUS, "T1027", "Obfuscated Files or Information",
                   "The command line references base64 encoding."),
        CmdlineTag("mshta_execution", _W_SUSPICIOUS, "T1218.005", "System Binary Proxy Execution: Mshta",
                   "mshta.exe runs HTML Application script; rarely used legitimately today."),
        CmdlineTag("script_host_execution", _W_SUSPICIOUS, "T1059.005", "Visual Basic",
                   "Windows Script Host (wscript/cscript) is running a script file."),
        CmdlineTag("certutil_download", _W_SUSPICIOUS, "T1105", "Ingress Tool Transfer",
                   "certutil.exe is being used to download a file, not to manage certificates."),
        CmdlineTag("certutil_decode", _W_SUSPICIOUS, "T1140", "Deobfuscate/Decode Files or Information",
                   "certutil.exe is being used to decode an encoded file."),
        CmdlineTag("bitsadmin_transfer", _W_SUSPICIOUS, "T1197", "BITS Jobs",
                   "bitsadmin.exe is creating a background transfer job."),
        CmdlineTag("rundll32_abuse", _W_SUSPICIOUS, "T1218.011", "System Binary Proxy Execution: Rundll32",
                   "rundll32.exe is running script, a remote/user-writable DLL, or no DLL at all."),
        CmdlineTag("regsvr32_scriptlet", _W_SUSPICIOUS, "T1218.010", "System Binary Proxy Execution: Regsvr32",
                   "regsvr32.exe is loading a remote scriptlet ('Squiblydoo' technique)."),
        CmdlineTag("scheduled_task_creation", _W_SUSPICIOUS, "T1053.005", "Scheduled Task/Job: Scheduled Task",
                   "A scheduled task is being created, a common persistence method."),
        CmdlineTag("wmic_execution", _W_SUSPICIOUS, "T1047", "Windows Management Instrumentation",
                   "WMIC is starting a process locally or on a remote host."),
        CmdlineTag("registry_run_key", _W_SUSPICIOUS, "T1547.001", "Registry Run Keys / Startup Folder",
                   "A program is being added to a registry Run key so it starts at logon."),
        CmdlineTag("account_creation", _W_SUSPICIOUS, "T1136.001", "Create Account: Local Account",
                   "A local user is being created or added to the Administrators group."),
        CmdlineTag("command_obfuscation", _W_SUSPICIOUS, "T1027.010", "Command Obfuscation",
                   "The command uses escape characters or variable slicing to hide its text."),
        CmdlineTag("lsass_memory_dump", _W_HIGH, "T1003.001", "OS Credential Dumping: LSASS Memory",
                   "Something is dumping LSASS memory, which holds logged-in users' credentials."),
        CmdlineTag("inhibit_system_recovery", _W_HIGH, "T1490", "Inhibit System Recovery",
                   "Shadow copies, backups or boot recovery are being deleted or disabled - a classic ransomware step."),
        CmdlineTag("defender_tampering", _W_HIGH, "T1562.001", "Impair Defenses: Disable or Modify Tools",
                   "Microsoft Defender protection is being disabled or given an exclusion."),
    )
}


# ── Normalisation ────────────────────────────────────────────────────────────

# PowerShell accepts these Unicode dashes as parameter prefixes, so "–enc"
# (en dash) works exactly like "-enc" but defeats a plain "-enc" match.
_DASH_TRANSLATION: Final[dict[int, str]] = {
    ord(ch): "-" for ch in ("\u2010", "\u2011", "\u2012", "\u2013", "\u2014", "\u2015", "\u2212")
}

_WHITESPACE_RE: Final[re.Pattern[str]] = re.compile(r"\s+")


def normalize_cmdline(raw: str) -> str:
    """Collapse equivalent spellings of a command line into one canonical form.

    * Unicode dashes -> ``-``
    * ``^`` removed (cmd.exe escape character, ignored at run time)
    * `````` removed (PowerShell escape character, ignored before letters)
    * quotes removed (``p"ower"shell`` runs as ``powershell`` from cmd)
    * whitespace collapsed, text lower-cased
    """
    if not raw:
        return ""
    text = raw.translate(_DASH_TRANSLATION)
    for ch in ("^", "`", '"', "'"):
        text = text.replace(ch, "")
    return _WHITESPACE_RE.sub(" ", text).strip().lower()


# ── Patterns ─────────────────────────────────────────────────────────────────

def _exe(name: str) -> str:
    """Regex for a program name with optional path and optional .exe."""
    return rf"(?:^|[\s\\/]){name}(?:\.exe)?(?=\s|$)"


# Every abbreviation PowerShell accepts for -EncodedCommand ("-e", "-en",
# "-enc", ..., "-encodedcommand") plus the documented "-ec" alias. Both "-"
# and "/" prefixes are accepted by powershell.exe.
_ENCODED_PARAM = "|".join(
    sorted({"encodedcommand"[:i] for i in range(1, len("encodedcommand") + 1)} | {"ec"}, key=len, reverse=True)
)

_POWERSHELL_RE = re.compile(_exe(r"(?:powershell|pwsh)"))
_ENCODED_RE = re.compile(rf"(?:^|\s)[-/](?:{_ENCODED_PARAM})\s+[a-z0-9+/=]{{16,}}")
_DOWNLOAD_RE = re.compile(
    r"downloadstring|downloadfile|downloaddata|net\.webclient|start-bitstransfer"
    r"|(?:invoke-webrequest|invoke-restmethod|iwr|irm|wget|curl)\s+(?:-\S+\s+)*\S*https?://"
)
_FROMBASE64_RE = re.compile(r"frombase64string")
_BASE64_RE = re.compile(r"base64")
_MSHTA_RE = re.compile(_exe("mshta"))
_SCRIPT_HOST_RE = re.compile(_exe(r"[wc]script"))
_RUNDLL32_RE = re.compile(_exe("rundll32") + r"(?P<args>.*)$")
_RUNDLL32_BAD_ARGS_RE = re.compile(
    r"javascript:|vbscript:|https?://|\\\\[a-z0-9]"  # script, URL, UNC share
    r"|\\users\\|\\programdata\\[^\\\s]+\.dll|\\temp\\|\\appdata\\"  # user-writable DLL
)
_DIRECT_LSASS_DUMP_RE = re.compile(r"comsvcs(?:\.dll)?[\s,]+(?:minidump|#\s*24)|out-minidump|sekurlsa::")
_DIRECT_DEFENDER_RE = re.compile(r"(?:^|[\s\\])sc(?:\.exe)?\s+(?:stop|delete|config)\s+windefend")

# "TOOL ... SWITCH" behaviours as (head, tail) pairs. Written as one regex
# ("certutil.*-urlcache") they are QUADRATIC: every occurrence of the tool name
# restarts a scan to the end of the line. The stress test showed a crafted
# 32,767-char command line ("certutil certutil certutil ...") costing 0.7 s per
# process - a cheap way for malware to stall a scan. Finding the head ONCE and
# then searching for the tail after it is linear and matches exactly the same
# inputs: any tail that follows a later head also follows the first one.
_SEQUENCE_RULES: Final[dict[str, tuple[tuple[re.Pattern[str], re.Pattern[str]], ...]]] = {
    tag: tuple((re.compile(head), re.compile(tail)) for head, tail in pairs)
    for tag, pairs in {
        "certutil_download": ((_exe("certutil"), r"[-/](?:urlcache|verifyctl)\b"),),
        "certutil_decode": ((_exe("certutil"), r"[-/](?:decode|decodehex)\b"),),
        "bitsadmin_transfer": ((_exe("bitsadmin"), r"[-/](?:transfer|addfile|setnotifycmdline)\b"),),
        "regsvr32_scriptlet": ((_exe("regsvr32"), r"/i:\s*(?:https?://|\\\\)|scrobj"),),
        "scheduled_task_creation": ((_exe("schtasks"), r"[-/]create\b"),),
        "wmic_execution": ((_exe("wmic"), r"process\s+call\s+create|[-/]node:"),),
        "registry_run_key": ((r"(?:reg(?:\.exe)?\s+add|new-itemproperty|set-itemproperty)\s",
                              r"\\currentversion\\run(?:once)?\b"),),
        "account_creation": ((_exe(r"net1?") + r"\s+(?:user|localgroup)\b", r"\s/add\b"),),
        "lsass_memory_dump": ((r"procdump(?:64)?(?:\.exe)?\s", r"-ma\s+lsass"),),
        "inhibit_system_recovery": (
            (r"vssadmin(?:\.exe)?\s", r"delete\s+shadows|resize\s+shadowstorage"),
            (r"wmic(?:\.exe)?\s", r"shadowcopy\s+delete"),
            (r"wbadmin(?:\.exe)?\s", r"delete\s+(?:catalog|systemstatebackup|backup)"),
            (r"bcdedit(?:\.exe)?\s", r"recoveryenabled\s+(?:no|off|0)|bootstatuspolicy\s+ignoreallfailures"),
            (r"win32_shadowcopy", r"delete|remove-"),
        ),
        "defender_tampering": (
            (r"set-mppreference\s", r"-disable(?:realtimemonitoring|behaviormonitoring|ioavprotection|scriptscanning)"),
            (r"add-mppreference\s", r"-exclusion(?:path|process|extension)"),
        ),
    }.items()
}


def _sequence_match(tag: str, text: str) -> bool:
    """True if any (head, tail) pair of ``tag`` matches: tail after first head."""
    for head, tail in _SEQUENCE_RULES[tag]:
        first = head.search(text)
        if first and tail.search(text, first.end()):
            return True
    return False
_ENV_SLICE_RE = re.compile(r"%[a-z0-9_]+:(?:~-?\d+(?:,-?\d+)?|[^=%\s]+=[^%]*)%")

# Obfuscation puts escape characters INSIDE words: p^o^w^e^r^s^h^e^l^l,
# I`E`X. Legitimate tooling escapes argument BOUNDARIES instead - Node's
# child_process launcher emits `npx ^-y^ ^convex@latest^`, which a plain
# caret count flagged on every MCP server launch (5 false positives on the
# reference host). Only carets between two alphanumerics count.
_INTRAWORD_CARET_RE = re.compile(r"(?<=[a-z0-9])\^(?=[a-z0-9])")
# PowerShell backtick between letters, excluding the escape sequences real
# scripts use (`n newline, `t tab, `r return, `0 null). "I`E`X" (2 hits) is
# the textbook obfuscation of Invoke-Expression, so backticks need only 2.
_INTRAWORD_BACKTICK_RE = re.compile(r"(?<=[a-z0-9])`(?=[a-z0-9])(?![ntr0])")
_OBFUSCATION_MIN_CARETS = 3
_OBFUSCATION_MIN_BACKTICKS = 2


def match_cmdline(raw: str) -> list[str]:
    """Return the names of every behaviour tag the command line matches.

    The result is ordered by TAGS declaration order and contains no
    duplicates. An empty list means no suspicious behaviour was found; it does
    NOT mean the command line was read (callers handle "N/A" separately).
    """
    if not raw or raw.strip().lower() == "n/a":
        return []

    norm = normalize_cmdline(raw)
    # 'Down'+'loadString' -> downloadstring once quotes and '+' are gone.
    # Only used for keyword checks; base64 detection keeps the '+'.
    compact = norm.replace("+", "")
    hits: set[str] = set()

    if _POWERSHELL_RE.search(norm):
        if _ENCODED_RE.search(norm):
            hits.add("encoded_powershell")
        if _DOWNLOAD_RE.search(compact):
            hits.add("powershell_download_cradle")
    if _FROMBASE64_RE.search(compact):
        hits.add("powershell_base64_decode")
    elif _BASE64_RE.search(norm):
        hits.add("base64_reference")

    if _MSHTA_RE.search(norm):
        hits.add("mshta_execution")
    if _SCRIPT_HOST_RE.search(norm):
        hits.add("script_host_execution")
    hits.update(tag for tag in _SEQUENCE_RULES if _sequence_match(tag, norm))

    if rundll := _RUNDLL32_RE.search(norm):
        args = rundll.group("args").strip()
        # A bare "rundll32.exe" with no DLL is a classic sacrificial process
        # that attack frameworks start and then inject into.
        if not args or _RUNDLL32_BAD_ARGS_RE.search(args):
            hits.add("rundll32_abuse")

    # Obfuscation is judged on the RAW text: normalisation removes the very
    # characters (carets, backticks) that reveal it.
    raw_lower = raw.lower()
    if (
        len(_INTRAWORD_CARET_RE.findall(raw_lower)) >= _OBFUSCATION_MIN_CARETS
        or len(_INTRAWORD_BACKTICK_RE.findall(raw_lower)) >= _OBFUSCATION_MIN_BACKTICKS
        or _ENV_SLICE_RE.search(raw_lower)
    ):
        hits.add("command_obfuscation")

    if _DIRECT_LSASS_DUMP_RE.search(norm):
        hits.add("lsass_memory_dump")
    if _DIRECT_DEFENDER_RE.search(norm):
        hits.add("defender_tampering")

    return [name for name in TAGS if name in hits]


def score_tags(tags: list[str]) -> int:
    """Points for a set of tags: the strongest single tag, not the sum.

    Summing would let one noisy command line stack many weak tags into a HIGH
    finding; taking the maximum keeps the score tied to the worst behaviour.
    """
    return max((TAGS[t].weight for t in tags if t in TAGS), default=0)
