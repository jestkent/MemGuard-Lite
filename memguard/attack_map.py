"""MITRE ATT&CK technique mapping for MemGuard scoring rules.

Read-only lookup: maps `triggered_rules` strings produced by scorer.py
to ATT&CK technique IDs and short names. Purely additive — used at
display/export time, never feeds back into scoring.

A rule can map to more than one technique: "suspicious_commandline
(encoded_powershell, lsass_memory_dump)" expands to one technique per
behaviour tag (see cmdline_rules.TAGS), so the report names the specific
technique rather than the generic T1059.
"""

from __future__ import annotations

import re
from typing import Final

from .cmdline_rules import TAGS as _CMDLINE_TAGS


_MASQUERADING: Final[tuple[str, str]] = ("T1036.005", "Masquerading: Match Legitimate Name or Location")

_RULE_TO_ATTACK: Final[dict[str, tuple[str, str]]] = {
    "temp_executable_path": ("T1036", "Masquerading"),
    "suspicious_commandline": ("T1059", "Command and Scripting Interpreter"),
    "elevated_user_running_from_user_space": ("T1078", "Valid Accounts"),
    "listening_ephemeral_port": ("T1571", "Non-Standard Port"),
    "unsigned_or_invalid_signature": ("T1553.002", "Subvert Trust Controls: Code Signing"),
    "Matched local blocklist": ("T1027", "Obfuscated Files or Information"),
    "VirusTotal malicious detections >= 5": ("T1027", "Obfuscated Files or Information"),
    "Memory anomaly detected": ("T1055", "Process Injection"),
}

# Prefixes for parametric rules — match by startswith().
_RULE_PREFIX_TO_ATTACK: Final[tuple[tuple[str, tuple[str, str]], ...]] = (
    ("listening_ephemeral_port", ("T1571", "Non-Standard Port")),
    ("suspicious_parent_child", ("T1059", "Command and Scripting Interpreter")),
    ("suspicious_commandline", ("T1059", "Command and Scripting Interpreter")),
    ("system_binary_wrong_location", _MASQUERADING),
    ("process_name_lookalike", _MASQUERADING),
    ("microsoft_name_wrong_signer", _MASQUERADING),
    ("duplicate_singleton_process", _MASQUERADING),
    ("unexpected_parent", _MASQUERADING),
)

_TAG_LIST_RE: Final[re.Pattern[str]] = re.compile(r"^suspicious_commandline \((?P<tags>[^)]*)\)")


def map_rule_to_techniques(rule: str) -> list[tuple[str, str]]:
    """Return every (technique_id, technique_name) a rule string maps to."""
    if not rule:
        return []
    if rule in _RULE_TO_ATTACK:
        return [_RULE_TO_ATTACK[rule]]

    match = _TAG_LIST_RE.match(rule)
    if match:
        techniques = [
            (_CMDLINE_TAGS[tag].technique_id, _CMDLINE_TAGS[tag].technique_name)
            for tag in (t.strip() for t in match.group("tags").split(","))
            if tag in _CMDLINE_TAGS
        ]
        if techniques:
            return techniques

    for prefix, technique in _RULE_PREFIX_TO_ATTACK:
        if rule.startswith(prefix):
            return [technique]
    return []


def map_rule_to_technique(rule: str) -> tuple[str, str] | None:
    """Return the primary (technique_id, technique_name) for a rule, or None."""
    techniques = map_rule_to_techniques(rule)
    return techniques[0] if techniques else None


def map_rules_to_techniques(rules: list[str] | None) -> list[tuple[str, str]]:
    """Return deduplicated list of (id, name) tuples for a list of rules."""
    if not rules:
        return []
    seen: set[str] = set()
    result: list[tuple[str, str]] = []
    for rule in rules:
        for technique in map_rule_to_techniques(rule):
            if technique[0] not in seen:
                seen.add(technique[0])
                result.append(technique)
    return result


def format_techniques(rules: list[str] | None) -> str:
    """Human-readable comma-separated string. Empty → '-'."""
    techniques = map_rules_to_techniques(rules)
    if not techniques:
        return "-"
    return ", ".join(f"{tid} {name}" for tid, name in techniques)
