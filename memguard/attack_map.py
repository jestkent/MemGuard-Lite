"""MITRE ATT&CK technique mapping for MemGuard scoring rules.

Read-only lookup: maps `triggered_rules` strings produced by scorer.py
to ATT&CK technique IDs and short names. Purely additive — used at
display/export time, never feeds back into scoring.
"""

from __future__ import annotations

from typing import Final


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
)


def map_rule_to_technique(rule: str) -> tuple[str, str] | None:
    """Return (technique_id, technique_name) for a rule string, or None."""
    if not rule:
        return None
    if rule in _RULE_TO_ATTACK:
        return _RULE_TO_ATTACK[rule]
    for prefix, technique in _RULE_PREFIX_TO_ATTACK:
        if rule.startswith(prefix):
            return technique
    return None


def map_rules_to_techniques(rules: list[str] | None) -> list[tuple[str, str]]:
    """Return deduplicated list of (id, name) tuples for a list of rules."""
    if not rules:
        return []
    seen: set[str] = set()
    result: list[tuple[str, str]] = []
    for rule in rules:
        technique = map_rule_to_technique(rule)
        if technique and technique[0] not in seen:
            seen.add(technique[0])
            result.append(technique)
    return result


def format_techniques(rules: list[str] | None) -> str:
    """Human-readable comma-separated string. Empty → '-'."""
    techniques = map_rules_to_techniques(rules)
    if not techniques:
        return "-"
    return ", ".join(f"{tid} {name}" for tid, name in techniques)
