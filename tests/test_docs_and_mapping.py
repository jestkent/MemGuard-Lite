"""ATT&CK mapping and the in-app documentation stay in sync with the scorer."""

from __future__ import annotations

from memguard import about, attack_map
from memguard.cmdline_rules import TAGS
from memguard.scorer import RULE_POINTS


# ── ATT&CK mapping ───────────────────────────────────────────────────────────

def test_commandline_tags_expand_to_specific_techniques():
    techniques = attack_map.map_rules_to_techniques(
        ["suspicious_commandline (encoded_powershell, lsass_memory_dump)"]
    )
    assert [t[0] for t in techniques] == ["T1059.001", "T1003.001"]


def test_masquerading_rules_map_to_t1036_005():
    for rule in (
        "system_binary_wrong_location (svchost.exe)",
        "process_name_lookalike (scvhost.exe ~ svchost.exe)",
        "microsoft_name_wrong_signer (svchost.exe signed by X)",
        "duplicate_singleton_process (lsass.exe x2)",
        "unexpected_parent (explorer.exe -> lsass.exe; expected wininit.exe)",
    ):
        assert attack_map.map_rule_to_technique(rule)[0] == "T1036.005"


def test_legacy_labels_still_map():
    assert attack_map.map_rule_to_technique("suspicious_commandline")[0] == "T1059"
    assert attack_map.map_rule_to_technique("Matched local blocklist")[0] == "T1027"
    assert attack_map.map_rule_to_technique("listening_ephemeral_port (loopback_only)")[0] == "T1571"
    assert attack_map.map_rule_to_technique("unverifiable_data (cmdline)") is None
    assert attack_map.format_techniques(None) == "-"


def test_techniques_are_deduplicated():
    techniques = attack_map.map_rules_to_techniques([
        "system_binary_wrong_location (a.exe)", "process_name_lookalike (b ~ c)",
    ])
    assert len(techniques) == 1


# ── Documentation ────────────────────────────────────────────────────────────

def test_every_scoring_rule_is_documented():
    documented = {doc.key for doc in about.RULE_DOCS}
    assert documented == set(RULE_POINTS)


def test_every_commandline_behaviour_is_in_the_guide():
    markdown = about.render_markdown()
    for tag in TAGS:
        assert tag in markdown


def test_guide_is_ascii_for_cp1252_consoles():
    assert about.render_markdown().isascii()


def test_points_shown_match_scorer():
    for doc in about.RULE_DOCS:
        assert doc.points == RULE_POINTS[doc.key]
        assert doc.points_text.startswith(f"+{doc.points}" if doc.points else "0")


def test_explain_rule_covers_real_labels():
    labels = [
        "temp_executable_path",
        "suspicious_commandline (encoded_powershell)",
        "listening_ephemeral_port (loopback_only)",
        "suspicious_parent_child (winword.exe -> cmd.exe)",
        "unexpected_parent (explorer.exe -> lsass.exe; expected wininit.exe)",
        "system_binary_wrong_location (svchost.exe)",
        "process_name_lookalike (scvhost.exe ~ svchost.exe)",
        "microsoft_name_wrong_signer (svchost.exe signed by X)",
        "duplicate_singleton_process (lsass.exe x2)",
        "unsigned_or_invalid_signature",
        "Matched local blocklist",
        "VirusTotal malicious detections >= 5",
        "unverifiable_data (cmdline)",
        "parent_unverifiable (ppid 5 reused)",
        "memguard_self (own process, not scored)",
        "Memory anomaly detected",
    ]
    for label in labels:
        assert about.explain_rule(label), label
    assert "base64-encoded" in about.explain_rule("suspicious_commandline (encoded_powershell)")


def test_report_glossary_lists_only_seen_rules():
    glossary = about.rule_glossary_markdown([
        "temp_executable_path", "suspicious_commandline (lsass_memory_dump)", "temp_executable_path",
    ])
    assert glossary.count("temp_executable_path") == 1
    assert "lsass_memory_dump" in glossary
    assert "process_name_lookalike" not in glossary


def test_sections_have_unique_ids_and_content():
    sections = about.build_sections()
    ids = [s.id for s in sections]
    assert len(ids) == len(set(ids))
    assert all(s.blocks for s in sections)
    for must_have in ("overview", "pipeline", "rules", "limits", "safety"):
        assert must_have in ids


def test_environment_facts():
    facts = dict(about.environment_facts())
    assert facts["Version"].startswith("MemGuard Lite")
    assert "Running as Administrator" in facts
