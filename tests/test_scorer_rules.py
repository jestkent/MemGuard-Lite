"""Scoring engine: each rule's points, labels and the evidence-handling contract."""

from __future__ import annotations

import os
import subprocess

import psutil
import pytest

from memguard import scorer
from tests.conftest import make_record

MS_SIGNER = "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
B64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="


def rules_of(record) -> list[str]:
    return record["triggered_rules"]


# ── Existing rules keep their behaviour ──────────────────────────────────────

def test_clean_record_is_safe(isolated_scorer):
    r = scorer.score_process(make_record())
    assert (r["threat_score"], r["threat_level"], r["data_confidence"], rules_of(r)) == (0, "SAFE", "FULL", [])


def test_temp_path(isolated_scorer):
    r = scorer.score_process(make_record(exe=r"C:\Users\u\AppData\Local\Temp\x.exe"))
    assert r["threat_score"] == 30 and rules_of(r) == ["temp_executable_path"]


def test_blocklist_and_virustotal_labels_unchanged(isolated_scorer):
    r = scorer.score_process(make_record(sha256="AB" * 32, vt_malicious=7), blocklist_hashes={"ab" * 32})
    assert r["threat_score"] == 120
    assert rules_of(r) == ["Matched local blocklist", "VirusTotal malicious detections >= 5"]


def test_denied_fields_are_recorded_not_scored(isolated_scorer):
    r = scorer.score_process(make_record(access_denied_fields=["user", "cmdline"]))
    assert r["threat_score"] == 0
    assert r["data_confidence"] == "PARTIAL"
    assert rules_of(r) == ["unverifiable_data (cmdline, user)"]


def test_memguard_never_scores_itself(isolated_scorer):
    r = scorer.score_process(make_record(pid=os.getpid(), exe=r"C:\Temp\svch0st.exe", cmdline=f"powershell -e {B64}"))
    assert r["threat_score"] == 0 and rules_of(r)[0].startswith("memguard_self")


def test_listening_port_adjustments(isolated_scorer, monkeypatch):
    monkeypatch.setattr(scorer, "_get_ephemeral_listening_addresses", lambda pid: {"0.0.0.0"})
    assert scorer.score_process(make_record())["threat_score"] == 25
    monkeypatch.setattr(scorer, "_get_ephemeral_listening_addresses", lambda pid: {"127.0.0.1", "::1"})
    assert scorer.score_process(make_record())["threat_score"] == 15
    # Verified system process: 25 -> 5, then loopback -10 floors at 0.
    r = scorer.score_process(make_record(name="svchost.exe", exe=r"C:\Windows\System32\svchost.exe"))
    assert r["threat_score"] == 0 and "listening_ephemeral_port (loopback_only)" in rules_of(r)


# ── Command line ─────────────────────────────────────────────────────────────

def test_commandline_label_lists_behaviours(isolated_scorer):
    r = scorer.score_process(make_record(cmdline=f"powershell -ec {B64}"))
    assert r["threat_score"] == 20
    assert rules_of(r) == ["suspicious_commandline (encoded_powershell)"]


def test_high_confidence_commandline_scores_40(isolated_scorer):
    r = scorer.score_process(make_record(cmdline="vssadmin delete shadows /all /quiet"))
    assert r["threat_score"] == 40 and r["threat_level"] == "HIGH"


def test_plain_cmd_c_no_longer_scores(isolated_scorer):
    # Deliberate change: "cmd.exe /c" alone used to add +20 to every Node /
    # VS Code child process. Only what cmd runs is judged now.
    assert scorer.score_process(make_record(cmdline="cmd.exe /c dir"))["threat_score"] == 0


def test_unreadable_commandline_is_not_matched(isolated_scorer):
    assert scorer.score_process(make_record(cmdline="N/A"))["threat_score"] == 0


# ── Process identity ─────────────────────────────────────────────────────────

def test_system_binary_wrong_location(isolated_scorer):
    r = scorer.score_process(make_record(name="svchost.exe", exe=r"C:\Users\bob\AppData\Roaming\svchost.exe"))
    assert "system_binary_wrong_location (svchost.exe)" in rules_of(r)
    assert r["threat_level"] == "HIGH"


def test_genuine_system_binary_is_clean(isolated_scorer, monkeypatch):
    monkeypatch.setattr(scorer, "_get_signature_info", lambda exe: ("Valid", MS_SIGNER))
    monkeypatch.setattr(scorer, "_resolve_parent", lambda pid, ppid: ("services.exe", "ok"))
    r = scorer.score_process(make_record(name="svchost.exe", exe=r"C:\Windows\System32\svchost.exe"))
    assert (r["threat_score"], rules_of(r)) == (0, [])


def test_unknown_exe_is_not_judged_for_location(isolated_scorer):
    r = scorer.score_process(make_record(name="lsass.exe", exe="N/A", access_denied_fields=["exe"]))
    assert not any(x.startswith("system_binary_wrong_location") for x in rules_of(r))
    assert r["data_confidence"] == "PARTIAL"


def test_lookalike_name(isolated_scorer):
    r = scorer.score_process(make_record(name="scvhost.exe"))
    assert rules_of(r) == ["process_name_lookalike (scvhost.exe ~ svchost.exe)"]
    assert r["threat_score"] == 30


def test_homoglyph_label_is_ascii_safe(isolated_scorer):
    r = scorer.score_process(make_record(name="sv\u0441host.exe"))
    label = rules_of(r)[0]
    assert label.isascii() and "\\u0441" in label and "svchost.exe" in label


def test_microsoft_name_wrong_signer(isolated_scorer, monkeypatch):
    monkeypatch.setattr(scorer, "_get_signature_info", lambda exe: ("Valid", "CN=Evil Corp, O=Evil Corp, C=US"))
    r = scorer.score_process(make_record(name="svchost.exe", exe=r"C:\Windows\System32\svchost.exe"))
    assert rules_of(r) == ["microsoft_name_wrong_signer (svchost.exe signed by Evil Corp)"]
    assert r["threat_score"] == 40


def test_non_protected_name_with_other_signer_is_fine(isolated_scorer, monkeypatch):
    monkeypatch.setattr(scorer, "_get_signature_info", lambda exe: ("Valid", "CN=Google LLC, O=Google LLC, C=US"))
    r = scorer.score_process(make_record(name="chrome.exe", exe=r"C:\Program Files\Google\chrome.exe"))
    assert r["threat_score"] == 0


def test_unsigned_still_scores_20(isolated_scorer, monkeypatch):
    monkeypatch.setattr(scorer, "_get_signature_info", lambda exe: ("NotSigned", ""))
    r = scorer.score_process(make_record(exe=r"C:\Tools\x.exe"))
    assert rules_of(r) == ["unsigned_or_invalid_signature"] and r["threat_score"] == 20


def test_duplicate_singleton_indistinguishable_copies_all_flagged(isolated_scorer):
    # Both copies in System32 (attacker with admin rights): cannot tell which
    # is real, so both are flagged.
    lsass = make_record(name="lsass.exe", exe=r"C:\Windows\System32\lsass.exe")
    scored = scorer.score_processes([dict(lsass, pid=900001), dict(lsass, pid=900002), make_record()])
    assert all("duplicate_singleton_process (lsass.exe x2)" in rules_of(p) for p in scored[:2])
    assert rules_of(scored[2]) == []


def test_duplicate_singleton_spares_the_verified_genuine_copy(isolated_scorer):
    # Regression from the live stress test: a fake lsass.exe in AppData made
    # the REAL lsass.exe score SUSPICIOUS. Only the impostor is flagged now.
    real = make_record(pid=900001, name="lsass.exe", exe=r"C:\Windows\System32\lsass.exe")
    fake = make_record(pid=900002, name="lsass.exe", exe=r"C:\Users\bob\AppData\Local\lsass.exe")
    scored_real, scored_fake = scorer.score_processes([real, fake])
    assert rules_of(scored_real) == []
    assert "duplicate_singleton_process (lsass.exe x2)" in rules_of(scored_fake)
    assert "system_binary_wrong_location (lsass.exe)" in rules_of(scored_fake)


def test_single_lsass_is_not_a_duplicate(isolated_scorer):
    scored = scorer.score_processes([make_record(name="lsass.exe", exe=r"C:\Windows\System32\lsass.exe")])
    assert rules_of(scored[0]) == []


# ── Parent relationship ──────────────────────────────────────────────────────

def test_unexpected_parent(isolated_scorer, monkeypatch):
    monkeypatch.setattr(scorer, "_resolve_parent", lambda pid, ppid: ("explorer.exe", "ok"))
    r = scorer.score_process(make_record(name="lsass.exe", exe=r"C:\Windows\System32\lsass.exe", ppid=4242))
    assert rules_of(r) == ["unexpected_parent (explorer.exe -> lsass.exe; expected wininit.exe)"]
    assert r["threat_level"] == "HIGH"


def test_suspicious_parent_child_still_fires(isolated_scorer, monkeypatch):
    monkeypatch.setattr(scorer, "_resolve_parent", lambda pid, ppid: ("winword.exe", "ok"))
    r = scorer.score_process(make_record(name="cmd.exe", exe=r"C:\Windows\System32\cmd.exe", ppid=1))
    assert rules_of(r) == ["suspicious_parent_child (winword.exe -> cmd.exe)"] and r["threat_score"] == 35


def test_reused_parent_pid_is_recorded_not_judged(isolated_scorer, monkeypatch):
    # A recycled PID must neither raise nor clear a parent-based finding.
    monkeypatch.setattr(scorer, "_resolve_parent", lambda pid, ppid: (None, "reused"))
    r = scorer.score_process(make_record(name="lsass.exe", exe=r"C:\Windows\System32\lsass.exe", ppid=777))
    assert rules_of(r) == ["parent_unverifiable (ppid 777 reused)"]
    assert r["threat_score"] == 0


def test_resolve_parent_live():
    name, status = scorer._resolve_parent(os.getpid(), os.getppid())
    assert status == "ok" and name == psutil.Process(os.getppid()).name().lower()
    assert scorer._resolve_parent(os.getpid(), 0) == (None, "gone")


def test_resolve_parent_detects_reuse(monkeypatch):
    class FakeProc:
        def __init__(self, pid):
            self.pid = pid
        def name(self):
            return "Explorer.EXE"
        def create_time(self):
            return 2000.0 if self.pid == 50 else 1000.0   # parent "born" after child

    monkeypatch.setattr(scorer.psutil, "Process", FakeProc)
    assert scorer._resolve_parent(10, 50) == (None, "reused")


# ── Labels and signature plumbing ────────────────────────────────────────────

def test_all_labels_ascii(isolated_scorer, monkeypatch):
    monkeypatch.setattr(scorer, "_resolve_parent", lambda pid, ppid: ("w\u00efnword.exe", "ok"))
    r = scorer.score_process(make_record(name="\u0441md.exe", cmdline="vssadmin delete shadows"))
    assert all(rule.isascii() for rule in rules_of(r))


def test_signature_output_parsing(monkeypatch):
    scorer._signature_info_cached.cache_clear()

    class Result:
        stdout = f"Valid{scorer._SIG_SEPARATOR}{MS_SIGNER}\n"

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: Result())
    monkeypatch.setattr(scorer.os, "name", "nt")
    assert scorer._signature_info_uncached(r"C:\x.exe") == ("Valid", MS_SIGNER)


@pytest.mark.skipif(os.name != "nt", reason="needs Windows Authenticode")
def test_real_windows_binary_is_microsoft_signed():
    status, signer = scorer._get_signature_info(os.path.join(os.environ["SystemRoot"], "System32", "svchost.exe"))
    assert status == "Valid"
    assert scorer.masquerade.is_microsoft_signer(signer)


@pytest.mark.parametrize("record", [
    {},
    {"pid": None, "ppid": None, "name": None, "exe": None, "cmdline": None, "user": None},
    {"pid": "abc", "ppid": "x", "name": "svchost.exe", "vt_malicious": "lots", "memory_anomaly_score": "?"},
    {"pid": 5, "name": 123, "exe": 456, "cmdline": ["not", "a", "string"], "user": 0, "sha256": 7},
])
def test_malformed_records_do_not_crash(isolated_scorer, record):
    """Regression (stress test): a non-numeric PID raised ValueError."""
    out = scorer.score_process(record)
    assert out["threat_level"] in ("SAFE", "SUSPICIOUS", "HIGH")


def test_rule_points_table_drives_scores(isolated_scorer):
    # The documented table and the scorer cannot disagree.
    assert scorer.score_process(make_record(name="scvhost.exe"))["threat_score"] == scorer.RULE_POINTS["process_name_lookalike"]
    assert scorer._classify_score(scorer.LEVEL_THRESHOLDS["HIGH"]) == "HIGH"
    assert scorer._classify_score(scorer.LEVEL_THRESHOLDS["SUSPICIOUS"]) == "SUSPICIOUS"
    assert scorer._classify_score(scorer.LEVEL_THRESHOLDS["SUSPICIOUS"] - 1) == "SAFE"
