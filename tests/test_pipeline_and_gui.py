"""Pipeline pieces (history, elevation, exports, ports) and the GUI About tab."""

from __future__ import annotations

import csv
import json
import sys

import pytest

from memguard import elevation, exporter, history_log, port_inspector
from memguard import main as mg_main
from tests.conftest import make_record


# ── Ports ────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("address, expected", [
    ("127.0.0.1", True), ("127.5.5.5", True), ("::1", True), ("::ffff:127.0.0.1", True),
    ("[::1]", True), ("0.0.0.0", False), ("192.168.1.5", False), ("", False), ("garbage", False),
])
def test_is_loopback_address(address, expected):
    assert port_inspector.is_loopback_address(address) is expected


# ── History: persistence counts scans, not rows ──────────────────────────────

def test_persistence_counts_distinct_scans(tmp_path):
    hist = tmp_path / "h.jsonl"
    flagged = [dict(make_record(exe=r"C:\a\app.exe", sha256="cd" * 32),
                    threat_level="SUSPICIOUS", threat_score=20, triggered_rules=["x"]) for _ in range(5)]
    history_log.append_scan_findings(flagged, path=hist, scan_timestamp="2026-01-01 00:00:01")
    assert history_log.find_persistent_threats(path=hist) == []
    history_log.append_scan_findings(flagged, path=hist, scan_timestamp="2026-01-01 00:00:02")
    history_log.append_scan_findings(flagged, path=hist, scan_timestamp="2026-01-01 00:00:03")
    assert len(history_log.find_persistent_threats(path=hist)) == 1
    assert history_log.append_scan_findings([dict(make_record(), threat_level="SAFE")], path=hist) == 0


# ── Elevation: --elevate is stripped before relaunch (no UAC prompt) ─────────

def test_cli_elevate_flag_is_stripped(monkeypatch):
    captured = {}

    def fake_relaunch(argv):
        captured["cmd"] = elevation.build_relaunch_command(argv)
        return True, "fake"

    monkeypatch.setattr(mg_main, "relaunch_as_admin", fake_relaunch)
    monkeypatch.setattr(sys, "argv", [r"C:\x\memguard\__main__.py", "--elevate", "--memory"])
    mg_main.main(["--elevate", "--memory"])
    args = captured["cmd"][1]
    assert args.startswith("-m memguard") and "--elevate" not in args and "--memory" in args


def test_about_flag_prints_guide_and_exits(capsys):
    mg_main.main(["--about"])
    out = capsys.readouterr().out
    assert "What MemGuard Lite is" in out and "Known limits" in out


# ── Exports ──────────────────────────────────────────────────────────────────

def _scored_records():
    return [dict(make_record(pid=i, cmdline="vssadmin delete shadows" if i == 1 else ""),
                 threat_score=40 if i == 1 else 0, threat_level="HIGH" if i == 1 else "SAFE",
                 triggered_rules=["suspicious_commandline (inhibit_system_recovery)"] if i == 1 else [],
                 data_confidence="FULL") for i in range(1, 6)]


def test_process_exports_parse(tmp_path):
    procs = _scored_records()
    rows = list(csv.DictReader(open(exporter.export_csv(procs, str(tmp_path / "p.csv")), encoding="utf-8")))
    assert len(rows) == 5 and "data_confidence" in rows[0]
    assert len(json.load(open(exporter.export_json(procs, str(tmp_path / "p.json")), encoding="utf-8"))) == 5


def test_csv_export_defuses_spreadsheet_formulas(tmp_path):
    """Regression (stress test): attacker-controlled command lines starting with
    '=' were written to CSV as live formulas (CWE-1236)."""
    procs = _scored_records()
    procs[0]["cmdline"] = "=cmd|' /C calc'!A0"
    procs[1]["name"] = "@SUM(1+1)"
    procs[2]["cmdline"] = "-2+3"
    rows = list(csv.DictReader(open(exporter.export_csv(procs, str(tmp_path / "p.csv")), encoding="utf-8")))
    assert rows[0]["cmdline"] == "'=cmd|' /C calc'!A0"
    assert rows[1]["name"] == "'@SUM(1+1)"
    assert rows[2]["cmdline"] == "'-2+3"
    assert not any(v[:1] in "=+@" for row in rows for v in row.values() if v)
    # JSON keeps the raw evidence untouched.
    data = json.load(open(exporter.export_json(procs, str(tmp_path / "p.json")), encoding="utf-8"))
    assert data[0]["cmdline"] == "=cmd|' /C calc'!A0"


def test_full_report_has_glossary_and_specific_technique(tmp_path):
    text = exporter.export_full_report(_scored_records(), path=str(tmp_path / "r.md")).read_text(encoding="utf-8")
    assert "## Rule Glossary" in text
    assert "inhibit_system_recovery" in text
    assert "T1490" in text


def test_ports_exports_parse(tmp_path):
    ports = port_inspector.collect_listening_ports()
    exporter.export_ports_csv(ports, str(tmp_path / "pt.csv"))
    exporter.export_ports_json(ports, str(tmp_path / "pt.json"))
    assert len(json.load(open(tmp_path / "pt.json", encoding="utf-8"))) == len(ports)
    assert exporter.export_ports_report(ports, path=str(tmp_path / "pt.md")).stat().st_size > 0


# ── GUI About tab ────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def gui():
    # One window for all GUI tests: repeatedly creating and destroying Tk
    # roots in one process intermittently fails on Windows with
    # 'invalid command name "tcl_findLibrary"'.
    tk = pytest.importorskip("tkinter")
    from memguard.gui import MemGuardGUI
    try:
        app = MemGuardGUI()
    except tk.TclError as exc:  # no display available
        pytest.skip(f"no display: {exc}")
    app.withdraw()
    yield app
    app.destroy()


def test_gui_has_scanner_and_about_tabs(gui):
    tabs = [gui.notebook.tab(t, "text").strip() for t in gui.notebook.tabs()]
    assert tabs == ["Scanner", "About"]


def test_about_contents_match_sections(gui):
    from memguard.about import build_sections
    assert list(gui.about_nav.get_children()) == [s.id for s in build_sections()]
    document = gui.about_text.get("1.0", "end")
    assert "Detection rules" in document and "system_binary_wrong_location" in document


def test_about_navigation_and_search(gui):
    gui.about_nav.selection_set("limits")
    gui.update()
    gui._on_about_nav(None)
    gui.about_search_var.set("svchost")
    gui._about_find()
    assert gui.about_text.tag_ranges("search_hit")
    assert "match" in gui.about_search_status.get()


def test_details_panel_explains_rules(gui):
    record = dict(make_record(name="scvhost.exe"), threat_score=30, threat_level="SUSPICIOUS",
                  triggered_rules=["process_name_lookalike (scvhost.exe ~ svchost.exe)"])
    details = gui._build_process_details(record)
    assert "Why flagged" in details and "keystroke" in details
