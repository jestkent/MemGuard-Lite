"""Process-identity checks: location, look-alike names, signer, parent."""

from __future__ import annotations

import os

import psutil
import pytest

from memguard import masquerade
from memguard.system_whitelist import is_system_process


# ── Expected location ────────────────────────────────────────────────────────

@pytest.mark.parametrize("name, path", [
    ("svchost.exe", r"C:\Windows\System32\svchost.exe"),
    ("svchost.exe", r"C:\Windows\SysWOW64\svchost.exe"),
    ("SVCHOST.EXE", r"c:\windows\system32\SVCHOST.exe"),
    ("lsass.exe", r"\\?\C:\Windows\System32\lsass.exe"),
    ("explorer.exe", r"C:\Windows\explorer.exe"),
    ("wmiprvse.exe", r"C:\Windows\System32\wbem\WmiPrvSE.exe"),
    ("powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
    ("MsMpEng.exe", r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26100.4-0\MsMpEng.exe"),
    ("MsMpEng.exe", r"C:\Program Files\Windows Defender\MsMpEng.exe"),
])
def test_genuine_locations_pass(windows_env, name, path):
    assert masquerade.is_in_expected_location(name, path) is True


@pytest.mark.parametrize("name, path", [
    ("svchost.exe", r"C:\Users\bob\AppData\Roaming\svchost.exe"),
    ("svchost.exe", r"C:\Windows\Temp\svchost.exe"),
    ("svchost.exe", r"C:\Windows2\System32\svchost.exe"),         # look-alike root folder
    ("lsass.exe", r"C:\WindowsUpdate\lsass.exe"),
    ("lsass.exe", r"C:\Windows\System32\drivers\lsass.exe"),       # right tree, wrong folder
    ("explorer.exe", r"C:\Windows\System32\explorer.exe"),
    ("cmd.exe", r"C:\Users\Public\cmd.exe"),                       # relocated LOLBin
    ("MsMpEng.exe", r"C:\Users\bob\MsMpEng.exe"),
    ("MsMpEng.exe", r"C:\ProgramData\MicrosoftX\Windows Defender\Platform\1\MsMpEng.exe"),
])
def test_wrong_locations_fail(windows_env, name, path):
    assert masquerade.is_in_expected_location(name, path) is False


def test_not_applicable_returns_none(windows_env):
    assert masquerade.is_in_expected_location("chrome.exe", r"C:\x\chrome.exe") is None
    assert masquerade.is_in_expected_location("svchost.exe", "N/A") is None
    assert masquerade.is_in_expected_location("svchost.exe", "") is None


def test_windows_on_another_drive(monkeypatch):
    monkeypatch.setenv("SystemRoot", r"D:\Windows")
    assert masquerade.is_in_expected_location("lsass.exe", r"D:\Windows\System32\lsass.exe") is True
    assert masquerade.is_in_expected_location("lsass.exe", r"C:\Windows\System32\lsass.exe") is False


def test_whitelist_rejects_lookalike_folder(windows_env):
    # Regression: the old check was path.startswith("c:\\windows").
    assert is_system_process("svchost.exe", r"C:\Windows\System32\svchost.exe") is True
    assert is_system_process("svchost.exe", r"C:\Windows2\svchost.exe") is False
    assert is_system_process("svchost.exe", r"C:\WindowsApps\svchost.exe") is False
    assert is_system_process("chrome.exe", r"C:\Windows\System32\chrome.exe") is False
    assert is_system_process("svchost.exe", None) is False


# ── Look-alike names ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("name, imitates", [
    ("svch0st.exe", "svchost.exe"),          # digit substitution
    ("scvhost.exe", "svchost.exe"),          # transposition
    ("svchosts.exe", "svchost.exe"),         # insertion
    ("svhost.exe", "svchost.exe"),           # deletion
    ("lsasss.exe", "lsass.exe"),
    ("1sass.exe", "lsass.exe"),
    ("sv\u0441host.exe", "svchost.exe"),     # Cyrillic es
    ("expl0rer.exe", "explorer.exe"),
    ("rundl32.exe", "rundll32.exe"),
    ("winlogin.exe", "winlogon.exe"),
])
def test_lookalikes_are_caught(name, imitates):
    assert masquerade.find_lookalike(name) == imitates


@pytest.mark.parametrize("name", [
    "svchost.exe", "lsass.exe", "csrss.exe", "smss.exe", "sihost.exe", "conhost.exe",
    "taskhost.exe", "taskhostex.exe", "taskhostw.exe", "dllhost.exe", "lsaiso.exe",
    "chrome.exe", "msedge.exe", "Code.exe", "python.exe", "node.exe", "pwsh.exe",
    "searchhost.exe", "searchapp.exe", "searchprotocolhost.exe", "searchfilterhost.exe",
    "startmenuexperiencehost.exe", "shellexperiencehost.exe", "textinputhost.exe",
    "securityhealthservice.exe", "securityhealthsystray.exe", "applicationframehost.exe",
    "nissrv.exe", "smartscreen.exe", "systemsettings.exe", "wudfhost.exe", "unsecapp.exe",
    "dashost.exe", "sgrmbroker.exe", "mousocoreworker.exe", "tiworker.exe",
    "trustedinstaller.exe", "usocoreworker.exe", "backgroundtaskhost.exe", "onedrive.exe",
    "steam.exe", "Registry", "System", "Memory Compression", "", "N/A",
])
def test_common_legitimate_names_are_not_lookalikes(name):
    assert masquerade.find_lookalike(name) is None


@pytest.mark.skipif(os.name != "nt", reason="live Windows process list")
def test_no_lookalikes_on_this_host():
    """Every process name running right now must pass (false-positive guard)."""
    flagged = {
        p.info["name"]: masquerade.find_lookalike(p.info["name"])
        for p in psutil.process_iter(["name"])
        if p.info["name"] and masquerade.find_lookalike(p.info["name"])
    }
    assert flagged == {}


@pytest.mark.skipif(os.name != "nt", reason="live Windows process list")
def test_no_wrong_locations_on_this_host():
    """Every protected process running right now must be in its real folder."""
    wrong = []
    for proc in psutil.process_iter(["name", "exe"]):
        if proc.info["exe"] and masquerade.is_in_expected_location(proc.info["name"], proc.info["exe"]) is False:
            wrong.append((proc.info["name"], proc.info["exe"]))
    assert wrong == []


# ── Signer and parents ───────────────────────────────────────────────────────

@pytest.mark.parametrize("subject, expected", [
    ("CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US", True),
    ("CN=Microsoft Windows Publisher, O=Microsoft Corporation, L=Redmond, C=US", True),
    ('CN=Microsoft Windows, O="Microsoft Corporation", C=US', True),
    ("CN=Evil Corp, O=Evil Corp, C=US", False),
    ("CN=Microsoft Windows, O=Not Microsoft Corporation Ltd, C=US", False),
    # The Common Name merely CONTAINS the organisation text - must not pass.
    ('CN="Totally Legit O=Microsoft Corporation", O=Evil Corp, C=US', False),
    ("", False),
])
def test_microsoft_signer(subject, expected):
    assert masquerade.is_microsoft_signer(subject) is expected


def test_parse_subject_respects_quotes():
    assert masquerade.parse_subject('CN=a, O="Contoso, Ltd", C=US') == [
        ("CN", "a"), ("O", '"Contoso, Ltd"'), ("C", "US"),
    ]


@pytest.mark.parametrize("child, parent, wrong", [
    ("lsass.exe", "wininit.exe", False),
    ("lsass.exe", "explorer.exe", True),
    ("svchost.exe", "services.exe", False),
    ("svchost.exe", "cmd.exe", True),
    ("services.exe", "winword.exe", True),
    ("smss.exe", "system", False),
    ("csrss.exe", "smss.exe", False),
    ("csrss.exe", None, False),            # parent gone is normal, never "wrong"
    ("lsass.exe", None, False),            # unknown parent is never judged
    ("chrome.exe", "explorer.exe", False), # no rule for this child
])
def test_unexpected_parent(child, parent, wrong):
    assert (masquerade.unexpected_parent(child, parent) is not None) is wrong


@pytest.mark.skipif(os.name != "nt", reason="live Windows process tree")
def test_live_core_processes_have_expected_parents():
    """No core process on this host may trip the parent rule (false-positive guard)."""
    bad = []
    for proc in psutil.process_iter(["name", "ppid", "create_time"]):
        try:
            parent = psutil.Process(proc.info["ppid"])
            if parent.create_time() > (proc.info["create_time"] or 0):
                continue  # PID reused; the scorer skips these too
            if masquerade.unexpected_parent(proc.info["name"], parent.name().lower()):
                bad.append((proc.info["name"], parent.name()))
        except (psutil.Error, ValueError):
            continue
    assert bad == []
