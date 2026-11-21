"""MemGuard live stress test: benign adversary emulation + load/churn + real CLI scan.

WHAT IT DOES
    Starts real processes that merely LOOK malicious - harmless programs
    (PING.EXE, node.exe, PowerShell `Start-Sleep`) that are renamed, relocated,
    encoded or obfuscated - plus benign look-alike "controls". It then runs the
    real MemGuard CLI and checks, by PID, that every emulation was detected and
    no control was flagged, while ~300 filler processes and continuous
    spawn/exit churn load the machine.

SAFETY
    * Nothing destructive is executed. Download cradles are inert
      (`if ($false) { ... }`); credential dumping, backup deletion and Defender
      tampering are covered by text-only unit tests, never executed here.
    * Copies are written only to %LOCALAPPDATA%\\MemGuardStress and deleted
      afterwards. Every spawned process is this script's own child and is
      terminated at the end, even on failure or Ctrl+C.
    * The CLI runs in a temporary folder, so processes.json and the history
      log never touch the repository or your real scan history.
    * Microsoft Defender may notice renamed system binaries (e.g. a ping.exe
      named lsass.exe in AppData). That is expected and harmless.

USAGE (Windows only)
    py -3.13 scripts/stress/stress_live.py --run

Exit code 0 = every emulation detected and no false positive; 1 otherwise.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import psutil

REPO = Path(__file__).resolve().parents[2]
EMU_DIR = Path(os.environ.get("LOCALAPPDATA", tempfile.gettempdir())) / "MemGuardStress"  # user space, NOT Temp
SYS32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
NO_WINDOW = 0x08000000
LIFETIME = "900"
NEW_RULES = ("system_binary_wrong_location", "process_name_lookalike", "microsoft_name_wrong_signer",
             "unexpected_parent", "duplicate_singleton_process", "suspicious_commandline")
LEVEL_RANK = {"SAFE": 0, "SUSPICIOUS": 1, "HIGH": 2}

spawned: list[subprocess.Popen] = []


def b64ps(script: str) -> str:
    return base64.b64encode(script.encode("utf-16le")).decode()


def spawn(args) -> subprocess.Popen:
    proc = subprocess.Popen(args, creationflags=NO_WINDOW, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    spawned.append(proc)
    return proc


def copy_as(src: Path, name: str) -> Path:
    dst = EMU_DIR / name
    shutil.copy2(src, dst)
    return dst


def find_non_microsoft_signed_binary() -> Path | None:
    """A standalone binary validly signed by someone other than Microsoft."""
    for candidate in (shutil.which("node.exe"), r"C:\Program Files\nodejs\node.exe"):
        if candidate and Path(candidate).exists():
            return Path(candidate)
    return None


def build_cases() -> tuple[list[dict], list[dict]]:
    """Return (emulations, controls). Each emulation lists rules that MUST fire."""
    ping = SYS32 / "PING.EXE"
    sleep_ps = b64ps(f"Start-Sleep -Seconds {LIFETIME}")
    pinger = ["-n", LIFETIME, "127.0.0.1"]

    emulations = [
        ("fake_svchost_in_appdata", [str(copy_as(ping, "svchost.exe")), *pinger],
         ["system_binary_wrong_location", "unexpected_parent"], "HIGH"),
        ("lookalike_scvhost", [str(copy_as(ping, "scvhost.exe")), *pinger], ["process_name_lookalike"], "SUSPICIOUS"),
        ("homoglyph_cyrillic_svchost", [str(copy_as(ping, "sv\u0441host.exe")), *pinger],
         ["process_name_lookalike"], "SUSPICIOUS"),
        ("digit_swap_expl0rer", [str(copy_as(ping, "expl0rer.exe")), *pinger], ["process_name_lookalike"], "SUSPICIOUS"),
        ("fake_lsass_duplicate", [str(copy_as(ping, "lsass.exe")), *pinger],
         ["system_binary_wrong_location", "unexpected_parent", "duplicate_singleton_process"], "HIGH"),
        ("relocated_cmd", [str(copy_as(SYS32 / "cmd.exe", "cmd.exe")), "/c", "ping", *pinger],
         ["system_binary_wrong_location"], "HIGH"),
        ("encoded_powershell_full", ["powershell", "-NoProfile", "-EncodedCommand", sleep_ps],
         ["suspicious_commandline (encoded_powershell"], "SUSPICIOUS"),
        ("encoded_powershell_ec_alias", ["powershell", "-nop", "-ec", sleep_ps],
         ["suspicious_commandline (encoded_powershell"], "SUSPICIOUS"),
        ("encoded_powershell_en_dash", ["powershell", "-nop", "\u2013EncodedCommand", sleep_ps],
         ["suspicious_commandline (encoded_powershell"], "SUSPICIOUS"),
        ("inert_download_cradle", ["powershell", "-NoProfile", "-Command",
                                   "if ($false) { IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1:9/x') }; "
                                   f"Start-Sleep {LIFETIME}"],
         ["suspicious_commandline (powershell_download_cradle"], "SUSPICIOUS"),
        ("inert_concat_cradle", ["powershell", "-NoProfile", "-Command",
                                 "if ($false) { IEX (New-Object Net.WebClient).('Down'+'loadString')('http://127.0.0.1:9/x') }; "
                                 f"Start-Sleep {LIFETIME}"],
         ["suspicious_commandline (powershell_download_cradle"], "SUSPICIOUS"),
        ("backtick_obfuscation", ["powershell", "-NoProfile", "-Command", f"s`l`e`e`p {LIFETIME}"],
         ["suspicious_commandline (command_obfuscation"], "SUSPICIOUS"),
        ("caret_obfuscation", ["cmd.exe", "/c", "p^i^n^g", *pinger],
         ["suspicious_commandline (command_obfuscation"], "SUSPICIOUS"),
    ]
    signed = find_non_microsoft_signed_binary()
    if signed:
        emulations.append(("third_party_signed_as_dllhost",
                           [str(copy_as(signed, "dllhost.exe")), "-e", f"setTimeout(() => {{}}, {LIFETIME}000)"],
                           ["microsoft_name_wrong_signer", "system_binary_wrong_location"], "HIGH"))
    else:
        print("note: node.exe not found - skipping the wrong-signer emulation")

    controls = [
        ("plain_cmd_c", ["cmd.exe", "/c", "ping", *pinger]),
        ("node_style_caret_escaping", ["cmd.exe", "/d", "/s", "/c", f"ping ^-n^ {LIFETIME} ^127.0.0.1^"]),
        ("powershell_bypass_policy", ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
                                      f"Start-Sleep {LIFETIME}"]),
        ("powershell_escape_sequences", ["powershell", "-NoProfile", "-Command", f"$x = \"a`nb`tc\"; Start-Sleep {LIFETIME}"]),
        ("renamed_tool_unrelated_name", [str(copy_as(ping, "mytool.exe")), *pinger]),
        ("genuine_ping_system32", [str(ping), *pinger]),
    ]

    emu_out = []
    for eid, argv, expect, level in emulations:
        emu_out.append({"id": eid, "pid": spawn(argv).pid, "expect": expect, "level": level})
    ctl_out = [{"id": cid, "pid": spawn(argv).pid} for cid, argv in controls]
    return emu_out, ctl_out


def load_and_churn(stop: threading.Event, stats: dict) -> None:
    """300 short-lived fillers (many exit mid-scan) + continuous spawn/exit churn."""
    for _ in range(300):
        spawn([str(SYS32 / "PING.EXE"), "-n", str(random.randint(5, 60)), "127.0.0.1"])
    while not stop.is_set():
        spawn(["cmd.exe", "/c", "exit"])
        stats["churn"] = stats.get("churn", 0) + 1
        time.sleep(0.05)


def cleanup() -> None:
    for proc in spawned:
        try:
            parent = psutil.Process(proc.pid)
            for child in parent.children(recursive=True):
                child.kill()
            parent.kill()
        except psutil.Error:
            pass
    time.sleep(1.5)
    shutil.rmtree(EMU_DIR, ignore_errors=True)


def run() -> int:
    if EMU_DIR.exists():
        shutil.rmtree(EMU_DIR, ignore_errors=True)
    EMU_DIR.mkdir(parents=True)
    run_dir = Path(tempfile.mkdtemp(prefix="memguard_stress_"))

    emulations, controls = build_cases()
    time.sleep(4)  # let interpreters / launchers start
    alive = {c["id"]: psutil.pid_exists(c["pid"]) for c in emulations + controls}

    stop, stats = threading.Event(), {}
    threading.Thread(target=load_and_churn, args=(stop, stats), daemon=True).start()
    time.sleep(3)
    peak = len(psutil.pids())

    env = dict(os.environ, PYTHONIOENCODING="cp1252", PYTHONPATH=str(REPO), COLUMNS="200")
    started = time.time()
    cli = subprocess.run([sys.executable, "-m", "memguard"], cwd=run_dir, env=env,
                         capture_output=True, text=True, encoding="cp1252", errors="replace")
    scan_secs = time.time() - started
    stop.set()

    data = json.loads((run_dir / "processes.json").read_text(encoding="utf-8"))
    by_pid = {p["pid"]: p for p in data}

    detected = missed = false_pos = 0
    print("=== Emulated threats ===")
    for emu in emulations:
        rec = by_pid.get(emu["pid"])
        if not rec:
            reason = "process exited before the scan (harness issue, not a detection miss)" if not alive[emu["id"]] \
                else "not in export"
            print(f"  [MISSING ] {emu['id']}: {reason}")
            missed += 1
            continue
        rules = rec["triggered_rules"]
        lacking = [x for x in emu["expect"] if not any(r.startswith(x) for r in rules)]
        ok = not lacking and LEVEL_RANK[rec["threat_level"]] >= LEVEL_RANK[emu["level"]]
        detected += ok
        missed += not ok
        print(f"  [{'DETECTED' if ok else 'MISSED  '}] {emu['id']:<32} {rec['threat_level']:<10} "
              f"score={rec['threat_score']:<4}{'' if ok else ' lacking=' + str(lacking)}")

    print("=== Benign controls ===")
    for ctl in controls:
        rec = by_pid.get(ctl["pid"])
        if not rec:
            print(f"  [MISSING ] {ctl['id']}")
            continue
        hits = [r for r in rec["triggered_rules"] if r.startswith(NEW_RULES)]
        false_pos += bool(hits)
        print(f"  [{'FALSE POS' if hits else 'CLEAN    '}] {ctl['id']:<32} {rec['threat_level']:<10} {hits or ''}")

    harness_pids = {e["pid"] for e in emulations} | {c["pid"] for c in controls}
    collateral = [(p["name"], p["pid"]) for p in data if p["pid"] not in harness_pids
                  and any(r.startswith(NEW_RULES[:5]) for r in p["triggered_rules"])]
    ascii_ok = all(r.isascii() for p in data for r in p["triggered_rules"])
    crashed = cli.returncode != 0 or "Traceback" in (cli.stdout + cli.stderr)

    print(f"\nDetected {detected}/{len(emulations)} | false positives {false_pos}/{len(controls)} | "
          f"collateral {collateral or 0}")
    print(f"CLI exit={cli.returncode} scan={scan_secs:.0f}s exported={len(data)} peak_processes={peak} "
          f"churn_spawns={stats.get('churn', 0)} ascii_labels={ascii_ok}")
    shutil.rmtree(run_dir, ignore_errors=True)
    return 0 if (missed == 0 and false_pos == 0 and not collateral and ascii_ok and not crashed) else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run", action="store_true", help="actually start the emulation (required)")
    args = parser.parse_args()
    if os.name != "nt":
        print("Windows only.")
        return 2
    if not args.run:
        parser.print_help()
        print("\nNothing was started. Re-run with --run after reading SAFETY above.")
        return 2
    try:
        return run()
    finally:
        cleanup()
        leftover = [p.pid for p in spawned if psutil.pid_exists(p.pid)]
        print(f"Cleanup: {len(spawned)} spawned, {len(leftover)} still alive, "
              f"emulation folder exists={EMU_DIR.exists()}")


if __name__ == "__main__":
    sys.exit(main())
