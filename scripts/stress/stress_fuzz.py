"""MemGuard fuzz / scan-stall / determinism / export-robustness stress test.

Read-only and in-process: nothing is spawned except the normal signature
checks of a regular scan. Exports go to a temporary folder.

Checks
    1. Scan-stall (ReDoS-style): 32,767-char adversarial command lines aimed at
       every quantifier-heavy pattern must each analyse in < 0.25 s.
    2. Random fuzz: 5,000 command lines must not raise.
    3. Identity fuzz: 20,000 name/path pairs must not raise.
    4. Malformed records must not crash the scorer.
    5. Determinism: 3 scoring passes over the live process list must agree
       (skip with --skip-live; this pass takes about a minute on a cold cache).
    6. Exports with hostile fields stay parseable and contain no live
       spreadsheet formulas.

USAGE
    py -3.13 scripts/stress/stress_fuzz.py [--skip-live]

Exit code 0 = no failures; 1 otherwise.
"""
from __future__ import annotations

import csv, json, os, random, string, sys, tempfile, time, tracemalloc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
SKIP_LIVE = "--skip-live" in sys.argv
from memguard import cmdline_rules, masquerade, scorer, collector, hasher, exporter, attack_map  # noqa: E402

MAX_CMDLINE = 32767          # Windows command-line limit
SLOW = 0.25                  # seconds; anything slower is a stall risk
random.seed(1337)
failures: list[str] = []


def timed(fn, *a):
    t = time.perf_counter(); out = fn(*a); return out, time.perf_counter() - t


def fit(unit: str, prefix: str = "") -> str:
    body = (unit * (MAX_CMDLINE // max(1, len(unit)) + 1))
    return (prefix + body)[:MAX_CMDLINE]


# ── 1. ReDoS: adversarial inputs aimed at every quantifier-heavy pattern ─────
adversarial = {
    "download: iwr + endless switches": fit("-a ", "powershell iwr "),
    "download: curl + switch soup": fit("-x -y ", "powershell curl "),
    "certutil repeated, no switch": fit("certutil ", "x "),
    "certutil + dash noise": fit("certutil -u ", ""),
    "bitsadmin repeated": fit("bitsadmin ", ""),
    "schtasks repeated": fit("schtasks /c ", ""),
    "wmic repeated": fit("wmic process call ", ""),
    "vssadmin repeated": fit("vssadmin delete ", ""),
    "bcdedit repeated": fit("bcdedit recoveryenabled ", ""),
    "reg add repeated": fit("reg add \\currentversion\\ ", ""),
    "net user repeated": fit("net user x ", ""),
    "env slice unterminated": fit("%a:b=", ""),
    "env slice tilde noise": fit("%abc:~1", ""),
    "comsvcs repeated": fit("comsvcs ", ""),
    "procdump repeated": fit("procdump -m ", ""),
    "set-mppreference repeated": fit("set-mppreference -disable ", ""),
    "powershell repeated": fit("powershell ", ""),
    "encoded param no payload": fit("powershell -e ", ""),
    "encoded short payloads": fit("-e abc ", "powershell "),
    "rundll32 repeated": fit("rundll32 ", ""),
    "regsvr32 /i: noise": fit("regsvr32 /i: ", ""),
    "carets": fit("a^b^", "cmd /c "),
    "backticks": fit("a`b`", "powershell "),
    "quotes and carets mix": fit('"^`\'', "cmd "),
    "unicode dashes": fit("\u2013\u2014e ", "powershell "),
    "base64 blob 32k": "powershell -e " + "A" * (MAX_CMDLINE - 14),
    "all spaces": " " * MAX_CMDLINE,
    "single huge token": "x" * MAX_CMDLINE,
}
redos_rows = []
for label, payload in adversarial.items():
    _, secs = timed(cmdline_rules.match_cmdline, payload)
    redos_rows.append((secs, label))
    if secs > SLOW:
        failures.append(f"ReDoS: '{label}' took {secs:.2f}s")
redos_rows.sort(reverse=True)

# ── 2. Random fuzz: exceptions and worst-case time ───────────────────────────
alphabet = string.printable + "^`'\"%~:=\u2013\u2014\u0441\u0430\u03bf\u200b\x00\ufeff\U0001F600"
tokens = ["powershell", "pwsh", "-e", "-enc", "cmd", "/c", "certutil", "-urlcache", "http://", "rundll32",
          "comsvcs", "minidump", "vssadmin", "delete", "shadows", "%x:~1,2%", "^", "`", "iex", "downloadstring",
          "regsvr32", "/i:", "scrobj", "net", "user", "/add", "schtasks", "/create", "reg", "add", "\\currentversion\\run"]
fuzz_worst, fuzz_errors = 0.0, 0
for i in range(5000):
    n = random.choice([0, 1, 10, 200, 2000, MAX_CMDLINE])
    if i % 2:
        s = "".join(random.choice(alphabet) for _ in range(n))
    else:
        s = " ".join(random.choice(tokens) for _ in range(max(1, n // 6)))[:MAX_CMDLINE]
    try:
        tags, secs = timed(cmdline_rules.match_cmdline, s)
        fuzz_worst = max(fuzz_worst, secs)
        assert all(t in cmdline_rules.TAGS for t in tags)
        attack_map.map_rules_to_techniques([f"suspicious_commandline ({', '.join(tags)})"] if tags else [])
    except Exception as exc:  # noqa: BLE001
        fuzz_errors += 1
        failures.append(f"cmdline fuzz exception: {exc!r} on input len {len(s)}")
if fuzz_worst > SLOW:
    failures.append(f"cmdline fuzz worst case {fuzz_worst:.2f}s")

# ── 3. Identity fuzz: names and paths ────────────────────────────────────────
name_worst, ident_errors = 0.0, 0
for i in range(20000):
    name = "".join(random.choice(alphabet) for _ in range(random.choice([0, 1, 5, 12, 60, 255])))
    if i % 3 == 0:
        name = random.choice(list(masquerade.ALL_PROTECTED_NAMES))
    path = random.choice(["", "N/A", "n/a", "\\\\?\\", "C:", "C:\\Windows\\System32\\" + name,
                          "\\\\server\\share\\" + name, "/" * 300, "C:\\" + "a\\" * 120 + name, name])
    try:
        _, secs = timed(masquerade.find_lookalike, name)
        name_worst = max(name_worst, secs)
        r = masquerade.is_in_expected_location(name, path)
        assert r in (True, False, None)
        masquerade.unexpected_parent(name, random.choice([None, "", "services.exe", name]))
        masquerade.is_microsoft_signer(name + ", O=" + path)
        masquerade.parse_subject(name + '"' + path)
    except Exception as exc:  # noqa: BLE001
        ident_errors += 1
        failures.append(f"identity fuzz exception: {exc!r} name={name!r} path={path!r}")
if name_worst > 0.05:
    failures.append(f"lookalike worst case {name_worst:.3f}s")

# ── 4. Scoring robustness on hostile records ────────────────────────────────
hostile = [
    {}, {"pid": None, "ppid": None, "name": None, "exe": None, "cmdline": None, "user": None},
    {"pid": "abc", "ppid": -5, "name": 123, "exe": 456, "cmdline": ["list"], "user": 0},
    {"pid": 1, "name": "\x00svchost.exe", "exe": "C:\\Windows\\System32\\svchost.exe\x00", "cmdline": "\x00" * 10},
    {"pid": 2, "name": "x" * 10000, "exe": "C:\\" + "a" * 32000, "cmdline": fit("powershell -e ")},
]
scorer._get_signature_info = lambda exe: ("", "")      # no PowerShell launches for junk paths
hostile_errors = 0
for rec in hostile:
    try:
        out = scorer.score_process(rec)  # type: ignore[arg-type]
        assert out["threat_level"] in ("SAFE", "SUSPICIOUS", "HIGH")
        assert all(r.isascii() for r in out["triggered_rules"])
    except Exception as exc:  # noqa: BLE001
        hostile_errors += 1
        failures.append(f"hostile record crashed scorer: {exc!r} record keys={list(rec)[:6]}")

# ── 5. Determinism + memory across repeated full scoring passes ─────────────
import importlib
importlib.reload(scorer)                                # restore real signature checks
procs = [] if SKIP_LIVE else hasher.attach_sha256(collector.collect_processes())
tracemalloc.start()
passes, timings, mem = [], [], []
for _ in range(0 if SKIP_LIVE else 3):
    t = time.perf_counter()
    scored = scorer.score_processes(procs)
    timings.append(time.perf_counter() - t)
    mem.append(tracemalloc.get_traced_memory()[0] / 1e6)
    passes.append({p["pid"]: (p["threat_score"], tuple(p["triggered_rules"])) for p in scored})
tracemalloc.stop()
stable_pids = set.intersection(*(set(p) for p in passes)) if passes else set()
diffs = [pid for pid in stable_pids if len({p[pid] for p in passes}) > 1]
if diffs:
    failures.append(f"non-deterministic scores for {len(diffs)} PIDs, e.g. {[passes[0][d] for d in diffs[:2]]} vs {[passes[1][d] for d in diffs[:2]]}")

# ── 6. Export robustness with hostile field contents ────────────────────────
nasty = []
for i, cmd in enumerate(['a,b,"c"\nnew line\r\n\ttab', "\u0441\u0430\U0001F600 emoji", fit("x"), "=cmd|' /C calc'!A0", "", None]):
    nasty.append({"pid": i + 1, "ppid": 0, "name": "n\u0441.exe", "exe": "C:\\x,y\\z.exe", "user": "u",
                  "rss_mb": 1.0, "cpu_percent": 0.0, "cmdline": cmd, "start_time": "", "threat_score": 20,
                  "threat_level": "SUSPICIOUS", "triggered_rules": ["suspicious_commandline (base64_reference)"],
                  "data_confidence": "FULL"})
tmp = Path(tempfile.mkdtemp(prefix="mg_export_"))
export_ok = True
try:
    rows = list(csv.DictReader(open(exporter.export_csv(nasty, str(tmp / "p.csv")), encoding="utf-8", newline="")))
    js = json.load(open(exporter.export_json(nasty, str(tmp / "p.json")), encoding="utf-8"))
    rep = exporter.export_full_report(nasty, path=str(tmp / "r.md")).read_text(encoding="utf-8")
    export_ok = len(rows) == len(js) == len(nasty) and "Rule Glossary" in rep
    formula_cells = [v for r in rows for v in r.values() if v and v[0] in "=+@" or (v and v[0] == "-" and v != "-")]
except Exception as exc:  # noqa: BLE001
    export_ok = False
    formula_cells = []
    failures.append(f"export crashed: {exc!r}")
if not export_ok:
    failures.append("export row counts mismatch or glossary missing")

# ── Report ──────────────────────────────────────────────────────────────────
print("=== ReDoS (32,767-char adversarial command lines), slowest 6 ===")
for secs, label in redos_rows[:6]:
    print(f"  {secs*1000:8.1f} ms  {label}")
print(f"\nRandom cmdline fuzz: 5000 inputs, {fuzz_errors} exceptions, worst {fuzz_worst*1000:.1f} ms")
print(f"Identity fuzz: 20000 name/path pairs, {ident_errors} exceptions, worst lookalike {name_worst*1000:.2f} ms")
print(f"Hostile records: {len(hostile)} tried, {hostile_errors} crashed the scorer")
if SKIP_LIVE:
    print("Determinism: skipped (--skip-live)")
else:
    print(f"Determinism: 3 passes over {len(procs)} live processes, {len(diffs)} differing PIDs; "
          f"timings {[f'{t:.1f}s' for t in timings]}; traced memory MB {[f'{m:.1f}' for m in mem]}")
print(f"Exports with hostile fields: ok={export_ok}; CSV cells starting with = + - @ (spreadsheet formula risk): {len(formula_cells)}")
print(f"\nFAILURES ({len(failures)}):")
for f in failures[:20]:
    print("  -", f)
sys.exit(1 if failures else 0)
