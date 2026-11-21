# MemGuard Lite

MemGuard Lite is a **read-only Windows process threat triage tool** built to answer one practical question:

> "Is something suspicious living on my machine, possibly abusing memory/RAM, and how can I investigate it quickly?"

It combines process telemetry, hashing, heuristic scoring, optional memory metadata inspection, optional VirusTotal enrichment, and an interactive GUI so suspicious entries are easier to spot, validate, and export.

## Why I Built This

My main reason for creating this project was to check whether my system might be compromised by malware operating through RAM-related behavior. I wanted a tool that is:

- Read-only and safe to run on my daily machine.
- Fast enough for regular personal health checks.
- Structured enough to produce evidence I can review later.
- Practical for employer conversations about security engineering decisions.

This project is intentionally focused on **triage and visibility**, not automatic remediation.

## What MemGuard Does

- Enumerates running processes with key metadata (`pid`, `exe`, `user`, `cmdline`, `rss_mb`, etc.).
- Computes executable SHA256 hashes when available.
- Scores each process using explicit, explainable heuristics.
- Optionally inspects memory metadata for high-risk processes.
- Optionally enriches selected hashes with VirusTotal reputation counts.
- Provides a desktop GUI for scan control, filtering, sorting, and detailed inspection.
- Exports filtered results to CSV/JSON for documentation and follow-up analysis.
- Validates selected suspicious rows with live checks (running state, file existence, hash consistency, code signature status).

## Safety Model (Important)

MemGuard runs in **read-only forensic mode**.

- It does not kill, suspend, inject, patch, or modify processes.
- It does not dump raw process memory.
- It degrades safely when permissions are limited (`AccessDenied`, vanished process, unsupported memory map calls).

This makes it suitable for routine inspection on a personal workstation without risky system modifications.

## Architecture and Data Flow

Pipeline (CLI and GUI share the same core flow):

1. Collect system/process telemetry.
2. Attach SHA256 hashes to executable paths.
3. Score processes with baseline heuristics.
4. Optionally inspect memory metadata for high-risk candidates.
5. Optionally enrich with VirusTotal data.
6. Re-score using all available evidence.
7. Display and export results.

Core modules:

- `memguard/collector.py`: process and system telemetry collection.
- `memguard/hasher.py`: executable hash attachment and local blocklist load.
- `memguard/scorer.py`: deterministic heuristic scoring engine (`RULE_POINTS` is the single source of rule weights).
- `memguard/cmdline_rules.py`: command-line normalisation and behaviour tags (encoded PowerShell, LOLBin abuse, ransomware precursors...).
- `memguard/masquerade.py`: process-identity checks - expected folders, look-alike names, Microsoft signer, expected parents.
- `memguard/attack_map.py`: MITRE ATT&CK mapping (one technique per command-line behaviour).
- `memguard/about.py`: the built-in guide shown in the GUI About tab, by `--about`, and as the report's rule glossary.
- `memguard/memory_inspector.py`: experimental memory metadata checks.
- `memguard/threat_intel.py`: optional VirusTotal v3 enrichment.
- `memguard/validator.py`: read-only validation checks for a selected process.
- `memguard/gui.py`: detailed desktop GUI experience.
- `memguard/main.py`: CLI/GUI entrypoint and orchestration.

## Scoring Logic (Explainable)

Threat levels:

- `HIGH`: score `>= 40`
- `SUSPICIOUS`: score `>= 15` and `< 40`
- `SAFE`: score `< 15`

Points from every rule that fires are added together, and each rule writes a label into `triggered_rules`, so every score can be explained. The same table is shown in the GUI **About** tab and by `py -3.13 -m memguard --about`; it is generated from `scorer.RULE_POINTS`, so the documentation cannot drift from the code.

| Rule | Points | What it means |
|---|---|---|
| `temp_executable_path` | +30 | Program file is in a Temp folder. |
| `suspicious_commandline (<behaviours>)` | +20 / +40 | The command line asks a Windows tool to do something attackers rely on. See *Command-line behaviours* below. |
| `elevated_user_running_from_user_space` | +15 | Admin/SYSTEM process whose file is under `C:\Users`. |
| `listening_ephemeral_port` | +25 (system +5, localhost -10) | Listening on a port >= 49152. |
| `suspicious_parent_child (parent -> child)` | +35 | Office/browser/script host started a shell (e.g. `winword.exe -> cmd.exe`). |
| `unexpected_parent (parent -> child; expected X)` | +40 | A core Windows process has the wrong parent (e.g. `lsass.exe` not started by `wininit.exe`). |
| `system_binary_wrong_location (name)` | +40 | A protected Windows name (svchost, lsass, csrss, explorer, cmd, powershell...) is running outside its real folder. |
| `process_name_lookalike (name ~ real)` | +30 | Name is one edit or a homoglyph away from a protected name (`svch0st`, `scvhost`, Cyrillic `svсhost`). |
| `microsoft_name_wrong_signer (name signed by X)` | +40 | Protected Windows name with a valid signature from someone other than Microsoft. |
| `duplicate_singleton_process (name xN)` | +30 | A second `lsass.exe` / `services.exe` / `wininit.exe` / `lsaiso.exe`. |
| `unsigned_or_invalid_signature` | +20 | No valid Authenticode signature. |
| `Matched local blocklist` | +70 | SHA256 is in `data/blocklist.txt`. |
| `VirusTotal malicious detections >= 5` | +50 | Five or more engines flag the hash (VT enabled only). |
| `Memory anomaly detected` | +memory score | From optional memory inspection. |
| `unverifiable_data (fields)` | 0 | Fields Windows refused to show; row marked `PARTIAL`. Recorded, never scored. |
| `parent_unverifiable (ppid N reused)` | 0 | The parent PID now belongs to a newer process, so the real parent is unknown. Recorded, never judged. |
| `memguard_self` | 0 | MemGuard's own process is listed but not scored. |

### Process-identity checks (masquerading, ATT&CK T1036.005)

Naming malware after a trusted Windows process is the most common way to hide in a process list. `memguard/masquerade.py` checks identity four independent ways: the **folder** each protected binary must run from (resolved against `%SystemRoot%`, so non-`C:` installs work), **look-alike names** (one edit incl. transposition, digit swaps, Cyrillic/Greek homoglyphs), the **signer** (Organization field must be exactly `Microsoft Corporation`, parsed field-by-field), and the **parent** (SANS "Hunt Evil" parent table, e.g. `svchost.exe` must be started by `services.exe`).

Parent checks are protected against **PID reuse**: if the process now holding the parent PID started *after* the child, it is a stranger that inherited a recycled number, so the relationship is reported as `parent_unverifiable` instead of being judged. Without that guard a child could be blamed on, or cleared by, an unrelated process.

The system-process whitelist (which softens the listening-port score) used to accept any path starting with `c:\windows`, which also matched `C:\Windows2\svchost.exe`. Standard users can create folders in the root of `C:\`, so that was a no-admin bypass. It now requires the exact folder.

### Command-line behaviours

`memguard/cmdline_rules.py` first **normalises** the command line so equivalent spellings collapse to one form (`-e` / `-ec` / `-EncodedCommand` / `/enc`, `pwsh`, `^` carets, PowerShell backticks, quote splitting, `'Down'+'loadString'` concatenation, Unicode dashes), then matches **behaviour**, not tool names. Only the strongest behaviour counts toward the score, so one noisy command line cannot stack itself to HIGH.

| Behaviour | Points | ATT&CK |
|---|---|---|
| `encoded_powershell`, `powershell_download_cradle`, `powershell_base64_decode`, `base64_reference` | +20 | T1059.001, T1105, T1140, T1027 |
| `mshta_execution`, `script_host_execution` | +20 | T1218.005, T1059.005 |
| `certutil_download`, `certutil_decode`, `bitsadmin_transfer` | +20 | T1105, T1140, T1197 |
| `rundll32_abuse` (script/URL/UNC/user-writable DLL/no DLL), `regsvr32_scriptlet` | +20 | T1218.011, T1218.010 |
| `scheduled_task_creation`, `wmic_execution`, `registry_run_key`, `account_creation` | +20 | T1053.005, T1047, T1547.001, T1136.001 |
| `command_obfuscation` (carets/backticks inside words, `%VAR:~x,y%` slicing) | +20 | T1027.010 |
| `lsass_memory_dump`, `inhibit_system_recovery`, `defender_tampering` | **+40** | T1003.001, T1490, T1562.001 |

Deliberate changes from the old substring list: plain `cmd.exe /c` and bare `rundll32` / `regsvr32` no longer score on their own. Node, VS Code and most build tools launch every child as `cmd.exe /d /s /c ...`, and Windows calls `rundll32 shell32.dll,...` constantly, so those patterns produced noise without evidence. Only what the wrapper *runs* is judged now. On the reference host the new rules raised **zero** new false positives across 528 processes, and caught one encoded-PowerShell launch the old `"powershell -enc"` substring missed (`powershell.EXE -EncodedCommand ...`).

### Running with Administrator rights

Elevation grants **read** access to SYSTEM-owned process metadata. MemGuard stays read-only and modifies nothing at any privilege level.

- CLI: `py -3.13 -m memguard --elevate`
- GUI: **Restart as Administrator** button (next to the auto-refresh controls)

Windows cannot elevate a process that is already running, so both paths relaunch MemGuard through the UAC consent prompt and close the original instance. Elevation is never requested automatically, and declining the prompt leaves the current scan running unchanged. Unsaved GUI results are lost on restart, so export first if you need them.

## Memory Inspection (RAM-Oriented Checks)

This is the part most aligned with my original goal (possible malware activity involving RAM behavior).

When enabled, MemGuard inspects up to 10 processes that already look risky (`threat_score >= memory_min_score`, default `30`) and records:

- `vms_mb`
- `num_memory_maps`
- `private_writable_regions`
- `executable_writable_regions`
- `memory_anomaly_score`
- `memory_flag` (`NORMAL` or `ANOMALOUS`)

Memory anomaly scoring:

- `+20` if `executable_writable_regions > 0`
- `+15` if `private_writable_regions > 100`
- `+15` if `vms_mb > 2000` and RSS `< 200 MB`

If anomaly score reaches at least `20`, MemGuard adds rule `Memory anomaly detected` and marks the process as `ANOMALOUS`.

## Validation Feature (New)

In GUI mode, you can now click **Validate Selected** for a suspicious row.

Validation checks are still read-only and include:

- Is PID still running?
- Is parent PID still running?
- Does executable file still exist on disk?
- Is the executable path in temp directories?
- Does current SHA256 match the scan-time SHA256?
- Windows Authenticode signature status and signer subject (best effort).

This helps bridge the gap between static scan output and immediate triage confidence.

## Network Port Monitoring (New)

MemGuard now monitors listening ports and active network connections to identify security risks.

### Port Risk Scoring

Ports are scored based on:

- **Insecure protocols** (+30): FTP (port 21), Telnet (23), unencrypted HTTP (80), IMAP (143), POP3 (110), SMTP (25)
- **Exposed services** (+20): MySQL (3306), PostgreSQL (5432), Redis (6379), MongoDB (27017), Elasticsearch (9200)
- **Common backdoor ports** (+15): 4444, 5555, 6666, 7777, 8888, 9999
- **Listening state** (+5): Port actively listening for incoming connections
- **Ephemeral port** (+5): Port number ≥ 49152 (outside well-known and registered ranges)
- **Localhost only** (-10): Risk reduction when the local address is loopback (127.0.0.0/8, `::1`, or `::ffff:127.0.0.1`)

### Risk Levels

- `HIGH` (score ≥ 35): Insecure protocol or exposed high-risk service
- `MEDIUM` (score ≥ 20): Potentially exposed database or development service
- `LOW` (score ≥ 10): Lower-risk listening port
- `SAFE` (score < 10): Likely safe or standard system port

### GUI PORT VIEWER

Click **Show Ports** in the GUI (after running a scan) to view:

- All listening ports with protocol and state
- Associated process name and PID
- Local and remote addresses
- Risk assessment with triggered rules (color-coded: HIGH = red, MEDIUM = orange, LOW = yellow)
- Summary of high-risk and medium-risk ports
- Localhost-only vs. externally exposed breakdown
- Export port results as CSV, JSON, or Markdown report via buttons in the ports window

This helps you quickly identify:

- Services accidentally exposed to the network
- Unencrypted protocols that should be replaced with TLS alternatives
- Suspicious processes binding to unexpected ports

## Desktop GUI

Launch:

```powershell
py -3.13 -m memguard --gui
```

The window has two tabs:

- **Scanner** - the triage workflow below.
- **About** (or press **F1**) - a built-in guide: what MemGuard is and is not, a 5-step quick start, how a scan works, how to read colours and confidence, every detection rule with its points, ATT&CK technique, why it matters and its common innocent causes, every button, the ports view, administrator mode, exported files, known limits, safety/privacy and a glossary. It has a clickable contents list, **Find in guide**, a live **This session** panel (elevation, VirusTotal key, blocklist size, history file, signature cache) and **Save guide as Markdown**.

GUI capabilities:

- Toggle memory inspection and VirusTotal options.
- Tune thresholds (`memory_min_score`, `vt_min_score`, `vt_max_requests`).
- **Test VT Key** button — one-click connectivity check before running a full scan.
- Search by name, path, user, or PID.
- Filter by threat level (`ALL`, `SAFE`, `SUSPICIOUS`, `HIGH`).
- Sort columns for quick prioritization.
- **Color-coded rows** — HIGH threat = red background, SUSPICIOUS = yellow, new process since last scan = green.
- **Scan delta** — status bar shows `+N new, -N gone` processes compared to the previous scan.
- **Active network connections** displayed in the details panel when a process row is selected.
- **Right-click context menu** on process rows to copy SHA256, command line, or PID to clipboard.
- Inspect detailed record and triggered rules, with a plain-language **Why flagged** line for each rule.
- Validate selected suspicious process.
- Monitor **listening ports and network connections** with security risk scoring (color-coded by risk level).
- Export ports as **CSV, JSON, or Markdown report** from the ports window.
- Save a full AI-friendly Markdown report containing scan metadata, summary findings, and the full JSON dataset.
- Export filtered process subset to timestamped CSV/JSON.

## CLI Usage

Install dependencies:

```powershell
py -3.13 -m pip install -r memguard/requirements.txt
```

Basic scan:

```powershell
py -3.13 -m memguard
```

Enable memory metadata checks:

```powershell
py -3.13 -m memguard --memory --memory-min-score 30
```

Enable VirusTotal:

```powershell
py -3.13 -m memguard --vt
```

Faster VT mode for routine runs:

```powershell
py -3.13 -m memguard --vt --vt-suspicious-only --vt-max-requests 3
```

Print the built-in guide (same content as the GUI About tab) and exit:

```powershell
py -3.13 -m memguard --about
```

## Tests

The `tests/` suite (pytest, ~240 tests) covers every scoring rule, the evasion spellings each command-line behaviour must catch, the everyday commands it must NOT flag (including real Node/VS Code/MCP launch lines), process-identity checks, PID-reuse handling, ATT&CK mapping, exports, `--elevate` stripping, the GUI About tab, and that the guide matches `RULE_POINTS`. A few tests also check the live machine: no running process may trip the look-alike, wrong-folder or wrong-parent rules (false-positive guards).

```powershell
py -3.13 -m pip install pytest
py -3.13 -m pytest
```

### Stress tests (opt-in)

`scripts/stress/` holds two scripts that go beyond the unit tests (see its README for the safety notes):

```powershell
py -3.13 scripts/stress/stress_fuzz.py --skip-live   # seconds; add nothing to skip the live pass
py -3.13 scripts/stress/stress_live.py --run         # benign adversary emulation + load, ~3 min
```

### Stress test results (2026-11-20)

- **Live adversary emulation (benign payloads):** 14 real processes made to look malicious (PING.EXE copied as `svchost.exe` / `lsass.exe` / `scvhost.exe` / Cyrillic `svсhost.exe` / `expl0rer.exe` in AppData, node.exe copied as `dllhost.exe`, a relocated `cmd.exe`, encoded / en-dash / `-ec` PowerShell, inert download cradles, caret and backtick obfuscation) plus 6 benign look-alike controls. Result: **14/14 detected, 0/6 false positives, 0 collateral hits** on the rest of the system, in both the CLI and the GUI.
- **Load and churn:** ~1,175 live processes with ~2,700 processes spawned and exiting *during* the scan: no crash, no traceback, every rule label ASCII-safe on a cp1252 console.
- **Fuzzing:** 5,000 random command lines, 20,000 name/path pairs and malformed records: 0 exceptions.
- **Repeatability:** 3 scoring passes over ~520 live processes gave identical results; memory flat (~1 MB traced); warm re-scan ~5 s vs ~66 s cold (signature cache).

Issues the stress test found and fixed:

1. **Scan-stall (ReDoS-style) attack:** `"tool.*switch"` regexes were quadratic; a crafted 32,767-char command line (`certutil certutil ...`) cost 0.7 s per process. Rewritten as find-head-then-tail: worst case now ~12 ms, identical matches.
2. **CSV formula injection (CWE-1236):** attacker-controlled command lines starting with `=` were exported as live spreadsheet formulas. CSV cells starting with `= + - @` are now prefixed with `'`; JSON is unchanged.
3. **Collateral on the genuine lsass.exe:** a fake `lsass.exe` made the real one score SUSPICIOUS. When exactly one copy is in the genuine folder, only the impostors are flagged now.
4. **Scorer crash on malformed records** (non-numeric PID, non-string fields): hardened.

## VirusTotal Setup

Temporary current-shell key:

```powershell
$env:VT_API_KEY="your_api_key_here"
```

Persist for current Windows user:

```powershell
setx VT_API_KEY "your_api_key_here"
```

Behavior notes:

- Queries VirusTotal v3 by SHA256.
- Default `vt_min_score` is `10` — only processes scoring ≥ 10 are queried (keeps quota usage practical on clean systems).
- Sleeps 15 seconds between requests (public API rate-limit friendly).
- Uses 10-second request timeout.
- Handles `404`, `429`, and network failures without crashing the scan.
- If `VT_API_KEY` is missing, logs a warning and continues.
- Use **Test VT Key** in the GUI to verify connectivity before a full scan.

## Local Blocklist

Path:

- `data/blocklist.txt`

Format:

- One SHA256 hash per line.
- Empty lines ignored.
- Lines starting with `#` treated as comments.

Matching behavior:

- Adds score `+70`.
- Adds triggered rule `Matched local blocklist`.

## Exported Artifacts

- CLI default outputs: `processes.csv`, `processes.json`.
- GUI outputs: user-selected Save-As paths (timestamped filename defaults).

Useful fields for investigations:

- Identity/context: `pid`, `ppid`, `name`, `user`, `exe`, `cmdline`, `start_time`
- Resource profile: `rss_mb`, `cpu_percent`
- Integrity/reputation: `sha256`, `vt_malicious`, `vt_suspicious`, `vt_harmless`
- Memory indicators: `memory_anomaly_score`, `memory_flag`, region counters
- Decision trace: `threat_score`, `threat_level`, `triggered_rules`, `data_confidence`
- CSV exports prefix cells starting with `= + - @` with `'` so attacker-controlled text cannot run as a spreadsheet formula; JSON keeps the raw values.
- The full Markdown report adds a **Rule Glossary** explaining every rule and command-line behaviour that fired, so a reader (or an AI) can interpret it without the source code.

## How To Explain This Project To Employers

Use this short narrative:

1. Problem: I wanted to detect signs of compromise on my own machine, especially suspicious processes that might be abusing memory behavior.
2. Constraint: I needed a safe, read-only approach suitable for regular use.
3. Solution: I built MemGuard Lite, a layered triage pipeline that combines local telemetry, hashing, explainable scoring, optional memory metadata checks, optional threat-intel enrichment, and interactive validation.
4. Engineering quality: I separated concerns by module, preserved graceful error handling, and ensured the output is exportable and auditable.
5. Security mindset: I favored deterministic heuristics plus evidence fields over opaque "black-box" decisions.
6. Outcome: I can quickly prioritize suspicious entries, validate them, and produce reports for follow-up.

Suggested demo flow in interviews:

1. Run GUI scan.
2. Sort by `Threat` descending.
3. Open top suspicious process and explain triggered rules.
4. Click `Validate Selected` and walk through live validation checks.
5. Export JSON and describe how it supports incident notes and repeatability.

## Project Journey (Build Story)

This project evolved in practical stages:

1. Built a CLI-first scanner and exporter for raw process visibility.
2. Added heuristic scoring so output became prioritized, not just descriptive.
3. Added local blocklist matching for deterministic high-confidence alerts.
4. Added optional VirusTotal enrichment to combine local and external evidence.
5. Added experimental memory metadata inspection for RAM-focused anomaly signals.
6. Built a detailed desktop GUI for usability, filtering, and export workflows.
7. Added per-row validation to support deeper analyst triage from the same interface.
8. Added network port monitoring with risk scoring, scan-to-scan delta tracking, live connections in the details panel, right-click copy, and structured port exports.

The design intentionally moved from "data collection" to "decision support" while staying read-only.

## Limitations and Honest Scope

MemGuard is a triage tool, not a full EDR or anti-malware replacement.

- Heuristics can produce false positives and false negatives.
- Memory checks are metadata-based, not raw memory forensics.
- VirusTotal coverage depends on API quota and known hashes.
- Signature status alone is not proof of safety.

Recommended use:

- Use MemGuard to prioritize suspicious processes.
- Validate findings with additional tools (Defender, Sysmon, Autoruns, ProcMon, sandboxing).
- Treat it as one layer in a defense-in-depth workflow.

## Future Enhancements

- Rule tuning profiles (developer workstation vs production workstation).
- Optional YARA-like file checks for selected executables.
- Better incident report templates from exported JSON.
- Persistence sweep (Run keys, scheduled tasks, services, WMI subscriptions) through the existing hash/signature/folder rules.
- Read Sysmon / Security 4688 event logs to cover the gaps between snapshots.
- Native-messaging allowlist keyed on `chrome-extension://<id>/` so browser-extension helpers stop scoring as `chrome.exe -> cmd.exe`.
- Tamper-evident (hash-chained) history log.

## Build Downloadable App (Windows)

This repository includes a build script to generate standalone executables before publishing.

Build steps:

```powershell
.\scripts\build_windows.ps1
```

Output:

- GUI executable: `release/MemGuardLite.exe`
- CLI executable: `release/MemGuardLite-CLI.exe`

Notes:

- The build includes `data/blocklist.txt` inside the executable bundle.
- GUI executable launches directly to desktop mode.
- CLI executable runs the terminal mode.

## Pre-Publish Security Checklist

Before pushing to GitHub, run this checklist:

1. Confirm runtime artifacts are not tracked:
	`processes.csv`, `processes.json`, `memguard/__pycache__/`
2. Confirm local environment files are not tracked:
	`.venv/`, `.env` files
3. Confirm no personal data is staged:
	usernames, local absolute paths, session tokens in command lines
4. Confirm no API keys are hardcoded.
5. Review staged changes with:

```powershell
git status
git diff --staged
```

This project is configured with `.gitignore` rules to prevent common personal/runtime files from being committed.

## License and Ethics

Built for defensive security, transparency, and system self-assessment in read-only mode.
