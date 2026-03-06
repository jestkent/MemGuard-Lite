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
- `memguard/scorer.py`: deterministic heuristic scoring engine.
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

Heuristic rules currently implemented:

- `+30` `temp_executable_path`
	- Executable path includes temp-like locations.
- `+20` `suspicious_commandline`
	- Command line contains patterns like encoded PowerShell/base64 indicators.
- `+15` `elevated_user_running_from_user_space`
	- Elevated context + user-space executable path (risk combination).
- `+25` / adjusted `listening_ephemeral_port`
	- Listening on ephemeral ports; reduced for loopback-only and whitelisted system behavior.
- `+70` `Matched local blocklist`
	- SHA256 appears in `data/blocklist.txt`.
- `+50` `VirusTotal malicious detections >= 5`
	- Applied when VT enrichment reports high malicious consensus.
- `+memory_anomaly_score`
	- Added from memory inspection findings.

Every score includes `triggered_rules` so the reasoning is audit-friendly.

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

## Desktop GUI

Launch:

```powershell
py -3.13 -m memguard --gui
```

GUI capabilities:

- Toggle memory inspection and VirusTotal options.
- Tune thresholds (`memory_min_score`, `vt_min_score`, `vt_max_requests`).
- Search by name, path, user, or PID.
- Filter by threat level (`ALL`, `SAFE`, `SUSPICIOUS`, `HIGH`).
- Sort columns for quick prioritization.
- Inspect detailed record and triggered rules.
- Validate selected suspicious process.
- Export filtered subset to timestamped CSV/JSON.

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
- Sleeps 15 seconds between requests (public API friendly).
- Uses 5-second request timeout.
- Handles `404`, `429`, and network failures without crashing the scan.
- If `VT_API_KEY` is missing, logs a warning and continues.

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
- Decision trace: `threat_score`, `threat_level`, `triggered_rules`

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

- Historical baseline and process drift comparison.
- Rule tuning profiles (developer workstation vs production workstation).
- Optional YARA-like file checks for selected executables.
- Better incident report templates from exported JSON.
- Unit/integration test expansion around scoring and validation logic.

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
