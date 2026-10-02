# CLAUDE.MD

This file gives Claude Code project context and strict guardrails before making changes.

## Project Identity

MemGuard Lite is a read-only Windows process and network triage tool.

Primary purpose:

- Identify suspicious process behavior quickly.
- Inspect memory-related anomalies in a safe way.
- Enrich findings with optional VirusTotal checks.
- Monitor listening ports and active sessions for insecure exposure.

Non-goal:

- No remediation actions (no kill, inject, suspend, patch, memory dump).

## Non-Negotiable Safety Rules

When editing this project, Claude must:

- Preserve read-only forensic behavior.
- Never add code that modifies processes, services, registry, or firewall state.
- Never add exploit, offensive, persistence, or evasion logic.
- Keep graceful handling for AccessDenied, missing processes, and partial data.
- Avoid collecting or persisting unnecessary personal/system-sensitive data.
- Avoid committing runtime scan artifacts.

## Architecture Map

Main flow (CLI and GUI):

1. Collect system/process telemetry.
2. Attach SHA256 hashes to process executables.
3. Score process risk with deterministic heuristics.
4. Optional memory metadata inspection.
5. Optional VirusTotal enrichment.
6. Re-score using all evidence.
7. Display + export + validation.

Core modules:

- memguard/main.py: app entrypoint and orchestration.
- memguard/collector.py: process and system telemetry collection, plus collection-integrity tracking (is_elevated(), _probe_denied_fields()).
- memguard/hasher.py: SHA256 attachment and blocklist loading.
- memguard/scorer.py: explainable scoring engine.
- memguard/memory_inspector.py: memory metadata checks.
- memguard/threat_intel.py: VirusTotal v3 enrichment + test_vt_connection().
- memguard/validator.py: read-only validation of selected process rows.
- memguard/port_inspector.py: listening ports/session inspection and risk scoring.
- memguard/exporter.py: CSV/JSON/full markdown report export (processes and ports).
- memguard/gui.py: Tkinter desktop workflow.
- memguard/ui.py: rich terminal UI rendering.
- memguard/attack_map.py: MITRE ATT&CK technique mapping for triggered_rules (display/export only).
- memguard/history_log.py: append-only JSONL of HIGH/SUSPICIOUS findings + persistent threat lookup.
- memguard/elevation.py: opt-in UAC relaunch (build_relaunch_command(), relaunch_as_admin()). Read-access only; never automatic.

## Current Feature Set

- Process telemetry with PID, user, cmdline, RSS/CPU.
- Deterministic threat scoring with triggered_rules evidence:
  - temp_executable_path (+30)
  - suspicious_commandline (+20): powershell -enc, base64, cmd.exe /c, mshta, wscript, cscript, certutil -decode/urlcache, bitsadmin /transfer, rundll32, regsvr32
  - elevated_user_running_from_user_space (+15)
  - listening_ephemeral_port (+25, system-adjusted to +5, loopback reduces by -10)
  - suspicious_parent_child (+35): e.g. winword.exe -> cmd.exe, explorer.exe -> mshta.exe (rule label uses an ASCII arrow; triggered_rules must stay ASCII-safe so cp1252 consoles cannot abort a scan before export)
  - unsigned_or_invalid_signature (+20): passive Authenticode check on every scan. Each check spawns PowerShell (~0.3s), so results are cached per binary keyed by (path, mtime, size) — a typical host runs 414 checks over only 145 unique executables, and the pipeline scores twice. Do not remove the cache without re-measuring scan time.
  - memguard_self (0 points): MemGuard's own PID is excluded from scoring entirely. Relaunched as Administrator its interpreter still sits in user space (.../AppData/.../python.exe), so elevated_user_running_from_user_space fired on itself on EVERY elevated scan and was written to the append-only history, where three elevated scans would have made MemGuard its own "persistent threat". The row stays visible in the table, labelled, so the exclusion is auditable rather than hidden. Verified: the rule still fires normally for other elevated user-space processes.
  - blocklist match (+70)
  - VirusTotal malicious >= 5 (+50)
- Collection integrity model (data_confidence):
  - psutil.process_iter() substitutes None for an AccessDenied attribute, making a denied field indistinguishable from an empty one. collector._probe_denied_fields() re-reads the missing fields to tell them apart and records access_denied_fields.
  - Every record carries data_confidence = FULL or PARTIAL.
  - unverifiable_data (cmdline, user, ...) is appended to triggered_rules and carries 0 points ON PURPOSE. Missing evidence is not evidence of guilt, so it must not add score; but leaving it silent let an unassessed process render identically to a verified-clean one. Record it, never score it.
  - Surfaced in: CLI "Collection Coverage" panel (ui.show_collection_coverage), GUI "Confidence" column, grey PARTIAL row tag, "Unverified" summary counter, and the post-scan status line. Exported as the data_confidence column.
  - Row tag priority is HIGH > SUSPICIOUS > NEW > PARTIAL, so a real finding is never masked by a confidence tag.
- Opt-in Administrator relaunch (--elevate on the CLI, "Restart as Administrator" button in the GUI):
  - Windows cannot raise the privilege of a running process, so elevation means relaunching via ShellExecuteW "runas" and letting the original instance exit.
  - NEVER automatic. CLI requires the flag; GUI requires a confirmation dialog that states what is gained, that read-only is unchanged, and that unsaved results are lost.
  - build_relaunch_command() is factored out so the reconstructed command can be tested without raising a UAC prompt. It handles three launch shapes: PyInstaller frozen, `py -m memguard` (argv[0] is __main__.py, which cannot be re-run as a plain script because relative imports need package context), and a plain script such as launch_gui.py.
  - Loop prevention is belt-and-braces: --elevate is stripped from the forwarded command AND relaunch_as_admin() refuses when already elevated.
  - A declined UAC prompt (ShellExecute code 5) returns (False, reason); the caller MUST keep running unchanged rather than exiting.
  - Elevation grants additional READ access only. It does not relax the read-only model, and no privileged write path may ever be added behind it.
- Elevation awareness: without an elevated token Windows denies cmdline/user on SYSTEM-owned processes. On a typical host that is ~36% of all processes, ~85 of them svchost.exe. Those processes CANNOT trigger suspicious_commandline. Verified: WMI Win32_Process is not a workaround (it returns CommandLine = null for the same processes), so elevation is the only fix.
- Optional memory anomaly scoring.
- Optional VirusTotal reputation enrichment (default min_threat_score=10, timeout=10s).
- Test VT Key button — one-click API connectivity check before scanning.
- GUI triage workflow with filtering/sorting/details.
- Color-coded process rows: HIGH=red, SUSPICIOUS=yellow, new-since-last-scan=green.
- Scan delta: status bar shows +N new / -N gone processes between consecutive scans.
- Active network connections shown in the details panel for the selected process.
- Right-click context menu on process rows: Copy SHA256, Copy Command Line, Copy PID.
- Validate Selected for live process/file/hash/signature checks.
- Show Ports viewer with risk scores for insecure/exposed services (color-coded rows).
- Port scoring: ephemeral range (>=49152, +5) and localhost reduction (-10) both correctly applied. Loopback detection is IPv6-aware (127.0.0.0/8, ::1, ::ffff:127.0.0.1) via port_inspector.is_loopback_address(), shared with scorer.py and the GUI.
- MITRE ATT&CK technique mapping: triggered_rules → ATT&CK IDs at display + full report time (T1036, T1059, T1078, T1571, T1553.002, T1027, T1055).
- Persistent scan history: HIGH/SUSPICIOUS findings appended to memguard_history.jsonl on each scan; "Show Persistent Threats" button surfaces processes flagged in 3+ separate scans (counted by distinct scan timestamp, not log rows, so multi-instance apps cannot self-report as persistent).
- GUI auto-refresh: optional checkbox + interval (sec, min 10) re-runs scan on a timer. The signature cache persists for the GUI session, so repeat scans skip the slow step.
- score_processes() accepts an optional progress_cb(done, total); the GUI drives its progress bar from it (30->76%) because signature verification, not hashing, is the long step.
- Exports:
  - processes.csv
  - processes.json
  - memguard full markdown report for AI analysis
  - ports CSV (export_ports_csv)
  - ports JSON (export_ports_json)
  - ports markdown report (export_ports_report)

## Known Detection Limits

State these honestly in any user-facing summary. Do not describe MemGuard as
detecting what it structurally cannot.

Enumeration itself is faithful. Measured against independent sources on the same
host: psutil 414, WMI Win32_Process 416, Get-Process 416, with a 10s window
showing 0 processes started and 0 exited. The small delta is sampling churn, not
concealment. Note that all three read the same kernel structure, so their
agreement rules out usermode API differences, NOT kernel-level hiding.

What is genuinely invisible:

- Kernel rootkits (DKOM): unlinking EPROCESS from ActiveProcessLinks hides a
  process from psutil, WMI and Task Manager alike. No usermode tool sees it.
- Process hollowing / injection: the process is listed and looks correct. Hashes
  and Authenticode are computed on THE FILE ON DISK, not the running image, so a
  hollowed svchost has a valid SHA256 and a valid signature. Reflective DLL loads
  never touch disk.
- Point-in-time blindness: a scan is a snapshot. Anything born and dead between
  scans is never seen; a 60s auto-refresh interval is a 60s hole.
- Memory inspection is metadata only: memory_inspector reads memory_info() and
  memory_maps() region attributes. It never scans memory CONTENTS. It is also
  opt-in, gated at threat_score >= 30, and capped at 10 processes, so the
  low-scoring PARTIAL processes never reach it. The gaps compound.
- Non-elevated runs lose cmdline/user on SYSTEM-owned processes (see
  data_confidence above). Fixable with --elevate / "Restart as Administrator";
  the other limits above are not fixable at any privilege level.

## Security and Privacy Expectations

Treat output data as sensitive machine telemetry:

- process paths
- usernames
- command lines
- hashes
- network endpoints

Do not add telemetry upload, background beaconing, or automatic remote sync.
If proposing cloud integration, require explicit user opt-in and clear UX disclosure.

## File Hygiene and Git Rules

Do not commit generated/runtime files such as:

- processes.csv
- processes.json
- memguard_results_*.csv
- memguard_results_*.json
- memguard_history.jsonl
- memguard_full_report*.md
- memguard_ports_report*.md
- memguard_ports_*.csv
- memguard_ports_*.json

Keep ignored build/runtime directories out of commits:

- __pycache__/
- build/
- dist/
- release/

## Environment and Run Commands

Recommended environment:

- Windows + Python 3.13 + local .venv

Install deps:

- py -3.13 -m pip install -r memguard/requirements.txt

Run GUI:

- py -3.13 -m memguard --gui

Run CLI:

- py -3.13 -m memguard

Useful options:

- --elevate (relaunch as Administrator for full process visibility)
- --memory --memory-min-score 30
- --vt --vt-suspicious-only --vt-max-requests 3

## Change Policy for Claude

Before coding:

- Read README.md and touched modules.
- Preserve existing naming/style patterns.
- Keep changes minimal and scoped.

During coding:

- Maintain backwards-compatible behavior unless change is requested.
- Prefer additive changes over broad rewrites.
- Keep scoring explainable (triggered_rules must remain transparent).
- Never let missing data render as clean data. If a field cannot be read, record
  it (access_denied_fields / data_confidence) and surface it; do not silently
  score the process as if the evidence were absent.
- Keep triggered_rules and console strings ASCII-safe. A non-encodable character
  aborts the CLI before the export step on a cp1252 console.

After coding:

- Run quick import/syntax checks for touched modules.
- Update README.md and CLAUDE.md when behavior changes.
- Summarize risks/regressions, not only happy path.

## High-Risk Areas (Extra Care)

- memguard/scorer.py: scoring logic impacts triage outcomes.
- memguard/collector.py: data fidelity and sanitization.
- memguard/threat_intel.py: external API behavior, throttling, failure handling.
- memguard/gui.py: user workflow, filter correctness, export behavior.
- memguard/collector.py AccessDenied probing: the distinction between "denied"
  and "empty" is what keeps data_confidence honest.
- memguard/port_inspector.py: network interpretation and false-positive risk.

## PyInstaller Note

Frozen build behavior depends on correct data-path resolution for blocklist assets:

- data/blocklist.txt may require sys._MEIPASS-aware path handling.

Do not break packaged runtime assumptions when changing path logic.

## Definition of Done for Changes

A change is complete when:

- Read-only safety model is preserved.
- Existing flows still run (GUI and/or CLI as applicable).
- Exports still produce parseable output.
- README.md and CLAUDE.md are updated for user-visible changes.
- No sensitive runtime artifacts are accidentally staged for commit.

## graphify

This project has a graphify knowledge graph at graphify-out/.

Rules:

- Before answering architecture or codebase questions, read graphify-out/GRAPH_REPORT.md for god nodes and community structure
- If graphify-out/wiki/index.md exists, navigate it instead of reading raw files
- For cross-module "how does X relate to Y" questions, prefer `graphify query "<question>"`, `graphify path "<A>" "<B>"`, or `graphify explain "<concept>"` over grep — these traverse the graph's EXTRACTED + INFERRED edges instead of scanning files
- After modifying code files in this session, run `graphify update .` to keep the graph current (AST-only, no API cost)

## Session Rules

- Check C:\Users\Cerus\OneDrive\Documents\Obsidian Vault\projects\MemGuard Lite.md before starting work each session
- Update the Session Log in that note at the end of each session
- Run /graphify . after major refactors to keep graph current
- Use py -m graphify not graphify directly (Windows PATH issue)
