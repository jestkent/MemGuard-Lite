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
- memguard/collector.py: process and system telemetry collection.
- memguard/hasher.py: SHA256 attachment and blocklist loading.
- memguard/scorer.py: explainable scoring engine.
- memguard/memory_inspector.py: memory metadata checks.
- memguard/threat_intel.py: VirusTotal v3 enrichment + test_vt_connection().
- memguard/validator.py: read-only validation of selected process rows.
- memguard/port_inspector.py: listening ports/session inspection and risk scoring.
- memguard/exporter.py: CSV/JSON/full markdown report export (processes and ports).
- memguard/gui.py: Tkinter desktop workflow.
- memguard/ui.py: rich terminal UI rendering.

## Current Feature Set

- Process telemetry with PID, user, cmdline, RSS/CPU.
- Deterministic threat scoring with triggered_rules evidence.
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
- Port scoring: ephemeral range (>=49152, +5) and localhost reduction (-10) both correctly applied.
- Exports:
  - processes.csv
  - processes.json
  - memguard full markdown report for AI analysis
  - ports CSV (export_ports_csv)
  - ports JSON (export_ports_json)
  - ports markdown report (export_ports_report)

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

After coding:

- Run quick import/syntax checks for touched modules.
- Update README.md and CLAUDE.md when behavior changes.
- Summarize risks/regressions, not only happy path.

## High-Risk Areas (Extra Care)

- memguard/scorer.py: scoring logic impacts triage outcomes.
- memguard/collector.py: data fidelity and sanitization.
- memguard/threat_intel.py: external API behavior, throttling, failure handling.
- memguard/gui.py: user workflow, filter correctness, export behavior.
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
