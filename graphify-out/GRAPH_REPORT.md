# Graph Report - D:/Desktop/MemGuard Lite  (2026-05-02)

## Corpus Check
- Corpus is ~12,286 words - fits in a single context window. You may not need a graph.

## Summary
- 227 nodes · 356 edges · 15 communities detected
- Extraction: 90% EXTRACTED · 10% INFERRED · 0% AMBIGUOUS · INFERRED: 34 edges (avg confidence: 0.78)
- Token cost: 68,503 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Core Data & Project Infrastructure|Core Data & Project Infrastructure]]
- [[_COMMUNITY_Tkinter GUI Interface|Tkinter GUI Interface]]
- [[_COMMUNITY_Process Data Collection|Process Data Collection]]
- [[_COMMUNITY_CLI Entrypoint & UI Rendering|CLI Entrypoint & UI Rendering]]
- [[_COMMUNITY_Export & Reporting|Export & Reporting]]
- [[_COMMUNITY_Process Risk Scoring|Process Risk Scoring]]
- [[_COMMUNITY_Memory Inspection & GUI Init|Memory Inspection & GUI Init]]
- [[_COMMUNITY_SHA256 Hashing & Blocklist|SHA256 Hashing & Blocklist]]
- [[_COMMUNITY_VirusTotal Threat Intelligence|VirusTotal Threat Intelligence]]
- [[_COMMUNITY_Process Validation|Process Validation]]
- [[_COMMUNITY_Port Monitoring & Export|Port Monitoring & Export]]
- [[_COMMUNITY_GUI Launcher|GUI Launcher]]
- [[_COMMUNITY_CLI Argument Parser|CLI Argument Parser]]
- [[_COMMUNITY_System Overview Data|System Overview Data]]
- [[_COMMUNITY_Validation Report|Validation Report]]

## God Nodes (most connected - your core abstractions)
1. `MemGuardGUI` - 44 edges
2. `main()` - 18 edges
3. `main() CLI/GUI Orchestrator` - 16 edges
4. `score_process() Heuristic Scoring` - 9 edges
5. `_scan_pipeline() Threaded Scan Pipeline` - 9 edges
6. `MemGuardGUI Tkinter Application` - 8 edges
7. `score_process()` - 7 edges
8. `ProcessRecord TypedDict` - 7 edges
9. `_to_dataframe()` - 6 edges
10. `export_full_report()` - 6 edges

## Surprising Connections (you probably didn't know these)
- `_resolve_resource_path() PyInstaller-Aware Path Resolution` --references--> `data/blocklist.txt SHA256 Blocklist File`  [INFERRED]
  memguard/hasher.py → data/blocklist.txt
- `Explainable Deterministic Scoring Principle` --rationale_for--> `score_process() Heuristic Scoring`  [EXTRACTED]
  README.md → memguard/scorer.py
- `MemGuardGUI` --uses--> `ProcessRecord`  [INFERRED]
  memguard\gui.py → memguard\collector.py
- `main()` --calls--> `collect_system_overview()`  [INFERRED]
  memguard\main.py → memguard\collector.py
- `main()` --calls--> `collect_processes()`  [INFERRED]
  memguard\main.py → memguard\collector.py

## Hyperedges (group relationships)
- **Core Triage Scan Pipeline** — collector_collect_processes, hasher_attach_sha256, scorer_score_processes, memory_inspector_inspect_memory, threat_intel_enrich_with_virustotal, port_inspector_collect_listening_ports [EXTRACTED 0.95]
- **ProcessRecord Progressive Enrichment Flow** — collector_ProcessRecord, hasher_attach_sha256, scorer_score_process, memory_inspector_inspect_process_memory, threat_intel_enrich_with_virustotal [EXTRACTED 0.95]
- **Multi-Format Export Surface** — exporter_export_csv, exporter_export_json, exporter_export_full_report, exporter_export_ports_csv, exporter_export_ports_json, exporter_export_ports_report [INFERRED 0.85]

## Communities

### Community 0 - "Core Data & Project Infrastructure"
Cohesion: 0.07
Nodes (43): build_windows.ps1 PyInstaller Build Script, CLAUDE.md Project Guardrails, ProcessRecord TypedDict, collect_processes(), collect_system_overview(), _sanitize_text() Credential Redaction, data/blocklist.txt SHA256 Blocklist File, Explainable Deterministic Scoring Principle (+35 more)

### Community 1 - "Tkinter GUI Interface"
Cohesion: 0.09
Nodes (3): MemGuardGUI, Thread-safe progress update — callable from the worker thread., Tkinter desktop application for MemGuard scans.

### Community 2 - "Process Data Collection"
Cohesion: 0.11
Nodes (21): collect_processes(), collect_system_overview(), ProcessRecord, Process data collection module.  Enumerates running processes and collects for, Internal process data model used across MemGuard layers., System-level telemetry shown above the process table., Remove newlines/tabs from text fields to keep exports parse-safe., Collect total/used/free RAM and current CPU usage percentage. (+13 more)

### Community 3 - "CLI Entrypoint & UI Rendering"
Cohesion: 0.12
Nodes (22): _build_parser(), main(), Allow running the package directly: python -m memguard, Build CLI parser for MemGuard options., Entry point for MemGuard CLI., _memory_flag_style(), _memory_style(), Terminal UI module.  Renders the startup banner and process table using rich, (+14 more)

### Community 4 - "Export & Reporting"
Cohesion: 0.13
Nodes (19): _build_summary(), _clean_export_strings(), export_csv(), export_full_report(), export_json(), export_ports_csv(), export_ports_json(), export_ports_report() (+11 more)

### Community 5 - "Process Risk Scoring"
Cohesion: 0.13
Nodes (18): _classify_score(), _get_ephemeral_listening_addresses(), _has_ephemeral_listening_port(), _is_process_elevated(), _is_windows_token_elevated(), Heuristic threat scoring engine for MemGuard.  Layer 2 scoring is read-only an, Detect elevated execution context while minimizing false positives., Return inet listening addresses where local port is > 49152.      Returns an e (+10 more)

### Community 6 - "Memory Inspection & GUI Init"
Cohesion: 0.2
Nodes (10): launch_gui(), Desktop GUI for MemGuard.  Provides a detailed read-only interface to run proc, Launch the MemGuard desktop GUI., inspect_memory(), _inspect_process_memory(), _is_anonymous_path(), Experimental memory metadata inspection for high-risk processes.  This module, Return True when a memory map path is empty or anonymous. (+2 more)

### Community 7 - "SHA256 Hashing & Blocklist"
Cohesion: 0.22
Nodes (9): attach_sha256(), _compute_sha256(), load_blocklist(), Executable hashing and local blocklist loading for MemGuard.  Layer 3 artifact, Resolve data file paths for source runs and frozen executable runs., Load local SHA256 blocklist once and return hashes as a lowercase set., Compute SHA256 hash for a file path, returning None on read errors., Attach executable SHA256 to each process using an in-memory path cache. (+1 more)

### Community 8 - "VirusTotal Threat Intelligence"
Cohesion: 0.27
Nodes (9): enrich_with_virustotal(), _extract_stats(), _get_vt_api_key(), Optional VirusTotal enrichment for MemGuard.  Queries VT v3 by SHA256 in read-, Ping the VT API with a single known hash to validate key + connectivity., Get VT API key from process env, with Windows user-env fallback., Extract VT last_analysis_stats safely from response payload., Optionally enrich process records with VirusTotal counts.      Behavior: (+1 more)

### Community 9 - "Process Validation"
Cohesion: 0.29
Nodes (9): _compute_sha256(), format_validation_report(), _get_windows_signature(), _is_temp_path(), _powershell_escape_single_quotes(), Read-only validation utilities for suspicious process entries., Format validation results for GUI display., Perform read-only validation checks on a selected process row. (+1 more)

### Community 10 - "Port Monitoring & Export"
Cohesion: 0.6
Nodes (5): export_ports_csv() Ports CSV Export, export_ports_json() Ports JSON Export, export_ports_report() Ports Markdown Report, show_ports_window() Port Viewer Window, PortRecord TypedDict

### Community 11 - "GUI Launcher"
Cohesion: 1.0
Nodes (1): Windows executable entrypoint for MemGuard GUI.

### Community 14 - "CLI Argument Parser"
Cohesion: 1.0
Nodes (1): _build_parser() CLI Argument Parser

### Community 15 - "System Overview Data"
Cohesion: 1.0
Nodes (1): SystemOverview TypedDict

### Community 16 - "Validation Report"
Cohesion: 1.0
Nodes (1): ValidationReport TypedDict

## Knowledge Gaps
- **80 isolated node(s):** `Windows executable entrypoint for MemGuard GUI.`, `Process data collection module.  Enumerates running processes and collects for`, `Internal process data model used across MemGuard layers.`, `System-level telemetry shown above the process table.`, `Remove newlines/tabs from text fields to keep exports parse-safe.` (+75 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `GUI Launcher`** (2 nodes): `launch_gui.py`, `Windows executable entrypoint for MemGuard GUI.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `CLI Argument Parser`** (1 nodes): `_build_parser() CLI Argument Parser`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `System Overview Data`** (1 nodes): `SystemOverview TypedDict`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Validation Report`** (1 nodes): `ValidationReport TypedDict`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `MemGuardGUI` connect `Tkinter GUI Interface` to `Process Data Collection`, `Memory Inspection & GUI Init`, `SHA256 Hashing & Blocklist`?**
  _High betweenness centrality (0.231) - this node is a cross-community bridge._
- **Why does `main()` connect `CLI Entrypoint & UI Rendering` to `Process Data Collection`, `Export & Reporting`, `Process Risk Scoring`, `Memory Inspection & GUI Init`, `SHA256 Hashing & Blocklist`, `VirusTotal Threat Intelligence`?**
  _High betweenness centrality (0.092) - this node is a cross-community bridge._
- **Are the 2 inferred relationships involving `MemGuardGUI` (e.g. with `ProcessRecord` and `PortRecord`) actually correct?**
  _`MemGuardGUI` has 2 INFERRED edges - model-reasoned connections that need verification._
- **Are the 15 inferred relationships involving `main()` (e.g. with `launch_gui()` and `show_banner()`) actually correct?**
  _`main()` has 15 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Windows executable entrypoint for MemGuard GUI.`, `Process data collection module.  Enumerates running processes and collects for`, `Internal process data model used across MemGuard layers.` to the rest of the system?**
  _80 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Core Data & Project Infrastructure` be split into smaller, more focused modules?**
  _Cohesion score 0.07 - nodes in this community are weakly interconnected._
- **Should `Tkinter GUI Interface` be split into smaller, more focused modules?**
  _Cohesion score 0.09 - nodes in this community are weakly interconnected._