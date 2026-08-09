# Graph Report - MemGuard Lite  (2026-05-05)

## Corpus Check
- 18 files · ~13,926 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 270 nodes · 424 edges · 15 communities detected
- Extraction: 91% EXTRACTED · 9% INFERRED · 0% AMBIGUOUS · INFERRED: 40 edges (avg confidence: 0.78)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Community 16|Community 16]]

## God Nodes (most connected - your core abstractions)
1. `MemGuardGUI` - 50 edges
2. `main()` - 18 edges
3. `main() CLI/GUI Orchestrator` - 16 edges
4. `score_process()` - 11 edges
5. `export_full_report()` - 9 edges
6. `score_process() Heuristic Scoring` - 9 edges
7. `_scan_pipeline() Threaded Scan Pipeline` - 9 edges
8. `MemGuardGUI Tkinter Application` - 8 edges
9. `_to_dataframe()` - 7 edges
10. `ProcessRecord TypedDict` - 7 edges

## Surprising Connections (you probably didn't know these)
- `_resolve_resource_path() PyInstaller-Aware Path Resolution` --references--> `data/blocklist.txt SHA256 Blocklist File`  [INFERRED]
  memguard/hasher.py → data/blocklist.txt
- `Explainable Deterministic Scoring Principle` --rationale_for--> `score_process() Heuristic Scoring`  [EXTRACTED]
  README.md → memguard/scorer.py
- `export_full_report()` --calls--> `map_rules_to_techniques()`  [INFERRED]
  memguard\exporter.py → memguard\attack_map.py
- `export_full_report()` --calls--> `format_techniques()`  [INFERRED]
  memguard\exporter.py → memguard\attack_map.py
- `MemGuardGUI` --uses--> `ProcessRecord`  [INFERRED]
  memguard\gui.py → memguard\collector.py

## Hyperedges (group relationships)
- **Core Triage Scan Pipeline** — collector_collect_processes, hasher_attach_sha256, scorer_score_processes, memory_inspector_inspect_memory, threat_intel_enrich_with_virustotal, port_inspector_collect_listening_ports [EXTRACTED 0.95]
- **ProcessRecord Progressive Enrichment Flow** — collector_ProcessRecord, hasher_attach_sha256, scorer_score_process, memory_inspector_inspect_process_memory, threat_intel_enrich_with_virustotal [EXTRACTED 0.95]
- **Multi-Format Export Surface** — exporter_export_csv, exporter_export_json, exporter_export_full_report, exporter_export_ports_csv, exporter_export_ports_json, exporter_export_ports_report [INFERRED 0.85]

## Communities

### Community 0 - "Community 0"
Cohesion: 0.08
Nodes (5): MemGuardGUI, Thread-safe progress update — callable from the worker thread., Thread-safe progress update — callable from the worker thread., Tkinter desktop application for MemGuard scans., Tkinter desktop application for MemGuard scans.

### Community 1 - "Community 1"
Cohesion: 0.07
Nodes (43): build_windows.ps1 PyInstaller Build Script, CLAUDE.md Project Guardrails, ProcessRecord TypedDict, collect_processes(), collect_system_overview(), _sanitize_text() Credential Redaction, data/blocklist.txt SHA256 Blocklist File, Explainable Deterministic Scoring Principle (+35 more)

### Community 2 - "Community 2"
Cohesion: 0.08
Nodes (28): collect_processes(), collect_system_overview(), ProcessRecord, Process data collection module.  Enumerates running processes and collects for, Internal process data model used across MemGuard layers., System-level telemetry shown above the process table., Remove newlines/tabs from text fields to keep exports parse-safe., Collect total/used/free RAM and current CPU usage percentage. (+20 more)

### Community 3 - "Community 3"
Cohesion: 0.09
Nodes (29): _check_signature_unsigned(), _classify_score(), _get_ephemeral_listening_addresses(), _get_parent_name(), _has_ephemeral_listening_port(), _is_process_elevated(), _is_suspicious_parent_child(), _is_windows_token_elevated() (+21 more)

### Community 4 - "Community 4"
Cohesion: 0.09
Nodes (27): _build_summary(), _clean_export_strings(), export_csv(), export_full_report(), export_json(), export_ports_csv(), export_ports_json(), export_ports_report() (+19 more)

### Community 5 - "Community 5"
Cohesion: 0.12
Nodes (22): _build_parser(), main(), Allow running the package directly: python -m memguard, Build CLI parser for MemGuard options., Entry point for MemGuard CLI., _memory_flag_style(), _memory_style(), Terminal UI module.  Renders the startup banner and process table using rich, (+14 more)

### Community 6 - "Community 6"
Cohesion: 0.11
Nodes (18): format_techniques(), map_rule_to_technique(), map_rules_to_techniques(), MITRE ATT&CK technique mapping for MemGuard scoring rules.  Read-only lookup: ma, Return (technique_id, technique_name) for a rule string, or None., Return deduplicated list of (id, name) tuples for a list of rules., Human-readable comma-separated string. Empty → '-'., launch_gui() (+10 more)

### Community 7 - "Community 7"
Cohesion: 0.22
Nodes (9): attach_sha256(), _compute_sha256(), load_blocklist(), Executable hashing and local blocklist loading for MemGuard.  Layer 3 artifact, Resolve data file paths for source runs and frozen executable runs., Load local SHA256 blocklist once and return hashes as a lowercase set., Compute SHA256 hash for a file path, returning None on read errors., Attach executable SHA256 to each process using an in-memory path cache. (+1 more)

### Community 8 - "Community 8"
Cohesion: 0.29
Nodes (9): _compute_sha256(), format_validation_report(), _get_windows_signature(), _is_temp_path(), _powershell_escape_single_quotes(), Read-only validation utilities for suspicious process entries., Format validation results for GUI display., Perform read-only validation checks on a selected process row. (+1 more)

### Community 9 - "Community 9"
Cohesion: 0.27
Nodes (9): enrich_with_virustotal(), _extract_stats(), _get_vt_api_key(), Optional VirusTotal enrichment for MemGuard.  Queries VT v3 by SHA256 in read-, Ping the VT API with a single known hash to validate key + connectivity., Get VT API key from process env, with Windows user-env fallback., Extract VT last_analysis_stats safely from response payload., Optionally enrich process records with VirusTotal counts.      Behavior: (+1 more)

### Community 10 - "Community 10"
Cohesion: 0.6
Nodes (5): export_ports_csv() Ports CSV Export, export_ports_json() Ports JSON Export, export_ports_report() Ports Markdown Report, show_ports_window() Port Viewer Window, PortRecord TypedDict

### Community 11 - "Community 11"
Cohesion: 1.0
Nodes (1): Windows executable entrypoint for MemGuard GUI.

### Community 14 - "Community 14"
Cohesion: 1.0
Nodes (1): _build_parser() CLI Argument Parser

### Community 15 - "Community 15"
Cohesion: 1.0
Nodes (1): SystemOverview TypedDict

### Community 16 - "Community 16"
Cohesion: 1.0
Nodes (1): ValidationReport TypedDict

## Knowledge Gaps
- **105 isolated node(s):** `Windows executable entrypoint for MemGuard GUI.`, `MITRE ATT&CK technique mapping for MemGuard scoring rules.  Read-only lookup: ma`, `Return (technique_id, technique_name) for a rule string, or None.`, `Return deduplicated list of (id, name) tuples for a list of rules.`, `Human-readable comma-separated string. Empty → '-'.` (+100 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Community 11`** (2 nodes): `launch_gui.py`, `Windows executable entrypoint for MemGuard GUI.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 14`** (1 nodes): `_build_parser() CLI Argument Parser`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 15`** (1 nodes): `SystemOverview TypedDict`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 16`** (1 nodes): `ValidationReport TypedDict`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `MemGuardGUI` connect `Community 0` to `Community 2`, `Community 6`, `Community 7`?**
  _High betweenness centrality (0.242) - this node is a cross-community bridge._
- **Why does `main()` connect `Community 5` to `Community 2`, `Community 3`, `Community 4`, `Community 6`, `Community 7`, `Community 9`?**
  _High betweenness centrality (0.083) - this node is a cross-community bridge._
- **Are the 2 inferred relationships involving `MemGuardGUI` (e.g. with `ProcessRecord` and `PortRecord`) actually correct?**
  _`MemGuardGUI` has 2 INFERRED edges - model-reasoned connections that need verification._
- **Are the 15 inferred relationships involving `main()` (e.g. with `launch_gui()` and `show_banner()`) actually correct?**
  _`main()` has 15 INFERRED edges - model-reasoned connections that need verification._
- **Are the 3 inferred relationships involving `export_full_report()` (e.g. with `map_rules_to_techniques()` and `format_techniques()`) actually correct?**
  _`export_full_report()` has 3 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Windows executable entrypoint for MemGuard GUI.`, `MITRE ATT&CK technique mapping for MemGuard scoring rules.  Read-only lookup: ma`, `Return (technique_id, technique_name) for a rule string, or None.` to the rest of the system?**
  _105 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.08 - nodes in this community are weakly interconnected._