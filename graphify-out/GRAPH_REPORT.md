# Graph Report - MemGuard Lite  (2026-10-01)

## Corpus Check
- 19 files · ~16,894 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 357 nodes · 534 edges · 16 communities detected
- Extraction: 91% EXTRACTED · 9% INFERRED · 0% AMBIGUOUS · INFERRED: 50 edges (avg confidence: 0.79)
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
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Community 16|Community 16]]
- [[_COMMUNITY_Community 17|Community 17]]

## God Nodes (most connected - your core abstractions)
1. `MemGuardGUI` - 53 edges
2. `main()` - 23 edges
3. `main() CLI/GUI Orchestrator` - 16 edges
4. `score_process()` - 15 edges
5. `export_full_report()` - 10 edges
6. `score_processes()` - 9 edges
7. `score_process() Heuristic Scoring` - 9 edges
8. `_scan_pipeline() Threaded Scan Pipeline` - 9 edges
9. `is_elevated()` - 8 edges
10. `_to_dataframe()` - 8 edges

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
Cohesion: 0.04
Nodes (55): _check_signature_unsigned(), _classify_score(), _get_ephemeral_listening_addresses(), _get_parent_name(), _has_ephemeral_listening_port(), _is_process_elevated(), _is_suspicious_parent_child(), _is_windows_token_elevated() (+47 more)

### Community 1 - "Community 1"
Cohesion: 0.07
Nodes (10): MemGuardGUI, Thread-safe progress update — callable from the worker thread., Thread-safe progress update — callable from the worker thread., Thread-safe progress update — callable from the worker thread., Thread-safe progress update — callable from the worker thread., Tkinter desktop application for MemGuard scans., Tkinter desktop application for MemGuard scans., Tkinter desktop application for MemGuard scans. (+2 more)

### Community 2 - "Community 2"
Cohesion: 0.07
Nodes (43): build_windows.ps1 PyInstaller Build Script, CLAUDE.md Project Guardrails, ProcessRecord TypedDict, collect_processes(), collect_system_overview(), _sanitize_text() Credential Redaction, data/blocklist.txt SHA256 Blocklist File, Explainable Deterministic Scoring Principle (+35 more)

### Community 3 - "Community 3"
Cohesion: 0.07
Nodes (36): is_elevated(), True when the current process holds an elevated (admin) token.      Without el, main(), Entry point for MemGuard CLI., Entry point for MemGuard CLI., Entry point for MemGuard CLI., _harden_stream_encoding(), _memory_flag_style() (+28 more)

### Community 4 - "Community 4"
Cohesion: 0.07
Nodes (35): _build_summary(), _clean_export_strings(), export_csv(), export_full_report(), export_json(), export_ports_csv(), export_ports_json(), export_ports_report() (+27 more)

### Community 5 - "Community 5"
Cohesion: 0.08
Nodes (27): collect_processes(), collect_system_overview(), _probe_denied_fields(), Process data collection module.  Enumerates running processes and collects for, Collect total/used/free RAM and current CPU usage percentage., Enumerate all running processes and collect metadata.      Returns:         L, Remove newlines/tabs from text fields to keep exports parse-safe., Remove newlines/tabs from text fields to keep exports parse-safe. (+19 more)

### Community 6 - "Community 6"
Cohesion: 0.09
Nodes (24): build_relaunch_command(), Opt-in privilege elevation for fuller read visibility.  Windows cannot raise the, Return (executable, argument_string) that re-runs this app as-is.      Kept sepa, Relaunch MemGuard elevated via the UAC prompt.      Returns:         (started, m, relaunch_as_admin(), launch_gui(), Desktop GUI for MemGuard.  Provides a detailed read-only interface to run proc, Launch the MemGuard desktop GUI. (+16 more)

### Community 7 - "Community 7"
Cohesion: 0.1
Nodes (21): ProcessRecord, Internal process data model used across MemGuard layers., Internal process data model used across MemGuard layers., System-level telemetry shown above the process table., System-level telemetry shown above the process table., SystemOverview, _assess_port_risk(), collect_listening_ports() (+13 more)

### Community 8 - "Community 8"
Cohesion: 0.15
Nodes (14): format_techniques(), map_rule_to_technique(), map_rules_to_techniques(), MITRE ATT&CK technique mapping for MemGuard scoring rules.  Read-only lookup: ma, Return (technique_id, technique_name) for a rule string, or None., Return deduplicated list of (id, name) tuples for a list of rules., Human-readable comma-separated string. Empty → '-'., append_scan_findings() (+6 more)

### Community 9 - "Community 9"
Cohesion: 0.27
Nodes (9): enrich_with_virustotal(), _extract_stats(), _get_vt_api_key(), Optional VirusTotal enrichment for MemGuard.  Queries VT v3 by SHA256 in read-, Ping the VT API with a single known hash to validate key + connectivity., Get VT API key from process env, with Windows user-env fallback., Extract VT last_analysis_stats safely from response payload., Optionally enrich process records with VirusTotal counts.      Behavior: (+1 more)

### Community 10 - "Community 10"
Cohesion: 0.29
Nodes (9): _compute_sha256(), format_validation_report(), _get_windows_signature(), _is_temp_path(), _powershell_escape_single_quotes(), Read-only validation utilities for suspicious process entries., Format validation results for GUI display., Perform read-only validation checks on a selected process row. (+1 more)

### Community 11 - "Community 11"
Cohesion: 0.6
Nodes (5): export_ports_csv() Ports CSV Export, export_ports_json() Ports JSON Export, export_ports_report() Ports Markdown Report, show_ports_window() Port Viewer Window, PortRecord TypedDict

### Community 12 - "Community 12"
Cohesion: 1.0
Nodes (1): Windows executable entrypoint for MemGuard GUI.

### Community 15 - "Community 15"
Cohesion: 1.0
Nodes (1): _build_parser() CLI Argument Parser

### Community 16 - "Community 16"
Cohesion: 1.0
Nodes (1): SystemOverview TypedDict

### Community 17 - "Community 17"
Cohesion: 1.0
Nodes (1): ValidationReport TypedDict

## Knowledge Gaps
- **178 isolated node(s):** `Windows executable entrypoint for MemGuard GUI.`, `MITRE ATT&CK technique mapping for MemGuard scoring rules.  Read-only lookup: ma`, `Return (technique_id, technique_name) for a rule string, or None.`, `Return deduplicated list of (id, name) tuples for a list of rules.`, `Human-readable comma-separated string. Empty → '-'.` (+173 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Community 12`** (2 nodes): `launch_gui.py`, `Windows executable entrypoint for MemGuard GUI.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 15`** (1 nodes): `_build_parser() CLI Argument Parser`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 16`** (1 nodes): `SystemOverview TypedDict`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 17`** (1 nodes): `ValidationReport TypedDict`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `MemGuardGUI` connect `Community 1` to `Community 8`, `Community 5`, `Community 6`, `Community 7`?**
  _High betweenness centrality (0.220) - this node is a cross-community bridge._
- **Why does `main()` connect `Community 3` to `Community 9`, `Community 4`, `Community 5`, `Community 6`?**
  _High betweenness centrality (0.121) - this node is a cross-community bridge._
- **Why does `score_process()` connect `Community 0` to `Community 5`, `Community 7`?**
  _High betweenness centrality (0.055) - this node is a cross-community bridge._
- **Are the 2 inferred relationships involving `MemGuardGUI` (e.g. with `ProcessRecord` and `PortRecord`) actually correct?**
  _`MemGuardGUI` has 2 INFERRED edges - model-reasoned connections that need verification._
- **Are the 18 inferred relationships involving `main()` (e.g. with `relaunch_as_admin()` and `is_elevated()`) actually correct?**
  _`main()` has 18 INFERRED edges - model-reasoned connections that need verification._
- **Are the 2 inferred relationships involving `score_process()` (e.g. with `is_system_process()` and `is_loopback_address()`) actually correct?**
  _`score_process()` has 2 INFERRED edges - model-reasoned connections that need verification._
- **Are the 3 inferred relationships involving `export_full_report()` (e.g. with `map_rules_to_techniques()` and `format_techniques()`) actually correct?**
  _`export_full_report()` has 3 INFERRED edges - model-reasoned connections that need verification._