# Graph Report - MemGuard Lite  (2026-11-21)

## Corpus Check
- 31 files · ~34,831 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 617 nodes · 913 edges · 22 communities detected
- Extraction: 88% EXTRACTED · 12% INFERRED · 0% AMBIGUOUS · INFERRED: 106 edges (avg confidence: 0.79)
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
- [[_COMMUNITY_Community 13|Community 13]]
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Community 16|Community 16]]
- [[_COMMUNITY_Community 17|Community 17]]
- [[_COMMUNITY_Community 18|Community 18]]
- [[_COMMUNITY_Community 21|Community 21]]
- [[_COMMUNITY_Community 22|Community 22]]
- [[_COMMUNITY_Community 23|Community 23]]

## God Nodes (most connected - your core abstractions)
1. `MemGuardGUI` - 65 edges
2. `make_record()` - 32 edges
3. `main()` - 25 edges
4. `rules_of()` - 23 edges
5. `score_process()` - 22 edges
6. `main() CLI/GUI Orchestrator` - 16 edges
7. `match_cmdline()` - 13 edges
8. `export_full_report()` - 12 edges
9. `_check_signature_unsigned()` - 11 edges
10. `score_processes()` - 11 edges

## Surprising Connections (you probably didn't know these)
- `gui()` --calls--> `MemGuardGUI`  [INFERRED]
  tests\test_pipeline_and_gui.py → memguard\gui.py
- `test_persistence_counts_distinct_scans()` --calls--> `make_record()`  [INFERRED]
  tests\test_pipeline_and_gui.py → tests\conftest.py
- `test_details_panel_explains_rules()` --calls--> `make_record()`  [INFERRED]
  tests\test_pipeline_and_gui.py → tests\conftest.py
- `_resolve_resource_path() PyInstaller-Aware Path Resolution` --references--> `data/blocklist.txt SHA256 Blocklist File`  [INFERRED]
  memguard/hasher.py → data/blocklist.txt
- `Explainable Deterministic Scoring Principle` --rationale_for--> `score_process() Heuristic Scoring`  [EXTRACTED]
  README.md → memguard/scorer.py

## Hyperedges (group relationships)
- **Core Triage Scan Pipeline** — collector_collect_processes, hasher_attach_sha256, scorer_score_processes, memory_inspector_inspect_memory, threat_intel_enrich_with_virustotal, port_inspector_collect_listening_ports [EXTRACTED 0.95]
- **ProcessRecord Progressive Enrichment Flow** — collector_ProcessRecord, hasher_attach_sha256, scorer_score_process, memory_inspector_inspect_process_memory, threat_intel_enrich_with_virustotal [EXTRACTED 0.95]
- **Multi-Format Export Surface** — exporter_export_csv, exporter_export_json, exporter_export_full_report, exporter_export_ports_csv, exporter_export_ports_json, exporter_export_ports_report [INFERRED 0.85]

## Communities

### Community 0 - "Community 0"
Cohesion: 0.03
Nodes (93): _ascii(), _check_signature_unsigned(), _classify_score(), _get_ephemeral_listening_addresses(), _get_parent_name(), _get_signature_info(), _has_ephemeral_listening_port(), _is_process_elevated() (+85 more)

### Community 1 - "Community 1"
Cohesion: 0.05
Nodes (24): environment_facts(), Live facts about this session for the About tab (read-only lookups)., Live facts about this session for the About tab (read-only lookups)., is_elevated(), True when the current process holds an elevated (admin) token.      Without el, MemGuardGUI, Reflect the current token in the button and status label., Relaunch MemGuard elevated after explicit confirmation.          Windows canno (+16 more)

### Community 2 - "Community 2"
Cohesion: 0.04
Nodes (48): attack(), build_sections(), explain_rule(), _level_text(), _md_table(), In-app documentation for MemGuard Lite.  One source of truth for the GUI "About", One-line plain-language explanation for a triggered_rules string., One-line plain-language explanation for a triggered_rules string. (+40 more)

### Community 3 - "Community 3"
Cohesion: 0.05
Nodes (49): collect_processes(), collect_system_overview(), _probe_denied_fields(), ProcessRecord, Process data collection module.  Enumerates running processes and collects for, Collect total/used/free RAM and current CPU usage percentage., Enumerate all running processes and collect metadata.      Returns:         L, Internal process data model used across MemGuard layers. (+41 more)

### Community 4 - "Community 4"
Cohesion: 0.06
Nodes (48): build_windows.ps1 PyInstaller Build Script, CLAUDE.md Project Guardrails, ProcessRecord TypedDict, collect_processes(), collect_system_overview(), _sanitize_text() Credential Redaction, data/blocklist.txt SHA256 Blocklist File, Explainable Deterministic Scoring Principle (+40 more)

### Community 5 - "Community 5"
Cohesion: 0.05
Nodes (47): _build_summary(), _clean_export_strings(), export_csv(), export_full_report(), export_json(), export_ports_csv(), export_ports_json(), export_ports_report() (+39 more)

### Community 6 - "Community 6"
Cohesion: 0.05
Nodes (45): build_relaunch_command(), Opt-in privilege elevation for fuller read visibility.  Windows cannot raise the, Return (executable, argument_string) that re-runs this app as-is.      Kept sepa, Relaunch MemGuard elevated via the UAC prompt.      Returns:         (started, m, relaunch_as_admin(), _build_parser(), main(), Allow running the package directly: python -m memguard (+37 more)

### Community 7 - "Community 7"
Cohesion: 0.12
Nodes (33): make_record(), A minimal ProcessRecord; PID 999999 avoids colliding with a live PID., Scoring engine: each rule's points, labels and the evidence-handling contract., Regression (stress test): a non-numeric PID raised ValueError., rules_of(), test_all_labels_ascii(), test_blocklist_and_virustotal_labels_unchanged(), test_clean_record_is_safe() (+25 more)

### Community 8 - "Community 8"
Cohesion: 0.09
Nodes (27): CmdlineTag, _exe(), match_cmdline(), normalize_cmdline(), Command-line detection rules for MemGuard.  Read-only string analysis of a proce, Collapse equivalent spellings of a command line into one canonical form.      *, Regex for a program name with optional path and optional .exe., True if any (head, tail) pair of ``tag`` matches: tail after first head. (+19 more)

### Community 9 - "Community 9"
Cohesion: 0.09
Nodes (12): is_system_process(), Logic-only whitelist checks for trusted Windows system processes., Return True when a process matches trusted system name and location., Return True when a process matches a trusted system name AND its real folder., Process-identity checks: location, look-alike names, signer, parent., Every process name running right now must pass (false-positive guard)., Every protected process running right now must be in its real folder., No core process on this host may trip the parent rule (false-positive guard). (+4 more)

### Community 10 - "Community 10"
Cohesion: 0.14
Nodes (18): find_lookalike(), is_in_expected_location(), is_microsoft_signer(), normalize_path(), _osa_distance(), parse_subject(), Process-identity checks: is this really the Windows process it claims to be?  Re, Lower-case, backslash-separated, no ``\\\\?\\`` prefix, no trailing slash. (+10 more)

### Community 11 - "Community 11"
Cohesion: 0.15
Nodes (9): gui(), Pipeline pieces (history, elevation, exports, ports) and the GUI About tab., Regression (stress test): attacker-controlled command lines starting with     '=, _scored_records(), test_csv_export_defuses_spreadsheet_formulas(), test_details_panel_explains_rules(), test_full_report_has_glossary_and_specific_technique(), test_persistence_counts_distinct_scans() (+1 more)

### Community 12 - "Community 12"
Cohesion: 0.23
Nodes (13): b64ps(), build_cases(), cleanup(), copy_as(), find_non_microsoft_signed_binary(), load_and_churn(), main(), MemGuard live stress test: benign adversary emulation + load/churn + real CLI sc (+5 more)

### Community 13 - "Community 13"
Cohesion: 0.14
Nodes (1): ATT&CK mapping and the in-app documentation stay in sync with the scorer.

### Community 14 - "Community 14"
Cohesion: 0.27
Nodes (9): enrich_with_virustotal(), _extract_stats(), _get_vt_api_key(), Optional VirusTotal enrichment for MemGuard.  Queries VT v3 by SHA256 in read-, Ping the VT API with a single known hash to validate key + connectivity., Get VT API key from process env, with Windows user-env fallback., Extract VT last_analysis_stats safely from response payload., Optionally enrich process records with VirusTotal counts.      Behavior: (+1 more)

### Community 15 - "Community 15"
Cohesion: 0.29
Nodes (9): _compute_sha256(), format_validation_report(), _get_windows_signature(), _is_temp_path(), _powershell_escape_single_quotes(), Read-only validation utilities for suspicious process entries., Format validation results for GUI display., Perform read-only validation checks on a selected process row. (+1 more)

### Community 16 - "Community 16"
Cohesion: 0.33
Nodes (5): isolated_scorer(), Shared fixtures for the MemGuard test suite.  Run from the repository root:  py, Pin the Windows folder layout so path rules are deterministic., Cut the scorer off from live system state.      Parent lookups, listening ports,, windows_env()

### Community 17 - "Community 17"
Cohesion: 0.5
Nodes (1): MemGuard fuzz / scan-stall / determinism / export-robustness stress test.  Rea

### Community 18 - "Community 18"
Cohesion: 1.0
Nodes (1): Windows executable entrypoint for MemGuard GUI.

### Community 21 - "Community 21"
Cohesion: 1.0
Nodes (1): _build_parser() CLI Argument Parser

### Community 22 - "Community 22"
Cohesion: 1.0
Nodes (1): SystemOverview TypedDict

### Community 23 - "Community 23"
Cohesion: 1.0
Nodes (1): ValidationReport TypedDict

## Knowledge Gaps
- **281 isolated node(s):** `Windows executable entrypoint for MemGuard GUI.`, `In-app documentation for MemGuard Lite.  One source of truth for the GUI "About"`, `Plain-language documentation for one scoring rule.`, `One page of documentation. Blocks are (kind, payload) pairs.`, `One-line plain-language explanation for a triggered_rules string.` (+276 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Community 13`** (14 nodes): `test_docs_and_mapping.py`, `ATT&CK mapping and the in-app documentation stay in sync with the scorer.`, `test_commandline_tags_expand_to_specific_techniques()`, `test_environment_facts()`, `test_every_commandline_behaviour_is_in_the_guide()`, `test_every_scoring_rule_is_documented()`, `test_explain_rule_covers_real_labels()`, `test_guide_is_ascii_for_cp1252_consoles()`, `test_legacy_labels_still_map()`, `test_masquerading_rules_map_to_t1036_005()`, `test_points_shown_match_scorer()`, `test_report_glossary_lists_only_seen_rules()`, `test_sections_have_unique_ids_and_content()`, `test_techniques_are_deduplicated()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 17`** (4 nodes): `stress_fuzz.py`, `fit()`, `MemGuard fuzz / scan-stall / determinism / export-robustness stress test.  Rea`, `timed()`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 18`** (2 nodes): `launch_gui.py`, `Windows executable entrypoint for MemGuard GUI.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 21`** (1 nodes): `_build_parser() CLI Argument Parser`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 22`** (1 nodes): `SystemOverview TypedDict`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 23`** (1 nodes): `ValidationReport TypedDict`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `MemGuardGUI` connect `Community 1` to `Community 11`, `Community 2`, `Community 3`?**
  _High betweenness centrality (0.259) - this node is a cross-community bridge._
- **Why does `score_process()` connect `Community 0` to `Community 9`, `Community 3`?**
  _High betweenness centrality (0.135) - this node is a cross-community bridge._
- **Why does `make_record()` connect `Community 7` to `Community 16`, `Community 11`?**
  _High betweenness centrality (0.112) - this node is a cross-community bridge._
- **Are the 4 inferred relationships involving `MemGuardGUI` (e.g. with `RuleDoc` and `ProcessRecord`) actually correct?**
  _`MemGuardGUI` has 4 INFERRED edges - model-reasoned connections that need verification._
- **Are the 30 inferred relationships involving `make_record()` (e.g. with `test_persistence_counts_distinct_scans()` and `_scored_records()`) actually correct?**
  _`make_record()` has 30 INFERRED edges - model-reasoned connections that need verification._
- **Are the 19 inferred relationships involving `main()` (e.g. with `render_markdown()` and `relaunch_as_admin()`) actually correct?**
  _`main()` has 19 INFERRED edges - model-reasoned connections that need verification._
- **Are the 2 inferred relationships involving `score_process()` (e.g. with `is_system_process()` and `is_loopback_address()`) actually correct?**
  _`score_process()` has 2 INFERRED edges - model-reasoned connections that need verification._