"""In-app documentation for MemGuard Lite.

One source of truth for the GUI "About" tab, the CLI ``--about`` flag and the
rule glossary appended to the full report. Rule points are read from
scorer.RULE_POINTS and ATT&CK IDs from attack_map, so the documentation
cannot drift from what the scorer actually does (tests enforce this).

All text is ASCII on purpose: it is printed to the console, and a character
that cp1252 cannot encode would abort the CLI.
"""

from __future__ import annotations

import os
import platform
import sys
from dataclasses import dataclass, field
from typing import Final

from . import __version__
from .attack_map import map_rule_to_technique
from .cmdline_rules import TAGS as CMDLINE_TAGS
from .scorer import LEVEL_THRESHOLDS, RULE_POINTS

APP_NAME: Final[str] = "MemGuard Lite"


# ── Data model ───────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class RuleDoc:
    """Plain-language documentation for one scoring rule."""

    key: str            # key in scorer.RULE_POINTS
    label: str          # prefix of the string that appears in triggered_rules
    title: str
    what: str           # what the rule checks
    why: str            # why an attacker would trigger it
    benign: str         # common innocent explanations
    points_note: str = ""  # extra detail when points are not a flat number

    @property
    def points(self) -> int:
        return RULE_POINTS[self.key]

    @property
    def points_text(self) -> str:
        base = f"+{self.points}" if self.points else "0 (informational)"
        return f"{base} {self.points_note}".strip()

    @property
    def attack(self) -> str:
        technique = map_rule_to_technique(self.label)
        return f"{technique[0]} {technique[1]}" if technique else "-"


@dataclass(frozen=True)
class Section:
    """One page of documentation. Blocks are (kind, payload) pairs."""

    id: str
    title: str
    blocks: list[tuple[str, object]] = field(default_factory=list)


# ── Rules ────────────────────────────────────────────────────────────────────

RULE_DOCS: Final[list[RuleDoc]] = [
    RuleDoc(
        "temp_executable_path", "temp_executable_path", "Running from a Temp folder",
        "The program file lives in a temporary folder (AppData\\Local\\Temp, \\Temp\\).",
        "Droppers and phishing payloads unpack into Temp because any user can write there "
        "and nobody looks there.",
        "Installers and updaters (for example a VS Code or driver update) run briefly from Temp.",
    ),
    RuleDoc(
        "suspicious_commandline", "suspicious_commandline", "Suspicious command line",
        "The command line asks a Windows tool to do something attackers rely on: run hidden "
        "(encoded) PowerShell, download a file, decode a payload, dump credentials, delete "
        "backups, and so on. The label lists exactly which behaviours matched. Evasive "
        "spellings are normalised first (-e / -ec / -EncodedCommand, carets, backticks, "
        "quotes, Unicode dashes) so they cannot slip past.",
        "Attackers 'live off the land': instead of bringing malware they abuse tools that "
        "already ship with Windows, because those tools are trusted and signed.",
        "Admin and developer tooling. Encoded PowerShell is also used by some legitimate "
        "automation (for example AI coding assistants and deployment agents) - decode it "
        "before deciding.",
        "(+40 for high-confidence behaviours: LSASS dumping, backup deletion, Defender tampering)",
    ),
    RuleDoc(
        "elevated_user_running_from_user_space", "elevated_user_running_from_user_space",
        "Administrator program in a user folder",
        "The process runs with administrator/SYSTEM rights, but its file is under C:\\Users.",
        "Malware that gained admin rights often keeps its file in a folder the user can write to.",
        "Developer tools and portable apps run as administrator from your profile.",
    ),
    RuleDoc(
        "listening_ephemeral_port", "listening_ephemeral_port", "Listening on a high port",
        "The process waits for incoming network connections on a port at or above 49152.",
        "Backdoors and remote-access tools open a listener so an attacker can connect in.",
        "Many apps (VS Code, LM Studio, Ollama, games) open local helper ports. Ports bound to "
        "127.0.0.1 / ::1 only are reachable from this PC only, so they score less.",
        "(+5 for verified Windows system processes; -10 when localhost only)",
    ),
    RuleDoc(
        "suspicious_parent_child", "suspicious_parent_child", "Suspicious parent -> child",
        "A program that should not start shells did: Word/Excel/Outlook/browser -> cmd, "
        "PowerShell, wscript or mshta.",
        "This is the classic shape of a malicious document macro or browser exploit "
        "handing control to a command shell.",
        "Browser extensions that use a native helper (for example the Claude extension) start "
        "cmd.exe from Chrome/Edge. Check the child's command line.",
    ),
    RuleDoc(
        "unexpected_parent", "unexpected_parent", "Wrong parent for a core Windows process",
        "Core processes have exactly one legitimate parent: lsass.exe and services.exe are "
        "always started by wininit.exe, svchost.exe always by services.exe, and so on. This "
        "rule fires when the live parent is something else.",
        "A fake lsass.exe or svchost.exe started by malware has the malware as its parent. "
        "Parent-PID spoofing (T1134.004) can also produce an impossible family tree.",
        "Very rare on a healthy system. If the original parent exited and Windows reused its "
        "PID, MemGuard detects that and reports parent_unverifiable instead of guessing.",
    ),
    RuleDoc(
        "system_binary_wrong_location", "system_binary_wrong_location",
        "Windows process name in the wrong folder",
        "A protected Windows name (svchost, lsass, csrss, explorer, cmd, powershell, ...) is "
        "running from somewhere other than its real folder (normally C:\\Windows\\System32).",
        "Naming malware after a trusted system process is the most common disguise "
        "(masquerading). The name looks right; the folder gives it away.",
        "Almost none. Windows never runs these binaries from user folders.",
    ),
    RuleDoc(
        "process_name_lookalike", "process_name_lookalike", "Look-alike process name",
        "The name is one keystroke away from a protected Windows name (scvhost.exe, "
        "lsasss.exe) or a visual twin (svch0st.exe, or 'svchost' spelled with a Cyrillic c).",
        "Typo-squatted names survive a quick glance down the process list.",
        "Rare. Known real neighbours such as taskhost.exe are excluded.",
    ),
    RuleDoc(
        "microsoft_name_wrong_signer", "microsoft_name_wrong_signer",
        "Windows name, non-Microsoft signature",
        "A protected Windows name carries a VALID digital signature - but from a publisher "
        "other than Microsoft.",
        "Attackers buy or steal code-signing certificates so their file passes 'is it "
        "signed?' checks. Checking WHO signed it defeats that.",
        "None expected for genuine Windows binaries.",
    ),
    RuleDoc(
        "duplicate_singleton_process", "duplicate_singleton_process",
        "Second copy of a one-per-boot process",
        "More than one lsass.exe, services.exe, wininit.exe or lsaiso.exe is running. If exactly one "
        "copy sits in the genuine Windows folder, only the other copies are flagged; if they cannot "
        "be told apart, all are flagged.",
        "There is only ever one real LSASS. An extra copy is an impostor, even in the right folder.",
        "None expected.",
    ),
    RuleDoc(
        "unsigned_or_invalid_signature", "unsigned_or_invalid_signature",
        "Unsigned or invalid signature",
        "Windows' Authenticode check says the file is not signed, or the signature is broken.",
        "Much custom malware is unsigned; a broken signature can mean the file was modified.",
        "Plenty of legitimate open-source and hobby software is unsigned. On its own this "
        "is a weak signal.",
    ),
    RuleDoc(
        "blocklist_match", "Matched local blocklist", "Local blocklist match",
        "The file's SHA256 hash is listed in data/blocklist.txt.",
        "A hash match is an exact identification of a known-bad file.",
        "Only if you added a hash by mistake.",
    ),
    RuleDoc(
        "virustotal_malicious", "VirusTotal malicious detections >= 5", "VirusTotal consensus",
        "Five or more antivirus engines on VirusTotal call this exact file malicious "
        "(only when VirusTotal is enabled).",
        "Independent engines agreeing is strong evidence.",
        "Occasional false positives on niche tools, cracked software or packers.",
    ),
    RuleDoc(
        "unverifiable_data", "unverifiable_data", "Data could not be read",
        "Windows refused to show some fields (usually command line or user) because "
        "MemGuard is not running as Administrator.",
        "Missing evidence is not evidence of guilt - so it adds no points. But it is not "
        "evidence of innocence either, so the row is marked PARTIAL instead of looking clean.",
        "Normal for SYSTEM processes in a non-elevated scan. Use Restart as Administrator.",
    ),
    RuleDoc(
        "parent_unverifiable", "parent_unverifiable", "Parent could not be verified",
        "The parent PID now belongs to a NEWER process (Windows recycled the number), so "
        "the real parent is unknown.",
        "Without this check, a child would be judged by a stranger's name - which could "
        "both cause false alarms and hide real ones.",
        "Common for long-running processes whose launcher has exited.",
    ),
    RuleDoc(
        "memguard_self", "memguard_self", "MemGuard itself",
        "MemGuard's own process is listed but never scored.",
        "Running elevated from a user-space Python install would otherwise make MemGuard "
        "flag itself on every scan.",
        "-",
    ),
]

_RULES_BY_LABEL: Final[list[tuple[str, RuleDoc]]] = sorted(
    ((doc.label, doc) for doc in RULE_DOCS), key=lambda item: len(item[0]), reverse=True
)


def explain_rule(rule: str) -> str:
    """One-line plain-language explanation for a triggered_rules string."""
    if not rule:
        return ""
    if rule.startswith("Memory anomaly detected"):
        return "Memory layout looks unusual (writable+executable regions or odd sizing)."
    for label, doc in _RULES_BY_LABEL:
        if rule.startswith(label):
            if doc.key == "suspicious_commandline" and "(" in rule:
                tags = rule[rule.index("(") + 1:rule.rindex(")")].split(",")
                summaries = [CMDLINE_TAGS[t.strip()].summary for t in tags if t.strip() in CMDLINE_TAGS]
                if summaries:
                    return " ".join(summaries)
            return doc.what
    return ""


# ── Sections ─────────────────────────────────────────────────────────────────

def _level_text() -> str:
    return (
        f"HIGH = score {LEVEL_THRESHOLDS['HIGH']} or more. "
        f"SUSPICIOUS = {LEVEL_THRESHOLDS['SUSPICIOUS']} to {LEVEL_THRESHOLDS['HIGH'] - 1}. "
        f"SAFE = below {LEVEL_THRESHOLDS['SUSPICIOUS']}."
    )


def build_sections() -> list[Section]:
    """Return the full documentation as ordered sections."""
    cmd_rows = [
        [tag.name, f"+{tag.weight}", f"{tag.technique_id} {tag.technique_name}", tag.summary]
        for tag in CMDLINE_TAGS.values()
    ]
    return [
        Section("overview", "What MemGuard Lite is", [
            ("p", f"{APP_NAME} is a read-only security triage tool for Windows. It looks at every "
                  "running program, scores how suspicious each one is, and explains WHY - so you can "
                  "decide in minutes whether something on this PC deserves a closer look."),
            ("h", "What it is for"),
            ("bullets", [
                "A quick health check of your own machine: 'is anything running that should not be?'",
                "First-response triage: rank hundreds of processes so the few odd ones rise to the top.",
                "Evidence: export findings to CSV/JSON/Markdown for notes, a ticket or an AI-assisted review.",
                "Learning: every finding is mapped to the MITRE ATT&CK technique it resembles.",
            ]),
            ("h", "What it is NOT"),
            ("bullets", [
                "Not an antivirus. It never deletes, quarantines, kills, suspends or modifies anything.",
                "Not a guarantee. A SAFE result means 'no rule fired', not 'proven clean' (see Known limits).",
                "Not a cloud service. Nothing leaves this PC unless you turn on VirusTotal, which sends "
                "file HASHES only - never files, names or command lines.",
            ]),
            ("note", "Golden rule: a score is a reason to look, not a verdict. Read the triggered rules, "
                     "check the details, then decide."),
        ]),
        Section("quickstart", "Quick start (5 steps)", [
            ("steps", [
                "Click Run Scan. The bar fills as MemGuard collects, hashes, verifies signatures and scores.",
                "Click the Threat column header to sort the most suspicious processes to the top.",
                "Click a row. The panel at the bottom shows its command line, triggered rules, a "
                "plain-language 'why flagged' explanation, ATT&CK techniques and network connections.",
                "Click Validate Selected to re-check that process live (still running? file still on "
                "disk? hash unchanged? signed by whom?).",
                "Save CSV / Save JSON / Save Full Report to keep the evidence.",
            ]),
            ("note", "Many rows marked PARTIAL (grey)? Click Restart as Administrator for a complete view. "
                     "MemGuard stays read-only when elevated."),
        ]),
        Section("pipeline", "How a scan works", [
            ("p", "Every scan (GUI or command line) runs the same pipeline:"),
            ("steps", [
                "Collect - list every process with psutil: PID, parent, name, file path, user, "
                "command line, memory, CPU, start time. Fields Windows refuses to show are recorded "
                "as 'denied', not treated as empty.",
                "Hash - compute the SHA256 fingerprint of each program file on disk.",
                "Score - apply the detection rules (next section). Each rule that fires adds points "
                "and writes a label into triggered_rules, so every score can be explained.",
                "Memory metadata (optional) - for the riskiest processes, count writable/executable "
                "memory regions. Region attributes only; memory contents are never read.",
                "VirusTotal (optional) - look up file hashes for processes above a minimum score.",
                "Re-score - recompute with the extra evidence from steps 4-5.",
                "Display, export and remember - show the table, and append HIGH/SUSPICIOUS findings "
                "to the local history file so repeat offenders can be spotted.",
            ]),
            ("p", "The slowest step is signature verification (Windows checks each file's digital "
                  "signature). Results are cached per file, so repeat scans in the same session are faster."),
        ]),
        Section("results", "Reading the results", [
            ("h", "Threat levels"),
            ("p", _level_text() + " Points from all rules that fire are added together."),
            ("h", "Row colours"),
            ("table", (["Colour", "Meaning"], [
                ["Red", "HIGH - look at this first."],
                ["Yellow", "SUSPICIOUS - worth a look."],
                ["Green", "NEW since the previous scan in this session."],
                ["Grey", "PARTIAL - some data could not be read; the row was NOT fully assessed."],
            ])),
            ("p", "When several apply, the most important wins: HIGH > SUSPICIOUS > NEW > PARTIAL. "
                  "A real finding is never hidden behind a grey row."),
            ("h", "Confidence column"),
            ("bullets", [
                "FULL - every field was readable; the score reflects all rules.",
                "PARTIAL - Windows denied some fields (typically command line/user of SYSTEM processes "
                "in a non-administrator scan). Rules that need those fields could not run.",
            ]),
            ("h", "Scan summary bar"),
            ("bullets", [
                "Processes / Suspicious / High - counts for the current scan.",
                "VT Enriched - processes that received a VirusTotal result.",
                "Unverified - processes with PARTIAL confidence.",
                "The status line also shows '+N new / -N gone' compared with the previous scan.",
            ]),
        ]),
        Section("rules", "Detection rules", [
            ("p", "Each rule is deterministic and explainable. The label shown in triggered_rules "
                  "starts with the rule name; text in brackets is the evidence."),
            ("rules", RULE_DOCS),
            ("h", "Command-line behaviours"),
            ("p", "The suspicious_commandline rule names the behaviour(s) it found. Only the strongest "
                  "behaviour counts toward the score (they are not added together), so one noisy "
                  "command line cannot inflate itself to HIGH. 'cmd /c' on its own is deliberately "
                  "NOT a behaviour: Node, VS Code and build tools launch every child that way."),
            ("table", (["Behaviour", "Points", "ATT&CK", "Meaning"], cmd_rows)),
        ]),
        Section("controls", "Buttons and options", [
            ("table", (["Control", "What it does"], [
                ["Run Scan", "Runs the full pipeline once."],
                ["Enable memory inspection / Memory min score",
                 "Adds memory-region checks for up to 10 processes whose score is at least the "
                 "minimum (default 30)."],
                ["Enable VirusTotal / VT max requests / VT min score",
                 "Looks up file hashes on VirusTotal for processes at or above the minimum score "
                 "(default 10), up to the request limit. Needs a free API key in VT_API_KEY. "
                 "The free API allows 4 lookups a minute, so MemGuard waits 15 s between requests."],
                ["VT suspicious only", "Shortcut: only query processes scoring 21 or more."],
                ["Test VT Key", "Checks your VirusTotal key works before you start a slow scan."],
                ["Search / Threat filter", "Filter the table by text (name, path, user, PID) or level."],
                ["Show Ports", "Opens the network view: listening ports and connections with risk scores."],
                ["Save CSV / Save JSON", "Export the currently filtered rows."],
                ["Save Full Report", "Markdown report with summary, findings, ATT&CK mapping, a rule "
                                     "glossary and the full dataset - ready for an AI or a colleague."],
                ["Validate Selected", "Live re-check of one process: running, file present, hash "
                                      "unchanged, signature and signer."],
                ["Auto-refresh / Interval", "Re-scan every N seconds (minimum 10)."],
                ["Show Persistent Threats", "Processes flagged in 3 or more separate scans "
                                            "(from the history file)."],
                ["Restart as Administrator", "Relaunches MemGuard through the Windows UAC prompt for "
                                             "full visibility. Asks first; unsaved results are lost."],
                ["Right-click a row", "Copy SHA256, command line or PID."],
            ])),
        ]),
        Section("ports", "Network ports view", [
            ("p", "Show Ports lists every listening port and active connection with the owning "
                  "process, scored separately from processes:"),
            ("table", (["Signal", "Points"], [
                ["Insecure protocol (FTP 21, Telnet 23, SMTP 25, HTTP 80, POP3 110, IMAP 143)", "+30"],
                ["Exposed database/service (MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch)", "+20"],
                ["Common backdoor port (4444, 5555, 6666, 7777, 8888, 9999)", "+15"],
                ["Listening for incoming connections", "+5"],
                ["Ephemeral port (49152 or higher)", "+5"],
                ["Localhost only (127.x.x.x, ::1)", "-10"],
            ])),
            ("p", "Port levels: HIGH 35+, MEDIUM 20-34, LOW 10-19, SAFE below 10."),
        ]),
        Section("admin", "Administrator mode", [
            ("p", "Without administrator rights, Windows hides the command line and user of SYSTEM-owned "
                  "processes - typically about a third of all processes, most of them svchost.exe. "
                  "Those processes cannot trigger command-line rules, which is why they are marked PARTIAL."),
            ("bullets", [
                "GUI: Restart as Administrator. CLI: py -3.13 -m memguard --elevate",
                "Windows cannot raise the rights of a running program, so MemGuard relaunches itself "
                "through the UAC prompt and the old window closes.",
                "Never automatic. Declining the prompt keeps the current session running unchanged.",
                "Elevation only grants more READ access. MemGuard modifies nothing at any privilege level.",
            ]),
        ]),
        Section("files", "Exports and files", [
            ("table", (["File", "Contents"], [
                ["processes.csv / processes.json", "CLI scan output (current folder)."],
                ["memguard_results_*.csv/json", "GUI Save CSV / Save JSON (filtered rows)."],
                ["memguard_full_report*.md", "GUI Save Full Report."],
                ["memguard_ports_*.csv/json, memguard_ports_report*.md", "Exports from the ports window."],
                ["memguard_history.jsonl", "Append-only log of HIGH/SUSPICIOUS findings, one line per "
                                           "finding per scan. Powers Show Persistent Threats."],
                ["data/blocklist.txt", "Your own list of known-bad SHA256 hashes (one per line, # for comments)."],
            ])),
            ("note", "These files contain sensitive machine data (paths, usernames, command lines, network "
                     "addresses). Treat them like logs: share deliberately, never commit them to git."),
            ("p", "Command lines and process names are controlled by whoever started the process - "
                  "including malware. In CSV exports, any cell that starts with = + - or @ is prefixed "
                  "with a ' so Excel shows it as text instead of running it as a formula. JSON exports "
                  "keep the original text unchanged."),
        ]),
        Section("limits", "Known limits (read this)", [
            ("p", "Honest scope matters more than a reassuring screen. MemGuard is a user-mode snapshot "
                  "tool. It structurally CANNOT see:"),
            ("bullets", [
                "Kernel rootkits. A rootkit that unlinks a process from the kernel's list hides it from "
                "MemGuard, Task Manager and every other user-mode tool alike.",
                "Process hollowing / injection. Hashes and signatures are computed on the FILE ON DISK. "
                "A legitimate svchost.exe with malicious code injected into its memory still has a valid "
                "hash and signature. Memory inspection reads region attributes only, never contents.",
                "Anything between scans. A scan is a snapshot; a program that starts and exits between "
                "scans is never seen. A 60-second auto-refresh is a 60-second blind spot.",
                "Parent spoofing in full. Malware can forge its parent process; MemGuard catches "
                "impossible family trees for core processes, not every forgery.",
                "SYSTEM process details without elevation (fixable: use Administrator mode).",
            ]),
            ("p", "Use MemGuard to decide WHERE to look, then confirm with Microsoft Defender, Sysmon, "
                  "Sysinternals Autoruns/Process Explorer, or a sandbox."),
        ]),
        Section("safety", "Safety and privacy", [
            ("bullets", [
                "Read-only by design: no killing, suspending, injecting, patching or memory dumping.",
                "No changes to services, registry, firewall or files (other than the exports you save "
                "and the local history log).",
                "No telemetry, no background uploads, no automatic sync.",
                "VirusTotal is opt-in and sends SHA256 hashes only.",
                "Missing data is always shown as missing (PARTIAL), never as clean.",
            ]),
        ]),
        Section("glossary", "Glossary", [
            ("table", (["Term", "Meaning"], [
                ["Process / PID", "A running program and its numeric ID."],
                ["Parent / PPID", "The process that started this one, and its ID."],
                ["SHA256 hash", "A fingerprint of a file. Same file = same hash; one changed byte = different hash."],
                ["Authenticode signature", "A publisher's digital signature on a program file. 'Valid' "
                                           "means untampered and signed - it says nothing about whether "
                                           "the publisher is trustworthy."],
                ["MITRE ATT&CK", "A public catalogue of attacker techniques (for example T1036.005). "
                                 "Used here to name what a finding resembles."],
                ["Masquerading", "Malware disguising itself as a trusted program (name, folder or icon)."],
                ["LOLBin", "'Living-off-the-land binary': a built-in Windows tool (certutil, mshta, "
                           "rundll32...) abused to avoid bringing malware files."],
                ["Encoded PowerShell", "A PowerShell script passed as base64 text so its content is "
                                       "not readable at a glance."],
                ["LSASS", "The Windows process that holds logon credentials - a prime target for theft."],
                ["Ephemeral port", "A high port number (49152+) normally used temporarily."],
                ["UAC", "User Account Control - the Windows 'allow this app to make changes?' prompt."],
            ])),
        ]),
    ]


def environment_facts() -> list[tuple[str, str]]:
    """Live facts about this session for the About tab (read-only lookups)."""
    from .collector import is_elevated
    from .hasher import load_blocklist
    from .history_log import DEFAULT_HISTORY_PATH
    from .scorer import _signature_info_cached
    from .threat_intel import _get_vt_api_key

    try:
        elevated = "Yes (full visibility)" if is_elevated() else "No - SYSTEM process details hidden"
    except Exception:
        elevated = "Unknown"
    try:
        blocklist = f"{len(load_blocklist())} hash(es)"
    except Exception:
        blocklist = "Unavailable"
    history = DEFAULT_HISTORY_PATH.resolve()
    return [
        ("Version", f"{APP_NAME} {__version__}"),
        ("Running as Administrator", elevated),
        ("VirusTotal key", "Configured" if _get_vt_api_key() else "Not set (optional)"),
        ("Local blocklist", blocklist),
        ("History file", f"{history}{'' if history.exists() else ' (not created yet)'}"),
        ("Signature cache", f"{_signature_info_cached.cache_info().currsize} file(s) verified this session"),
        ("Python", f"{platform.python_version()} ({'packaged .exe' if getattr(sys, 'frozen', False) else 'running from source'})"),
        ("Windows", platform.platform()),
        ("Working folder", os.getcwd()),
    ]


# ── Markdown rendering (CLI --about and report glossary) ────────────────────

def _md_table(headers: list[str], rows: list[list[str]]) -> list[str]:
    def esc(cell: str) -> str:
        return str(cell).replace("|", "\\|")
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines += ["| " + " | ".join(esc(c) for c in row) + " |" for row in rows]
    return lines


def render_markdown(sections: list[Section] | None = None) -> str:
    """Render the documentation as Markdown."""
    sections = sections if sections is not None else build_sections()
    out: list[str] = [f"# {APP_NAME} {__version__}", ""]
    for section in sections:
        out += [f"## {section.title}", ""]
        for kind, payload in section.blocks:
            if kind == "p":
                out += [str(payload), ""]
            elif kind == "h":
                out += [f"### {payload}", ""]
            elif kind == "note":
                out += [f"> {payload}", ""]
            elif kind == "bullets":
                out += [f"- {item}" for item in payload] + [""]  # type: ignore[union-attr]
            elif kind == "steps":
                out += [f"{i}. {item}" for i, item in enumerate(payload, 1)] + [""]  # type: ignore[arg-type]
            elif kind == "table":
                headers, rows = payload  # type: ignore[misc]
                out += _md_table(headers, rows) + [""]
            elif kind == "rules":
                for doc in payload:  # type: ignore[union-attr]
                    out += [
                        f"**{doc.label}** - {doc.title} ({doc.points_text}; {doc.attack})",
                        "",
                        f"- What: {doc.what}",
                        f"- Why it matters: {doc.why}",
                        f"- Innocent causes: {doc.benign}",
                        "",
                    ]
    return "\n".join(out).rstrip() + "\n"


def rule_glossary_markdown(rules_seen: list[str]) -> str:
    """Glossary of only the rules that appear in a report (for exporter.py)."""
    lines: list[str] = []
    seen: set[str] = set()
    for rule in rules_seen:
        for label, doc in _RULES_BY_LABEL:
            if rule.startswith(label) and doc.key not in seen:
                seen.add(doc.key)
                lines.append(f"- **{doc.label}** ({doc.points_text}): {doc.what}")
                break
    tags_seen = sorted({
        t.strip()
        for r in rules_seen if r.startswith("suspicious_commandline (")
        for t in r[r.index("(") + 1:r.rindex(")")].split(",")
        if t.strip() in CMDLINE_TAGS
    })
    for tag in tags_seen:
        info = CMDLINE_TAGS[tag]
        lines.append(f"  - `{tag}` ({info.technique_id}): {info.summary}")
    return "\n".join(lines)
