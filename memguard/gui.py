"""Desktop GUI for MemGuard.

Provides a detailed read-only interface to run process scans,
review suspicious processes, and export results to CSV/JSON files.
"""

from __future__ import annotations

import logging
import socket
import threading
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import psutil

from .collector import ProcessRecord, collect_processes, collect_system_overview
from .exporter import (
    export_csv, export_full_report, export_json,
    export_ports_csv, export_ports_json, export_ports_report,
)
from .hasher import attach_sha256, load_blocklist
from .memory_inspector import inspect_memory
from .port_inspector import PortRecord, collect_listening_ports
from .scorer import score_processes
from .threat_intel import enrich_with_virustotal, test_vt_connection
from .validator import format_validation_report, validate_process_record

logger = logging.getLogger(__name__)


class MemGuardGUI(tk.Tk):
    """Tkinter desktop application for MemGuard scans."""

    def __init__(self) -> None:
        super().__init__()
        self.title("MemGuard Lite - Desktop GUI")
        self.geometry("1450x860")
        self.minsize(1180, 720)

        self.blocklist_hashes = load_blocklist()
        self.last_scan_time: str = "Never"
        self.overview: dict[str, float] = {}
        self.processes: list[ProcessRecord] = []
        self.filtered_processes: list[ProcessRecord] = []
        self.ports: list[PortRecord] = []
        self.filtered_ports: list[PortRecord] = []

        self.memory_enabled_var = tk.BooleanVar(value=False)
        self.memory_min_score_var = tk.StringVar(value="30")
        self.vt_enabled_var = tk.BooleanVar(value=False)
        self.vt_max_requests_var = tk.StringVar(value="8")
        self.vt_min_score_var = tk.StringVar(value="10")
        self.vt_suspicious_only_var = tk.BooleanVar(value=False)

        self.search_var = tk.StringVar(value="")
        self.threat_filter_var = tk.StringVar(value="ALL")
        self.status_var = tk.StringVar(value="Ready")

        self.summary_total_var = tk.StringVar(value="0")
        self.summary_suspicious_var = tk.StringVar(value="0")
        self.summary_high_var = tk.StringVar(value="0")
        self.summary_vt_var = tk.StringVar(value="0")
        self.summary_ram_var = tk.StringVar(value="-")
        self.summary_cpu_var = tk.StringVar(value="-")
        self.summary_scan_time_var = tk.StringVar(value=self.last_scan_time)

        self._sort_column = "threat_score"
        self._sort_desc = True

        self.prev_process_keys: set[tuple[int, str, str]] = set()
        self.new_process_keys: set[tuple[int, str, str]] = set()

        self._build_layout()

    def _build_layout(self) -> None:
        self._build_controls()
        self._build_summary()
        self._build_results_table()
        self._build_details_panel()
        self._build_context_menu()

    def _build_controls(self) -> None:
        controls = ttk.LabelFrame(self, text="Scan Controls")
        controls.pack(fill="x", padx=10, pady=(10, 6))

        ttk.Checkbutton(controls, text="Enable memory inspection", variable=self.memory_enabled_var).grid(
            row=0, column=0, sticky="w", padx=8, pady=6
        )
        ttk.Label(controls, text="Memory min score:").grid(row=0, column=1, sticky="e")
        ttk.Entry(controls, textvariable=self.memory_min_score_var, width=7).grid(row=0, column=2, padx=(4, 10))

        ttk.Checkbutton(controls, text="Enable VirusTotal", variable=self.vt_enabled_var).grid(
            row=0, column=3, sticky="w", padx=8
        )
        ttk.Label(controls, text="VT max requests:").grid(row=0, column=4, sticky="e")
        ttk.Entry(controls, textvariable=self.vt_max_requests_var, width=7).grid(row=0, column=5, padx=(4, 10))
        ttk.Label(controls, text="VT min score:").grid(row=0, column=6, sticky="e")
        ttk.Entry(controls, textvariable=self.vt_min_score_var, width=7).grid(row=0, column=7, padx=(4, 10))
        ttk.Checkbutton(controls, text="VT suspicious only", variable=self.vt_suspicious_only_var).grid(
            row=0, column=8, sticky="w", padx=8
        )
        ttk.Button(controls, text="Test VT Key", command=self.test_vt_key).grid(
            row=0, column=9, padx=(8, 4), pady=6
        )

        ttk.Label(controls, text="Search:").grid(row=1, column=0, sticky="e", padx=(8, 4), pady=(0, 8))
        search_entry = ttk.Entry(controls, textvariable=self.search_var, width=35)
        search_entry.grid(row=1, column=1, columnspan=2, sticky="w", pady=(0, 8))
        search_entry.bind("<KeyRelease>", lambda _: self._refresh_filtered_results())

        ttk.Label(controls, text="Threat filter:").grid(row=1, column=3, sticky="e", pady=(0, 8))
        threat_combo = ttk.Combobox(
            controls,
            textvariable=self.threat_filter_var,
            width=14,
            values=("ALL", "SAFE", "SUSPICIOUS", "HIGH"),
            state="readonly",
        )
        threat_combo.grid(row=1, column=4, sticky="w", padx=(4, 8), pady=(0, 8))
        threat_combo.bind("<<ComboboxSelected>>", lambda _: self._refresh_filtered_results())

        ttk.Button(controls, text="Run Scan", command=self.run_scan).grid(row=1, column=5, padx=6, pady=(0, 8))
        ttk.Button(controls, text="Show Ports", command=self.show_ports_window).grid(row=1, column=6, padx=6, pady=(0, 8))
        ttk.Button(controls, text="Save CSV", command=self.save_csv).grid(row=1, column=7, padx=6, pady=(0, 8))
        ttk.Button(controls, text="Save JSON", command=self.save_json).grid(row=1, column=8, padx=6, pady=(0, 8))
        ttk.Button(controls, text="Save Full Report", command=self.save_full_report).grid(row=1, column=9, padx=6, pady=(0, 8))
        ttk.Button(controls, text="Validate Selected", command=self.validate_selected).grid(row=1, column=10, padx=6, pady=(0, 8))

        self.progress = ttk.Progressbar(controls, mode="determinate", length=220, maximum=100)
        self.progress.grid(row=1, column=11, padx=(8, 4), pady=(0, 8), sticky="e")

        status_label = ttk.Label(controls, textvariable=self.status_var)
        status_label.grid(row=1, column=12, sticky="w", padx=(4, 8), pady=(0, 8))

    def _build_summary(self) -> None:
        summary = ttk.LabelFrame(self, text="Scan Summary")
        summary.pack(fill="x", padx=10, pady=(0, 6))

        fields = [
            ("Processes", self.summary_total_var),
            ("Suspicious", self.summary_suspicious_var),
            ("High", self.summary_high_var),
            ("VT Enriched", self.summary_vt_var),
            ("Used RAM", self.summary_ram_var),
            ("CPU", self.summary_cpu_var),
            ("Last Scan", self.summary_scan_time_var),
        ]

        for index, (label_text, var) in enumerate(fields):
            ttk.Label(summary, text=f"{label_text}:", font=("Segoe UI", 9, "bold")).grid(
                row=0,
                column=index * 2,
                padx=(10 if index == 0 else 14, 4),
                pady=8,
                sticky="e",
            )
            ttk.Label(summary, textvariable=var).grid(row=0, column=index * 2 + 1, sticky="w", pady=8)

    def _build_results_table(self) -> None:
        table_frame = ttk.LabelFrame(self, text="Processes")
        table_frame.pack(fill="both", expand=True, padx=10, pady=(0, 6))

        columns = (
            "pid",
            "ppid",
            "name",
            "user",
            "rss_mb",
            "cpu_percent",
            "threat_score",
            "threat_level",
            "memory_flag",
            "vt_malicious",
            "exe",
            "start_time",
        )

        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=18)

        headings = {
            "pid": ("PID", 70),
            "ppid": ("PPID", 70),
            "name": ("Name", 190),
            "user": ("User", 150),
            "rss_mb": ("RSS MB", 90),
            "cpu_percent": ("CPU %", 80),
            "threat_score": ("Threat", 80),
            "threat_level": ("Level", 100),
            "memory_flag": ("Mem Flag", 90),
            "vt_malicious": ("VT M", 70),
            "exe": ("Executable", 360),
            "start_time": ("Start Time", 150),
        }

        for column, (title, width) in headings.items():
            self.tree.heading(column, text=title, command=lambda c=column: self._sort_by(c))
            anchor = "e" if column in {"pid", "ppid", "rss_mb", "cpu_percent", "threat_score", "vt_malicious"} else "w"
            self.tree.column(column, width=width, anchor=anchor)

        vbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        hbar = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscroll=vbar.set, xscroll=hbar.set)

        self.tree.tag_configure("HIGH", background="#ffcccc")
        self.tree.tag_configure("SUSPICIOUS", background="#fff3cc")
        self.tree.tag_configure("NEW", background="#ccffcc")

        self.tree.grid(row=0, column=0, sticky="nsew")
        vbar.grid(row=0, column=1, sticky="ns")
        hbar.grid(row=1, column=0, sticky="ew")

        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Button-3>", self._show_context_menu)

    def _build_details_panel(self) -> None:
        panel = ttk.LabelFrame(self, text="Selected Process Details")
        panel.pack(fill="both", padx=10, pady=(0, 10))

        self.details_text = tk.Text(panel, height=7, wrap="word", font=("Consolas", 10))
        self.details_text.pack(fill="both", expand=True, padx=8, pady=8)
        self.details_text.configure(state="disabled")

    def _parse_int(self, value: str, fallback: int, minimum: int = 0) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return fallback
        return max(minimum, parsed)

    def _scan_pipeline(
        self,
        memory_enabled: bool,
        memory_min_score: int,
        vt_enabled: bool,
        vt_max_requests: int,
        vt_min_score: int,
        vt_suspicious_only: bool,
        progress_cb=None,
    ) -> tuple[dict[str, float], list[ProcessRecord], list[PortRecord]]:
        def _report(value: int, message: str) -> None:
            if progress_cb:
                progress_cb(value, message)

        _report(5, "Collecting system overview...")
        overview = collect_system_overview()

        _report(15, "Collecting processes...")
        processes = collect_processes()

        _report(25, f"Hashing {len(processes)} executables (slow step)...")
        processes = attach_sha256(processes)

        _report(70, "Scoring processes...")
        processes = score_processes(processes, blocklist_hashes=self.blocklist_hashes)

        if memory_enabled:
            _report(78, "Inspecting memory regions...")
            processes = inspect_memory(
                processes,
                min_threat_score=memory_min_score,
                max_processes=10,
            )

        effective_vt_min_score = 21 if vt_suspicious_only else vt_min_score
        if vt_enabled:
            _report(83, "Querying VirusTotal (may take a while)...")
        processes = enrich_with_virustotal(
            processes,
            enabled=vt_enabled,
            max_requests=vt_max_requests,
            min_threat_score=effective_vt_min_score,
        )

        _report(92, "Re-scoring with all evidence...")
        processes = score_processes(processes, blocklist_hashes=self.blocklist_hashes)

        _report(97, "Collecting listening ports...")
        ports = collect_listening_ports()

        return overview, processes, ports

    def _post_progress(self, value: int, message: str) -> None:
        """Thread-safe progress update — callable from the worker thread."""
        self.after(0, lambda: self._apply_progress(value, message))

    def _apply_progress(self, value: int, message: str) -> None:
        self.progress["value"] = value
        self.status_var.set(message)

    def run_scan(self) -> None:
        self.progress["value"] = 0
        self.status_var.set("Starting scan...")

        memory_enabled = self.memory_enabled_var.get()
        memory_min_score = self._parse_int(self.memory_min_score_var.get(), fallback=30, minimum=0)
        vt_enabled = self.vt_enabled_var.get()
        vt_max_requests = self._parse_int(self.vt_max_requests_var.get(), fallback=8, minimum=1)
        vt_min_score = self._parse_int(self.vt_min_score_var.get(), fallback=20, minimum=0)
        vt_suspicious_only = self.vt_suspicious_only_var.get()

        def _worker() -> None:
            try:
                overview, processes, ports = self._scan_pipeline(
                    memory_enabled=memory_enabled,
                    memory_min_score=memory_min_score,
                    vt_enabled=vt_enabled,
                    vt_max_requests=vt_max_requests,
                    vt_min_score=vt_min_score,
                    vt_suspicious_only=vt_suspicious_only,
                    progress_cb=self._post_progress,
                )
                self.after(0, lambda: self._on_scan_success(overview, processes, ports))
            except Exception as exc:  # pragma: no cover - GUI runtime safety
                logger.exception("Scan failed")
                self.after(0, lambda: self._on_scan_error(exc))

        threading.Thread(target=_worker, daemon=True).start()

    def _on_scan_success(self, overview: dict[str, float], processes: list[ProcessRecord], ports: list[PortRecord]) -> None:
        self.progress["value"] = 100
        self.overview = overview

        # Compute scan diff before overwriting self.processes
        current_keys: set[tuple[int, str, str]] = {
            (int(p.get("pid", 0)), str(p.get("name", "")), str(p.get("exe", "")))
            for p in processes
        }
        if self.prev_process_keys:
            self.new_process_keys = current_keys - self.prev_process_keys
            gone_count = len(self.prev_process_keys - current_keys)
        else:
            self.new_process_keys = set()
            gone_count = 0
        self.prev_process_keys = current_keys

        self.processes = processes
        self.ports = ports
        self.filtered_ports = ports
        self.last_scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.summary_scan_time_var.set(self.last_scan_time)

        self._refresh_filtered_results()
        self._refresh_summary()

        new_count = len(self.new_process_keys)
        status = f"Scan complete — {len(processes)} processes, {len(ports)} ports"
        if new_count or gone_count:
            status += f" | delta: +{new_count} new, -{gone_count} gone"
        if self.vt_enabled_var.get():
            vt_enriched = sum(isinstance(p.get("vt_malicious"), int) for p in processes)
            if vt_enriched == 0:
                vt_min = self._parse_int(self.vt_min_score_var.get(), fallback=10, minimum=0)
                status += f" | VT: no processes scored ≥ {vt_min} — try lowering VT min score"
            else:
                status += f" | VT: {vt_enriched} process(es) enriched"
        self.status_var.set(status)

    def _on_scan_error(self, exc: Exception) -> None:
        self.progress["value"] = 0
        self.status_var.set("Scan failed")
        messagebox.showerror("MemGuard Scan Error", f"Scan failed:\n{exc}")

    def _current_filtered(self) -> list[ProcessRecord]:
        search_text = self.search_var.get().strip().lower()
        selected_level = self.threat_filter_var.get().strip().upper()

        result = self.processes

        if selected_level and selected_level != "ALL":
            result = [
                process
                for process in result
                if str(process.get("threat_level", "SAFE")).upper() == selected_level
            ]

        if search_text:
            result = [
                process
                for process in result
                if (
                    search_text in str(process.get("name", "")).lower()
                    or search_text in str(process.get("exe", "")).lower()
                    or search_text in str(process.get("user", "")).lower()
                    or search_text in str(process.get("pid", "")).lower()
                )
            ]

        return result

    def _sort_by(self, column: str) -> None:
        if self._sort_column == column:
            self._sort_desc = not self._sort_desc
        else:
            self._sort_column = column
            self._sort_desc = True

        self._refresh_filtered_results()

    def _sort_rows(self, rows: list[ProcessRecord]) -> list[ProcessRecord]:
        numeric_columns = {"pid", "ppid", "rss_mb", "cpu_percent", "threat_score", "vt_malicious"}

        if self._sort_column in numeric_columns:
            return sorted(
                rows,
                key=lambda process: float(process.get(self._sort_column, 0) or 0),
                reverse=self._sort_desc,
            )

        return sorted(
            rows,
            key=lambda process: str(process.get(self._sort_column, "") or "").lower(),
            reverse=self._sort_desc,
        )

    def _refresh_filtered_results(self) -> None:
        filtered = self._current_filtered()
        self.filtered_processes = self._sort_rows(filtered)

        self.tree.delete(*self.tree.get_children())

        for process in self.filtered_processes:
            level = str(process.get("threat_level", "SAFE")).upper()
            proc_key = (int(process.get("pid", 0)), str(process.get("name", "")), str(process.get("exe", "")))
            if level == "HIGH":
                row_tag = "HIGH"
            elif level == "SUSPICIOUS":
                row_tag = "SUSPICIOUS"
            elif proc_key in self.new_process_keys:
                row_tag = "NEW"
            else:
                row_tag = ""
            self.tree.insert(
                "",
                "end",
                tags=(row_tag,) if row_tag else (),
                values=(
                    process.get("pid", 0),
                    process.get("ppid", 0),
                    process.get("name", "N/A"),
                    process.get("user", "N/A"),
                    f"{float(process.get('rss_mb', 0) or 0):.2f}",
                    f"{float(process.get('cpu_percent', 0) or 0):.1f}",
                    int(process.get("threat_score", 0) or 0),
                    process.get("threat_level", "SAFE"),
                    process.get("memory_flag", "-"),
                    int(process.get("vt_malicious", 0) or 0),
                    process.get("exe", "N/A"),
                    process.get("start_time", "N/A"),
                ),
            )

        self._refresh_summary()
        self._clear_details_if_needed()

    def _refresh_summary(self) -> None:
        total = len(self.filtered_processes)
        suspicious = sum(process.get("threat_level") == "SUSPICIOUS" for process in self.filtered_processes)
        high = sum(process.get("threat_level") == "HIGH" for process in self.filtered_processes)
        vt_enriched = sum(isinstance(process.get("vt_malicious"), int) for process in self.filtered_processes)

        self.summary_total_var.set(str(total))
        self.summary_suspicious_var.set(str(suspicious))
        self.summary_high_var.set(str(high))
        self.summary_vt_var.set(str(vt_enriched))

        if self.overview:
            used_ram = float(self.overview.get("used_ram_mb", 0.0) or 0.0)
            cpu = float(self.overview.get("cpu_percent", 0.0) or 0.0)
            self.summary_ram_var.set(f"{used_ram:,.2f} MB")
            self.summary_cpu_var.set(f"{cpu:.1f}%")
        else:
            self.summary_ram_var.set("-")
            self.summary_cpu_var.set("-")

    def _clear_details_if_needed(self) -> None:
        selected = self.tree.selection()
        if not selected:
            self._set_details_text("Select a process row to inspect command line and triggered rules.")

    def _on_select(self, _: object) -> None:
        if not (process := self._get_selected_process()):
            return

        base = self._build_process_details(process)
        pid = int(process.get("pid", 0) or 0)
        conn_text = self._get_process_connections_text(pid)
        self._set_details_text(f"{base}\n\nConnections:\n{conn_text}")

    def _get_selected_process(self) -> ProcessRecord | None:
        selected = self.tree.selection()
        if not selected:
            return None

        item_id = selected[0]
        row_index = self.tree.index(item_id)
        if row_index < 0 or row_index >= len(self.filtered_processes):
            return None

        return self.filtered_processes[row_index]

    def _build_process_details(self, process: ProcessRecord) -> str:
        rules = process.get("triggered_rules") or []
        if isinstance(rules, list):
            rules_text = ", ".join(str(rule) for rule in rules) if rules else "-"
        else:
            rules_text = str(rules)

        return (
            f"PID: {process.get('pid', 'N/A')}\n"
            f"Name: {process.get('name', 'N/A')}\n"
            f"Threat: {process.get('threat_level', 'SAFE')} (score {process.get('threat_score', 0)})\n"
            f"SHA256: {process.get('sha256', 'N/A')}\n"
            f"Memory Flag: {process.get('memory_flag', '-')}, Memory Score: {process.get('memory_anomaly_score', '-') }\n"
            f"VT (M/S/H): {process.get('vt_malicious', 0)}/{process.get('vt_suspicious', 0)}/{process.get('vt_harmless', 0)}\n"
            f"Triggered Rules: {rules_text}\n"
            f"Command Line: {process.get('cmdline', 'N/A')}"
        )

    def validate_selected(self) -> None:
        if not (process := self._get_selected_process()):
            messagebox.showinfo("MemGuard Validation", "Select a process row first.")
            return

        self.status_var.set("Validating selected process...")

        def _worker() -> None:
            report = validate_process_record(process)
            pid = int(process.get("pid", 0) or 0)
            conn_text = self._get_process_connections_text(pid)

            def _apply_result() -> None:
                base = self._build_process_details(process)
                validation = format_validation_report(report)
                self._set_details_text(
                    f"{base}\n\nConnections:\n{conn_text}\n\n{validation}"
                )
                self.status_var.set("Validation complete")

            self.after(0, _apply_result)

        threading.Thread(target=_worker, daemon=True).start()

    def _set_details_text(self, text: str) -> None:
        self.details_text.configure(state="normal")
        self.details_text.delete("1.0", tk.END)
        self.details_text.insert(tk.END, text)
        self.details_text.configure(state="disabled")

    def _current_scan_options(self) -> dict[str, object]:
        return {
            "memory_enabled": self.memory_enabled_var.get(),
            "memory_min_score": self._parse_int(self.memory_min_score_var.get(), fallback=30, minimum=0),
            "virustotal_enabled": self.vt_enabled_var.get(),
            "virustotal_max_requests": self._parse_int(self.vt_max_requests_var.get(), fallback=8, minimum=1),
            "virustotal_min_score": self._parse_int(self.vt_min_score_var.get(), fallback=20, minimum=0),
            "virustotal_suspicious_only": self.vt_suspicious_only_var.get(),
        }

    def _current_filter_state(self) -> dict[str, object]:
        return {
            "search": self.search_var.get().strip() or "<none>",
            "threat_filter": self.threat_filter_var.get().strip().upper() or "ALL",
            "filtered_result_count": len(self.filtered_processes),
            "full_result_count": len(self.processes),
        }

    def _export_to_path(self, destination: Path, format_name: str) -> None:
        if not self.filtered_processes:
            messagebox.showinfo("MemGuard Export", "No filtered results available to export.")
            return

        if format_name == "csv":
            export_csv(self.filtered_processes, path=str(destination))
        else:
            export_json(self.filtered_processes, path=str(destination))

        self.status_var.set(f"Saved {format_name.upper()} to {destination}")
        messagebox.showinfo("MemGuard Export", f"Saved {format_name.upper()} file:\n{destination}")

    def save_csv(self) -> None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if path := filedialog.asksaveasfilename(
            title="Save MemGuard CSV",
            defaultextension=".csv",
            initialfile=f"memguard_results_{timestamp}.csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
        ):
            self._export_to_path(Path(path), "csv")

    def save_json(self) -> None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if path := filedialog.asksaveasfilename(
            title="Save MemGuard JSON",
            defaultextension=".json",
            initialfile=f"memguard_results_{timestamp}.json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
        ):
            self._export_to_path(Path(path), "json")

    def save_full_report(self) -> None:
        if not self.processes:
            messagebox.showinfo("MemGuard Report", "Run a scan first to generate a full report.")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            title="Save MemGuard Full Report",
            defaultextension=".md",
            initialfile=f"memguard_full_report_{timestamp}.md",
            filetypes=[("Markdown Files", "*.md"), ("Text Files", "*.txt"), ("All Files", "*.*")],
        )
        if not path:
            return

        destination = export_full_report(
            self.processes,
            overview=self.overview,
            path=path,
            scan_options=self._current_scan_options(),
            generated_at=self.last_scan_time,
            active_filters=self._current_filter_state(),
        )

        self.status_var.set(f"Saved full report to {destination}")
        messagebox.showinfo(
            "MemGuard Report",
            "Saved AI-friendly full report:\n"
            f"{destination}",
        )

    def show_ports_window(self) -> None:
        if not self.ports:
            messagebox.showinfo("MemGuard Ports", "Run a scan first to view listening ports.")
            return

        ports_window = tk.Toplevel(self)
        ports_window.title("MemGuard - Listening Ports")
        ports_window.geometry("1200x600")
        ports_window.minsize(900, 400)

        # Create frame for ports table
        table_frame = ttk.LabelFrame(ports_window, text="Listening Ports & Connections")
        table_frame.pack(fill="both", expand=True, padx=10, pady=10)

        columns = ("Port", "Protocol", "State", "Process", "PID", "Risk", "Local Addr", "Remote Addr")
        tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=20)

        headings = {
            "Port": ("Port", 60),
            "Protocol": ("Protocol", 70),
            "State": ("State", 100),
            "Process": ("Process", 150),
            "PID": ("PID", 60),
            "Risk": ("Risk", 80),
            "Local Addr": ("Local Addr", 180),
            "Remote Addr": ("Remote Addr", 180),
        }

        for column, (title, width) in headings.items():
            tree.heading(column, text=title)
            anchor = "e" if column in {"Port", "PID"} else "w"
            tree.column(column, width=width, anchor=anchor)

        tree.tag_configure("HIGH", background="#ffcccc")
        tree.tag_configure("MEDIUM", background="#ffe5cc")
        tree.tag_configure("LOW", background="#fff3cc")

        sorted_ports = sorted(self.ports, key=lambda p: p["risk_score"], reverse=True)

        for port in sorted_ports:
            level = port["risk_level"]
            row_tag = level if level in {"HIGH", "MEDIUM", "LOW"} else ""
            tree.insert(
                "",
                "end",
                tags=(row_tag,) if row_tag else (),
                values=(
                    port["port"],
                    port["protocol"],
                    port["state"],
                    port["process_name"],
                    port["pid"] or "-",
                    f"{level} ({port['risk_score']})",
                    port["local_addr"],
                    port["remote_addr"],
                ),
            )

        vbar = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
        hbar = ttk.Scrollbar(table_frame, orient="horizontal", command=tree.xview)
        tree.configure(yscroll=vbar.set, xscroll=hbar.set)

        tree.grid(row=0, column=0, sticky="nsew")
        vbar.grid(row=0, column=1, sticky="ns")
        hbar.grid(row=1, column=0, sticky="ew")

        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        # Details panel
        details_frame = ttk.LabelFrame(ports_window, text="Port Details", height=150)
        details_frame.pack(fill="x", padx=10, pady=(0, 10))

        details_text = tk.Text(details_frame, height=6, wrap="word", font=("Consolas", 9))
        details_text.pack(fill="both", expand=True, padx=8, pady=8)
        details_text.configure(state="disabled")

        def on_port_select(_: object) -> None:
            selected = tree.selection()
            if not selected:
                return

            row_index = tree.index(selected[0])
            if row_index < 0 or row_index >= len(sorted_ports):
                return

            port_rec = sorted_ports[row_index]
            rules_text = ", ".join(port_rec["triggered_rules"]) if port_rec["triggered_rules"] else "-"
            details = (
                f"Port: {port_rec['port']}\n"
                f"Protocol: {port_rec['protocol']}\n"
                f"State: {port_rec['state']}\n"
                f"Process: {port_rec['process_name']} (PID {port_rec['pid']})\n"
                f"Risk Level: {port_rec['risk_level']} (Score: {port_rec['risk_score']})\n"
                f"Local Address: {port_rec['local_addr']}\n"
                f"Remote Address: {port_rec['remote_addr']}\n"
                f"Triggered Rules: {rules_text}"
            )
            details_text.configure(state="normal")
            details_text.delete("1.0", tk.END)
            details_text.insert(tk.END, details)
            details_text.configure(state="disabled")

        tree.bind("<<TreeviewSelect>>", on_port_select)

        def save_ports_report() -> None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = filedialog.asksaveasfilename(
                title="Save Ports Report",
                defaultextension=".md",
                initialfile=f"memguard_ports_report_{timestamp}.md",
                filetypes=[("Markdown Files", "*.md"), ("Text Files", "*.txt"), ("All Files", "*.*")],
                parent=ports_window,
            )
            if not path:
                return
            destination = export_ports_report(self.ports, path=path, generated_at=self.last_scan_time)
            messagebox.showinfo("MemGuard Ports", f"Saved ports report:\n{destination}", parent=ports_window)

        def save_ports_csv() -> None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = filedialog.asksaveasfilename(
                title="Save Ports CSV",
                defaultextension=".csv",
                initialfile=f"memguard_ports_{timestamp}.csv",
                filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
                parent=ports_window,
            )
            if not path:
                return
            destination = export_ports_csv(self.ports, path=path)
            messagebox.showinfo("MemGuard Ports", f"Saved CSV:\n{destination}", parent=ports_window)

        def save_ports_json_file() -> None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = filedialog.asksaveasfilename(
                title="Save Ports JSON",
                defaultextension=".json",
                initialfile=f"memguard_ports_{timestamp}.json",
                filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
                parent=ports_window,
            )
            if not path:
                return
            destination = export_ports_json(self.ports, path=path)
            messagebox.showinfo("MemGuard Ports", f"Saved JSON:\n{destination}", parent=ports_window)

        btn_frame = ttk.Frame(ports_window)
        btn_frame.pack(fill="x", padx=10, pady=(0, 4))
        ttk.Button(btn_frame, text="Save Report (.md)", command=save_ports_report).pack(side="right", padx=4)
        ttk.Button(btn_frame, text="Save JSON", command=save_ports_json_file).pack(side="right", padx=4)
        ttk.Button(btn_frame, text="Save CSV", command=save_ports_csv).pack(side="right", padx=4)

        # Summary at bottom
        summary_frame = ttk.LabelFrame(ports_window, text="Summary")
        summary_frame.pack(fill="x", padx=10, pady=(0, 10))

        high_risk = sum(p["risk_level"] == "HIGH" for p in self.ports)
        medium_risk = sum(p["risk_level"] == "MEDIUM" for p in self.ports)
        is_localhost_only = sum("127.0.0.1" in p["local_addr"] for p in self.ports)

        summary_text = (
            f"Total Ports: {len(self.ports)} | "
            f"High Risk: {high_risk} | "
            f"Medium Risk: {medium_risk} | "
            f"Localhost Only: {is_localhost_only}"
        )
        ttk.Label(summary_frame, text=summary_text).pack(padx=10, pady=8)

    # ── Test VT Key ───────────────────────────────────────────

    def test_vt_key(self) -> None:
        self.status_var.set("Testing VT API key…")

        def _worker() -> None:
            success, message = test_vt_connection()

            def _apply() -> None:
                self.status_var.set("VT key test complete")
                if success:
                    messagebox.showinfo("VT Key Test", message)
                else:
                    messagebox.showerror("VT Key Test", message)

            self.after(0, _apply)

        threading.Thread(target=_worker, daemon=True).start()

    # ── Right-click copy ──────────────────────────────────────

    def _build_context_menu(self) -> None:
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Copy SHA256",      command=self._copy_sha256)
        self.context_menu.add_command(label="Copy Command Line", command=self._copy_cmdline)
        self.context_menu.add_command(label="Copy PID",          command=self._copy_pid)

    def _show_context_menu(self, event: tk.Event) -> None:  # type: ignore[type-arg]
        row = self.tree.identify_row(event.y)
        if row:
            self.tree.selection_set(row)
            self.context_menu.post(event.x_root, event.y_root)

    def _copy_to_clipboard(self, value: str, label: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(value)
        self.status_var.set(f"Copied {label} to clipboard")

    def _copy_sha256(self) -> None:
        if process := self._get_selected_process():
            self._copy_to_clipboard(str(process.get("sha256", "N/A")), "SHA256")

    def _copy_cmdline(self) -> None:
        if process := self._get_selected_process():
            self._copy_to_clipboard(str(process.get("cmdline", "N/A")), "command line")

    def _copy_pid(self) -> None:
        if process := self._get_selected_process():
            self._copy_to_clipboard(str(process.get("pid", "N/A")), "PID")

    # ── Network connections ───────────────────────────────────

    def _get_process_connections_text(self, pid: int) -> str:
        if not pid:
            return "  N/A"
        try:
            proc = psutil.Process(pid)
            conns = proc.net_connections(kind="inet")
        except psutil.AccessDenied:
            return "  (access denied)"
        except psutil.NoSuchProcess:
            return "  (process no longer running)"
        except Exception as exc:
            return f"  (error: {exc})"

        if not conns:
            return "  none"

        lines = []
        for c in conns[:8]:
            proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
            local = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "?"
            remote = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "*"
            status = f" [{c.status}]" if c.status else ""
            lines.append(f"  {proto}  {local} → {remote}{status}")

        if len(conns) > 8:
            lines.append(f"  … and {len(conns) - 8} more")
        return "\n".join(lines)


def launch_gui() -> None:
    """Launch the MemGuard desktop GUI."""
    app = MemGuardGUI()
    app.mainloop()
