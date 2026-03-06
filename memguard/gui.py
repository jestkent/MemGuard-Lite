"""Desktop GUI for MemGuard.

Provides a detailed read-only interface to run process scans,
review suspicious processes, and export results to CSV/JSON files.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .collector import ProcessRecord, collect_processes, collect_system_overview
from .exporter import export_csv, export_json
from .hasher import attach_sha256, load_blocklist
from .memory_inspector import inspect_memory
from .scorer import score_processes
from .threat_intel import enrich_with_virustotal
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

        self.memory_enabled_var = tk.BooleanVar(value=False)
        self.memory_min_score_var = tk.StringVar(value="30")
        self.vt_enabled_var = tk.BooleanVar(value=False)
        self.vt_max_requests_var = tk.StringVar(value="8")
        self.vt_min_score_var = tk.StringVar(value="20")
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

        self._build_layout()

    def _build_layout(self) -> None:
        self._build_controls()
        self._build_summary()
        self._build_results_table()
        self._build_details_panel()

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

        ttk.Label(controls, text="Search:").grid(row=1, column=0, sticky="e", padx=(8, 4), pady=(0, 8))
        search_entry = ttk.Entry(controls, textvariable=self.search_var, width=35)
        search_entry.grid(row=1, column=1, columnspan=2, sticky="w", pady=(0, 8))
        search_entry.bind("<KeyRelease>", lambda _event: self._refresh_filtered_results())

        ttk.Label(controls, text="Threat filter:").grid(row=1, column=3, sticky="e", pady=(0, 8))
        threat_combo = ttk.Combobox(
            controls,
            textvariable=self.threat_filter_var,
            width=14,
            values=("ALL", "SAFE", "SUSPICIOUS", "HIGH"),
            state="readonly",
        )
        threat_combo.grid(row=1, column=4, sticky="w", padx=(4, 8), pady=(0, 8))
        threat_combo.bind("<<ComboboxSelected>>", lambda _event: self._refresh_filtered_results())

        ttk.Button(controls, text="Run Scan", command=self.run_scan).grid(row=1, column=5, padx=6, pady=(0, 8))
        ttk.Button(controls, text="Save CSV", command=self.save_csv).grid(row=1, column=6, padx=6, pady=(0, 8))
        ttk.Button(controls, text="Save JSON", command=self.save_json).grid(row=1, column=7, padx=6, pady=(0, 8))
        ttk.Button(controls, text="Validate Selected", command=self.validate_selected).grid(row=1, column=8, padx=6, pady=(0, 8))

        self.progress = ttk.Progressbar(controls, mode="indeterminate", length=220)
        self.progress.grid(row=1, column=9, padx=(8, 4), pady=(0, 8), sticky="e")

        status_label = ttk.Label(controls, textvariable=self.status_var)
        status_label.grid(row=1, column=10, sticky="w", padx=(4, 8), pady=(0, 8))

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

        self.tree.grid(row=0, column=0, sticky="nsew")
        vbar.grid(row=0, column=1, sticky="ns")
        hbar.grid(row=1, column=0, sticky="ew")

        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self._on_select)

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
    ) -> tuple[dict[str, float], list[ProcessRecord]]:
        overview = collect_system_overview()
        processes = collect_processes()
        processes = attach_sha256(processes)
        processes = score_processes(processes, blocklist_hashes=self.blocklist_hashes)

        if memory_enabled:
            processes = inspect_memory(
                processes,
                min_threat_score=memory_min_score,
                max_processes=10,
            )

        effective_vt_min_score = 21 if vt_suspicious_only else vt_min_score
        processes = enrich_with_virustotal(
            processes,
            enabled=vt_enabled,
            max_requests=vt_max_requests,
            min_threat_score=effective_vt_min_score,
        )

        processes = score_processes(processes, blocklist_hashes=self.blocklist_hashes)
        return overview, processes

    def run_scan(self) -> None:
        self.status_var.set("Scanning processes...")
        self.progress.start(8)

        memory_enabled = self.memory_enabled_var.get()
        memory_min_score = self._parse_int(self.memory_min_score_var.get(), fallback=30, minimum=0)
        vt_enabled = self.vt_enabled_var.get()
        vt_max_requests = self._parse_int(self.vt_max_requests_var.get(), fallback=8, minimum=1)
        vt_min_score = self._parse_int(self.vt_min_score_var.get(), fallback=20, minimum=0)
        vt_suspicious_only = self.vt_suspicious_only_var.get()

        def _worker() -> None:
            try:
                overview, processes = self._scan_pipeline(
                    memory_enabled=memory_enabled,
                    memory_min_score=memory_min_score,
                    vt_enabled=vt_enabled,
                    vt_max_requests=vt_max_requests,
                    vt_min_score=vt_min_score,
                    vt_suspicious_only=vt_suspicious_only,
                )
                self.after(0, lambda: self._on_scan_success(overview, processes))
            except Exception as exc:  # pragma: no cover - GUI runtime safety
                logger.exception("Scan failed")
                self.after(0, lambda: self._on_scan_error(exc))

        threading.Thread(target=_worker, daemon=True).start()

    def _on_scan_success(self, overview: dict[str, float], processes: list[ProcessRecord]) -> None:
        self.progress.stop()
        self.overview = overview
        self.processes = processes
        self.last_scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.summary_scan_time_var.set(self.last_scan_time)

        self._refresh_filtered_results()
        self._refresh_summary()

        self.status_var.set(f"Scan complete - {len(processes)} processes")

    def _on_scan_error(self, exc: Exception) -> None:
        self.progress.stop()
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
            self.tree.insert(
                "",
                "end",
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
        suspicious = sum(1 for process in self.filtered_processes if process.get("threat_level") == "SUSPICIOUS")
        high = sum(1 for process in self.filtered_processes if process.get("threat_level") == "HIGH")
        vt_enriched = sum(1 for process in self.filtered_processes if isinstance(process.get("vt_malicious"), int))

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

    def _on_select(self, _event: object) -> None:
        process = self._get_selected_process()
        if not process:
            return

        self._set_details_text(self._build_process_details(process))

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
        process = self._get_selected_process()
        if not process:
            messagebox.showinfo("MemGuard Validation", "Select a process row first.")
            return

        self.status_var.set("Validating selected process...")

        def _worker() -> None:
            report = validate_process_record(process)

            def _apply_result() -> None:
                base = self._build_process_details(process)
                validation = format_validation_report(report)
                self._set_details_text(f"{base}\n\n{validation}")
                self.status_var.set("Validation complete")

            self.after(0, _apply_result)

        threading.Thread(target=_worker, daemon=True).start()

    def _set_details_text(self, text: str) -> None:
        self.details_text.configure(state="normal")
        self.details_text.delete("1.0", tk.END)
        self.details_text.insert(tk.END, text)
        self.details_text.configure(state="disabled")

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
        path = filedialog.asksaveasfilename(
            title="Save MemGuard CSV",
            defaultextension=".csv",
            initialfile=f"memguard_results_{timestamp}.csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
        )
        if path:
            self._export_to_path(Path(path), "csv")

    def save_json(self) -> None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            title="Save MemGuard JSON",
            defaultextension=".json",
            initialfile=f"memguard_results_{timestamp}.json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
        )
        if path:
            self._export_to_path(Path(path), "json")


def launch_gui() -> None:
    """Launch the MemGuard desktop GUI."""
    app = MemGuardGUI()
    app.mainloop()
