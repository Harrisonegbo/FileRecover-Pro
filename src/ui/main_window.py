"""
Retrievo main window – professional forensic recovery suite UI.
"""

from __future__ import annotations

import logging
import threading
import tkinter as tk
import tkinter.filedialog as fd
import tkinter.messagebox as mb
from pathlib import Path
from typing import List, Optional

import customtkinter as ctk

from core.scanner import RecoveryScanner, RecoverableItem
from core.recover import RecoveryEngine
from core.disk_access import list_physical_drives, list_volumes
from core.forensics import CaseInfo, hash_bytes, hash_file
from ui.results_view import ResultsView
from ui.widgets import ProgressPanel, StatusBar
from ui.dialogs import (
    CaseDialog, SettingsDialog, AboutDialog, HexViewerDialog, HashResultDialog,
)

logger = logging.getLogger("Retrievo")


class MainWindow(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Retrievo – Forensic File Recovery Suite")
        self.geometry("1280x800")
        self.minsize(1024, 680)

        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        log_dir = Path.home() / "Retrievo_logs"
        log_dir.mkdir(exist_ok=True)
        self.scanner = RecoveryScanner(
            progress_callback=self._on_progress,
            log_path=str(log_dir / "scan.log"),
        )
        self.engine = RecoveryEngine(progress_callback=self._on_progress)
        self.case = CaseInfo()
        self.engine.set_case(self.case)
        self.current_items: List[RecoverableItem] = []
        self._scan_thread: Optional[threading.Thread] = None
        self.settings = {
            "media_only": False,
            "compute_hashes": True,
            "auto_select_high": True,
            "theme": "Dark",
        }

        self._build_menu()
        self._build_ui()
        self._show_disclaimer()
        self._update_case_label()

    # ------------------------------------------------------------------
    # Menu bar (native tk Menu for reliability)
    # ------------------------------------------------------------------
    def _build_menu(self) -> None:
        menubar = tk.Menu(self)

        file_m = tk.Menu(menubar, tearoff=0)
        file_m.add_command(label="Open Disk Image…", command=self._browse_file, accelerator="Ctrl+O")
        file_m.add_command(label="Open Folder…", command=self._browse_folder)
        file_m.add_command(label="List Drives / Volumes…", command=self._list_drives)
        file_m.add_separator()
        file_m.add_command(label="Case Information…", command=self._edit_case)
        file_m.add_command(label="Export Case Report…", command=self._export_case_summary)
        file_m.add_separator()
        file_m.add_command(label="Exit", command=self.destroy)
        menubar.add_cascade(label="File", menu=file_m)

        scan_m = tk.Menu(menubar, tearoff=0)
        scan_m.add_command(label="Signature Carve (Deep)", command=lambda: self._set_mode_and_scan("carve"))
        scan_m.add_command(label="Media-Only Carve", command=lambda: self._set_mode_and_scan("carve_media"))
        scan_m.add_command(label="Recycle Bin Recovery", command=lambda: self._set_mode_and_scan("recycle"))
        scan_m.add_command(label="Quick Media Scan", command=lambda: self._set_mode_and_scan("quick"))
        scan_m.add_separator()
        scan_m.add_command(label="Stop Current Scan", command=self._stop_scan)
        menubar.add_cascade(label="Scan", menu=scan_m)

        tools_m = tk.Menu(menubar, tearoff=0)
        tools_m.add_command(label="Hash Selected Files…", command=self._hash_selected)
        tools_m.add_command(label="Hex View Selected…", command=self._hex_selected)
        tools_m.add_separator()
        tools_m.add_command(label="Recover Selected…", command=self._start_recover)
        tools_m.add_separator()
        tools_m.add_command(label="Settings…", command=self._open_settings)
        menubar.add_cascade(label="Tools", menu=tools_m)

        view_m = tk.Menu(menubar, tearoff=0)
        view_m.add_command(label="Select All Results", command=lambda: self.results.select_all())
        view_m.add_command(label="Select None", command=lambda: self.results.select_none())
        view_m.add_command(label="Select High Confidence", command=lambda: self.results.select_high())
        menubar.add_cascade(label="View", menu=view_m)

        help_m = tk.Menu(menubar, tearoff=0)
        help_m.add_command(label="Forensic Best Practices", command=self._show_disclaimer)
        help_m.add_command(label="About Retrievo", command=lambda: AboutDialog(self))
        menubar.add_cascade(label="Help", menu=help_m)

        self.configure(menu=menubar)
        self.bind("<Control-o>", lambda e: self._browse_file())

    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # Case strip
        case_bar = ctk.CTkFrame(self, height=36)
        case_bar.grid(row=0, column=0, sticky="ew", padx=10, pady=(8, 2))
        case_bar.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(case_bar, text="Retrievo", font=ctk.CTkFont(size=16, weight="bold")).grid(
            row=0, column=0, padx=12, pady=6
        )
        self.case_label = ctk.CTkLabel(case_bar, text="", anchor="w", text_color="gray70")
        self.case_label.grid(row=0, column=1, sticky="ew", padx=8)
        ctk.CTkButton(case_bar, text="Case…", width=70, command=self._edit_case).grid(
            row=0, column=2, padx=8, pady=4
        )

        # Mode toolbar
        toolbar = ctk.CTkFrame(self)
        toolbar.grid(row=1, column=0, sticky="ew", padx=10, pady=4)
        self.mode_var = ctk.StringVar(value="carve")
        modes = [
            ("Deep Carve", "carve"),
            ("Media Carve", "carve_media"),
            ("Recycle Bin", "recycle"),
            ("Quick Scan", "quick"),
        ]
        for i, (text, value) in enumerate(modes):
            ctk.CTkRadioButton(
                toolbar, text=text, variable=self.mode_var, value=value
            ).grid(row=0, column=i, padx=10, pady=8)

        # Main content
        content = ctk.CTkFrame(self)
        content.grid(row=2, column=0, sticky="nsew", padx=10, pady=4)
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(1, weight=1)

        controls = ctk.CTkFrame(content)
        controls.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        controls.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(controls, text="Source:").grid(row=0, column=0, padx=(8, 4), pady=8)
        self.target_var = ctk.StringVar(value="")
        ctk.CTkEntry(
            controls, textvariable=self.target_var,
            placeholder_text="Disk image (.dd/.img/.raw), folder, \\\\.\\PhysicalDriveN or \\\\.\\C:",
        ).grid(row=0, column=1, sticky="ew", padx=4, pady=8)

        ctk.CTkButton(controls, text="Image…", width=80, command=self._browse_file).grid(row=0, column=2, padx=2, pady=8)
        ctk.CTkButton(controls, text="Folder…", width=80, command=self._browse_folder).grid(row=0, column=3, padx=2, pady=8)
        ctk.CTkButton(controls, text="Drives", width=70, command=self._list_drives).grid(row=0, column=4, padx=2, pady=8)

        self.scan_btn = ctk.CTkButton(
            controls, text="▶ Start Scan", width=120,
            fg_color="#27ae60", hover_color="#1e8449", command=self._start_scan,
        )
        self.scan_btn.grid(row=0, column=5, padx=4, pady=8)
        self.stop_btn = ctk.CTkButton(
            controls, text="⏹ Stop", width=70,
            fg_color="#c0392b", hover_color="#922b21",
            command=self._stop_scan, state="disabled",
        )
        self.stop_btn.grid(row=0, column=6, padx=4, pady=8)

        self.results = ResultsView(
            content,
            on_selection_change=self._update_recover_btn,
            on_item_activate=self._on_item_activate,
        )
        self.results.grid(row=1, column=0, sticky="nsew")

        self.progress_panel = ProgressPanel(content)
        self.progress_panel.grid(row=2, column=0, sticky="ew", pady=(6, 0))

        recover_bar = ctk.CTkFrame(content)
        recover_bar.grid(row=3, column=0, sticky="ew", pady=(6, 0))
        recover_bar.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(recover_bar, text="Recover to:").grid(row=0, column=0, padx=8, pady=8)
        self.dest_var = ctk.StringVar(value=str(Path.home() / "Retrievo_Recovered"))
        ctk.CTkEntry(recover_bar, textvariable=self.dest_var).grid(row=0, column=1, sticky="ew", padx=4, pady=8)
        ctk.CTkButton(recover_bar, text="Browse…", width=80, command=self._browse_dest).grid(row=0, column=2, padx=4, pady=8)

        self.hash_btn = ctk.CTkButton(
            recover_bar, text="🔏 Hash", width=80, command=self._hash_selected, state="disabled",
        )
        self.hash_btn.grid(row=0, column=3, padx=2, pady=8)
        self.hex_btn = ctk.CTkButton(
            recover_bar, text="Hex", width=70, command=self._hex_selected, state="disabled",
        )
        self.hex_btn.grid(row=0, column=4, padx=2, pady=8)
        self.recover_btn = ctk.CTkButton(
            recover_bar, text="💾 Recover Selected", width=150,
            fg_color="#2980b9", hover_color="#1f618d",
            command=self._start_recover, state="disabled",
        )
        self.recover_btn.grid(row=0, column=5, padx=8, pady=8)

        self.status = StatusBar(self)
        self.status.grid(row=3, column=0, sticky="ew", padx=10, pady=(0, 8))
        self.status.set_text("Ready – Open a disk image or select a scan mode from the Scan menu")

    # ------------------------------------------------------------------
    # Case / settings
    # ------------------------------------------------------------------
    def _edit_case(self) -> None:
        CaseDialog(self, self.case, on_save=self._on_case_saved)

    def _on_case_saved(self, case: CaseInfo) -> None:
        self.case = case
        self.engine.set_case(case)
        self._update_case_label()
        self.status.set_text(f"Case updated – {case.summary_line()}")

    def _update_case_label(self) -> None:
        self.case_label.configure(text=self.case.summary_line())

    def _open_settings(self) -> None:
        SettingsDialog(self, self.settings, on_save=self._on_settings_saved)

    def _on_settings_saved(self, settings: dict) -> None:
        self.settings = settings
        theme = settings.get("theme", "Dark")
        ctk.set_appearance_mode(theme)
        self.status.set_text("Settings saved")

    def _export_case_summary(self) -> None:
        path = fd.asksaveasfilename(
            title="Export case summary",
            defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("All", "*.*")],
        )
        if not path:
            return
        lines = [
            "Retrievo Case Summary",
            "=" * 40,
            f"Case ID: {self.case.case_id}",
            f"Examiner: {self.case.examiner}",
            f"Organization: {self.case.organization}",
            f"Source media: {self.case.source_media}",
            f"Created (UTC): {self.case.created_utc}",
            f"Notes: {self.case.notes}",
            "",
            f"Items currently in results: {len(self.current_items)}",
            f"Source path: {self.target_var.get()}",
        ]
        Path(path).write_text("\n".join(lines), encoding="utf-8")
        mb.showinfo("Exported", f"Case summary saved to:\n{path}")

    # ------------------------------------------------------------------
    # Browse / drives
    # ------------------------------------------------------------------
    def _browse_file(self) -> None:
        path = fd.askopenfilename(
            title="Select disk image or binary evidence file",
            filetypes=[
                ("Disk images", "*.dd *.img *.raw *.bin"),
                ("All files", "*.*"),
            ],
        )
        if path:
            self.target_var.set(path)
            self.mode_var.set("carve")
            if not self.case.source_media:
                self.case.source_media = path

    def _browse_folder(self) -> None:
        path = fd.askdirectory(title="Select folder to scan")
        if path:
            self.target_var.set(path)

    def _browse_dest(self) -> None:
        path = fd.askdirectory(title="Select recovery destination (different drive recommended)")
        if path:
            self.dest_var.set(path)

    def _list_drives(self) -> None:
        try:
            drives = list_physical_drives() + list_volumes()
            if not drives:
                mb.showinfo("Drives", "No drives enumerated.\nOn Windows run as Administrator.")
                return
            top = ctk.CTkToplevel(self)
            top.title("Select Drive / Volume")
            top.geometry("540x420")
            top.transient(self)
            top.grab_set()
            ctk.CTkLabel(top, text="Select evidence source", font=ctk.CTkFont(weight="bold")).pack(pady=8)
            lb = ctk.CTkScrollableFrame(top)
            lb.pack(fill="both", expand=True, padx=10, pady=5)

            def choose(path: str):
                self.target_var.set(path)
                self.mode_var.set("carve")
                top.destroy()

            for d in drives:
                ctk.CTkButton(
                    lb, text=f"{d.display_name}\n{d.path}",
                    anchor="w", height=48, command=lambda p=d.path: choose(p),
                ).pack(fill="x", pady=3)
        except Exception as e:
            mb.showerror("Error", str(e))

    # ------------------------------------------------------------------
    # Scan
    # ------------------------------------------------------------------
    def _set_mode_and_scan(self, mode: str) -> None:
        if mode == "carve_media":
            self.mode_var.set("carve")
            self.settings["media_only"] = True
        else:
            self.mode_var.set(mode)
            if mode == "carve":
                self.settings["media_only"] = False
        self._start_scan()

    def _start_scan(self) -> None:
        target = self.target_var.get().strip()
        mode = self.mode_var.get()

        if mode != "recycle" and not target:
            mb.showwarning("No source", "Select a disk image, folder, or drive first.")
            return

        self.scan_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.recover_btn.configure(state="disabled")
        self.hash_btn.configure(state="disabled")
        self.hex_btn.configure(state="disabled")
        self.results.set_items([])
        self.current_items = []

        media_only = self.settings.get("media_only", False) or mode == "carve_media"

        def worker():
            try:
                if mode == "recycle":
                    items = self.scanner.scan_recycle_bin()
                elif mode in ("carve", "carve_media"):
                    items = self.scanner.scan_signatures(target, media_only=media_only)
                else:
                    items = self.scanner.quick_scan(target)
                self.after(0, lambda: self._scan_finished(items))
            except Exception as exc:
                self.after(0, lambda: self._scan_error(str(exc)))

        self._scan_thread = threading.Thread(target=worker, daemon=True)
        self._scan_thread.start()

    def _stop_scan(self) -> None:
        self.scanner.stop()
        self.status.set_text("Stopping scan…")

    def _scan_finished(self, items: List[RecoverableItem]) -> None:
        self.current_items = items
        self.results.set_items(items, auto_select_high=self.settings.get("auto_select_high", True))
        self.scan_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self._update_recover_btn()
        self.status.set_text(f"Scan complete – {len(items)} recoverable item(s)")

    def _scan_error(self, message: str) -> None:
        self.scan_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.status.set_text(f"Error: {message}")
        mb.showerror("Scan Error", message)

    def _update_recover_btn(self) -> None:
        selected = self.results.get_selected()
        state = "normal" if selected else "disabled"
        self.recover_btn.configure(state=state)
        self.hash_btn.configure(state=state)
        self.hex_btn.configure(state=state)

    # ------------------------------------------------------------------
    # Tools: hash / hex / recover
    # ------------------------------------------------------------------
    def _on_item_activate(self, item: RecoverableItem) -> None:
        if item.data:
            HexViewerDialog(self, item.name, item.data, base_offset=item.offset)
        elif item.original_path and Path(item.original_path).is_file():
            try:
                data = Path(item.original_path).read_bytes()[:4096]
                HexViewerDialog(self, item.name, data, base_offset=0)
            except Exception as e:
                mb.showerror("Hex View", str(e))
        else:
            mb.showinfo("Hex View", "No binary data available for this item.")

    def _hex_selected(self) -> None:
        selected = self.results.get_selected()
        if not selected:
            return
        self._on_item_activate(selected[0])

    def _hash_selected(self) -> None:
        selected = self.results.get_selected()
        if not selected:
            return
        item = selected[0]
        try:
            if item.data is not None:
                hashes = hash_bytes(item.data)
            elif item.original_path and Path(item.original_path).is_file():
                hashes = hash_file(item.original_path)
            else:
                mb.showinfo("Hash", "No data available to hash.")
                return
            HashResultDialog(self, item.name, hashes)
        except Exception as e:
            mb.showerror("Hash Error", str(e))

    def _start_recover(self) -> None:
        selected = self.results.get_selected()
        if not selected:
            return
        dest = self.dest_var.get().strip()
        if not dest:
            mb.showwarning("No destination", "Choose a recovery folder on a different drive.")
            return

        self.recover_btn.configure(state="disabled")
        self.scan_btn.configure(state="disabled")

        compute_hashes = self.settings.get("compute_hashes", True)

        def worker():
            try:
                written = self.engine.recover_items(
                    selected, dest, write_report=True, compute_hashes=compute_hashes,
                )
                self.after(0, lambda: self._recover_finished(written))
            except Exception as exc:
                self.after(0, lambda: self._recover_error(str(exc)))

        threading.Thread(target=worker, daemon=True).start()

    def _recover_finished(self, paths: list) -> None:
        self.recover_btn.configure(state="normal")
        self.scan_btn.configure(state="normal")
        self.status.set_text(f"Recovered {len(paths)} file(s) – report includes hashes")
        mb.showinfo(
            "Recovery Complete",
            f"{len(paths)} file(s) saved to:\n{self.dest_var.get()}\n\n"
            "CSV + JSON forensic report written (with MD5/SHA hashes when enabled).",
        )

    def _recover_error(self, message: str) -> None:
        self.recover_btn.configure(state="normal")
        self.scan_btn.configure(state="normal")
        mb.showerror("Recovery Error", message)

    def _on_progress(self, value: float, message: str) -> None:
        self.after(0, lambda: self.progress_panel.update(value, message))
        self.after(0, lambda: self.status.set_text(message))

    def _show_disclaimer(self) -> None:
        mb.showinfo(
            "Forensic Use Notice",
            "Retrievo is a forensic recovery suite.\n\n"
            "• Prefer disk images (dd/raw), not live drives.\n"
            "• Run as Administrator for raw volume/physical disk access.\n"
            "• Never recover files onto the same drive you are scanning.\n"
            "• Verify recovered files; false positives are possible.\n"
            "• Document case ID, examiner, and source media for chain of custody.\n\n"
            "For legitimate recovery and digital forensics training only.",
        )
