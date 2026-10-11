"""
Main application window – Forensic File Recovery Tool.
"""

from __future__ import annotations

import logging
import threading
import tkinter.filedialog as fd
import tkinter.messagebox as mb
from pathlib import Path
from typing import List, Optional

import customtkinter as ctk

from core.scanner import RecoveryScanner, RecoverableItem
from core.recover import RecoveryEngine
from core.disk_access import list_physical_drives, list_volumes
from ui.results_view import ResultsView
from ui.widgets import ProgressPanel, StatusBar

logger = logging.getLogger("FileRecoverPro")


class MainWindow(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("FileRecover Pro – Forensic File Recovery")
        self.geometry("1180x740")
        self.minsize(960, 640)

        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        log_dir = Path.home() / "FileRecoverPro_logs"
        log_dir.mkdir(exist_ok=True)
        self.scanner = RecoveryScanner(
            progress_callback=self._on_progress,
            log_path=str(log_dir / "scan.log"),
        )
        self.engine = RecoveryEngine(progress_callback=self._on_progress)
        self.current_items: List[RecoverableItem] = []
        self._scan_thread: Optional[threading.Thread] = None

        self._build_ui()
        self._show_disclaimer()

    def _show_disclaimer(self) -> None:
        mb.showinfo(
            "Forensic Use Notice",
            "FileRecover Pro is a forensic recovery tool.\n\n"
            "• Prefer working on disk images (dd/raw), not live drives.\n"
            "• Run as Administrator for raw volume/physical disk access.\n"
            "• Never recover files onto the same drive you are scanning.\n"
            "• Always verify recovered files; false positives are possible.\n\n"
            "This software is provided as-is for legitimate recovery and educational use."
        )

    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Toolbar
        toolbar = ctk.CTkFrame(self, height=64)
        toolbar.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 5))
        toolbar.grid_columnconfigure(5, weight=1)

        ctk.CTkLabel(
            toolbar, text="FileRecover Pro",
            font=ctk.CTkFont(size=18, weight="bold")
        ).grid(row=0, column=0, padx=12, pady=12)

        self.mode_var = ctk.StringVar(value="carve")
        modes = [
            ("Signature Carve (Forensic)", "carve"),
            ("Recycle Bin", "recycle"),
            ("Quick Media Scan", "quick"),
        ]
        for i, (text, value) in enumerate(modes):
            ctk.CTkRadioButton(
                toolbar, text=text, variable=self.mode_var, value=value
            ).grid(row=0, column=i + 1, padx=10)

        # Content
        content = ctk.CTkFrame(self)
        content.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(1, weight=1)

        # Target controls
        controls = ctk.CTkFrame(content)
        controls.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        controls.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(controls, text="Source:").grid(row=0, column=0, padx=(8, 4), pady=8)

        self.target_var = ctk.StringVar(value="")
        self.target_entry = ctk.CTkEntry(
            controls, textvariable=self.target_var,
            placeholder_text="Disk image (.dd/.img/.raw), folder, or \\\\.\\PhysicalDriveN / \\\\.\\C:"
        )
        self.target_entry.grid(row=0, column=1, sticky="ew", padx=4, pady=8)

        ctk.CTkButton(controls, text="Browse File…", width=100, command=self._browse_file).grid(
            row=0, column=2, padx=3, pady=8
        )
        ctk.CTkButton(controls, text="Browse Folder…", width=110, command=self._browse_folder).grid(
            row=0, column=3, padx=3, pady=8
        )
        ctk.CTkButton(controls, text="List Drives", width=90, command=self._list_drives).grid(
            row=0, column=4, padx=3, pady=8
        )

        self.scan_btn = ctk.CTkButton(
            controls, text="▶ Start Scan", width=120,
            fg_color="#27ae60", hover_color="#1e8449",
            command=self._start_scan
        )
        self.scan_btn.grid(row=0, column=5, padx=4, pady=8)

        self.stop_btn = ctk.CTkButton(
            controls, text="⏹ Stop", width=80,
            fg_color="#c0392b", hover_color="#922b21",
            command=self._stop_scan, state="disabled"
        )
        self.stop_btn.grid(row=0, column=6, padx=4, pady=8)

        # Results
        self.results = ResultsView(content, on_selection_change=self._update_recover_btn)
        self.results.grid(row=1, column=0, sticky="nsew")

        # Progress
        self.progress_panel = ProgressPanel(content)
        self.progress_panel.grid(row=2, column=0, sticky="ew", pady=(8, 0))

        # Recover bar
        recover_bar = ctk.CTkFrame(content)
        recover_bar.grid(row=3, column=0, sticky="ew", pady=(8, 0))
        recover_bar.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(recover_bar, text="Recover to:").grid(row=0, column=0, padx=8, pady=8)
        self.dest_var = ctk.StringVar(value=str(Path.home() / "RecoveredFiles"))
        ctk.CTkEntry(recover_bar, textvariable=self.dest_var).grid(
            row=0, column=1, sticky="ew", padx=4, pady=8
        )
        ctk.CTkButton(recover_bar, text="Browse…", width=90, command=self._browse_dest).grid(
            row=0, column=2, padx=4, pady=8
        )
        self.recover_btn = ctk.CTkButton(
            recover_bar, text="💾 Recover Selected", width=160,
            fg_color="#2980b9", hover_color="#1f618d",
            command=self._start_recover, state="disabled"
        )
        self.recover_btn.grid(row=0, column=3, padx=8, pady=8)

        # Status
        self.status = StatusBar(self)
        self.status.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 8))
        self.status.set_text("Ready – Select a disk image or drive and start a Signature Carve scan")

    # ------------------------------------------------------------------
    def _browse_file(self) -> None:
        path = fd.askopenfilename(
            title="Select disk image or binary file",
            filetypes=[
                ("Disk images", "*.dd *.img *.raw *.bin"),
                ("All files", "*.*"),
            ],
        )
        if path:
            self.target_var.set(path)
            self.mode_var.set("carve")

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
            lines = [f"{d.display_name}\n  → {d.path}" for d in drives]
            # Simple selection dialog
            top = ctk.CTkToplevel(self)
            top.title("Select Drive / Volume")
            top.geometry("520x400")
            top.transient(self)
            top.grab_set()

            ctk.CTkLabel(top, text="Double-click or select and press Use", font=ctk.CTkFont(weight="bold")).pack(pady=8)
            lb_frame = ctk.CTkScrollableFrame(top)
            lb_frame.pack(fill="both", expand=True, padx=10, pady=5)

            selected = ctk.StringVar()

            def choose(path: str):
                selected.set(path)
                self.target_var.set(path)
                self.mode_var.set("carve")
                top.destroy()

            for d in drives:
                btn = ctk.CTkButton(
                    lb_frame, text=f"{d.display_name}\n{d.path}",
                    anchor="w", height=48,
                    command=lambda p=d.path: choose(p)
                )
                btn.pack(fill="x", pady=3)
        except Exception as e:
            mb.showerror("Error", str(e))

    def _start_scan(self) -> None:
        target = self.target_var.get().strip()
        mode = self.mode_var.get()

        if mode != "recycle" and not target:
            mb.showwarning("No source", "Select a disk image, folder, or drive first.")
            return

        self.scan_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.recover_btn.configure(state="disabled")
        self.results.set_items([])
        self.current_items = []

        def worker():
            try:
                if mode == "recycle":
                    items = self.scanner.scan_recycle_bin()
                elif mode == "carve":
                    items = self.scanner.scan_signatures(target, media_only=False)
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
        self.results.set_items(items)
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
        self.recover_btn.configure(state="normal" if selected else "disabled")

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

        def worker():
            try:
                written = self.engine.recover_items(selected, dest, write_report=True)
                self.after(0, lambda: self._recover_finished(written))
            except Exception as exc:
                self.after(0, lambda: self._recover_error(str(exc)))

        threading.Thread(target=worker, daemon=True).start()

    def _recover_finished(self, paths: list) -> None:
        self.recover_btn.configure(state="normal")
        self.scan_btn.configure(state="normal")
        self.status.set_text(f"Recovered {len(paths)} file(s) + forensic report written")
        mb.showinfo(
            "Recovery Complete",
            f"{len(paths)} file(s) saved to:\n{self.dest_var.get()}\n\n"
            "A CSV + JSON recovery report was also written to the same folder."
        )

    def _recover_error(self, message: str) -> None:
        self.recover_btn.configure(state="normal")
        self.scan_btn.configure(state="normal")
        mb.showerror("Recovery Error", message)

    def _on_progress(self, value: float, message: str) -> None:
        self.after(0, lambda: self.progress_panel.update(value, message))
        self.after(0, lambda: self.status.set_text(message))
