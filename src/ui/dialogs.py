"""Modal dialogs: Case, Settings, About, Hash results, Hex viewer."""

from __future__ import annotations

import customtkinter as ctk
import tkinter.messagebox as mb
from typing import Callable, Optional

from core.forensics import CaseInfo, hex_dump


class CaseDialog(ctk.CTkToplevel):
    def __init__(self, master, case: CaseInfo, on_save: Callable[[CaseInfo], None]):
        super().__init__(master)
        self.title("Case Information")
        self.geometry("480x420")
        self.transient(master)
        self.grab_set()
        self.on_save = on_save
        self.case = case

        pad = {"padx": 12, "pady": 6}
        ctk.CTkLabel(self, text="Forensic Case Metadata", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(16, 8))

        form = ctk.CTkFrame(self, fg_color="transparent")
        form.pack(fill="both", expand=True, padx=16)

        self.vars = {}
        fields = [
            ("case_id", "Case ID / Number"),
            ("examiner", "Examiner"),
            ("organization", "Organization / Lab"),
            ("source_media", "Source media description"),
        ]
        for key, label in fields:
            ctk.CTkLabel(form, text=label, anchor="w").pack(fill="x", **pad)
            var = ctk.StringVar(value=getattr(case, key, ""))
            self.vars[key] = var
            ctk.CTkEntry(form, textvariable=var).pack(fill="x", padx=12)

        ctk.CTkLabel(form, text="Notes", anchor="w").pack(fill="x", **pad)
        self.notes = ctk.CTkTextbox(form, height=100)
        self.notes.pack(fill="both", expand=True, padx=12, pady=4)
        if case.notes:
            self.notes.insert("1.0", case.notes)

        btn = ctk.CTkFrame(self, fg_color="transparent")
        btn.pack(fill="x", pady=12)
        ctk.CTkButton(btn, text="Save", width=100, command=self._save).pack(side="right", padx=16)
        ctk.CTkButton(btn, text="Cancel", width=100, fg_color="gray", command=self.destroy).pack(side="right")

    def _save(self) -> None:
        self.case.case_id = self.vars["case_id"].get().strip()
        self.case.examiner = self.vars["examiner"].get().strip()
        self.case.organization = self.vars["organization"].get().strip()
        self.case.source_media = self.vars["source_media"].get().strip()
        self.case.notes = self.notes.get("1.0", "end").strip()
        self.on_save(self.case)
        self.destroy()


class SettingsDialog(ctk.CTkToplevel):
    def __init__(self, master, settings: dict, on_save: Callable[[dict], None]):
        super().__init__(master)
        self.title("Settings")
        self.geometry("420x360")
        self.transient(master)
        self.grab_set()
        self.on_save = on_save
        self.settings = dict(settings)

        ctk.CTkLabel(self, text="Recovery Settings", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(16, 12))

        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(fill="both", expand=True, padx=20)

        self.media_only = ctk.BooleanVar(value=settings.get("media_only", False))
        self.compute_hashes = ctk.BooleanVar(value=settings.get("compute_hashes", True))
        self.auto_select_high = ctk.BooleanVar(value=settings.get("auto_select_high", True))
        self.theme = ctk.StringVar(value=settings.get("theme", "Dark"))

        ctk.CTkCheckBox(frame, text="Carve media files only (images + videos)", variable=self.media_only).pack(anchor="w", pady=6)
        ctk.CTkCheckBox(frame, text="Compute MD5 / SHA-1 / SHA-256 on recovery", variable=self.compute_hashes).pack(anchor="w", pady=6)
        ctk.CTkCheckBox(frame, text="Auto-select high-confidence results", variable=self.auto_select_high).pack(anchor="w", pady=6)

        ctk.CTkLabel(frame, text="Appearance", anchor="w").pack(fill="x", pady=(16, 4))
        ctk.CTkOptionMenu(frame, values=["Dark", "Light", "System"], variable=self.theme).pack(fill="x")

        btn = ctk.CTkFrame(self, fg_color="transparent")
        btn.pack(fill="x", pady=16)
        ctk.CTkButton(btn, text="Save", width=100, command=self._save).pack(side="right", padx=16)
        ctk.CTkButton(btn, text="Cancel", width=100, fg_color="gray", command=self.destroy).pack(side="right")

    def _save(self) -> None:
        self.settings["media_only"] = self.media_only.get()
        self.settings["compute_hashes"] = self.compute_hashes.get()
        self.settings["auto_select_high"] = self.auto_select_high.get()
        self.settings["theme"] = self.theme.get()
        self.on_save(self.settings)
        self.destroy()


class HexViewerDialog(ctk.CTkToplevel):
    def __init__(self, master, title: str, data: bytes, base_offset: int = 0):
        super().__init__(master)
        self.title(f"Hex Viewer – {title}")
        self.geometry("720x480")
        self.transient(master)

        ctk.CTkLabel(self, text=f"Offset base: 0x{base_offset:X}  |  Showing first {min(len(data), 512)} bytes",
                     anchor="w").pack(fill="x", padx=12, pady=8)
        box = ctk.CTkTextbox(self, font=ctk.CTkFont(family="Consolas", size=13))
        box.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        box.insert("1.0", hex_dump(data, offset=base_offset, length=512))
        box.configure(state="disabled")


class HashResultDialog(ctk.CTkToplevel):
    def __init__(self, master, name: str, hashes: dict):
        super().__init__(master)
        self.title(f"Hashes – {name}")
        self.geometry("560x240")
        self.transient(master)

        box = ctk.CTkTextbox(self, font=ctk.CTkFont(family="Consolas", size=13))
        box.pack(fill="both", expand=True, padx=12, pady=12)
        lines = [f"{algo.upper():8s}  {digest}" for algo, digest in hashes.items()]
        box.insert("1.0", "\n".join(lines))
        box.configure(state="disabled")


class AboutDialog(ctk.CTkToplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("About Retrievo")
        self.geometry("480x360")
        self.transient(master)
        self.grab_set()

        ctk.CTkLabel(self, text="Retrievo", font=ctk.CTkFont(size=22, weight="bold")).pack(pady=(24, 4))
        ctk.CTkLabel(self, text="Forensic File Recovery Suite  v1.1").pack()
        ctk.CTkLabel(
            self,
            text=(
                "Signature carving • Recycle Bin recovery\n"
                "Raw disk / volume access • Hash verification\n"
                "Case metadata • Forensic reporting\n\n"
                "For legitimate recovery and digital forensics training.\n"
                "Always work on disk images when possible.\n"
                "Never recover onto the source media."
            ),
            justify="center",
        ).pack(pady=16, padx=20)
        ctk.CTkButton(self, text="Close", width=100, command=self.destroy).pack(pady=8)


class ProcessPickerDialog(ctk.CTkToplevel):
    """Select a process for memory dump."""

    def __init__(self, master, processes, on_select):
        super().__init__(master)
        self.title("Select Process for Memory Dump")
        self.geometry("640x480")
        self.transient(master)
        self.grab_set()
        self.on_select = on_select
        self.processes = processes

        ctk.CTkLabel(
            self, text="Choose a process to dump (run as Administrator for protected processes)",
            font=ctk.CTkFont(weight="bold"),
        ).pack(pady=(12, 6), padx=12)

        self.search_var = ctk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._filter())
        ctk.CTkEntry(self, textvariable=self.search_var, placeholder_text="Filter by name or PID…").pack(
            fill="x", padx=12, pady=4
        )

        self.list_frame = ctk.CTkScrollableFrame(self)
        self.list_frame.pack(fill="both", expand=True, padx=12, pady=8)
        self._filter()

        btn = ctk.CTkFrame(self, fg_color="transparent")
        btn.pack(fill="x", pady=8)
        ctk.CTkButton(btn, text="Cancel", width=100, fg_color="gray", command=self.destroy).pack(side="right", padx=12)

    def _filter(self) -> None:
        for w in self.list_frame.winfo_children():
            w.destroy()
        q = self.search_var.get().strip().lower()
        for p in self.processes:
            label = f"{p.name}  (PID {p.pid})"
            if p.memory_bytes:
                label += f"  –  {p.memory_bytes / (1024*1024):.1f} MB"
            if p.username:
                label += f"  [{p.username}]"
            if q and q not in label.lower() and q not in str(p.pid):
                continue
            ctk.CTkButton(
                self.list_frame,
                text=label,
                anchor="w",
                height=32,
                command=lambda pid=p.pid, name=p.name: self._choose(pid, name),
            ).pack(fill="x", pady=1)

    def _choose(self, pid: int, name: str) -> None:
        self.on_select(pid, name)
        self.destroy()
