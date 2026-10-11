"""Reusable custom widgets."""

from __future__ import annotations

import customtkinter as ctk


class StatusBar(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, height=28, **kwargs)
        self.label = ctk.CTkLabel(self, text="Ready", anchor="w")
        self.label.pack(side="left", fill="x", expand=True, padx=8)

    def set_text(self, text: str) -> None:
        self.label.configure(text=text)


class ProgressPanel(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.progress = ctk.CTkProgressBar(self, height=12)
        self.progress.set(0)
        self.progress.pack(fill="x", padx=10, pady=(8, 2))

        self.label = ctk.CTkLabel(self, text="", anchor="w", font=ctk.CTkFont(size=12))
        self.label.pack(fill="x", padx=10, pady=(0, 8))

    def update(self, value: float, message: str = "") -> None:
        self.progress.set(max(0.0, min(1.0, value)))
        if message:
            self.label.configure(text=message)
