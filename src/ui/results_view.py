"""Results table with type filters, search, and preview."""

from __future__ import annotations

import io
from typing import Callable, List, Optional

import customtkinter as ctk
from PIL import Image, ImageTk

from core.scanner import RecoverableItem
from utils.helpers import format_size


class ResultsView(ctk.CTkFrame):
    def __init__(
        self,
        master,
        on_selection_change: Optional[Callable[[], None]] = None,
        on_item_activate: Optional[Callable[[RecoverableItem], None]] = None,
        **kwargs,
    ):
        super().__init__(master, **kwargs)
        self.on_selection_change = on_selection_change
        self.on_item_activate = on_item_activate
        self._all_items: List[RecoverableItem] = []
        self.items: List[RecoverableItem] = []
        self.check_vars: List[ctk.BooleanVar] = []
        self._filter_type = "all"
        self._search = ""

        self.grid_columnconfigure(0, weight=3)
        self.grid_columnconfigure(1, weight=2)
        self.grid_rowconfigure(1, weight=1)

        # Filter bar
        filt = ctk.CTkFrame(self, fg_color="transparent")
        filt.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 4))
        ctk.CTkLabel(filt, text="Filter:").pack(side="left", padx=(4, 6))
        self.filter_var = ctk.StringVar(value="all")
        for label, val in [("All", "all"), ("Images", "image"), ("Videos", "video"),
                           ("Documents", "document"), ("Other", "other")]:
            ctk.CTkRadioButton(
                filt, text=label, variable=self.filter_var, value=val,
                command=self._apply_filter, width=70
            ).pack(side="left", padx=4)

        self.search_var = ctk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._apply_filter())
        ctk.CTkEntry(filt, textvariable=self.search_var, placeholder_text="Search name…", width=180).pack(
            side="right", padx=6
        )

        # Left list
        left = ctk.CTkFrame(self)
        left.grid(row=1, column=0, sticky="nsew", padx=(0, 6))
        left.grid_rowconfigure(1, weight=1)
        left.grid_columnconfigure(0, weight=1)

        header = ctk.CTkFrame(left, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=4, pady=4)
        ctk.CTkLabel(header, text="Evidence / Recoverable Items", font=ctk.CTkFont(weight="bold")).pack(side="left")
        self.count_label = ctk.CTkLabel(header, text="0 items")
        self.count_label.pack(side="right")

        self.list_frame = ctk.CTkScrollableFrame(left)
        self.list_frame.grid(row=1, column=0, sticky="nsew", padx=4, pady=4)

        btn_row = ctk.CTkFrame(left, fg_color="transparent")
        btn_row.grid(row=2, column=0, sticky="ew", padx=4, pady=4)
        ctk.CTkButton(btn_row, text="Select All", width=90, command=self.select_all).pack(side="left", padx=2)
        ctk.CTkButton(btn_row, text="Select None", width=90, command=self.select_none).pack(side="left", padx=2)
        ctk.CTkButton(btn_row, text="High conf. only", width=110, command=self.select_high).pack(side="left", padx=2)

        # Right preview
        right = ctk.CTkFrame(self)
        right.grid(row=1, column=1, sticky="nsew")
        right.grid_rowconfigure(1, weight=1)
        right.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(right, text="Preview / Details", font=ctk.CTkFont(weight="bold")).grid(
            row=0, column=0, sticky="w", padx=8, pady=4
        )
        self.preview_label = ctk.CTkLabel(right, text="Select an item to inspect", anchor="center")
        self.preview_label.grid(row=1, column=0, sticky="nsew", padx=8, pady=8)

        self.info_label = ctk.CTkLabel(right, text="", justify="left", anchor="nw")
        self.info_label.grid(row=2, column=0, sticky="ew", padx=8, pady=4)

    def set_items(self, items: List[RecoverableItem], auto_select_high: bool = True) -> None:
        self._all_items = list(items)
        self._apply_filter(auto_select_high=auto_select_high)

    def _apply_filter(self, auto_select_high: bool = False) -> None:
        ftype = self.filter_var.get()
        q = self.search_var.get().strip().lower()
        filtered = []
        for item in self._all_items:
            if ftype != "all" and item.file_type != ftype:
                continue
            if q and q not in item.name.lower() and q not in item.path.lower():
                continue
            filtered.append(item)
        self._render(filtered, auto_select_high=auto_select_high)

    def _render(self, items: List[RecoverableItem], auto_select_high: bool = False) -> None:
        for widget in self.list_frame.winfo_children():
            widget.destroy()
        self.items = items
        self.check_vars = []

        for idx, item in enumerate(items):
            default = item.confidence >= 0.75 if auto_select_high else item.confidence >= 0.6
            var = ctk.BooleanVar(value=default)
            self.check_vars.append(var)

            row = ctk.CTkFrame(self.list_frame, fg_color=("gray90", "gray17"))
            row.pack(fill="x", pady=2, padx=2)

            cb = ctk.CTkCheckBox(row, text="", variable=var, width=24, command=self._notify)
            cb.pack(side="left", padx=4)

            icon = {"image": "🖼", "video": "🎬", "document": "📄"}.get(item.file_type, "📎")
            conf = f"{item.confidence:.0%}"
            off = f" @0x{item.offset:X}" if item.offset else ""
            label_text = f"{icon}  {item.name}  |  {format_size(item.size)}  |  {conf}  |  {item.source}{off}"
            lbl = ctk.CTkLabel(row, text=label_text, anchor="w")
            lbl.pack(side="left", fill="x", expand=True, padx=4)
            lbl.bind("<Button-1>", lambda e, i=idx: self._show_preview(i))
            lbl.bind("<Double-Button-1>", lambda e, i=idx: self._activate(i))

        self.count_label.configure(text=f"{len(items)} shown / {len(self._all_items)} total")
        self._notify()

    def get_selected(self) -> List[RecoverableItem]:
        return [item for item, var in zip(self.items, self.check_vars) if var.get()]

    def select_all(self) -> None:
        for v in self.check_vars:
            v.set(True)
        self._notify()

    def select_none(self) -> None:
        for v in self.check_vars:
            v.set(False)
        self._notify()

    def select_high(self) -> None:
        for item, var in zip(self.items, self.check_vars):
            var.set(item.confidence >= 0.75)
        self._notify()

    def _notify(self) -> None:
        if self.on_selection_change:
            self.on_selection_change()

    def _activate(self, index: int) -> None:
        if 0 <= index < len(self.items) and self.on_item_activate:
            self.on_item_activate(self.items[index])

    def _show_preview(self, index: int) -> None:
        if index < 0 or index >= len(self.items):
            return
        item = self.items[index]
        info = (
            f"Name: {item.name}\n"
            f"Type: {item.file_type}\n"
            f"Size: {format_size(item.size)}\n"
            f"Source: {item.source}\n"
            f"Confidence: {item.confidence:.0%}\n"
            f"Offset: 0x{item.offset:X}\n"
            f"Path: {item.path}"
        )
        self.info_label.configure(text=info)

        if item.file_type == "image":
            try:
                if item.data:
                    img = Image.open(io.BytesIO(item.data))
                elif item.original_path:
                    img = Image.open(item.original_path)
                else:
                    self.preview_label.configure(image=None, text="No image data")
                    return
                img.thumbnail((340, 260))
                photo = ImageTk.PhotoImage(img)
                self.preview_label.configure(image=photo, text="")
                self.preview_label.image = photo
            except Exception:
                self.preview_label.configure(image=None, text="Preview unavailable")
        else:
            self.preview_label.configure(
                image=None,
                text=f"{item.file_type.upper()} file\nOffset 0x{item.offset:X}\nDouble-click for tools",
            )
