"""Small utility helpers."""

from __future__ import annotations

import os
from pathlib import Path


def format_size(num_bytes: int) -> str:
    """Human-readable file size."""
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def get_available_drives() -> list[str]:
    """Return list of existing drive roots on Windows (or mount points elsewhere)."""
    drives = []
    if os.name == "nt":
        import string
        for letter in string.ascii_uppercase:
            root = f"{letter}:\\"
            if os.path.exists(root):
                drives.append(root)
    else:
        for p in ["/", "/home", "/mnt", "/media"]:
            if Path(p).exists():
                drives.append(p)
    return drives


def ensure_dir(path: str | Path) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p
