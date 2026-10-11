"""
Forensic utility helpers: hashing, case metadata, hex preview.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class CaseInfo:
    case_id: str = ""
    examiner: str = ""
    organization: str = ""
    notes: str = ""
    created_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source_media: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    def summary_line(self) -> str:
        parts = []
        if self.case_id:
            parts.append(f"Case: {self.case_id}")
        if self.examiner:
            parts.append(f"Examiner: {self.examiner}")
        return "  |  ".join(parts) if parts else "No case metadata set"


def hash_bytes(data: bytes, algorithms: Optional[List[str]] = None) -> Dict[str, str]:
    algorithms = algorithms or ["md5", "sha1", "sha256"]
    result = {}
    for name in algorithms:
        h = hashlib.new(name)
        h.update(data)
        result[name] = h.hexdigest()
    return result


def hash_file(path: str | Path, algorithms: Optional[List[str]] = None, chunk: int = 1024 * 1024) -> Dict[str, str]:
    algorithms = algorithms or ["md5", "sha1", "sha256"]
    hashers = {name: hashlib.new(name) for name in algorithms}
    with open(path, "rb") as f:
        while True:
            block = f.read(chunk)
            if not block:
                break
            for h in hashers.values():
                h.update(block)
    return {name: h.hexdigest() for name, h in hashers.items()}


def hex_dump(data: bytes, offset: int = 0, length: int = 256, width: int = 16) -> str:
    """Return a classic hex dump string for forensic inspection."""
    data = data[:length]
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        hex_part = hex_part.ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset + i:08X}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines)


def classify_evidence_value(confidence: float, file_type: str) -> str:
    if confidence >= 0.85:
        tier = "High"
    elif confidence >= 0.6:
        tier = "Medium"
    else:
        tier = "Low"
    return f"{tier} ({file_type})"
