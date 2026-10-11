"""
Forensic file carving engine.

Scans binary data (disk images, raw volumes, or files) for known signatures
and extracts candidate files with confidence scoring.
Designed for media-focused recovery (images & videos) but supports
documents and archives as well.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Callable, Iterator, List, Optional, Tuple

from .signatures import SIGNATURES, Signature


@dataclass
class CarvedFile:
    """A file recovered by signature carving."""
    name: str
    extension: str
    offset: int                 # absolute offset in the source
    size: int
    data: bytes = field(repr=False)
    confidence: float = 0.8
    source_path: str = ""

    @property
    def display_name(self) -> str:
        return f"{self.name}_{self.offset:012X}{self.extension}"

    @property
    def size_human(self) -> str:
        size = float(self.size)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"


class FileCarver:
    """
    Streaming signature carver.

    - Reads the source in overlapping chunks to avoid missing headers on boundaries.
    - Uses per-format validators and footer search for better size estimation.
    - Never loads the entire source into memory.
    """

    DEFAULT_CHUNK = 4 * 1024 * 1024          # 4 MB
    OVERLAP = 64 * 1024                      # 64 KB overlap

    def __init__(
        self,
        signatures: Optional[List[Signature]] = None,
        chunk_size: int = DEFAULT_CHUNK,
        progress_callback: Optional[Callable[[float, str], None]] = None,
        max_files: int = 50_000,
    ):
        self.signatures = signatures or SIGNATURES
        self.chunk_size = chunk_size
        self.progress_callback = progress_callback
        self.max_files = max_files
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    def _report(self, progress: float, msg: str) -> None:
        if self.progress_callback:
            self.progress_callback(min(max(progress, 0.0), 1.0), msg)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def carve_stream(
        self,
        stream: BinaryIO,
        total_size: int,
        source_name: str = "stream",
    ) -> List[CarvedFile]:
        """Carve from an already-open binary stream (file, disk image, raw device)."""
        results: List[CarvedFile] = []
        self._stop = False
        offset = 0
        prev_tail = b""

        while offset < total_size and not self._stop and len(results) < self.max_files:
            to_read = min(self.chunk_size, total_size - offset)
            chunk = stream.read(to_read)
            if not chunk:
                break

            data = prev_tail + chunk
            base = offset - len(prev_tail)

            found = self._scan_buffer(data, base, source_name)
            results.extend(found)

            # Keep overlap for next iteration
            prev_tail = data[-self.OVERLAP:] if len(data) > self.OVERLAP else data
            offset += len(chunk)

            self._report(
                offset / total_size if total_size else 0,
                f"Carving {source_name}… {offset:,} / {total_size:,} bytes  |  {len(results)} found",
            )

        self._report(1.0, f"Carving finished – {len(results)} candidate(s)")
        return results

    def carve_file(self, path: str | Path) -> List[CarvedFile]:
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(path)
        size = path.stat().st_size
        with open(path, "rb") as f:
            return self.carve_stream(f, size, source_name=path.name)

    def carve_path(self, path: str | Path) -> List[CarvedFile]:
        """File or directory. Directories are walked non-recursively for safety."""
        path = Path(path)
        if path.is_file():
            return self.carve_file(path)
        if path.is_dir():
            results = []
            files = [p for p in path.iterdir() if p.is_file()]
            for i, f in enumerate(files):
                if self._stop:
                    break
                try:
                    results.extend(self.carve_file(f))
                except Exception:
                    pass
                self._report((i + 1) / max(len(files), 1), f"Processed {f.name}")
            return results
        raise FileNotFoundError(path)

    # ------------------------------------------------------------------
    # Internal scanning
    # ------------------------------------------------------------------

    def _scan_buffer(self, data: bytes, base_offset: int, source: str) -> List[CarvedFile]:
        found: List[CarvedFile] = []
        for name, ext, header, footer, max_size, validator in self.signatures:
            start = 0
            while True:
                idx = data.find(header, start)
                if idx == -1:
                    break
                abs_off = base_offset + idx
                remaining = data[idx:]
                size = self._estimate_size(remaining, footer, max_size, name)

                if size <= len(header):
                    start = idx + 1
                    continue

                candidate = remaining[:size]

                # Confidence & validation
                conf = 0.55
                if footer and candidate.endswith(footer):
                    conf += 0.25
                if validator:
                    try:
                        if validator(candidate):
                            conf += 0.20
                        else:
                            conf -= 0.30
                    except Exception:
                        conf -= 0.20

                conf = max(0.0, min(1.0, conf))
                if conf >= 0.45:
                    found.append(CarvedFile(
                        name=name,
                        extension=ext,
                        offset=abs_off,
                        size=size,
                        data=candidate,
                        confidence=conf,
                        source_path=source,
                    ))

                start = idx + max(1, len(header) // 2)  # avoid tight loops on same header

        return found

    def _estimate_size(
        self,
        data: bytes,
        footer: Optional[bytes],
        max_size: int,
        name: str,
    ) -> int:
        limit = min(len(data), max_size)

        if footer:
            # Search for footer after a minimum payload
            search_start = min(64, len(data))
            pos = data.find(footer, search_start)
            if pos != -1:
                return pos + len(footer)

        # Format-specific heuristics
        if name == "JPEG":
            # Find last EOI marker within limit
            eoi = data.rfind(b"\xFF\xD9", 0, limit)
            if eoi != -1:
                return eoi + 2
        elif name == "PNG":
            # Walk chunks until IEND
            pos = 8
            while pos + 12 <= limit:
                length = int.from_bytes(data[pos:pos+4], "big")
                chunk_type = data[pos+4:pos+8]
                pos += 12 + length
                if chunk_type == b"IEND":
                    return pos
                if length > 50_000_000:  # sanity
                    break
        elif name == "BMP" and len(data) >= 6:
            declared = int.from_bytes(data[2:6], "little")
            if 14 <= declared <= limit:
                return declared
        elif name in ("MP4", "MOV", "AVI") and len(data) >= 8:
            # Try first box size
            box_size = int.from_bytes(data[0:4], "big")
            if 8 <= box_size <= limit:
                # For container formats we often need the whole file;
                # take a reasonable upper bound or keep searching for more boxes.
                return min(limit, max(box_size, 1024 * 1024))

        # Fallback: capped chunk
        return min(limit, max_size)
