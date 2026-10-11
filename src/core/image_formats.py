"""
Forensic disk image format support: E01 (EnCase/EWF) and AFF/AFF4.

E01:
  - Pure-Python reader for common unencrypted, zlib-compressed Expert Witness
    / EnCase evidence files (.E01 and multi-segment .E02…).
  - Optional acceleration via pyewf/libewf when installed.

AFF / AFF4:
  - AFF4 via optional ``pyaff4`` package when installed.
  - Classic AFF is detected and rejected with a clear conversion message.

Images are exposed as file-like objects with seek/read/tell so NTFS parsing
and signature carving work unchanged through disk_access.open_source().
"""

from __future__ import annotations

import logging
import os
import struct
import zlib
from pathlib import Path
from typing import BinaryIO, Dict, List, Optional, Tuple

logger = logging.getLogger("Retrievo")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _u32(b: bytes, off: int = 0) -> int:
    return struct.unpack_from("<I", b, off)[0]


def _u64(b: bytes, off: int = 0) -> int:
    return struct.unpack_from("<Q", b, off)[0]


def is_e01(path: str | Path) -> bool:
    path = Path(path)
    if path.suffix.lower() in (".e01", ".ex01", ".l01", ".lx01", ".s01"):
        return True
    try:
        with open(path, "rb") as f:
            sig = f.read(8)
        return sig == b"EVF\x09\r\n\xff\x00"
    except OSError:
        return False


def is_aff(path: str | Path) -> bool:
    path = Path(path)
    ext = path.suffix.lower()
    if ext in (".aff", ".afd", ".afm", ".aff4"):
        return True
    try:
        with open(path, "rb") as f:
            sig = f.read(16)
        if sig.startswith(b"AFF"):
            return True
        # AFF4 often starts with ZIP local header or "AFF4"
        if sig.startswith(b"PK") or sig.startswith(b"AFF4"):
            # Heuristic – caller may still try AFF4 open
            return ext == ".aff4"
    except OSError:
        pass
    return False


def find_e01_segments(path: Path) -> List[Path]:
    """Locate multi-segment E01 series: file.E01, file.E02, …"""
    path = path.resolve()
    stem = path.stem  # e.g. evidence from evidence.E01
    parent = path.parent
    # Pattern: name.E01, name.E02 … or name.e01
    segments = []
    # First segment is the given path
    if path.is_file():
        segments.append(path)
    # Subsequent segments
    for i in range(2, 1000):
        for ext in (f".E{i:02d}", f".e{i:02d}", f".E{i}", f".e{i}"):
            cand = parent / f"{stem}{ext}"
            if cand.is_file():
                segments.append(cand)
                break
        else:
            # Also try EX01 style continuation
            if i == 2:
                continue
            break
        # If we found E02 keep going; if not found break after gap
        if i > 2 and not any((parent / f"{stem}{e}").is_file() for e in (f".E{i:02d}", f".e{i:02d}")):
            # already handled by for/else
            pass
    # Deduplicate preserve order
    seen = set()
    out = []
    for s in segments:
        rp = s.resolve()
        if rp not in seen:
            seen.add(rp)
            out.append(s)
    return out if out else [path]


# ---------------------------------------------------------------------------
# E01 pure-Python reader
# ---------------------------------------------------------------------------

class E01Error(Exception):
    pass


class E01Image:
    """
    Read-only, seekable view of an EnCase/EWF (.E01) evidence file.

    Supports the common case:
      - EVF signature
      - zlib compressed chunks
      - single or multi-segment sets
      - unencrypted volumes
    """

    SIGNATURE = b"EVF\x09\r\n\xff\x00"

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.segments = find_e01_segments(self.path)
        self._files: List[BinaryIO] = []
        self._chunk_size = 64 * 512  # default 64 sectors
        self._bytes_per_sector = 512
        self._chunk_count = 0
        self._media_size = 0
        self._chunk_offsets: List[Tuple[int, int, int]] = []  # (seg_index, file_offset, compressed_size_hint)
        self._table: List[int] = []  # absolute offsets into concatenated stream model
        self._pos = 0
        self._cache: Dict[int, bytes] = {}
        self._cache_order: List[int] = []
        self._cache_limit = 64
        self._closed = False
        self._open()

    # -- open / parse -------------------------------------------------------

    def _open(self) -> None:
        for seg in self.segments:
            fh = open(seg, "rb")
            sig = fh.read(8)
            if sig != self.SIGNATURE:
                fh.close()
                raise E01Error(f"Not an E01/EVF file: {seg} (bad signature)")
            self._files.append(fh)

        # Parse sections from all segments; collect volume + table + data layout
        self._parse_sections()
        if self._media_size <= 0 and self._chunk_count and self._chunk_size:
            self._media_size = self._chunk_count * self._chunk_size
        if self._media_size <= 0:
            raise E01Error("Could not determine media size from E01 volume section")
        logger.info(
            "E01 opened: %s segment(s), media_size=%s, chunk_size=%s, chunks=%s",
            len(self.segments), self._media_size, self._chunk_size, self._chunk_count,
        )

    def _parse_sections(self) -> None:
        """Walk section headers in every segment."""
        data_section_offsets: List[Tuple[int, int]] = []  # (seg_idx, data_section_start)
        tables: List[List[int]] = []

        for seg_idx, fh in enumerate(self._files):
            fh.seek(8)  # after signature
            while True:
                hdr = fh.read(76)  # type(16) + next(8) + size(8) + pad(40) + crc(4) = 76
                if len(hdr) < 76:
                    break
                sec_type = hdr[0:16].split(b"\x00", 1)[0].decode("ascii", errors="replace")
                next_off = _u64(hdr, 16)
                sec_size = _u64(hdr, 24)
                # payload follows header
                payload_pos = fh.tell()
                payload_size = max(0, sec_size - 76) if sec_size >= 76 else 0

                if sec_type in ("header", "header2"):
                    # case info text – skip
                    fh.seek(payload_pos + payload_size)
                elif sec_type == "volume" or sec_type == "disk":
                    payload = fh.read(min(payload_size, 1024))
                    self._parse_volume(payload)
                    if payload_size > len(payload):
                        fh.seek(payload_pos + payload_size)
                elif sec_type == "data":
                    data_section_offsets.append((seg_idx, payload_pos))
                    fh.seek(payload_pos + payload_size)
                elif sec_type in ("table", "table2"):
                    payload = fh.read(payload_size)
                    entries = self._parse_table(payload)
                    tables.append(entries)
                    # offsets in table are relative to the previous data section
                elif sec_type in ("sectors",):
                    # some variants store chunk data in 'sectors'
                    data_section_offsets.append((seg_idx, payload_pos))
                    fh.seek(payload_pos + payload_size)
                elif sec_type in ("hash", "digest", "done", "next", "error", "session", "data2"):
                    fh.seek(payload_pos + payload_size)
                else:
                    fh.seek(payload_pos + payload_size)

                if next_off == 0 or next_off <= fh.tell() - 76:
                    # end of section chain for this segment
                    break
                fh.seek(next_off)

        # Build chunk location table
        # Standard layout: each table entry is offset of compressed chunk relative to data section
        if tables and data_section_offsets:
            # Pair tables with data sections in order
            self._chunk_offsets = []
            for t_idx, entries in enumerate(tables):
                if t_idx >= len(data_section_offsets):
                    data_seg, data_base = data_section_offsets[-1]
                else:
                    data_seg, data_base = data_section_offsets[t_idx]
                for ent in entries:
                    # bit 31 may indicate compressed (in older formats); offset is lower bits
                    off = ent & 0x7FFFFFFF
                    compressed_flag = 1 if (ent & 0x80000000) else 0
                    self._chunk_offsets.append((data_seg, data_base + off, compressed_flag))
            self._chunk_count = max(self._chunk_count, len(self._chunk_offsets))
        elif data_section_offsets and self._chunk_count:
            # Fallback: assume contiguous compressed chunks (rare)
            logger.warning("E01 table section missing – sequential chunk read may fail")

    def _parse_volume(self, payload: bytes) -> None:
        if len(payload) < 52:
            return
        # Media type (1), unknown, chunk count (4), sectors per chunk (4), bytes/sector (4),
        # sector count (4 or 8 depending on version), …
        # Layout differs slightly between EWF-E01 versions; use robust field extraction.
        try:
            chunk_count = _u32(payload, 0x04)
            sectors_per_chunk = _u32(payload, 0x08)
            bytes_per_sector = _u32(payload, 0x0C)
            if bytes_per_sector in (512, 1024, 2048, 4096):
                self._bytes_per_sector = bytes_per_sector
            if sectors_per_chunk > 0:
                self._chunk_size = sectors_per_chunk * self._bytes_per_sector
            if chunk_count > 0:
                self._chunk_count = chunk_count
            # sector count – try 32-bit then 64-bit
            sector_count = _u32(payload, 0x10)
            if sector_count == 0 and len(payload) >= 0x18:
                sector_count = _u64(payload, 0x10)
            if sector_count:
                self._media_size = sector_count * self._bytes_per_sector
        except Exception as e:
            logger.debug("Volume parse soft-fail: %s", e)

    def _parse_table(self, payload: bytes) -> List[int]:
        """Parse EWF table section payload → list of chunk offsets."""
        if len(payload) < 24:
            return []
        # First 4 bytes: number of entries; then padding/offsets array
        try:
            nentries = _u32(payload, 0)
            # Offsets start after header (often at 0x10 or after 24-byte header)
            # libewf: table header is 24 bytes then uint32 offsets
            start = 24
            if start + nentries * 4 > len(payload):
                start = 16
            if start + nentries * 4 > len(payload):
                nentries = (len(payload) - start) // 4
            entries = []
            for i in range(nentries):
                entries.append(_u32(payload, start + i * 4))
            return entries
        except Exception:
            return []

    # -- chunk read ---------------------------------------------------------

    def _read_chunk(self, index: int) -> bytes:
        if index in self._cache:
            return self._cache[index]
        if index < 0 or index >= len(self._chunk_offsets):
            return b"\x00" * self._chunk_size

        seg_idx, file_off, _flag = self._chunk_offsets[index]
        fh = self._files[seg_idx]
        fh.seek(file_off)

        # Compressed chunk: 4-byte size (bits 0-30 size, bit 31 = compressed flag in some versions)
        # Actually each chunk is: zlib data ending before next chunk offset.
        # Size = next_offset - this_offset (or remaining to section end).
        if index + 1 < len(self._chunk_offsets):
            next_seg, next_off, _ = self._chunk_offsets[index + 1]
            if next_seg == seg_idx and next_off > file_off:
                comp_size = next_off - file_off
            else:
                comp_size = self._chunk_size + 1024  # guess
        else:
            comp_size = self._chunk_size + 4096

        # Clamp
        comp_size = max(4, min(comp_size, 16 * 1024 * 1024))
        raw = fh.read(comp_size)
        if not raw:
            data = b"\x00" * self._chunk_size
        else:
            data = self._decompress_chunk(raw)
            if len(data) < self._chunk_size:
                data = data + b"\x00" * (self._chunk_size - len(data))
            elif len(data) > self._chunk_size:
                data = data[: self._chunk_size]

        self._cache[index] = data
        self._cache_order.append(index)
        if len(self._cache_order) > self._cache_limit:
            old = self._cache_order.pop(0)
            self._cache.pop(old, None)
        return data

    def _decompress_chunk(self, raw: bytes) -> bytes:
        # Try zlib; if fail, treat as uncompressed
        # Some chunks have a 4-byte header before zlib stream
        for candidate in (raw, raw[4:], raw[1:]):
            try:
                return zlib.decompress(candidate)
            except zlib.error:
                continue
        # Uncompressed
        return raw[: self._chunk_size]

    # -- file-like API ------------------------------------------------------

    def read(self, n: int = -1) -> bytes:
        if self._closed:
            raise ValueError("I/O on closed E01 image")
        if n < 0:
            n = self._media_size - self._pos
        if n <= 0 or self._pos >= self._media_size:
            return b""
        n = min(n, self._media_size - self._pos)
        out = bytearray()
        while len(out) < n:
            chunk_idx = self._pos // self._chunk_size
            offset_in_chunk = self._pos % self._chunk_size
            chunk = self._read_chunk(chunk_idx)
            take = min(n - len(out), self._chunk_size - offset_in_chunk)
            out.extend(chunk[offset_in_chunk: offset_in_chunk + take])
            self._pos += take
        return bytes(out)

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            self._pos = offset
        elif whence == 1:
            self._pos += offset
        elif whence == 2:
            self._pos = self._media_size + offset
        else:
            raise ValueError("invalid whence")
        self._pos = max(0, min(self._pos, self._media_size))
        return self._pos

    def tell(self) -> int:
        return self._pos

    def close(self) -> None:
        if not self._closed:
            for fh in self._files:
                try:
                    fh.close()
                except Exception:
                    pass
            self._files.clear()
            self._cache.clear()
            self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    @property
    def size(self) -> int:
        return self._media_size


# ---------------------------------------------------------------------------
# AFF4 (optional dependency)
# ---------------------------------------------------------------------------

class AFF4Error(Exception):
    pass


def open_aff4(path: str | Path) -> Tuple[BinaryIO, int]:
    """
    Open an AFF4 image if pyaff4 is installed.
    Returns (file-like, size).
    """
    path = Path(path)
    try:
        # pyaff4 API varies by version; try common patterns
        import pyaff4  # type: ignore
    except ImportError:
        raise AFF4Error(
            "AFF4 support requires the optional 'pyaff4' package.\n"
            "Install with:  pip install pyaff4\n"
            "Or convert the image to raw/dd with an external tool."
        )

    # Attempt several known APIs
    try:
        from pyaff4 import aff4_image  # type: ignore
        img = aff4_image.AFF4Image(str(path))
        size = getattr(img, "size", None) or getattr(img, "media_size", 0)
        if not size:
            # try seek end
            img.seek(0, 2)
            size = img.tell()
            img.seek(0)
        return img, int(size)
    except Exception:
        pass

    try:
        from pyaff4.container import Container  # type: ignore
        c = Container.open(str(path))
        # Pick first image stream
        for stream in getattr(c, "images", []) or []:
            size = getattr(stream, "size", 0)
            return stream, int(size)
    except Exception as e:
        raise AFF4Error(f"Failed to open AFF4 image: {e}") from e

    raise AFF4Error("Could not open AFF4 image with available pyaff4 API")


# ---------------------------------------------------------------------------
# Optional libewf path
# ---------------------------------------------------------------------------

def open_e01_pyewf(path: str | Path) -> Optional[Tuple[BinaryIO, int]]:
    try:
        import pyewf  # type: ignore
    except ImportError:
        return None
    try:
        filenames = pyewf.glob(str(path))
        handle = pyewf.handle()
        handle.open(filenames)
        size = handle.get_media_size()

        class _PyewfWrapper:
            def __init__(self, h):
                self._h = h
                self._pos = 0

            def read(self, n=-1):
                if n < 0:
                    n = size - self._pos
                if n <= 0:
                    return b""
                data = self._h.read(n)
                self._pos += len(data)
                return data

            def seek(self, off, whence=0):
                if whence == 0:
                    self._pos = off
                elif whence == 1:
                    self._pos += off
                else:
                    self._pos = size + off
                self._h.seek(self._pos)
                return self._pos

            def tell(self):
                return self._pos

            def close(self):
                try:
                    self._h.close()
                except Exception:
                    pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                self.close()

        return _PyewfWrapper(handle), int(size)
    except Exception as e:
        logger.warning("pyewf open failed, falling back to pure Python: %s", e)
        return None


# ---------------------------------------------------------------------------
# Public open
# ---------------------------------------------------------------------------

def open_forensic_image(path: str | Path) -> Tuple[BinaryIO, int]:
    """
    Open E01 or AFF/AFF4 forensic image.
    Returns (stream, media_size).
    """
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(path)

    suffix = path.suffix.lower()

    # E01 / EX01 / L01
    if is_e01(path) or suffix in (".e01", ".ex01", ".l01", ".lx01", ".s01"):
        via = open_e01_pyewf(path)
        if via is not None:
            logger.info("Opened E01 via pyewf/libewf: %s", path)
            return via
        img = E01Image(path)
        return img, img.size

    # AFF4
    if suffix == ".aff4" or (suffix == ".aff" and path.read_bytes()[:4] == b"AFF4"):
        return open_aff4(path)

    # Classic AFF
    if suffix in (".aff", ".afd", ".afm"):
        raise AFF4Error(
            "Classic AFF format is not supported natively.\n"
            "Convert to raw or AFF4, or install a tool such as affconvert.\n"
            "AFF4 files can be opened if pyaff4 is installed."
        )

    raise ValueError(f"Unrecognized forensic image format: {path}")
