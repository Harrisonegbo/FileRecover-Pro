"""
Forensic recovery scanner for Windows local disks.

Modes:
- NTFS deleted files ($MFT)
- Signature carving
- Recycle Bin ($I / $R metadata)
- Quick media filesystem walk
"""

from __future__ import annotations

import logging
import os
import string
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

from .carver import FileCarver
from .disk_access import open_source, list_physical_drives, list_volumes, DriveInfo
from .signatures import get_all_signatures, get_image_signatures, get_video_signatures
from .ntfs import open_ntfs_and_scan, DeletedFile

logger = logging.getLogger("Retrievo")


@dataclass
class RecoverableItem:
    id: str
    name: str
    path: str
    size: int
    file_type: str
    source: str
    confidence: float = 1.0
    offset: int = 0
    data: Optional[bytes] = field(default=None, repr=False)
    original_path: Optional[str] = None

    @property
    def size_human(self) -> str:
        size = float(self.size)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"


class RecoveryScanner:
    def __init__(
        self,
        progress_callback: Optional[Callable[[float, str], None]] = None,
        log_path: Optional[str] = None,
    ):
        self.progress_callback = progress_callback
        self._stop = False
        self.carver = FileCarver(progress_callback=progress_callback)
        self._setup_logging(log_path)

    def _setup_logging(self, log_path: Optional[str]) -> None:
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
            sh = logging.StreamHandler()
            sh.setFormatter(fmt)
            logger.addHandler(sh)
            if log_path:
                fh = logging.FileHandler(log_path, encoding="utf-8")
                fh.setFormatter(fmt)
                logger.addHandler(fh)

    def stop(self) -> None:
        self._stop = True
        self.carver.stop()
        logger.info("Scan stop requested")

    def _report(self, p: float, msg: str) -> None:
        if self.progress_callback:
            self.progress_callback(p, msg)

    # ------------------------------------------------------------------
    # NTFS deleted files (primary Windows local-disk recovery)
    # ------------------------------------------------------------------

    def scan_ntfs_deleted(self, target: str) -> List[RecoverableItem]:
        """Recover deleted files from NTFS $MFT on a volume or image."""
        logger.info("NTFS deleted-file scan: %s", target)
        self._report(0.0, "Opening volume for NTFS $MFT analysis…")

        def prog(p: float, msg: str) -> None:
            self._report(p, msg)

        try:
            deleted = open_ntfs_and_scan(target, progress=prog, extract_data=True)
        except Exception as e:
            logger.error("NTFS scan failed: %s", e)
            raise

        items: List[RecoverableItem] = []
        for d in deleted:
            if self._stop:
                break
            if d.is_directory:
                continue
            ext = Path(d.name).suffix.lower()
            display = d.full_path or d.name
            items.append(RecoverableItem(
                id=f"mft_{d.mft_ref}_{d.sequence}",
                name=d.name,
                path=display,
                size=d.size,
                file_type=self._classify(ext),
                source="ntfs_deleted",
                confidence=d.confidence,
                offset=d.mft_ref,
                data=d.resident_data,
                original_path=display,
            ))
        logger.info("NTFS deleted scan finished: %d files", len(items))
        self._report(1.0, f"Found {len(items):,} deleted NTFS file(s)")
        return items

    # ------------------------------------------------------------------
    # Recycle Bin with $I metadata
    # ------------------------------------------------------------------

    def scan_recycle_bin(self) -> List[RecoverableItem]:
        logger.info("Starting Recycle Bin scan")
        items: List[RecoverableItem] = []
        self._report(0.0, "Enumerating Recycle Bin…")

        roots: List[Path] = []
        if os.name == "nt":
            for letter in string.ascii_uppercase:
                rb = Path(f"{letter}:/$Recycle.Bin")
                if rb.exists():
                    roots.append(rb)
        for env in ("TEMP", "TMP"):
            t = os.environ.get(env)
            if t:
                roots.append(Path(t))

        total = max(len(roots), 1)
        for idx, root in enumerate(roots):
            if self._stop:
                break
            self._report(idx / total, f"Scanning {root}")
            try:
                # Pair $I (metadata) with $R (data) files
                i_files = {f.name[2:]: f for f in root.rglob("$I*") if f.is_file()}
                r_files = {f.name[2:]: f for f in root.rglob("$R*") if f.is_file()}

                for key, r_path in r_files.items():
                    if self._stop:
                        break
                    try:
                        size = r_path.stat().st_size
                        if size == 0:
                            continue
                        original_name = r_path.name
                        original_path = str(r_path)
                        if key in i_files:
                            meta = self._parse_recycle_i(i_files[key])
                            if meta:
                                original_name = meta.get("name") or original_name
                                original_path = meta.get("path") or original_path
                        ext = Path(original_name).suffix.lower()
                        items.append(RecoverableItem(
                            id=f"rb_{len(items)}",
                            name=original_name,
                            path=str(r_path),
                            size=size,
                            file_type=self._classify(ext),
                            source="recycle_bin",
                            confidence=0.97,
                            original_path=str(r_path),
                        ))
                    except (PermissionError, OSError):
                        continue

                # Also pick up any leftover files in recycle without $R pattern
                for entry in root.rglob("*"):
                    if self._stop:
                        break
                    if not entry.is_file():
                        continue
                    if entry.name.startswith("$I") or entry.name.startswith("$R"):
                        continue
                    try:
                        size = entry.stat().st_size
                        if size == 0:
                            continue
                        items.append(RecoverableItem(
                            id=f"rb_{len(items)}",
                            name=entry.name,
                            path=str(entry),
                            size=size,
                            file_type=self._classify(entry.suffix.lower()),
                            source="recycle_bin",
                            confidence=0.9,
                            original_path=str(entry),
                        ))
                    except (PermissionError, OSError):
                        continue
            except (PermissionError, OSError) as e:
                logger.warning("Cannot access %s: %s", root, e)

        logger.info("Recycle Bin scan finished: %d items", len(items))
        self._report(1.0, f"Recycle Bin – {len(items)} item(s)")
        return items

    @staticmethod
    def _parse_recycle_i(path: Path) -> Optional[dict]:
        """Parse Windows $I recycle metadata (Win7+ format)."""
        try:
            data = path.read_bytes()
            if len(data) < 28:
                return None
            # Version (8 bytes on Win10, 4 on Win7) – try Win10 layout
            # Win10: header 8 + size 8 + delete time 8 + name length 4 + name UTF-16
            if len(data) >= 24:
                version = struct.unpack_from("<Q", data, 0)[0]
                if version in (1, 2) or data[0] in (1, 2):
                    # Win7: version 4 bytes
                    size = struct.unpack_from("<Q", data, 8)[0]
                    name_len = struct.unpack_from("<I", data, 24)[0]
                    name = data[28:28 + name_len * 2].decode("utf-16-le", errors="replace").rstrip("\x00")
                    return {"name": Path(name).name, "path": name, "size": size}
            # Fallback Win7
            size = struct.unpack_from("<Q", data, 8)[0]
            name = data[24:].decode("utf-16-le", errors="replace").split("\x00")[0]
            return {"name": Path(name).name, "path": name, "size": size}
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Signature carve
    # ------------------------------------------------------------------

    def scan_signatures(self, target: str, media_only: bool = True) -> List[RecoverableItem]:
        logger.info("Signature carve: %s media_only=%s", target, media_only)
        sigs = (get_image_signatures() + get_video_signatures()) if media_only else get_all_signatures()
        self.carver.signatures = sigs

        stream, size = open_source(target)
        try:
            carved = self.carver.carve_stream(stream, size, source_name=Path(target).name)
        finally:
            try:
                stream.close()
            except Exception:
                pass

        items: List[RecoverableItem] = []
        for c in carved:
            ftype = "image" if c.name in ("JPEG", "PNG", "GIF", "BMP", "TIFF", "WebP") else \
                    "video" if c.name in ("MP4", "AVI", "MOV", "MKV", "FLV", "WMV") else \
                    "document" if c.name in ("PDF", "ZIP", "RAR", "RAR5", "7z", "SQLite") else "other"
            items.append(RecoverableItem(
                id=f"carve_{c.offset:012X}",
                name=c.display_name,
                path=f"{target}@0x{c.offset:X}",
                size=c.size,
                file_type=ftype,
                source="carved",
                confidence=c.confidence,
                offset=c.offset,
                data=c.data,
            ))
        return items

    def quick_scan(self, folder: str) -> List[RecoverableItem]:
        logger.info("Quick media scan: %s", folder)
        root = Path(folder)
        media_ext = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp",
                     ".mp4", ".avi", ".mov", ".mkv", ".wmv", ".flv", ".webm",
                     ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".zip", ".rar"}
        items: List[RecoverableItem] = []
        files = [p for p in root.rglob("*") if p.is_file()]
        total = max(len(files), 1)
        for idx, f in enumerate(files):
            if self._stop:
                break
            if f.suffix.lower() in media_ext:
                try:
                    size = f.stat().st_size
                    items.append(RecoverableItem(
                        id=f"fs_{idx}",
                        name=f.name,
                        path=str(f),
                        size=size,
                        file_type=self._classify(f.suffix.lower()),
                        source="filesystem",
                        confidence=0.85,
                        original_path=str(f),
                    ))
                except OSError:
                    pass
            if idx % 100 == 0:
                self._report(idx / total, f"Quick scan… {f.name}")
        self._report(1.0, f"Quick scan – {len(items)} file(s)")
        return items

    def list_drives(self) -> List[DriveInfo]:
        return list_physical_drives() + list_volumes()

    @staticmethod
    def _classify(ext: str) -> str:
        images = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp"}
        videos = {".mp4", ".avi", ".mov", ".mkv", ".wmv", ".flv", ".webm"}
        docs = {".pdf", ".zip", ".rar", ".7z", ".db", ".doc", ".docx", ".xls", ".xlsx", ".txt"}
        if ext in images:
            return "image"
        if ext in videos:
            return "video"
        if ext in docs:
            return "document"
        return "other"
