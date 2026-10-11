"""
Forensic recovery scanner.

Combines:
- Signature-based carving (primary method, works on any media)
- Recycle Bin / temporary folder enumeration
- Optional raw disk / volume access
"""

from __future__ import annotations

import logging
import os
import string
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

from .carver import CarvedFile, FileCarver
from .disk_access import open_source, list_physical_drives, list_volumes, DriveInfo
from .signatures import get_all_signatures, get_image_signatures, get_video_signatures

logger = logging.getLogger("FileRecoverPro")


@dataclass
class RecoverableItem:
    id: str
    name: str
    path: str
    size: int
    file_type: str          # image | video | document | other
    source: str             # carved | recycle_bin | filesystem | volume
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

    def scan_recycle_bin(self) -> List[RecoverableItem]:
        logger.info("Starting Recycle Bin / TEMP scan")
        items: List[RecoverableItem] = []
        self._report(0.0, "Enumerating Recycle Bin locations…")

        roots: List[Path] = []
        if os.name == "nt":
            for letter in string.ascii_uppercase:
                rb = Path(f"{letter}:/$Recycle.Bin")
                if rb.exists():
                    roots.append(rb)
            local = Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "Windows" / "Explorer"
            if local.exists():
                roots.append(local)
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
                for entry in root.rglob("*"):
                    if self._stop:
                        break
                    if not entry.is_file():
                        continue
                    try:
                        st = entry.stat()
                        if st.st_size == 0:
                            continue
                        ext = entry.suffix.lower()
                        items.append(RecoverableItem(
                            id=f"rb_{len(items)}",
                            name=entry.name,
                            path=str(entry),
                            size=st.st_size,
                            file_type=self._classify(ext),
                            source="recycle_bin",
                            confidence=0.92,
                            original_path=str(entry),
                        ))
                    except (PermissionError, OSError):
                        continue
            except (PermissionError, OSError) as e:
                logger.warning("Cannot access %s: %s", root, e)

        logger.info("Recycle Bin scan finished: %d items", len(items))
        self._report(1.0, f"Recycle Bin scan complete – {len(items)} item(s)")
        return items

    def scan_signatures(
        self,
        target: str,
        media_only: bool = True,
    ) -> List[RecoverableItem]:
        logger.info("Starting signature carve on %s (media_only=%s)", target, media_only)
        sigs = (get_image_signatures() + get_video_signatures()) if media_only else get_all_signatures()
        self.carver.signatures = sigs

        try:
            stream, size = open_source(target)
        except Exception as e:
            logger.error("Cannot open source %s: %s", target, e)
            raise

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

        logger.info("Signature carve finished: %d candidates from %s", len(items), target)
        return items

    def quick_scan(self, folder: str) -> List[RecoverableItem]:
        logger.info("Quick media scan of %s", folder)
        root = Path(folder)
        media_ext = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp",
                     ".mp4", ".avi", ".mov", ".mkv", ".wmv", ".flv", ".webm"}
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

        self._report(1.0, f"Quick scan finished – {len(items)} media file(s)")
        logger.info("Quick scan finished: %d items", len(items))
        return items

    def list_drives(self) -> List[DriveInfo]:
        return list_physical_drives() + list_volumes()

    @staticmethod
    def _classify(ext: str) -> str:
        images = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp"}
        videos = {".mp4", ".avi", ".mov", ".mkv", ".wmv", ".flv", ".webm"}
        docs = {".pdf", ".zip", ".rar", ".7z", ".db"}
        if ext in images:
            return "image"
        if ext in videos:
            return "video"
        if ext in docs:
            return "document"
        return "other"
