"""Low-level disk and volume access for forensic recovery.

Supports regular files, disk images, and Windows raw devices
(PhysicalDrive and volume paths). Requires Administrator rights
on Windows for raw device access.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, List, Optional, Tuple


@dataclass
class DriveInfo:
    path: str           # e.g. \\.\PhysicalDrive0 or C:\ or /dev/sda
    display_name: str
    size_bytes: int
    is_physical: bool
    is_removable: bool = False
    file_system: str = ""


def is_windows() -> bool:
    return sys.platform == "win32"


def list_physical_drives() -> List[DriveInfo]:
    """Enumerate physical disks (Windows only for now)."""
    drives: List[DriveInfo] = []
    if not is_windows():
        # Linux fallback – common block devices
        for dev in Path("/dev").glob("sd?") + list(Path("/dev").glob("nvme*n1")):
            try:
                size = _linux_block_size(dev)
                drives.append(DriveInfo(
                    path=str(dev),
                    display_name=f"Disk {dev.name}",
                    size_bytes=size,
                    is_physical=True,
                ))
            except Exception:
                pass
        return drives

    # Windows
    try:
        import ctypes
        from ctypes import wintypes

        for i in range(16):  # up to 16 physical drives
            path = f"\\\\.\\PhysicalDrive{i}"
            try:
                handle = _win_open_raw(path)
                if handle is None:
                    continue
                size = _win_get_size(handle)
                _win_close(handle)
                if size > 0:
                    drives.append(DriveInfo(
                        path=path,
                        display_name=f"Physical Drive {i} ({_human(size)})",
                        size_bytes=size,
                        is_physical=True,
                    ))
            except Exception:
                continue
    except Exception:
        pass
    return drives


def list_volumes() -> List[DriveInfo]:
    """Logical volumes / mount points."""
    vols: List[DriveInfo] = []
    if is_windows():
        import string
        for letter in string.ascii_uppercase:
            root = f"{letter}:\\"
            if os.path.exists(root):
                try:
                    # Use the volume path for raw access when possible
                    vol_path = f"\\\\.\\{letter}:"
                    size = 0
                    try:
                        h = _win_open_raw(vol_path)
                        if h:
                            size = _win_get_size(h)
                            _win_close(h)
                    except Exception:
                        # Fallback to free space info
                        import shutil
                        usage = shutil.disk_usage(root)
                        size = usage.total
                    vols.append(DriveInfo(
                        path=vol_path,
                        display_name=f"Volume {letter}: ({_human(size)})",
                        size_bytes=size,
                        is_physical=False,
                    ))
                except Exception:
                    continue
    else:
        # Linux – mount points
        for mp in ["/", "/home", "/mnt", "/media"]:
            p = Path(mp)
            if p.exists():
                try:
                    size = sum(f.stat().st_size for f in p.glob("**/*") if f.is_file())  # rough
                except Exception:
                    size = 0
                vols.append(DriveInfo(path=mp, display_name=mp, size_bytes=size, is_physical=False))
    return vols


def open_source(path: str) -> Tuple[BinaryIO, int]:
    """
    Open a file, disk image, or raw device and return (stream, size).
    Caller is responsible for closing the stream.
    """
    # Prefer ordinary file open first (works for images everywhere)
    p = Path(path)
    if p.is_file() and not path.startswith("\\\\.\\") and not path.startswith("/dev/"):
        size = p.stat().st_size
        return open(path, "rb"), size

    if is_windows() and (path.startswith("\\\\.\\") or path.startswith(r"\\.\ ")):
        handle = _win_open_raw(path)
        if handle is None:
            raise PermissionError(
                f"Cannot open {path}. Run as Administrator and ensure the volume is not locked."
            )
        size = _win_get_size(handle)
        # Wrap the Windows handle in a file-like object
        return _WinRawStream(handle, size), size

    # Linux raw device
    if path.startswith("/dev/"):
        size = _linux_block_size(Path(path))
        return open(path, "rb"), size

    # Fallback
    size = Path(path).stat().st_size
    return open(path, "rb"), size


# ------------------------------------------------------------------
# Windows helpers (ctypes)
# ------------------------------------------------------------------

def _win_open_raw(path: str):
    import ctypes
    from ctypes import wintypes

    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x80

    CreateFileW = ctypes.windll.kernel32.CreateFileW
    CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE
    ]
    CreateFileW.restype = wintypes.HANDLE

    handle = CreateFileW(
        path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None
    )
    if handle == wintypes.HANDLE(-1).value:
        return None
    return handle


def _win_close(handle) -> None:
    import ctypes
    ctypes.windll.kernel32.CloseHandle(handle)


def _win_get_size(handle) -> int:
    import ctypes
    from ctypes import wintypes

    GetFileSizeEx = ctypes.windll.kernel32.GetFileSizeEx
    GetFileSizeEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_longlong)]
    GetFileSizeEx.restype = wintypes.BOOL

    size = ctypes.c_longlong(0)
    if GetFileSizeEx(handle, ctypes.byref(size)):
        return size.value
    return 0


class _WinRawStream:
    """Minimal file-like wrapper around a Windows HANDLE for sequential reading."""

    def __init__(self, handle, size: int):
        self._handle = handle
        self._size = size
        self._pos = 0

    def read(self, n: int = -1) -> bytes:
        import ctypes
        from ctypes import wintypes

        if n < 0:
            n = self._size - self._pos
        if n <= 0:
            return b""

        buf = ctypes.create_string_buffer(n)
        read = wintypes.DWORD(0)
        ok = ctypes.windll.kernel32.ReadFile(
            self._handle, buf, n, ctypes.byref(read), None
        )
        if not ok:
            return b""
        self._pos += read.value
        return buf.raw[:read.value]

    def seek(self, offset: int, whence: int = 0) -> int:
        import ctypes
        from ctypes import wintypes

        FILE_BEGIN = 0
        FILE_CURRENT = 1
        FILE_END = 2
        move = {0: FILE_BEGIN, 1: FILE_CURRENT, 2: FILE_END}[whence]

        high = ctypes.c_long(offset >> 32)
        low = ctypes.windll.kernel32.SetFilePointer(
            self._handle, offset & 0xFFFFFFFF, ctypes.byref(high), move
        )
        if low == 0xFFFFFFFF:
            raise OSError("Seek failed")
        self._pos = (high.value << 32) | (low & 0xFFFFFFFF)
        return self._pos

    def tell(self) -> int:
        return self._pos

    def close(self) -> None:
        _win_close(self._handle)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def _linux_block_size(dev: Path) -> int:
    # Try /sys
    name = dev.name
    sys_size = Path(f"/sys/block/{name}/size")
    if sys_size.exists():
        sectors = int(sys_size.read_text().strip())
        return sectors * 512
    # Fallback
    with open(dev, "rb") as f:
        f.seek(0, 2)
        return f.tell()


def _human(n: int) -> str:
    size = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024:
            return f"{size:.1f} {u}"
        size /= 1024
    return f"{size:.1f} PB"
