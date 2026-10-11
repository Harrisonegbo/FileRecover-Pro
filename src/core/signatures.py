"""
File signatures (magic numbers) for forensic carving.
Includes validation helpers for higher confidence recovery.
"""

from __future__ import annotations

from typing import List, Optional, Tuple, Callable

# (name, extension, header, footer_or_None, max_size_bytes, validator_fn_or_None)
Signature = Tuple[str, str, bytes, Optional[bytes], int, Optional[Callable[[bytes], bool]]]


def _is_jpeg(data: bytes) -> bool:
    if len(data) < 4 or data[0:3] != b"\xFF\xD8\xFF":
        return False
    # Look for at least one valid marker
    return b"\xFF\xD9" in data or any(data[i] == 0xFF and data[i+1] in (0xC0, 0xC2, 0xC4, 0xDB, 0xE0, 0xE1)
                                       for i in range(2, min(len(data)-1, 512)))


def _is_png(data: bytes) -> bool:
    return len(data) >= 24 and data[0:8] == b"\x89PNG\r\n\x1a\n" and b"IHDR" in data[8:24]


def _is_gif(data: bytes) -> bool:
    return len(data) >= 6 and data[0:6] in (b"GIF87a", b"GIF89a")


def _is_bmp(data: bytes) -> bool:
    if len(data) < 14 or data[0:2] != b"BM":
        return False
    # File size field at offset 2 (little-endian)
    declared = int.from_bytes(data[2:6], "little")
    return 14 <= declared <= len(data) + 1024 * 1024  # allow some slack


def _is_webp(data: bytes) -> bool:
    return len(data) >= 12 and data[0:4] == b"RIFF" and data[8:12] == b"WEBP"


def _is_avi(data: bytes) -> bool:
    return len(data) >= 12 and data[0:4] == b"RIFF" and data[8:12] == b"AVI "


def _is_mp4(data: bytes) -> bool:
    if len(data) < 12:
        return False
    # ftyp box
    if data[4:8] == b"ftyp":
        return True
    # sometimes size is 0x00000018 etc.
    return b"ftyp" in data[0:32]


def _is_pdf(data: bytes) -> bool:
    return data.startswith(b"%PDF-") and b"%%EOF" in data[-1024:] if len(data) > 1024 else b"%%EOF" in data


SIGNATURES: List[Signature] = [
    # Images – high priority for media recovery
    ("JPEG", ".jpg", b"\xFF\xD8\xFF", b"\xFF\xD9", 80 * 1024 * 1024, _is_jpeg),
    ("PNG", ".png", b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82", 80 * 1024 * 1024, _is_png),
    ("GIF", ".gif", b"GIF87a", b"\x00\x3B", 30 * 1024 * 1024, _is_gif),
    ("GIF", ".gif", b"GIF89a", b"\x00\x3B", 30 * 1024 * 1024, _is_gif),
    ("BMP", ".bmp", b"BM", None, 50 * 1024 * 1024, _is_bmp),
    ("TIFF", ".tif", b"II*\x00", None, 100 * 1024 * 1024, None),
    ("TIFF", ".tif", b"MM\x00*", None, 100 * 1024 * 1024, None),
    ("WebP", ".webp", b"RIFF", None, 40 * 1024 * 1024, _is_webp),

    # Video
    ("MP4", ".mp4", b"\x00\x00\x00", None, 4 * 1024 * 1024 * 1024, _is_mp4),  # refined by validator
    ("AVI", ".avi", b"RIFF", None, 4 * 1024 * 1024 * 1024, _is_avi),
    ("MOV", ".mov", b"\x00\x00\x00\x14ftypqt", None, 4 * 1024 * 1024 * 1024, None),
    ("MOV", ".mov", b"\x00\x00\x00\x18ftypqt", None, 4 * 1024 * 1024 * 1024, None),
    ("MKV", ".mkv", b"\x1A\x45\xDF\xA3", None, 8 * 1024 * 1024 * 1024, None),
    ("FLV", ".flv", b"FLV\x01", None, 2 * 1024 * 1024 * 1024, None),
    ("WMV", ".wmv", b"\x30\x26\xB2\x75\x8E\x66\xCF\x11", None, 4 * 1024 * 1024 * 1024, None),

    # Documents / containers often recovered in forensic cases
    ("PDF", ".pdf", b"%PDF-", b"%%EOF", 200 * 1024 * 1024, _is_pdf),
    ("ZIP", ".zip", b"PK\x03\x04", None, 1024 * 1024 * 1024, None),
    ("RAR", ".rar", b"Rar!\x1A\x07\x00", None, 1024 * 1024 * 1024, None),
    ("RAR5", ".rar", b"Rar!\x1A\x07\x01\x00", None, 1024 * 1024 * 1024, None),
    ("7z", ".7z", b"\x37\x7A\xBC\xAF\x27\x1C", None, 1024 * 1024 * 1024, None),
    ("SQLite", ".db", b"SQLite format 3\x00", None, 500 * 1024 * 1024, None),
]


def get_image_signatures() -> List[Signature]:
    return [s for s in SIGNATURES if s[0] in ("JPEG", "PNG", "GIF", "BMP", "TIFF", "WebP")]


def get_video_signatures() -> List[Signature]:
    return [s for s in SIGNATURES if s[0] in ("MP4", "AVI", "MOV", "MKV", "FLV", "WMV")]


def get_all_signatures() -> List[Signature]:
    return list(SIGNATURES)
