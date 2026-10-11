"""
NTFS deleted-file recovery via Master File Table ($MFT).

Reads the boot sector, locates $MFT, walks FILE records, and extracts
entries that are no longer in-use (deleted). Where data runs are still
valid, file contents can be reconstructed.

Requires raw volume access (Administrator on Windows).
Works on live volumes (\\\\.\\C:) and NTFS disk images.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Callable, List, Optional, Tuple

logger = logging.getLogger("Retrievo")

ProgressCB = Optional[Callable[[float, str], None]]


@dataclass
class NTFSBoot:
    bytes_per_sector: int
    sectors_per_cluster: int
    mft_lcn: int
    mft_record_size: int
    cluster_size: int
    volume_size: int = 0


@dataclass
class DeletedFile:
    mft_ref: int
    name: str
    parent_ref: int
    size: int
    is_directory: bool
    data_runs: List[Tuple[int, int]] = field(default_factory=list)  # (lcn, clusters)
    resident_data: Optional[bytes] = None
    confidence: float = 0.9

    @property
    def has_data(self) -> bool:
        return bool(self.resident_data) or bool(self.data_runs)


def _u16(b: bytes, off: int) -> int:
    return struct.unpack_from("<H", b, off)[0]


def _u32(b: bytes, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]


def _u64(b: bytes, off: int) -> int:
    return struct.unpack_from("<Q", b, off)[0]


def _i8(b: bytes, off: int) -> int:
    return struct.unpack_from("<b", b, off)[0]


def parse_boot_sector(data: bytes) -> NTFSBoot:
    if len(data) < 512:
        raise ValueError("Boot sector too small")
    if data[3:7] != b"NTFS":
        # Some images still have OEM ID NTFS at 3
        if data[0x03:0x07] != b"NTFS":
            raise ValueError("Not an NTFS volume (missing NTFS OEM ID)")
    bps = _u16(data, 0x0B)
    spc = data[0x0D]
    mft_lcn = struct.unpack_from("<q", data, 0x30)[0]
    # Clusters per MFT record (signed byte at 0x40)
    cpr = _i8(data, 0x40)
    if cpr < 0:
        mft_record_size = 1 << (-cpr)
    else:
        mft_record_size = cpr * bps * spc
    cluster_size = bps * spc
    return NTFSBoot(
        bytes_per_sector=bps,
        sectors_per_cluster=spc,
        mft_lcn=mft_lcn,
        mft_record_size=mft_record_size,
        cluster_size=cluster_size,
    )


def _apply_fix_fix(record: bytearray) -> None:
    """Apply NTFS update sequence (fix-fix) to an MFT record."""
    if len(record) < 42 or record[0:4] != b"FILE":
        return
    usa_offset = _u16(record, 0x04)
    usa_count = _u16(record, 0x06)
    if usa_offset == 0 or usa_count < 2:
        return
    usa = record[usa_offset : usa_offset + usa_count * 2]
    if len(usa) < usa_count * 2:
        return
    sector_size = 512
    for i in range(1, usa_count):
        pos = i * sector_size - 2
        if pos + 2 <= len(record):
            record[pos : pos + 2] = usa[i * 2 : i * 2 + 2]


def _decode_runs(run_list: bytes) -> List[Tuple[int, int]]:
    """Decode NTFS data runs → list of (lcn, cluster_count). lcn=-1 for sparse."""
    runs: List[Tuple[int, int]] = []
    offset = 0
    current_lcn = 0
    while offset < len(run_list):
        header = run_list[offset]
        offset += 1
        if header == 0:
            break
        length_size = header & 0x0F
        offset_size = (header >> 4) & 0x0F
        if length_size == 0 or offset + length_size > len(run_list):
            break
        run_len = int.from_bytes(run_list[offset : offset + length_size], "little")
        offset += length_size
        if offset_size == 0:
            runs.append((-1, run_len))  # sparse
            continue
        if offset + offset_size > len(run_list):
            break
        raw = run_list[offset : offset + offset_size]
        offset += offset_size
        # Sign-extend
        val = int.from_bytes(raw, "little", signed=True)
        current_lcn += val
        runs.append((current_lcn, run_len))
    return runs


def _parse_attribute(data: bytes, offset: int) -> Optional[dict]:
    if offset + 16 > len(data):
        return None
    attr_type = _u32(data, offset)
    if attr_type == 0xFFFFFFFF:
        return None
    attr_len = _u32(data, offset + 4)
    if attr_len < 16 or offset + attr_len > len(data):
        return None
    non_resident = data[offset + 8]
    name_len = data[offset + 9]
    name_off = _u16(data, offset + 10)
    name = ""
    if name_len and name_off:
        try:
            name = data[offset + name_off : offset + name_off + name_len * 2].decode("utf-16-le", errors="replace")
        except Exception:
            pass
    result = {
        "type": attr_type,
        "length": attr_len,
        "non_resident": non_resident,
        "name": name,
        "content": None,
        "runs": [],
        "data_size": 0,
    }
    if non_resident == 0:
        content_len = _u32(data, offset + 16)
        content_off = _u16(data, offset + 20)
        start = offset + content_off
        result["content"] = data[start : start + content_len]
        result["data_size"] = content_len
    else:
        # Non-resident
        data_size = _u64(data, offset + 0x30) if offset + 0x40 <= len(data) else 0
        run_off = _u16(data, offset + 0x20)
        result["data_size"] = data_size
        if run_off and offset + run_off < offset + attr_len:
            result["runs"] = _decode_runs(data[offset + run_off : offset + attr_len])
    return result


def parse_mft_record(raw: bytes, record_index: int) -> Optional[DeletedFile]:
    if len(raw) < 48 or raw[0:4] != b"FILE":
        return None
    record = bytearray(raw)
    _apply_fix_fix(record)

    flags = _u16(record, 0x16)
    in_use = bool(flags & 0x01)
    is_dir = bool(flags & 0x02)
    # We want deleted files (not in use). Also include in-use if needed later.
    if in_use:
        return None

    attr_off = _u16(record, 0x14)
    names: List[str] = []
    parent_ref = 0
    data_runs: List[Tuple[int, int]] = []
    resident_data: Optional[bytes] = None
    data_size = 0

    offset = attr_off
    while offset < len(record) - 8:
        attr = _parse_attribute(record, offset)
        if attr is None:
            break
        atype = attr["type"]
        if atype == 0x30:  # $FILE_NAME
            content = attr.get("content") or b""
            if len(content) >= 66:
                parent_ref = _u64(content, 0) & 0xFFFFFFFFFFFF  # lower 6 bytes sequence+ref
                name_len = content[0x40]
                name_type = content[0x41]
                try:
                    fname = content[0x42 : 0x42 + name_len * 2].decode("utf-16-le", errors="replace")
                except Exception:
                    fname = ""
                # Prefer Win32 names (type 1 or 3) over DOS (2)
                if fname and name_type != 2:
                    names.insert(0, fname)
                elif fname:
                    names.append(fname)
                real_size = _u64(content, 0x30) if len(content) >= 0x38 else 0
                if real_size:
                    data_size = max(data_size, real_size)
        elif atype == 0x80 and not attr["name"]:  # unnamed $DATA
            data_size = max(data_size, attr.get("data_size") or 0)
            if attr["non_resident"]:
                data_runs = attr.get("runs") or []
            else:
                resident_data = attr.get("content")

        offset += attr["length"]
        if attr["length"] == 0:
            break

    if not names and not resident_data and not data_runs:
        return None

    name = names[0] if names else f"$MFT_{record_index}"
    conf = 0.92 if (resident_data or data_runs) else 0.7
    return DeletedFile(
        mft_ref=record_index,
        name=name,
        parent_ref=parent_ref,
        size=data_size or (len(resident_data) if resident_data else 0),
        is_directory=is_dir,
        data_runs=data_runs,
        resident_data=resident_data,
        confidence=conf,
    )


def read_clusters(
    stream: BinaryIO,
    boot: NTFSBoot,
    runs: List[Tuple[int, int]],
    max_bytes: int,
) -> bytes:
    chunks: List[bytes] = []
    remaining = max_bytes
    for lcn, nclusters in runs:
        if remaining <= 0:
            break
        if lcn < 0:
            # sparse – zeros
            to_read = min(remaining, nclusters * boot.cluster_size)
            chunks.append(b"\x00" * to_read)
            remaining -= to_read
            continue
        byte_off = lcn * boot.cluster_size
        to_read = min(remaining, nclusters * boot.cluster_size)
        try:
            stream.seek(byte_off)
            data = stream.read(to_read)
            chunks.append(data)
            remaining -= len(data)
            if len(data) < to_read:
                break
        except Exception as e:
            logger.warning("Failed reading LCN %s: %s", lcn, e)
            break
    return b"".join(chunks)


def scan_deleted_files(
    stream: BinaryIO,
    volume_size: int,
    progress: ProgressCB = None,
    max_records: int = 2_000_000,
    extract_data: bool = True,
    max_file_size: int = 100 * 1024 * 1024,
) -> List[DeletedFile]:
    """
    Scan NTFS $MFT for deleted file records.
    """
    def report(p: float, msg: str) -> None:
        if progress:
            progress(p, msg)

    stream.seek(0)
    boot_data = stream.read(512)
    boot = parse_boot_sector(boot_data)
    boot.volume_size = volume_size
    report(0.02, f"NTFS detected – cluster {boot.cluster_size} B, MFT record {boot.mft_record_size} B")

    mft_offset = boot.mft_lcn * boot.cluster_size
    stream.seek(mft_offset)
    # Read first MFT record ($MFT itself) to get full run list
    first = stream.read(boot.mft_record_size)
    if first[0:4] != b"FILE":
        raise ValueError("Could not read $MFT record 0 – volume may be damaged or not NTFS")

    # Parse $DATA runs of $MFT for full coverage
    record = bytearray(first)
    _apply_fix_fix(record)
    attr_off = _u16(record, 0x14)
    mft_runs: List[Tuple[int, int]] = []
    offset = attr_off
    while offset < len(record) - 8:
        attr = _parse_attribute(record, offset)
        if attr is None:
            break
        if attr["type"] == 0x80 and not attr["name"] and attr["non_resident"]:
            mft_runs = attr["runs"]
            break
        offset += attr["length"]
        if attr["length"] == 0:
            break

    if not mft_runs:
        # Fallback: sequential from mft_lcn for a limited range
        mft_runs = [(boot.mft_lcn, 64)]

    # Walk all MFT records via runs
    results: List[DeletedFile] = []
    record_index = 0
    total_clusters = sum(c for _, c in mft_runs if c > 0) or 1
    clusters_done = 0

    for lcn, nclusters in mft_runs:
        if lcn < 0:
            clusters_done += nclusters
            continue
        byte_off = lcn * boot.cluster_size
        bytes_to_read = nclusters * boot.cluster_size
        stream.seek(byte_off)
        # Read in chunks of records
        remaining = bytes_to_read
        while remaining > 0 and record_index < max_records:
            chunk_size = min(remaining, boot.mft_record_size * 64)
            chunk = stream.read(chunk_size)
            if not chunk:
                break
            for i in range(0, len(chunk) - boot.mft_record_size + 1, boot.mft_record_size):
                rec = chunk[i : i + boot.mft_record_size]
                deleted = parse_mft_record(rec, record_index)
                record_index += 1
                if deleted and not deleted.is_directory:
                    if extract_data and deleted.has_data and deleted.size <= max_file_size:
                        if deleted.resident_data is not None:
                            pass  # already have data
                        elif deleted.data_runs:
                            try:
                                deleted.resident_data = read_clusters(
                                    stream, boot, deleted.data_runs, min(deleted.size, max_file_size)
                                )
                                # restore stream position for MFT walk – re-seek
                                stream.seek(byte_off + (len(chunk) - remaining) + chunk_size)
                            except Exception as e:
                                logger.debug("Data extract failed for %s: %s", deleted.name, e)
                    results.append(deleted)
                if record_index >= max_records:
                    break
            remaining -= len(chunk)
            clusters_done += len(chunk) / boot.cluster_size
            report(
                min(0.95, clusters_done / total_clusters),
                f"Scanning $MFT… record {record_index:,} – {len(results):,} deleted files",
            )

    report(1.0, f"NTFS scan complete – {len(results):,} deleted file record(s)")
    return results


def open_ntfs_and_scan(
    path: str,
    progress: ProgressCB = None,
    extract_data: bool = True,
) -> List[DeletedFile]:
    from .disk_access import open_source

    stream, size = open_source(path)
    try:
        return scan_deleted_files(stream, size, progress=progress, extract_data=extract_data)
    finally:
        try:
            stream.close()
        except Exception:
            pass
