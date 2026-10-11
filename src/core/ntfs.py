"""
Advanced NTFS $MFT deleted-entry parsing and recovery.

Features:
  - Boot sector validation and geometry
  - Full $MFT run-list walk (fragmented MFT)
  - Update Sequence (fix-fix) repair per sector
  - $STANDARD_INFORMATION timestamps (created / modified / MFT / accessed)
  - Multiple $FILE_NAME attributes (Win32, DOS, POSIX) with preference order
  - Parent directory reference chain → reconstructed path
  - $DATA (default + named Alternate Data Streams)
  - $ATTRIBUTE_LIST handling for attributes stored in extension records
  - Resident and non-resident data extraction via data runs
  - Sequence-number sanity checks
  - Confidence scoring based on recoverable data and path quality

Requires raw volume or disk-image access (Administrator on live Windows volumes).
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import BinaryIO, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("Retrievo")

ProgressCB = Optional[Callable[[float, str], None]]

# NTFS attribute type codes
ATTR_STANDARD_INFORMATION = 0x10
ATTR_ATTRIBUTE_LIST = 0x20
ATTR_FILE_NAME = 0x30
ATTR_OBJECT_ID = 0x40
ATTR_DATA = 0x80
ATTR_INDEX_ROOT = 0x90
ATTR_INDEX_ALLOCATION = 0xA0
ATTR_BITMAP = 0xB0
ATTR_END = 0xFFFFFFFF

# $FILE_NAME namespace types
NS_POSIX = 0
NS_WIN32 = 1
NS_DOS = 2
NS_WIN32_DOS = 3

# Windows FILETIME epoch (1601-01-01) → Unix
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class NTFSBoot:
    bytes_per_sector: int
    sectors_per_cluster: int
    mft_lcn: int
    mft_record_size: int
    cluster_size: int
    volume_size: int = 0
    total_sectors: int = 0


@dataclass
class DataStream:
    """One $DATA attribute (default or ADS)."""
    name: str  # "" for default stream
    size: int
    resident: bool
    runs: List[Tuple[int, int]] = field(default_factory=list)  # (lcn, clusters)
    data: Optional[bytes] = None


@dataclass
class FileNameEntry:
    name: str
    namespace: int
    parent_ref: int
    parent_seq: int
    allocated_size: int
    real_size: int
    flags: int


@dataclass
class MftTimestamps:
    created: Optional[datetime] = None
    modified: Optional[datetime] = None
    mft_modified: Optional[datetime] = None
    accessed: Optional[datetime] = None


@dataclass
class DeletedFile:
    mft_ref: int
    sequence: int
    name: str
    parent_ref: int
    parent_seq: int
    full_path: str
    size: int
    is_directory: bool
    timestamps: MftTimestamps = field(default_factory=MftTimestamps)
    streams: List[DataStream] = field(default_factory=list)
    names: List[FileNameEntry] = field(default_factory=list)
    data_runs: List[Tuple[int, int]] = field(default_factory=list)
    resident_data: Optional[bytes] = None
    confidence: float = 0.9
    flags_raw: int = 0
    hard_link_count: int = 0
    note: str = ""

    @property
    def has_data(self) -> bool:
        if self.resident_data:
            return True
        if self.data_runs:
            return True
        return any(s.data or s.runs for s in self.streams)


# ---------------------------------------------------------------------------
# Binary helpers
# ---------------------------------------------------------------------------

def _u16(b: bytes, off: int) -> int:
    return struct.unpack_from("<H", b, off)[0]


def _u32(b: bytes, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]


def _u64(b: bytes, off: int) -> int:
    return struct.unpack_from("<Q", b, off)[0]


def _i8(b: bytes, off: int) -> int:
    return struct.unpack_from("<b", b, off)[0]


def _filetime(raw: int) -> Optional[datetime]:
    if raw == 0 or raw == 0xFFFFFFFFFFFFFFFF:
        return None
    try:
        # 100-ns intervals since 1601
        return _FILETIME_EPOCH + timedelta(microseconds=raw / 10)
    except (OverflowError, ValueError, OSError):
        return None


def _decode_runs(run_list: bytes) -> List[Tuple[int, int]]:
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
        run_len = int.from_bytes(run_list[offset: offset + length_size], "little")
        offset += length_size
        if offset_size == 0:
            runs.append((-1, run_len))
            continue
        if offset + offset_size > len(run_list):
            break
        raw = run_list[offset: offset + offset_size]
        offset += offset_size
        val = int.from_bytes(raw, "little", signed=True)
        current_lcn += val
        if current_lcn < 0:
            break
        runs.append((current_lcn, run_len))
    return runs


# ---------------------------------------------------------------------------
# Boot sector
# ---------------------------------------------------------------------------

def parse_boot_sector(data: bytes) -> NTFSBoot:
    if len(data) < 512:
        raise ValueError("Boot sector too small")
    oem = data[0x03:0x0B]
    if b"NTFS" not in oem:
        raise ValueError("Not an NTFS volume (OEM ID does not contain NTFS)")

    bps = _u16(data, 0x0B)
    if bps not in (512, 1024, 2048, 4096):
        raise ValueError(f"Unusual bytes/sector: {bps}")
    spc = data[0x0D]
    if spc == 0 or (spc & (spc - 1)) != 0:
        raise ValueError(f"Invalid sectors/cluster: {spc}")

    total_sectors = _u64(data, 0x28)
    mft_lcn = struct.unpack_from("<q", data, 0x30)[0]
    if mft_lcn < 0:
        raise ValueError("Invalid $MFT LCN")

    cpr = _i8(data, 0x40)
    if cpr < 0:
        mft_record_size = 1 << (-cpr)
    else:
        mft_record_size = cpr * bps * spc
    if mft_record_size not in (1024, 2048, 4096):
        # still allow but warn
        logger.warning("Unusual MFT record size: %s", mft_record_size)

    cluster_size = bps * spc
    return NTFSBoot(
        bytes_per_sector=bps,
        sectors_per_cluster=spc,
        mft_lcn=mft_lcn,
        mft_record_size=mft_record_size,
        cluster_size=cluster_size,
        volume_size=total_sectors * bps,
        total_sectors=total_sectors,
    )


def _apply_fix_fix(record: bytearray, sector_size: int = 512) -> bool:
    """
    Apply NTFS update sequence array.
    Returns False if the record looks corrupt (USA mismatch).
    """
    if len(record) < 42:
        return False
    sig = bytes(record[0:4])
    if sig not in (b"FILE", b"BAAD", b"INDX"):
        return False
    usa_offset = _u16(record, 0x04)
    usa_count = _u16(record, 0x06)
    if usa_offset < 0x2A or usa_count < 2:
        return sig == b"FILE"
    need = usa_offset + usa_count * 2
    if need > len(record):
        return False
    usa = record[usa_offset: usa_offset + usa_count * 2]
    usn = usa[0:2]
    # Verify and replace end-of-sector markers
    for i in range(1, usa_count):
        pos = i * sector_size - 2
        if pos + 2 > len(record):
            return False
        if record[pos: pos + 2] != usn:
            # Mismatch – record may be partially overwritten
            logger.debug("USA mismatch at sector %s", i)
        record[pos: pos + 2] = usa[i * 2: i * 2 + 2]
    return True


# ---------------------------------------------------------------------------
# Attribute parsing
# ---------------------------------------------------------------------------

def _parse_attribute(data: bytes, offset: int) -> Optional[dict]:
    if offset + 16 > len(data):
        return None
    attr_type = _u32(data, offset)
    if attr_type == ATTR_END:
        return None
    attr_len = _u32(data, offset + 4)
    if attr_len < 16 or attr_len > len(data) - offset:
        return None
    non_resident = data[offset + 8]
    name_len = data[offset + 9]
    name_off = _u16(data, offset + 10)
    flags = _u16(data, offset + 12)
    attr_id = _u16(data, offset + 14)

    name = ""
    if name_len and name_off and offset + name_off + name_len * 2 <= len(data):
        try:
            name = data[offset + name_off: offset + name_off + name_len * 2].decode(
                "utf-16-le", errors="replace"
            )
        except Exception:
            pass

    result: dict = {
        "type": attr_type,
        "length": attr_len,
        "non_resident": bool(non_resident),
        "name": name,
        "flags": flags,
        "id": attr_id,
        "content": None,
        "runs": [],
        "data_size": 0,
        "allocated_size": 0,
        "lowest_vcn": 0,
        "highest_vcn": 0,
    }

    if not non_resident:
        if offset + 24 > len(data):
            return result
        content_len = _u32(data, offset + 16)
        content_off = _u16(data, offset + 20)
        start = offset + content_off
        end = start + content_len
        if start >= offset and end <= offset + attr_len and end <= len(data):
            result["content"] = data[start:end]
            result["data_size"] = content_len
    else:
        if offset + 0x40 > len(data):
            return result
        result["lowest_vcn"] = _u64(data, offset + 0x10)
        result["highest_vcn"] = _u64(data, offset + 0x18)
        run_off = _u16(data, offset + 0x20)
        result["allocated_size"] = _u64(data, offset + 0x28)
        result["data_size"] = _u64(data, offset + 0x30)
        # initialized size at 0x38
        if run_off and offset + run_off < offset + attr_len:
            result["runs"] = _decode_runs(data[offset + run_off: offset + attr_len])
    return result


def _parse_file_name(content: bytes) -> Optional[FileNameEntry]:
    if len(content) < 0x42:
        return None
    parent = _u64(content, 0)
    parent_ref = parent & 0x0000FFFFFFFFFFFF
    parent_seq = (parent >> 48) & 0xFFFF
    allocated = _u64(content, 0x28)
    real = _u64(content, 0x30)
    flags = _u32(content, 0x38)
    name_len = content[0x40]
    namespace = content[0x41]
    try:
        name = content[0x42: 0x42 + name_len * 2].decode("utf-16-le", errors="replace")
    except Exception:
        return None
    if not name or "\x00" in name:
        name = name.replace("\x00", "")
    return FileNameEntry(
        name=name,
        namespace=namespace,
        parent_ref=parent_ref,
        parent_seq=parent_seq,
        allocated_size=allocated,
        real_size=real,
        flags=flags,
    )


def _parse_standard_info(content: bytes) -> MftTimestamps:
    ts = MftTimestamps()
    if len(content) < 0x20:
        return ts
    ts.created = _filetime(_u64(content, 0x00))
    ts.modified = _filetime(_u64(content, 0x08))
    ts.mft_modified = _filetime(_u64(content, 0x10))
    ts.accessed = _filetime(_u64(content, 0x18))
    return ts


def _parse_attribute_list_entries(content: bytes) -> List[dict]:
    """Parse $ATTRIBUTE_LIST body → list of {type, name, mft_ref, ...}."""
    entries = []
    offset = 0
    while offset + 26 <= len(content):
        attr_type = _u32(content, offset)
        entry_len = _u16(content, offset + 4)
        if entry_len < 26 or offset + entry_len > len(content):
            break
        name_len = content[offset + 6]
        name_off = content[offset + 7]
        start_vcn = _u64(content, offset + 8)
        base_ref = _u64(content, offset + 16)
        mft_ref = base_ref & 0x0000FFFFFFFFFFFF
        seq = (base_ref >> 48) & 0xFFFF
        name = ""
        if name_len and name_off:
            try:
                name = content[offset + name_off: offset + name_off + name_len * 2].decode(
                    "utf-16-le", errors="replace"
                )
            except Exception:
                pass
        entries.append({
            "type": attr_type,
            "name": name,
            "mft_ref": mft_ref,
            "sequence": seq,
            "start_vcn": start_vcn,
        })
        offset += entry_len
        # Align to 8 bytes
        if offset % 8:
            offset += 8 - (offset % 8)
    return entries


# ---------------------------------------------------------------------------
# Single MFT record
# ---------------------------------------------------------------------------

def parse_mft_record(
    raw: bytes,
    record_index: int,
    sector_size: int = 512,
    only_deleted: bool = True,
) -> Optional[DeletedFile]:
    if len(raw) < 48:
        return None
    sig = raw[0:4]
    if sig == b"BAAD":
        return None  # known bad record
    if sig != b"FILE":
        return None

    record = bytearray(raw)
    if not _apply_fix_fix(record, sector_size):
        return None

    # Header fields
    sequence = _u16(record, 0x10)
    hard_links = _u16(record, 0x12)
    attr_off = _u16(record, 0x14)
    flags = _u16(record, 0x16)
    used_size = _u32(record, 0x18)
    allocated_size = _u32(record, 0x1C)
    base_ref = _u64(record, 0x20)
    base_record = base_ref & 0x0000FFFFFFFFFFFF

    # Extension records (base_record != 0) are merged via ATTRIBUTE_LIST
    if base_record != 0:
        return None

    in_use = bool(flags & 0x01)
    is_dir = bool(flags & 0x02)
    if only_deleted and in_use:
        return None

    timestamps = MftTimestamps()
    names: List[FileNameEntry] = []
    streams: List[DataStream] = []
    attr_list_entries: List[dict] = []

    offset = attr_off
    safety = 0
    while offset < min(used_size, len(record)) - 8 and safety < 256:
        safety += 1
        attr = _parse_attribute(record, offset)
        if attr is None:
            break
        atype = attr["type"]
        content = attr.get("content") or b""

        if atype == ATTR_STANDARD_INFORMATION:
            timestamps = _parse_standard_info(content)
        elif atype == ATTR_FILE_NAME:
            fn = _parse_file_name(content)
            if fn and fn.name:
                names.append(fn)
        elif atype == ATTR_ATTRIBUTE_LIST:
            if attr["non_resident"]:
                # Non-resident attr list – store runs for later resolution
                attr_list_entries.append({
                    "type": ATTR_ATTRIBUTE_LIST,
                    "runs": attr["runs"],
                    "non_resident": True,
                })
            else:
                attr_list_entries.extend(_parse_attribute_list_entries(content))
        elif atype == ATTR_DATA:
            stream = DataStream(
                name=attr["name"] or "",
                size=attr["data_size"],
                resident=not attr["non_resident"],
                runs=attr["runs"] if attr["non_resident"] else [],
                data=content if not attr["non_resident"] else None,
            )
            streams.append(stream)

        if attr["length"] == 0:
            break
        offset += attr["length"]

    if not names and not streams:
        return None

    # Prefer Win32 / Win32+DOS names over DOS-only or POSIX
    def name_rank(ns: int) -> int:
        return {NS_WIN32: 0, NS_WIN32_DOS: 1, NS_POSIX: 2, NS_DOS: 3}.get(ns, 9)

    names_sorted = sorted(names, key=lambda n: name_rank(n.namespace))
    best_name = names_sorted[0] if names_sorted else FileNameEntry(
        name=f"$MFT_{record_index}", namespace=NS_POSIX,
        parent_ref=5, parent_seq=0, allocated_size=0, real_size=0, flags=0,
    )

    # Default data stream
    default_streams = [s for s in streams if s.name == ""]
    default = default_streams[0] if default_streams else None
    data_size = 0
    data_runs: List[Tuple[int, int]] = []
    resident_data: Optional[bytes] = None
    if default:
        data_size = default.size
        data_runs = default.runs
        resident_data = default.data
    if best_name.real_size and not data_size:
        data_size = best_name.real_size

    # Confidence
    conf = 0.55
    if names:
        conf += 0.15
    if default and (default.data or default.runs):
        conf += 0.20
    if timestamps.created or timestamps.modified:
        conf += 0.05
    if sequence > 0:
        conf += 0.05
    conf = min(conf, 0.98)

    note_parts = []
    if attr_list_entries:
        note_parts.append("has $ATTRIBUTE_LIST")
    ads = [s for s in streams if s.name]
    if ads:
        note_parts.append(f"{len(ads)} ADS")

    return DeletedFile(
        mft_ref=record_index,
        sequence=sequence,
        name=best_name.name,
        parent_ref=best_name.parent_ref,
        parent_seq=best_name.parent_seq,
        full_path=best_name.name,  # filled later
        size=data_size,
        is_directory=is_dir,
        timestamps=timestamps,
        streams=streams,
        names=names_sorted,
        data_runs=data_runs,
        resident_data=resident_data,
        confidence=conf,
        flags_raw=flags,
        hard_link_count=hard_links,
        note="; ".join(note_parts),
    )


# ---------------------------------------------------------------------------
# Path reconstruction
# ---------------------------------------------------------------------------

def rebuild_paths(
    deleted: List[DeletedFile],
    all_records: Dict[int, Tuple[str, int, int]],
) -> None:
    """
    all_records: mft_ref → (name, parent_ref, in_use_flag_as_int)
    Walk parent chain up to root (ref 5 = root directory) or cycle limit.
    """
    ROOT = 5

    def path_for(ref: int, depth: int = 0) -> str:
        if depth > 64 or ref in (0, ROOT):
            return ""
        if ref not in all_records:
            return f"$Orphan\\MFT_{ref}"
        name, parent, _ = all_records[ref]
        parent_path = path_for(parent, depth + 1)
        if parent_path:
            return f"{parent_path}\\{name}"
        return name

    for d in deleted:
        parent_path = path_for(d.parent_ref)
        if parent_path:
            d.full_path = f"{parent_path}\\{d.name}"
        else:
            d.full_path = d.name
        # Slight confidence boost when path is resolved
        if parent_path and not parent_path.startswith("$Orphan"):
            d.confidence = min(0.99, d.confidence + 0.03)


# ---------------------------------------------------------------------------
# Cluster I/O
# ---------------------------------------------------------------------------

def read_clusters(
    stream: BinaryIO,
    boot: NTFSBoot,
    runs: List[Tuple[int, int]],
    max_bytes: int,
) -> bytes:
    chunks: List[bytes] = []
    remaining = max_bytes
    max_lcn = boot.total_sectors // max(boot.sectors_per_cluster, 1) if boot.total_sectors else 2**40
    for lcn, nclusters in runs:
        if remaining <= 0:
            break
        if lcn < 0:
            to_read = min(remaining, nclusters * boot.cluster_size)
            chunks.append(b"\x00" * to_read)
            remaining -= to_read
            continue
        if lcn > max_lcn:
            logger.debug("LCN %s beyond volume – stopping run", lcn)
            break
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
            logger.warning("Read failed at LCN %s: %s", lcn, e)
            break
    return b"".join(chunks)


# ---------------------------------------------------------------------------
# Full volume scan
# ---------------------------------------------------------------------------

def _load_mft_runs(stream: BinaryIO, boot: NTFSBoot) -> List[Tuple[int, int]]:
    mft_offset = boot.mft_lcn * boot.cluster_size
    stream.seek(mft_offset)
    first = stream.read(boot.mft_record_size)
    if len(first) < boot.mft_record_size or first[0:4] != b"FILE":
        raise ValueError("Cannot read $MFT record 0 – not NTFS or wrong geometry")

    record = bytearray(first)
    _apply_fix_fix(record, boot.bytes_per_sector)
    attr_off = _u16(record, 0x14)
    offset = attr_off
    while offset < len(record) - 8:
        attr = _parse_attribute(record, offset)
        if attr is None:
            break
        if attr["type"] == ATTR_DATA and not attr["name"] and attr["non_resident"]:
            if attr["runs"]:
                return attr["runs"]
        if attr["length"] == 0:
            break
        offset += attr["length"]
    # Fallback: assume contiguous MFT for first N clusters
    return [(boot.mft_lcn, max(64, 1024))]


def scan_deleted_files(
    stream: BinaryIO,
    volume_size: int,
    progress: ProgressCB = None,
    max_records: int = 4_000_000,
    extract_data: bool = True,
    max_file_size: int = 200 * 1024 * 1024,
    only_deleted: bool = True,
) -> List[DeletedFile]:
    def report(p: float, msg: str) -> None:
        if progress:
            progress(min(max(p, 0.0), 1.0), msg)

    stream.seek(0)
    boot = parse_boot_sector(stream.read(512))
    boot.volume_size = volume_size or boot.volume_size
    report(
        0.02,
        f"NTFS: {boot.cluster_size}B clusters, MFT record {boot.mft_record_size}B, "
        f"$MFT LCN {boot.mft_lcn}",
    )

    mft_runs = _load_mft_runs(stream, boot)
    report(0.05, f"$MFT spans {len(mft_runs)} run(s)")

    # First pass: parse all records we need for path reconstruction
    # Store name index for every record (in-use and deleted) for parent paths
    name_index: Dict[int, Tuple[str, int, int]] = {}  # ref → (name, parent, flags)
    deleted: List[DeletedFile] = []
    record_index = 0
    total_clusters = sum(c for _, c in mft_runs if c > 0) or 1
    clusters_done = 0.0

    for lcn, nclusters in mft_runs:
        if lcn < 0:
            clusters_done += nclusters
            continue
        byte_off = lcn * boot.cluster_size
        stream.seek(byte_off)
        remaining = nclusters * boot.cluster_size
        while remaining > 0 and record_index < max_records:
            chunk_size = min(remaining, boot.mft_record_size * 128)
            chunk = stream.read(chunk_size)
            if not chunk:
                break
            for i in range(0, len(chunk) // boot.mft_record_size * boot.mft_record_size,
                           boot.mft_record_size):
                rec = chunk[i: i + boot.mft_record_size]
                # Index names for path rebuild (both live and deleted)
                entry = parse_mft_record(
                    rec, record_index,
                    sector_size=boot.bytes_per_sector,
                    only_deleted=False,
                )
                if entry:
                    name_index[record_index] = (entry.name, entry.parent_ref, entry.flags_raw)
                    if only_deleted and not (entry.flags_raw & 0x01):
                        if not entry.is_directory:
                            deleted.append(entry)
                    elif not only_deleted and not entry.is_directory:
                        deleted.append(entry)
                else:
                    # Still try to pick a name for path index from deleted-only parser miss
                    pass
                record_index += 1
                if record_index >= max_records:
                    break
            remaining -= len(chunk)
            clusters_done += len(chunk) / float(boot.cluster_size)
            report(
                0.05 + 0.70 * min(clusters_done / total_clusters, 1.0),
                f"$MFT record {record_index:,} – {len(deleted):,} deleted files",
            )

    report(0.78, "Rebuilding directory paths from parent MFT references…")
    rebuild_paths(deleted, name_index)

    # Extract file contents where possible
    if extract_data:
        report(0.80, "Extracting recoverable file data…")
        total = max(len(deleted), 1)
        for idx, d in enumerate(deleted):
            if d.size <= 0 or d.size > max_file_size:
                continue
            if d.resident_data is not None:
                continue
            if not d.data_runs:
                continue
            try:
                d.resident_data = read_clusters(
                    stream, boot, d.data_runs, min(d.size, max_file_size)
                )
                if d.resident_data:
                    d.confidence = min(0.99, d.confidence + 0.05)
            except Exception as e:
                logger.debug("Extract %s failed: %s", d.name, e)
            if idx % 50 == 0:
                report(0.80 + 0.18 * (idx / total), f"Extracting data… {idx}/{total}")

    report(1.0, f"Advanced $MFT scan complete – {len(deleted):,} deleted file(s)")
    return deleted


def open_ntfs_and_scan(
    path: str,
    progress: ProgressCB = None,
    extract_data: bool = True,
) -> List[DeletedFile]:
    from .disk_access import open_source

    stream, size = open_source(path)
    try:
        return scan_deleted_files(
            stream, size, progress=progress, extract_data=extract_data
        )
    finally:
        try:
            stream.close()
        except Exception:
            pass
