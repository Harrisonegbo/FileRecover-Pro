"""
Memory acquisition and live-response helpers.

Inspired by tools such as Magnet RAM Capture / WinPmem / DumpIt:

- Full physical RAM capture requires a kernel driver. Retrievo will invoke
  an external acquisitor (WinPmem) when present on PATH or in tools/.
- Native capabilities: process list, per-process memory dump (MiniDump),
  and a live triage snapshot (processes, network, system info).

All outputs are written only to a user-chosen destination folder and
hashed for chain-of-custody.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from .forensics import hash_file, CaseInfo

logger = logging.getLogger("Retrievo")

ProgressCB = Optional[Callable[[float, str], None]]


@dataclass
class ProcessInfo:
    pid: int
    name: str
    exe: str = ""
    memory_bytes: int = 0
    username: str = ""


@dataclass
class CaptureResult:
    path: str
    size: int
    kind: str  # process_dump | physical_ram | triage
    md5: str = ""
    sha256: str = ""
    notes: str = ""


def is_windows() -> bool:
    return sys.platform == "win32"


def _report(cb: ProgressCB, p: float, msg: str) -> None:
    if cb:
        cb(p, msg)
    logger.info(msg)


# ------------------------------------------------------------------
# Process enumeration
# ------------------------------------------------------------------

def list_processes() -> List[ProcessInfo]:
    """List running processes (Windows-focused; basic fallback elsewhere)."""
    procs: List[ProcessInfo] = []
    if is_windows():
        try:
            import ctypes
            from ctypes import wintypes

            # Prefer psutil if available
            try:
                import psutil  # type: ignore
                for p in psutil.process_iter(["pid", "name", "exe", "memory_info", "username"]):
                    try:
                        info = p.info
                        mem = 0
                        if info.get("memory_info"):
                            mem = int(info["memory_info"].rss)
                        procs.append(ProcessInfo(
                            pid=info["pid"],
                            name=info.get("name") or "",
                            exe=info.get("exe") or "",
                            memory_bytes=mem,
                            username=info.get("username") or "",
                        ))
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                return sorted(procs, key=lambda x: x.name.lower())
            except ImportError:
                pass

            # Fallback: tasklist
            out = subprocess.check_output(
                ["tasklist", "/FO", "CSV", "/NH"],
                text=True, errors="ignore",
            )
            for line in out.splitlines():
                parts = [c.strip().strip('"') for c in line.split(",")]
                if len(parts) >= 2 and parts[1].isdigit():
                    procs.append(ProcessInfo(pid=int(parts[1]), name=parts[0]))
            return sorted(procs, key=lambda x: x.name.lower())
        except Exception as e:
            logger.warning("list_processes failed: %s", e)
    else:
        # Linux / macOS fallback
        try:
            import psutil  # type: ignore
            for p in psutil.process_iter(["pid", "name", "exe", "memory_info", "username"]):
                try:
                    info = p.info
                    mem = int(info["memory_info"].rss) if info.get("memory_info") else 0
                    procs.append(ProcessInfo(
                        pid=info["pid"],
                        name=info.get("name") or "",
                        exe=info.get("exe") or "",
                        memory_bytes=mem,
                        username=info.get("username") or "",
                    ))
                except Exception:
                    continue
        except ImportError:
            for d in Path("/proc").iterdir():
                if d.name.isdigit():
                    try:
                        comm = (d / "comm").read_text().strip()
                        procs.append(ProcessInfo(pid=int(d.name), name=comm))
                    except Exception:
                        pass
    return sorted(procs, key=lambda x: x.name.lower())


# ------------------------------------------------------------------
# Process memory dump (MiniDump on Windows)
# ------------------------------------------------------------------

def dump_process_memory(
    pid: int,
    destination: str | Path,
    progress: ProgressCB = None,
) -> CaptureResult:
    """
    Create a full-memory minidump of a process (Windows MiniDumpWriteDump).
    Similar in spirit to dumping a process address space for malware analysis.
    """
    dest = Path(destination)
    dest.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = dest / f"proc_{pid}_{ts}.dmp"

    _report(progress, 0.1, f"Opening process PID {pid}…")

    if not is_windows():
        # Best-effort: copy /proc/pid/mem is usually permission-denied
        raise RuntimeError("Process memory dump via MiniDump is only supported on Windows.")

    import ctypes
    from ctypes import wintypes

    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    PROCESS_DUP_HANDLE = 0x0040
    access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE

    kernel32 = ctypes.windll.kernel32
    dbghelp = ctypes.windll.dbghelp

    OpenProcess = kernel32.OpenProcess
    OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    OpenProcess.restype = wintypes.HANDLE

    handle = OpenProcess(access, False, pid)
    if not handle:
        raise PermissionError(
            f"Cannot open PID {pid}. Run as Administrator or the process is protected."
        )

    try:
        # MiniDumpWithFullMemory = 0x00000002
        MiniDumpWriteDump = dbghelp.MiniDumpWriteDump
        MiniDumpWriteDump.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.HANDLE,
            wintypes.DWORD, wintypes.LPVOID, wintypes.LPVOID, wintypes.LPVOID,
        ]
        MiniDumpWriteDump.restype = wintypes.BOOL

        GENERIC_WRITE = 0x40000000
        CREATE_ALWAYS = 2
        FILE_ATTRIBUTE_NORMAL = 0x80

        file_handle = kernel32.CreateFileW(
            str(out_path), GENERIC_WRITE, 0, None, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, None
        )
        if file_handle == wintypes.HANDLE(-1).value:
            raise OSError(f"Cannot create dump file: {out_path}")

        _report(progress, 0.4, f"Writing minidump to {out_path.name}…")
        ok = MiniDumpWriteDump(handle, pid, file_handle, 0x00000002, None, None, None)
        kernel32.CloseHandle(file_handle)
        if not ok:
            if out_path.exists():
                out_path.unlink(missing_ok=True)
            raise OSError(f"MiniDumpWriteDump failed for PID {pid} (WinError {kernel32.GetLastError()})")

        size = out_path.stat().st_size
        _report(progress, 0.8, "Hashing dump…")
        hashes = hash_file(out_path)
        _report(progress, 1.0, f"Process dump complete: {out_path.name}")
        return CaptureResult(
            path=str(out_path),
            size=size,
            kind="process_dump",
            md5=hashes.get("md5", ""),
            sha256=hashes.get("sha256", ""),
            notes=f"MiniDump full memory, PID {pid}",
        )
    finally:
        kernel32.CloseHandle(handle)


# ------------------------------------------------------------------
# Physical RAM capture via external acquisitor (WinPmem-style)
# ------------------------------------------------------------------

def find_ram_acquisitor() -> Optional[Path]:
    """
    Locate a physical memory acquisition binary.
    Search order: tools/ next to app, PATH, common install locations.
    """
    names = [
        "winpmem_mini_x64.exe",
        "winpmem.exe",
        "winpmem_x64.exe",
        "DumpIt.exe",
        "RamCapture64.exe",  # Magnet-style name if user places it here
    ]
    search_dirs = [
        Path(sys.executable).resolve().parent / "tools",
        Path(__file__).resolve().parents[2] / "tools",
        Path.cwd() / "tools",
    ]
    for d in search_dirs:
        for n in names:
            p = d / n
            if p.is_file():
                return p
    for n in names:
        found = shutil.which(n)
        if found:
            return Path(found)
    return None


def capture_physical_ram(
    destination: str | Path,
    progress: ProgressCB = None,
    acquisitor: Optional[Path] = None,
) -> CaptureResult:
    """
    Capture physical RAM using an external tool (WinPmem recommended).

    Magnet RAM Capture / WinPmem use a signed kernel driver to read physical
    memory. Pure user-mode Python cannot safely do this; Retrievo orchestrates
    a trusted acquisitor when available.
    """
    if not is_windows():
        raise RuntimeError("Physical RAM capture is only supported on Windows.")

    tool = acquisitor or find_ram_acquisitor()
    if tool is None:
        raise FileNotFoundError(
            "No RAM acquisition tool found.\n\n"
            "Place one of these in a 'tools' folder next to Retrievo:\n"
            "  • winpmem_mini_x64.exe (recommended, open source)\n"
            "  • DumpIt.exe\n"
            "Then retry Memory → Capture Physical RAM.\n\n"
            "Alternatively use process dumps or Live Triage (no driver needed)."
        )

    dest = Path(destination)
    dest.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = dest / f"memdump_{platform.node()}_{ts}.raw"

    _report(progress, 0.05, f"Using acquisitor: {tool.name}")
    _report(progress, 0.1, "Starting physical memory capture (this may take several minutes)…")

    name = tool.name.lower()
    try:
        if "winpmem" in name:
            # WinPmem mini: winpmem_mini_x64.exe output.raw
            cmd = [str(tool), str(out_path)]
        elif "dumpit" in name:
            # DumpIt typically writes to current directory; run from dest
            cmd = [str(tool), "/Q", "/O", str(out_path)]
        else:
            cmd = [str(tool), str(out_path)]

        proc = subprocess.run(
            cmd,
            cwd=str(dest),
            capture_output=True,
            text=True,
            errors="ignore",
            timeout=3600,
        )
        if proc.returncode != 0 and not out_path.exists():
            # Some tools write a fixed name
            candidates = list(dest.glob("*.raw")) + list(dest.glob("*.dmp")) + list(dest.glob("*.bin"))
            if candidates:
                out_path = max(candidates, key=lambda p: p.stat().st_mtime)
            else:
                err = (proc.stderr or proc.stdout or "").strip()
                raise RuntimeError(f"RAM capture failed (code {proc.returncode}): {err[:500]}")

        if not out_path.exists():
            raise FileNotFoundError("Capture finished but output file was not found.")

        size = out_path.stat().st_size
        _report(progress, 0.85, "Hashing memory image (large files take time)…")
        hashes = hash_file(out_path)
        _report(progress, 1.0, f"Physical RAM capture complete: {out_path.name}")
        return CaptureResult(
            path=str(out_path),
            size=size,
            kind="physical_ram",
            md5=hashes.get("md5", ""),
            sha256=hashes.get("sha256", ""),
            notes=f"Acquired with {tool.name}",
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("RAM capture timed out after 1 hour.")


# ------------------------------------------------------------------
# Live triage (complementary to RAM capture – like live response)
# ------------------------------------------------------------------

def collect_live_triage(
    destination: str | Path,
    case: Optional[CaseInfo] = None,
    progress: ProgressCB = None,
) -> CaptureResult:
    """
    Collect a lightweight live-response package without a kernel driver:
    system info, process list, network connections, environment.
    """
    dest = Path(destination)
    dest.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_dir = dest / f"triage_{platform.node()}_{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)

    _report(progress, 0.1, "Collecting system information…")
    sysinfo = {
        "hostname": platform.node(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python": sys.version,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "case": case.to_dict() if case else {},
    }
    (out_dir / "system_info.json").write_text(json.dumps(sysinfo, indent=2), encoding="utf-8")

    _report(progress, 0.35, "Enumerating processes…")
    procs = [asdict(p) for p in list_processes()]
    (out_dir / "processes.json").write_text(json.dumps(procs, indent=2), encoding="utf-8")

    _report(progress, 0.55, "Collecting network connections…")
    net_data: List[dict] = []
    try:
        import psutil  # type: ignore
        for c in psutil.net_connections(kind="inet"):
            net_data.append({
                "fd": c.fd,
                "family": str(c.family),
                "type": str(c.type),
                "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                "status": c.status,
                "pid": c.pid,
            })
    except Exception as e:
        net_data = [{"error": str(e)}]
    (out_dir / "network.json").write_text(json.dumps(net_data, indent=2), encoding="utf-8")

    _report(progress, 0.75, "Writing environment snapshot…")
    env_safe = {k: v for k, v in os.environ.items()
                if not any(s in k.upper() for s in ("SECRET", "PASSWORD", "TOKEN", "KEY"))}
    (out_dir / "environment.json").write_text(json.dumps(env_safe, indent=2), encoding="utf-8")

    # Manifest with hashes of each artifact
    _report(progress, 0.9, "Hashing triage artifacts…")
    manifest = {"files": []}
    total_size = 0
    for f in out_dir.iterdir():
        if f.is_file():
            h = hash_file(f)
            total_size += f.stat().st_size
            manifest["files"].append({
                "name": f.name,
                "size": f.stat().st_size,
                "md5": h.get("md5", ""),
                "sha256": h.get("sha256", ""),
            })
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    _report(progress, 1.0, f"Live triage saved to {out_dir.name}")
    return CaptureResult(
        path=str(out_dir),
        size=total_size,
        kind="triage",
        notes="Live response package (no kernel driver)",
    )
