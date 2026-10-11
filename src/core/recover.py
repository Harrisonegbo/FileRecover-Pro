"""
Recovery / export engine – writes recovered items to a safe destination.
Never writes back to the source media. Produces forensic reports with hashes.
"""

from __future__ import annotations

import csv
import json
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional

from .scanner import RecoverableItem
from .forensics import CaseInfo, hash_bytes, hash_file

logger = logging.getLogger("Retrievo")


class RecoveryEngine:
    def __init__(
        self,
        progress_callback: Optional[Callable[[float, str], None]] = None,
    ):
        self.progress_callback = progress_callback
        self.case: Optional[CaseInfo] = None

    def set_case(self, case: CaseInfo) -> None:
        self.case = case

    def _report(self, p: float, msg: str) -> None:
        if self.progress_callback:
            self.progress_callback(p, msg)

    def recover_items(
        self,
        items: List[RecoverableItem],
        destination: str | Path,
        overwrite: bool = False,
        write_report: bool = True,
        compute_hashes: bool = True,
    ) -> List[Path]:
        dest = Path(destination)
        dest.mkdir(parents=True, exist_ok=True)

        written: List[Path] = []
        total = max(len(items), 1)
        report_rows = []

        for idx, item in enumerate(items):
            try:
                out_name = self._safe_name(item.name)
                out_path = dest / out_name

                if out_path.exists() and not overwrite:
                    stem, suffix = out_path.stem, out_path.suffix
                    counter = 1
                    while out_path.exists():
                        out_path = dest / f"{stem}_{counter}{suffix}"
                        counter += 1

                if item.data is not None:
                    out_path.write_bytes(item.data)
                    hashes = hash_bytes(item.data) if compute_hashes else {}
                elif item.original_path and Path(item.original_path).is_file():
                    shutil.copy2(item.original_path, out_path)
                    hashes = hash_file(out_path) if compute_hashes else {}
                else:
                    logger.warning("No data for %s – skipped", item.name)
                    continue

                written.append(out_path)
                row = {
                    "name": out_path.name,
                    "original_name": item.name,
                    "size": item.size,
                    "type": item.file_type,
                    "source": item.source,
                    "offset": f"0x{item.offset:X}" if item.offset else "",
                    "confidence": f"{item.confidence:.2f}",
                    "recovered_path": str(out_path),
                    "md5": hashes.get("md5", ""),
                    "sha1": hashes.get("sha1", ""),
                    "sha256": hashes.get("sha256", ""),
                }
                report_rows.append(row)
                self._report(
                    (idx + 1) / total,
                    f"Recovered: {out_path.name} ({item.size_human})",
                )
                logger.info("Recovered %s -> %s", item.name, out_path)
            except Exception as exc:
                logger.error("Failed to recover %s: %s", item.name, exc)
                self._report(idx / total, f"Failed {item.name}: {exc}")

        if write_report and report_rows:
            self._write_report(dest, report_rows)

        self._report(1.0, f"Done – {len(written)} file(s) recovered to {dest}")
        return written

    def _write_report(self, dest: Path, rows: list) -> None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        csv_path = dest / f"recovery_report_{ts}.csv"
        json_path = dest / f"recovery_report_{ts}.json"

        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)

        payload = {
            "generated": datetime.now(timezone.utc).isoformat(),
            "tool": "Retrievo",
            "version": "1.1",
            "count": len(rows),
            "files": rows,
        }
        if self.case:
            payload["case"] = self.case.to_dict()

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        logger.info("Forensic report written: %s", csv_path)

    @staticmethod
    def _safe_name(name: str) -> str:
        bad = '<>:"/\\|?*\0'
        cleaned = "".join(c if c not in bad else "_" for c in name).strip(" .")
        return cleaned or "recovered_file"
