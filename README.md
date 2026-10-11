# Retrievo

**Open-source Forensic File Recovery Tool for Windows**

Recovers lost and deleted files (especially images and videos) from disk images, volumes, and physical drives using signature-based carving and Recycle Bin enumeration.

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows)
![License](https://img.shields.io/badge/License-MIT-green)
![Type](https://img.shields.io/badge/Type-Forensic%20Recovery-red)

---

## Features

| Capability | Details |
|------------|---------|
| **Signature Carving** | Scans raw data for known magic numbers (JPEG, PNG, GIF, BMP, TIFF, WebP, MP4, AVI, MOV, MKV, FLV, WMV, PDF, ZIP, RAR, 7z, SQLite) |
| **Raw Disk Access** | Opens Windows physical drives (`\\.\PhysicalDriveN`) and volumes (`\\.\C:`) when run as Administrator |
| **Disk Image Support** | Works with `.dd`, `.img`, `.raw`, `.bin` and any binary dump |
| **Recycle Bin Recovery** | Enumerates files still present in `$Recycle.Bin` and TEMP locations |
| **Confidence Scoring** | Header + footer + format-specific validators produce a confidence score |
| **Forensic Reporting** | Generates CSV + JSON recovery reports with offsets, sizes, and confidence |
| **Safe by Design** | Never writes to the source media – all recovered files go to a user-chosen destination |
| **Modern UI** | Dark-themed CustomTkinter interface with live progress, preview, and multi-select |

---

## Recommended Workflow (Forensic Best Practice)

1. **Create a disk image** of the suspect media (using FTK Imager, `dd`, or similar).
2. Work **only on the image**, never on the original live drive when possible.
3. Run Retrievo **as Administrator**.
4. Select the image → choose **Signature Carve**.
5. Review results (confidence, offset, preview) and recover to a **different** drive.
6. Keep the generated recovery report with your case notes.

---

## Quick Start

### Requirements
- Windows 10 / 11 (primary target)
- Python 3.10+
- Administrator rights for raw device access

### Install & Run

```bash
git clone https://github.com/Harrisonegbo/FileRecover-Pro.git
cd FileRecover-Pro

python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

python src/main.py
# or double-click run.bat
```

---

## Project Structure

```
Retrievo/
├── src/
│   ├── main.py
│   ├── core/
│   │   ├── carver.py          # Streaming signature carver
│   │   ├── disk_access.py     # Raw drives, volumes, images
│   │   ├── scanner.py         # High-level scan orchestration
│   │   ├── recover.py         # Safe export + forensic reports
│   │   └── signatures.py      # Magic numbers + validators
│   ├── ui/                    # CustomTkinter GUI
│   └── utils/
├── docs/architecture.md
├── requirements.txt
├── run.bat
├── LICENSE
└── README.md
```

---

## Technical Notes

### Carving Engine
- Reads source in overlapping 4 MB chunks (never loads entire disk into RAM).
- Per-format size estimation (JPEG EOI search, PNG chunk walk, BMP size field, container box sizes).
- Validators raise confidence when structure matches expected format.

### Raw Access (Windows)
Uses `CreateFileW` + `ReadFile` via ctypes for `\\.\PhysicalDriveN` and `\\.\X:` paths.  
Requires the process to run elevated.

### Limitations
- Fragmented files that have been overwritten are not reconstructed (true for almost all carvers).
- Advanced NTFS $MFT deleted-entry parsing is not yet implemented (planned).
- Encrypted volumes / BitLocker must be unlocked or imaged after decryption.
- E01 / AFF forensic image formats are not natively parsed (convert to raw first).

---

## Disclaimer

This tool is intended for **legitimate data recovery, digital forensics training, and educational purposes**.

- Always obtain proper authorization before examining any storage media.
- The authors accept no liability for data loss, legal issues, or misuse.
- For high-stakes cases, cross-validate with established tools (PhotoRec, Autopsy, X-Ways, etc.).

---

## License

MIT License – see [LICENSE](LICENSE).

---

## Author

Portfolio / open-source forensic recovery project demonstrating low-level I/O, file-system concepts, and desktop application design.
