# Architecture – FileRecover Pro (Forensic)

## Core Pipeline

```
Source (image / volume / physical disk)
        │
        ▼
  disk_access.open_source()     → binary stream + size
        │
        ▼
  FileCarver.carve_stream()     → list[CarvedFile]
        │   (overlapping chunks, signature search,
        │    footer / heuristic size, validators)
        ▼
  RecoveryScanner               → list[RecoverableItem]
        │
        ▼
  UI (ResultsView)              → user selects subset
        │
        ▼
  RecoveryEngine.recover_items() → files + CSV/JSON report
```

## Modules

| Module | Responsibility |
|--------|----------------|
| `disk_access` | Cross-platform open of files, images, Windows raw devices |
| `signatures` | Magic numbers + optional validators |
| `carver` | Streaming signature search & extraction |
| `scanner` | High-level modes (carve / recycle / quick) + logging |
| `recover` | Safe write + forensic report generation |
| `ui.*` | CustomTkinter front-end |

## Design Principles

1. **Never write to source media.**
2. **Prefer disk images over live volumes.**
3. **Streaming I/O** – constant memory footprint regardless of disk size.
4. **Confidence scoring** so the examiner can triage results.
5. **Full audit trail** via log file and recovery reports.
