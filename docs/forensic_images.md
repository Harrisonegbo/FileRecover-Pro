# Forensic Image Formats (E01 / AFF)

Retrievo can open common forensic disk image containers so NTFS recovery and carving run against the **logical media**, not the container file bytes.

## E01 (EnCase / Expert Witness Format)

| Support | Detail |
|---------|--------|
| Pure Python | Built-in reader for typical zlib-compressed, unencrypted `.E01` (+ multi-segment `.E02`…) |
| libewf | If `pyewf` is installed, it is preferred automatically |
| EX01 / L01 | Detected by extension; best results with pyewf |

**Limits:** encrypted E01, some EX01 variants, and unusual compression schemes may require `ewfexport` to raw first.

### Multi-segment sets
Place `case.E01`, `case.E02`, … in the same folder and open `case.E01`.

## AFF / AFF4

| Format | Support |
|--------|---------|
| AFF4 | Via optional `pip install pyaff4` |
| Classic AFF | Convert to raw or AFF4 externally |

## Usage

1. **File → Open Disk Image…** and choose `.E01` / `.AFF4`
2. Run **Deleted (NTFS)** or **Deep Carve** as usual
3. Recovered files still write only to your chosen destination folder

## Convert if needed

```bash
ewfexport -t rawimage evidence.E01
```
