# Advanced NTFS $MFT Deleted-Entry Parsing

Retrievo implements a multi-pass $MFT parser for deleted file recovery on NTFS volumes.

## Pipeline

1. **Boot sector** – OEM ID, bytes/sector, sectors/cluster, $MFT LCN, record size
2. **$MFT run list** – from record 0 `$DATA` (handles fragmented MFT)
3. **Record walk** – every FILE record; USA (fix-fix) applied per sector
4. **Attributes parsed**
   - `$STANDARD_INFORMATION` → created / modified / MFT / accessed (FILETIME)
   - `$FILE_NAME` → all namespaces (Win32 preferred over DOS)
   - `$DATA` → default stream + Alternate Data Streams (ADS)
   - `$ATTRIBUTE_LIST` → entries pointing at extension records
5. **Path rebuild** – parent MFT reference chain up to root (inode 5)
6. **Data extraction** – resident body or non-resident cluster runs

## Confidence scoring

| Factor | Effect |
|--------|--------|
| Filename present | +0.15 |
| Recoverable data (runs or resident) | +0.20 |
| Timestamps present | +0.05 |
| Valid sequence number | +0.05 |
| Resolved non-orphan path | +0.03 |

## Limits

- Overwritten clusters cannot be restored
- Extension records via non-resident `$ATTRIBUTE_LIST` are partially supported (list is parsed; external record merge is best-effort on the primary record’s resident attributes)
- Encrypted (EFS) content is recovered as ciphertext
