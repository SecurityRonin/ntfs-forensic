# `ntfs-forensic` test fixtures

Per-file provenance for the committed test data. The fleet-wide machine index is
[`issen/docs/corpus-catalog.md`](https://github.com/SecurityRonin/issen) (§A3c for the
LZNT1 fixtures, §A1 for the boot sector) — this README is the co-located human detail;
cross-reference, never duplicate.

`tests/data/` here is **not** gitignored (`.gitignore` is just `/target`), so these small
fixtures are committed.

#### defcon2018_cdrive_boot.bin

- **Source / Identity:** first 4 KiB (NTFS boot sector) of the C: partition from the publicly
  distributed DEF CON DFIR CTF 2018 `MaxPowers` disk image.
- **Used by:** `core/tests/real_image.rs` — boot-parser values checked against TSK `fsstat`.
- **Catalog:** `issen/docs/corpus-catalog.md` §A1 (DEF CON DFIR CTF 2018 `MaxPowersCDrive.E01`).

#### lznt1_real.bin / lznt1_real.expected

Real on-disk **LZNT1** stream + its TSK-decompressed plaintext, used by
`core/tests/lznt1_real.rs` to validate the `lznt1` codec against real bytes (doer-checker)
rather than a self-consistent synthetic round-trip — with **The Sleuth Kit as the independent
oracle** for the plaintext.

- **Source image:** DFIR Madness "Stolen Szechuan Sauce" Case 001 — **CITADEL-DC01** C: drive
  (Windows Server 2012 R2), `20200918_0347_CDrive.E01`. By James Smith, dfirmadness.com.
  Case page: <https://dfirmadness.com/the-stolen-szechuan-sauce/> · image:
  <https://dfirmadness.com/case001/DC01-E01.zip>. Educational/research use.
- **In-image file:** `C:\ProgramData\Microsoft\Windows\WER\...\Report.wer` — **MFT inode 437**.
  Its `$DATA` is `Non-Resident, Compressed`, actual size **1832 bytes**, occupying a single
  allocated cluster at **LCN 291553** (one 16-cluster LZNT1 compression unit → the cluster holds
  the entire compressed stream, so `icat` returns the full plaintext). **Single-unit**, no fallback.
- **NTFS geometry:** partition at sector **offset 718848**; cluster size **4096** (8 sectors/cluster).
- **Verbatim TSK commands** (TSK decompresses independently — the oracle):

  ```sh
  E01=".../extracted/E01-DC01/20200918_0347_CDrive.E01"
  istat  -o 718848 "$E01" 437                                   # $DATA Non-Resident, Compressed  size 1832 → LCN 291553
  icat   -o 718848 "$E01" 437      > lznt1_real.expected         # TSK plaintext (oracle), 1832 bytes
  blkcat -o 718848 "$E01" 291553 1 > lznt1_real.bin             # raw on-disk LZNT1 stream, one 4096-byte cluster
  ```

- **Oracle agreement (verified before committing):** `ntfs_core::decompress(lznt1_real.bin)`
  truncated to 1832 bytes equals `lznt1_real.expected` byte-for-byte.

| File | Bytes | MD5 |
|---|---|---|
| `lznt1_real.bin` | 4096 | `8c791f1d34a7f4a9aaeaddce71210a26` |
| `lznt1_real.expected` | 1832 | `f4cc46d7e07ab76540a46471622e10af` |
