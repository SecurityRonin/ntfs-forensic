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

#### SampleTinyNtfsVolume.zip

A small synthetic NTFS volume (`$MFT`, `$LogFile`, `$MFTMirr`, …) that ships inside Joakim
Schicht's **LogFileParser** release as its self-contained `$LogFile`/NTFS validation sample.
Used as the small-input case for the `$LogFile` transaction decoder + its oracle harness
(LogFileParser via Wine — see `issen/docs/plans/2026-06-21-four-depth-builds-design.md` §B);
the primary `$LogFile` test data is the real DC01 stream (§A1/§A3c image), TSK-cross-validated.

- **Author / source:** [jschicht/LogFileParser](https://github.com/jschicht/LogFileParser),
  bundled in `LogFileParser_v2.0.0.53.zip`
  (<https://github.com/jschicht/LogFileParser/releases/download/v2.0.0.53/LogFileParser_v2.0.0.53.zip>).
- **Redistribution / license:** LogFileParser is **MIT** (`LICENSE.md`, SPDX `MIT`, verified via
  `gh api repos/jschicht/LogFileParser`), which permits redistribution with attribution — so this
  bundled sample is committed. Attribution: © Joakim Schicht, MIT.

| File | Bytes | MD5 |
|---|---|---|
| `SampleTinyNtfsVolume.zip` | 2169791 | `5e3a65e60920fe6bb089ebf6cecc5595` |

#### real_logfile_rcrd_page.bin

A single **real RCRD record page** (one 4096-byte LFS page) carved from the **CITADEL-DC01**
`$LogFile`, used by `core/tests/logfile_rcrd.rs` to validate the RCRD reader + multi-sector USA
fixup against genuine on-disk bytes (doer-checker) rather than a self-encoded synthetic page.

- **Source image:** DFIR Madness "Stolen Szechuan Sauce" Case 001 — **CITADEL-DC01** C: drive
  (Windows Server 2012 R2), `20200918_0347_CDrive.E01`. Same corpus as `lznt1_real.bin` above.
  Case page: <https://dfirmadness.com/the-stolen-szechuan-sauce/>. Educational/research use.
- **Extraction (TSK as the independent input oracle):** `$LogFile` is MFT inode 2; the partition
  is at sector offset **718848**. The full stream was extracted with `icat -o 718848 "$E01" 2`
  (byte-identical to issen's own extraction, MD5 `a8e8582498464b4fbc15f83db8782516` — two
  independent extractors agree), then the second 4096-byte page (file offset `0x2000`, the first
  RCRD after the RSTR restart pages) was sliced out.
- **Page facts:** signature `RCRD`, `usa_offset` `0x28`, `usa_count` `9` (→ 8 × 512-byte sectors),
  `last_lsn` `0x0d54fa40` at offset `0x08`. The USA fixup must restore each sector's last two
  bytes from `usa[1..9]`; a page whose on-disk sector tail no longer matches `usa[0]` (the USN) is
  rejected by the integrity self-check.

| File | Bytes | MD5 |
|---|---|---|
| `real_logfile_rcrd_page.bin` | 4096 | `b5ef734e91222a606b675ced9db2ea92` |
