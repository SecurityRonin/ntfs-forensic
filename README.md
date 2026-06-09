# ntfs-forensic

[![ntfs-core](https://img.shields.io/crates/v/ntfs-core.svg?label=ntfs-core)](https://crates.io/crates/ntfs-core)
[![ntfs-forensic](https://img.shields.io/crates/v/ntfs-forensic.svg?label=ntfs-forensic)](https://crates.io/crates/ntfs-forensic)
[![Docs.rs](https://img.shields.io/docsrs/ntfs-forensic)](https://docs.rs/ntfs-forensic)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/ntfs-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/ntfs-forensic/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**A from-scratch NTFS reader and a graded anomaly auditor — surface the timestomping, alternate data streams, deleted records, and MFT slack that a "clean" filesystem driver is built to hide.**

Two crates, one workspace:

- **[`ntfs-core`](https://crates.io/crates/ntfs-core)** — the reader: `$MFT`, attributes, indexes, data runs, LZNT1, `$UsnJrnl:$J` change-journal record decode, and `NtfsFs` path navigation over any `Read + Seek` source. No `unsafe`, no C bindings.
- **[`ntfs-forensic`](https://crates.io/crates/ntfs-forensic)** — the auditor: turns parsed MFT records into severity-graded [`forensicnomicon::report::Finding`](https://crates.io/crates/forensicnomicon)s, so an NTFS volume's anomalies aggregate uniformly with the partition and container layers.

## Audit a raw MFT record in 30 seconds

```toml
[dependencies]
ntfs-forensic = "0.5"   # pulls in ntfs-core
```

```rust
use ntfs_forensic::audit_record;
use forensicnomicon::report::Source;

let src = Source { analyzer: "ntfs-forensic".into(), scope: "NTFS".into(), version: None };

// Feed it a single raw 1024-byte MFT record; get back graded anomalies.
for anomaly in audit_record(&mft_record_bytes) {
    let finding = anomaly.to_finding(src.clone());
    println!("[{:?}] {} — {}", finding.severity, finding.code, finding.note);
    // e.g. [Some(High)] NTFS-TIMESTOMP — $SI created before $FN …
}
```

`audit_record` parses the header and attributes, extracts `$STANDARD_INFORMATION`/`$FILE_NAME`, and grades what it finds. A record whose header does not parse yields no anomalies (structural corruption is surfaced by the reader/carver, never a panic).

## The anomaly codes

Each anomaly is an **observation** ("consistent with …"); the examiner draws the conclusions. Codes are a stable, published contract.

| Code | Severity | What it observes |
|---|---|---|
| `NTFS-TIMESTOMP` | High | `$STANDARD_INFORMATION` times show forgery tells vs. the harder-to-forge `$FILE_NAME` times (`$SI` predates `$FN`, or lands on a whole second) |
| `NTFS-ADS` | Low | A named `$DATA` attribute — an alternate data stream (also used benignly, e.g. `Zone.Identifier`) |
| `NTFS-SLACK-RESIDUE` | Low | Non-zero residue in an MFT record's slack, past its used size |
| `NTFS-DELETED-RECORD` | Info | An MFT record not in use — a recoverable deleted file |
| `NTFS-MFTMIRR-MISMATCH` | High | A system record in `$MFT` differs from its `$MFTMirr` copy |
| `NTFS-LOGFILE-CLEARED` | Medium | `$LogFile` shows restart-area gaps consistent with the journal having been cleared |

Per-record anomalies come from `audit_record` / `audit_components`; the volume-level pair (`NTFS-MFTMIRR-MISMATCH`, `NTFS-LOGFILE-CLEARED`) come from `audit_mft_mirror($MFT, $MFTMirr)` and `audit_logfile($LogFile)`.

## The reader: navigate a volume

`NtfsFs` (in `ntfs-core`, imported as `ntfs_core`) reads files and directories from any `Read + Seek` source:

```rust
use ntfs_core::NtfsFs;
use std::fs::File;

let mut fs = NtfsFs::open(File::open("ntfs.img")?)?;

// Read a file by path…
let hosts = fs.read_file(r"\Windows\System32\drivers\etc\hosts")?;

// …or list the root directory (MFT record 5).
let root = fs.read_record(5)?;
for entry in fs.directory_entries(&root)? {
    if let Some(name) = entry.file_name {
        println!("{}", name.name);
    }
}
# Ok::<(), ntfs_core::NtfsError>(())
```

The bare crate name `ntfs` on crates.io is Colin Finck's general-purpose reader, so this crate publishes as `ntfs-core` and imports as `ntfs_core`.

### Opening a partition inside a whole disk

`OffsetReader` re-bases a partition to offset 0 and **structurally cannot read past the partition boundary** — feed it the offset and length from [`mbr-forensic`](https://github.com/SecurityRonin/mbr-forensic) / [`gpt-partition-forensic`](https://github.com/SecurityRonin/gpt-partition-forensic):

```rust
use ntfs_core::{NtfsFs, OffsetReader};
use std::fs::File;

let part = OffsetReader::new(File::open("disk.img")?, 1_048_576, 500_000_000)?;
let mut fs = NtfsFs::open(part)?;
# Ok::<(), ntfs_core::NtfsError>(())
```

## What makes this different from a general-purpose NTFS crate

Most NTFS crates answer one question: "what files are on this volume?" This workspace answers the questions a digital forensics examiner actually needs:

| Capability | General-purpose NTFS crate | this workspace |
|---|---|---|
| MFT record + attribute parsing | ✅ | ✅ |
| Directory index traversal (`$INDEX_ROOT` / INDX) | ✅ | ✅ |
| Data runs, sparse files, LZNT1 decompression | ✅ | ✅ |
| `$ATTRIBUTE_LIST` (heavily fragmented files) | partial | ✅ |
| `$SI`-vs-`$FN` timestomping detection | ✗ | ✅ |
| Alternate data stream enumeration | ✗ | ✅ |
| Deleted-record carving (unallocated `FILE`/`BAAD`) | ✗ | ✅ |
| MFT record slack extraction | ✗ | ✅ |
| `$MFTMirr` / `$LogFile` tamper checks | ✗ | ✅ |
| Update-sequence (fixup) torn-write detection | ✗ | ✅ |
| `$UsnJrnl:$J` change-journal record decode (create / delete / rename / overwrite history) | ✗ | ✅ |
| Partition-window isolation (cannot read past the volume) | ✗ | ✅ |
| Severity-graded `report::Finding` output | ✗ | ✅ |
| `#![forbid(unsafe_code)]` | — | ✅ |

## Reader API (`ntfs-core`)

| Item | Purpose |
|---|---|
| `NtfsFs::open` / `read_file` / `read_record` / `directory_entries` / `resolve_path` / `read_named_stream` | Navigate a volume by path or MFT record number |
| `BootSector` | Volume boot record (BPB / extended BPB) |
| `MftRecordHeader` / `apply_fixup` | FILE records and update-sequence-array fixup |
| `parse_attributes` / `Attribute` | Resident and non-resident attribute walking |
| `StandardInformation` / `FileName` | The two timestamp sets |
| `decode_runlist` / `read_attribute_value` / `read_runs` | Data runs (VCN→LCN), sparse + non-resident reads |
| `IndexRoot` / `parse_index_buffer` / `parse_entries` | Directory B-tree (`$INDEX_ROOT` / INDX) |
| `parse_attribute_list` | Extension records for fragmented files |
| `decompress` | LZNT1 decompression |
| `carve_mft_entries` | Carve `FILE`/`BAAD` records from a raw `$MFT` region |
| `compare_mft_mirror` / `parse_logfile` / `detect_journal_clearing` | `$MFTMirr` / `$LogFile` parsing primitives |
| `parse_usn_record_v2` / `UsnRecord` / `UsnReason` / `FileAttributes` | Decode `$UsnJrnl:$J` change-journal records (V2/V3) — each event's MFT + parent-MFT reference, reason flags, filename, attributes, and timestamp |
| `OffsetReader` | Bounded partition window |

The auditor primitives — `detect_timestomp`, `alternate_data_streams`, `record_slack`, `is_deleted`, `carve_file_records` — live in `ntfs-forensic` alongside `audit_record`.

## Trust, but verify

`ntfs-forensic` is built for untrusted disk images from potentially compromised systems:

- **`#![forbid(unsafe_code)]`** across both crates — no C bindings, no FFI.
- **Panic-free on malicious input** — every length and offset is validated against both the structure's declared size and the actual buffer; the workspace denies `clippy::unwrap_used` and `clippy::expect_used` in production code.
- **Fuzzed** — seven `cargo-fuzz` targets (`boot`, `record`, `attributes`, `attribute_list`, `runlist`, `index_buffer`, `compress`); a `fuzz.yml` CI workflow builds and smoke-runs each.
- **Validated on real artifacts** — the boot parser is cross-validated against The Sleuth Kit on a real disk image (`tests/real_image.rs`), and MFT parsing is cross-checked against the `mft` crate as an independent oracle (`tests/parity_mft.rs`).
- **100% line coverage** enforced in CI (`cargo llvm-cov --lib`, failing on any zero-hit line).

```bash
cargo test
cargo +nightly fuzz run record   # requires nightly + cargo-fuzz
```

## Where this fits

`ntfs-core` is the NTFS FS-layer foundation for the SecurityRonin forensic family — [`usnjrnl-forensic`](https://github.com/SecurityRonin/usnjrnl-forensic) builds full `$UsnJrnl:$J` path reconstruction (journal rewind) on `ntfs-core`'s USN record decoder, and [`issen`](https://github.com/SecurityRonin/issen) consumes the workspace as its single, auditable NTFS engine. To get a `Read + Seek` over a disk image and locate the NTFS partition within it, these crates compose upstream:

| Crate | Role |
|---|---|
| [`disk-forensic`](https://github.com/SecurityRonin/disk-forensic) | **Orchestrator** — auto-detects MBR / GPT / APM and yields each partition's offset / length |
| [`mbr-forensic`](https://github.com/SecurityRonin/mbr-forensic) | MBR partition table → NTFS partition offset / length |
| [`gpt-partition-forensic`](https://github.com/SecurityRonin/gpt-partition-forensic) | GPT partition table → NTFS partition offset / length |
| [`ewf-forensic`](https://github.com/SecurityRonin/ewf-forensic) | E01 / Expert Witness Format container |
| [`vhdx-forensic`](https://github.com/SecurityRonin/vhdx-forensic) | VHDX container |

---

[Privacy Policy](https://securityronin.github.io/ntfs-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/ntfs-forensic/terms/) · © 2026 Security Ronin Ltd
