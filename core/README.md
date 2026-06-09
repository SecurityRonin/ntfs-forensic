# ntfs-core

[![ntfs-core](https://img.shields.io/crates/v/ntfs-core.svg?label=ntfs-core)](https://crates.io/crates/ntfs-core)
[![ntfs-forensic](https://img.shields.io/crates/v/ntfs-forensic.svg?label=ntfs-forensic)](https://crates.io/crates/ntfs-forensic)
[![Docs.rs](https://img.shields.io/docsrs/ntfs-core)](https://docs.rs/ntfs-core)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/ntfs-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/ntfs-forensic/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**A from-scratch, forensic-grade NTFS reader — `$MFT`, attributes, indexes, data runs, named streams, LZNT1, and `$UsnJrnl:$J` change-journal records over any `Read + Seek` source. No `unsafe`, no C bindings.**

```toml
[dependencies]
ntfs-core = "0.6"
```

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

The bare crate name `ntfs` on crates.io is Colin Finck's general-purpose reader, so this crate publishes as **`ntfs-core`** and imports as **`ntfs_core`**.

## What it parses

`BootSector` (BPB / extended BPB) · `MftRecordHeader` + `apply_fixup` (FILE records, update-sequence-array fixup) · `parse_attributes` (resident + non-resident) · `StandardInformation` / `FileName` (both timestamp sets) · `decode_runlist` + `read_attribute_value` (data runs, sparse, non-resident) · `IndexRoot` / `parse_index_buffer` (directory `$INDEX_ROOT` / INDX) · `parse_attribute_list` (fragmented files) · `decompress` (LZNT1) · `carve_mft_entries` (`FILE`/`BAAD` carving) · `compare_mft_mirror` / `parse_logfile` (`$MFTMirr`, `$LogFile`). Open a partition inside a whole disk with the bounded `OffsetReader`, which structurally cannot read past the volume boundary.

### `$UsnJrnl:$J` change journal

A full change-journal reader, not just a record decoder. The headline capability is **full-path reconstruction**: the journal stores only each event's *own* filename, but `RewindEngine` reconstructs the complete path of every event — **even for deleted files whose `$MFT` record was reused** — by replaying the journal:

```rust
let mut engine = ntfs_core::mft::MftData::parse(&mft_bytes)?.seed_rewind();
for resolved in engine.rewind(&ntfs_core::usn::parse_usn_journal(&usn_bytes)?) {
    // resolved.full_path, resolved.record.reason, resolved.source (Allocated/Carved/Ghost)
}
# Ok::<(), ntfs_core::NtfsError>(())
```

- `RewindEngine` / `ResolvedRecord` — **full-path reconstruction** via the *Rewind* algorithm: two passes (reverse + forward) so renames and MFT-entry reuse resolve to the correct path at each point in time.
- `MftData` / `MftEntry` — high-level `$MFT` aggregator (`$SI`/`$FN` timestamps, ADS, path resolution) that seeds the `RewindEngine`.
- `parse_usn_record_v2` / `parse_usn_record_v3` / `parse_usn_journal` · `UsnRecord` / `UsnReason` / `FileAttributes` — decode V2/V3 records (MFT + parent-MFT references, reason flags, filename, attributes, timestamp).
- `UsnJournalReader` — streaming, low-memory iterator over a `$J` stream too large to load whole.
- `carve_usn_records` — recover USN records from free space and corrupt journals (V2/V3, timestamp-range gated).
- `RefsAnalyzer` / `RefsFileId` — ReFS USN V3 support (128-bit file IDs, journal-rewind-only path reconstruction).

> **Credit:** the journal-`$J` path-reconstruction technique was pioneered by [**CyberCX**](https://cybercx.com/) — [*NTFS Usnjrnl Rewind*](https://cybercx.com/blog/ntfs-usnjrnl-rewind/) (April 2024) · [`CyberCX-DFIR/usnjrnl_rewind`](https://github.com/CyberCX-DFIR/usnjrnl_rewind). `RewindEngine` is an independent, clean-room Rust implementation.

## Trust, but verify

`#![forbid(unsafe_code)]`; panic-free on crafted input (the workspace denies `clippy::unwrap_used` / `expect_used` in production code, every length and offset bounds-checked); fuzzed with seven `cargo-fuzz` targets; the boot parser is cross-validated against The Sleuth Kit on a real disk image and MFT parsing against the `mft` crate as an independent oracle; 100% line coverage enforced in CI.

## Forensic analysis

Severity-graded anomaly auditing (timestomp / ADS / deleted-record / slack / `$MFTMirr` / `$LogFile` findings) lives in the sibling **[`ntfs-forensic`](https://crates.io/crates/ntfs-forensic)** crate, built on this one — the reader/analyzer split mirrors `vmdk-core`/`vmdk-forensic`.

---

[Privacy Policy](https://securityronin.github.io/ntfs-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/ntfs-forensic/terms/) · © 2026 Security Ronin Ltd
