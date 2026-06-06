# ntfs-forensic

[![Crates.io](https://img.shields.io/crates/v/ntfs-forensic.svg)](https://crates.io/crates/ntfs-forensic)
[![docs.rs](https://img.shields.io/docsrs/ntfs-forensic)](https://docs.rs/ntfs-forensic)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/ntfs-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/ntfs-forensic/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

Forensic-grade NTFS reader for Rust. A clean, from-scratch implementation that reads files and directories from any `Read + Seek` source — and goes beyond a normal filesystem driver to surface the artifacts an examiner needs: timestomping indicators, alternate data streams, deleted MFT records, and record slack that a "clean" reader is designed to hide.

It is the NTFS FS-layer foundation for the SecurityRonin forensic family: [`usnjrnl-forensic`](https://github.com/SecurityRonin/usnjrnl-forensic) and [`issen`](https://github.com/SecurityRonin/issen) consume it as their single, auditable NTFS engine.

## Rust library

```toml
[dependencies]
ntfs-forensic = "0.1"
```

## Quick start

```rust
use ntfs_forensic::NtfsFs;
use std::fs::File;

// Open an NTFS volume (a raw partition image, or any Read + Seek source).
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
# Ok::<(), ntfs_forensic::NtfsError>(())
```

## What makes this different from a general-purpose NTFS crate

Most NTFS crates answer one question: "what files are on this volume?" `ntfs-forensic` answers the questions a digital forensics examiner actually needs:

| Capability | General-purpose NTFS crate | ntfs-forensic |
|---|---|---|
| MFT record + attribute parsing | ✅ | ✅ |
| Directory index traversal (`$INDEX_ROOT` / INDX) | ✅ | ✅ |
| Data runs, sparse files, LZNT1 decompression | ✅ | ✅ |
| `$ATTRIBUTE_LIST` (heavily fragmented files) | partial | ✅ |
| `$SI`-vs-`$FN` timestomping detection | ✗ | ✅ |
| Alternate data stream enumeration | ✗ | ✅ |
| Deleted-record carving (unallocated `FILE`/`BAAD`) | ✗ | ✅ |
| MFT record slack extraction | ✗ | ✅ |
| Update-sequence (fixup) torn-write / tamper detection | ✗ | ✅ |
| Partition-window isolation (cannot read past the volume) | ✗ | ✅ |
| Adversarial-input hardening + fuzz testing | ✗ | ✅ |
| `#![forbid(unsafe_code)]` | — | ✅ |

## Forensic capabilities

Every analysis is a pure function over already-parsed structures — exact and side-effect free.

### Timestomping detection

NTFS keeps two timestamp sets: `$STANDARD_INFORMATION` (updatable via the Win32 API — what timestomp tools target) and `$FILE_NAME` (set by the kernel on create/rename). Divergence between them, or `$SI` times landing on a whole second, is a tampering tell.

```rust
use ntfs_forensic::detect_timestomp;

let flags = detect_timestomp(&std_info, &file_name);
if flags.is_suspicious() {
    // si_created_before_fn, created_mismatch, si_whole_second
    eprintln!("timestomp indicators: {flags:?}");
}
```

### Alternate data streams

```rust
use ntfs_forensic::alternate_data_streams;

for ads in alternate_data_streams(&attributes) {
    println!("ADS: {}", ads.name.as_deref().unwrap_or(""));  // e.g. "Zone.Identifier"
}
```

### Deleted records and record slack

```rust
use ntfs_forensic::{carve_file_records, is_deleted, record_slack, MftRecordHeader};

// Scan a raw $MFT for FILE/BAAD records at record-size boundaries.
for offset in carve_file_records(&mft_bytes, 1024) {
    let header = MftRecordHeader::parse(&mft_bytes[offset..])?;
    if is_deleted(&header) {
        // residue past the record's used size may hold a previous resident attribute
        let slack = record_slack(&mft_bytes[offset..offset + 1024], &header);
        println!("deleted record {} ({} slack bytes)", header.record_number, slack.len());
    }
}
# Ok::<(), ntfs_forensic::NtfsError>(())
```

## Opening a partition inside a whole disk

`OffsetReader` re-bases a partition to offset 0 and **structurally cannot read past the partition boundary** — feed it the offset and length from [`mbr-forensic`](https://github.com/SecurityRonin/mbr-forensic) / [`gpt-forensic`](https://github.com/SecurityRonin/gpt-forensic):

```rust
use ntfs_forensic::{NtfsFs, OffsetReader};
use std::fs::File;

let part = OffsetReader::new(File::open("disk.img")?, 1_048_576, 500_000_000)?;
let mut fs = NtfsFs::open(part)?;
# Ok::<(), ntfs_forensic::NtfsError>(())
```

## API

| Item | Purpose |
|---|---|
| `NtfsFs::open` / `read_file` / `read_record` / `directory_entries` / `resolve_path` | Navigate a volume by path or MFT record number |
| `BootSector::parse` | Volume boot record (BPB / extended BPB) |
| `MftRecordHeader::parse` / `apply_fixup` | FILE records and update-sequence-array fixup |
| `parse_attributes` / `Attribute` | Resident and non-resident attribute walking |
| `StandardInformation` / `FileName` | The two timestamp sets |
| `decode_runlist` / `read_attribute_value` | Data runs (VCN→LCN), sparse + non-resident reads |
| `IndexRoot::parse` / `parse_index_buffer` | Directory B-tree (`$INDEX_ROOT` / INDX) |
| `parse_attribute_list` | Extension records for fragmented files |
| `decompress` | LZNT1 decompression |
| `detect_timestomp` / `alternate_data_streams` / `record_slack` / `is_deleted` / `carve_file_records` | Forensic Tier-2 |
| `OffsetReader` | Bounded partition window |

All parsers accept `&[u8]` or a `Read + Seek` source and return a typed `Result<_, NtfsError>`.

## Security

`ntfs-forensic` is designed for use on untrusted disk images from potentially compromised systems:

- **No panics on malicious input** — every length and offset is validated against *both* the structure's declared size and the actual buffer; arithmetic is checked or saturating
- **`#![forbid(unsafe_code)]`** across the whole crate
- **Bounded allocations** — `try_reserve_exact` and explicit ceilings refuse allocation bombs (e.g. a crafted runlist or LZNT1 stream)
- **Loop caps** — attribute chains, runlists, and index entries are bounded against non-terminating walks
- **Fixup verification** — torn writes and USA tampering surface as `FixupMismatch` rather than silently-wrong output
- **Partition isolation** — `OffsetReader` makes reading past the volume boundary structurally impossible
- **Fuzz-tested** — seven `cargo-fuzz` targets, tens of millions of executions; the one panic they found (an LZNT1 chunk-size overflow) is fixed and pinned as a regression test

### Running the fuzz targets

```bash
# Requires nightly Rust and cargo-fuzz
rustup install nightly
cargo install cargo-fuzz

cargo +nightly fuzz run compress     # LZNT1 — loops + back-references
cargo +nightly fuzz run record       # MFT record + fixup
cargo +nightly fuzz run attributes   # attribute chain walking
```

## Testing

140 unit tests plus a real-image cross-validation test, covering every public API, every error path, and adversarial inputs (truncated records, crafted runlists, torn fixups, out-of-bounds indexes). The boot parser is cross-validated against The Sleuth Kit's `fsstat` on a real disk image. **No source line is left uncovered** — enforced in CI.

```bash
cargo test
cargo install cargo-llvm-cov
cargo llvm-cov --lib --show-missing-lines
```

> Aggregate line coverage can read slightly under 100% because the generic, reader-agnostic functions (`NtfsFs<R>`, `OffsetReader<R>`) are monomorphized once per reader type in the tests; the CI gate confirms no source line is left uncovered (zero zero-hit lines in `lcov`).

## Related

`ntfs-forensic` reads an NTFS volume. To get a `Read + Seek` over a disk image, and to locate the NTFS partition within it, these crates compose upstream:

| Crate | Role |
|---|---|
| [`disk-forensic`](https://github.com/SecurityRonin/disk-forensic) | **Orchestrator** — auto-detects MBR / GPT / APM and yields each partition's offset / length |
| [`mbr-forensic`](https://github.com/SecurityRonin/mbr-forensic) | MBR partition table → NTFS partition offset / length |
| [`gpt-forensic`](https://github.com/SecurityRonin/gpt-forensic) | GPT partition table → NTFS partition offset / length |
| [`apm-forensic`](https://github.com/SecurityRonin/apm-forensic) | Apple Partition Map (classic Mac / hybrid media — rarely hosts NTFS) |
| [`ewf-forensic`](https://github.com/SecurityRonin/ewf-forensic) | E01 / Expert Witness Format container |
| [`vhdx-forensic`](https://github.com/SecurityRonin/vhdx-forensic) | VHDX container |

## Sibling crates

One forensic reader per filesystem — each a `Read + Seek` library that composes with the container and partition crates above:

| Crate | Filesystem |
|---|---|
| [`ext4fs-forensic`](https://github.com/SecurityRonin/ext4fs-forensic) | ext2 / ext3 / ext4 |
| **ntfs-forensic** | NTFS |

---

[Privacy Policy](https://securityronin.github.io/ntfs-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/ntfs-forensic/terms/) · © 2026 Security Ronin Ltd
