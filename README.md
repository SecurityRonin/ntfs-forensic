# ntfs-forensic

[![Crates.io](https://img.shields.io/crates/v/ntfs-forensic.svg)](https://crates.io/crates/ntfs-forensic)
[![Docs.rs](https://docs.rs/ntfs-forensic/badge.svg)](https://docs.rs/ntfs-forensic)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/ntfs-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/ntfs-forensic/actions/workflows/ci.yml)
[![Sponsor](https://img.shields.io/badge/Sponsor-%E2%9D%A4-db61a2.svg)](https://github.com/sponsors/h4x0r)

**A from-scratch, panic-hardened NTFS reader for DFIR — the MFT, deleted records, slack, and timestomping that a "clean" filesystem driver is built to hide.**

Point it at a raw image, an EWF/VMDK-backed source, or a single partition, and read NTFS directly — no Sleuth Kit FFI, no `unsafe`, no surprises on crafted input.

```rust
use std::fs::File;
use ntfs_forensic::NtfsFs;

let mut fs = NtfsFs::open(File::open("disk.ntfs")?)?;

// Read a file by path…
let hosts = fs.read_file(r"\Windows\System32\drivers\etc\hosts")?;

// …or list the root directory (MFT record 5).
let root = fs.read_record(5)?;
for entry in fs.directory_entries(&root)? {
    if let Some(fname) = entry.file_name {
        println!("{}", fname.name);
    }
}
# Ok::<(), ntfs_forensic::NtfsError>(())
```

```text
$MFT
$LogFile
Windows
Users
hiberfil.sys
pagefile.sys
```

## Install

```toml
[dependencies]
ntfs-forensic = "0.1"
```

## What it surfaces

A forensic reader's job is the artifacts the OS won't show you:

- **Deleted records** — `is_deleted` and `carve_file_records` scan the MFT for unallocated `FILE`/`BAAD` records.
- **Timestomping** — `detect_timestomp` flags `$STANDARD_INFORMATION` timestamps that predate their `$FILE_NAME` pair or land on a suspiciously round whole second.
- **Alternate data streams** — `alternate_data_streams` enumerates named `$DATA` (the classic `Zone.Identifier` / hidden-payload trick).
- **Record slack** — `record_slack` returns the bytes past a record's used size, where a previous resident attribute may linger.

```rust
use ntfs_forensic::detect_timestomp;

let flags = detect_timestomp(&std_info, &file_name);
if flags.is_suspicious() {
    eprintln!("timestomp indicators: {flags:?}");
}
```

## Open a partition inside a whole disk

`OffsetReader` re-bases a partition to offset 0 and **structurally cannot read past the partition boundary** — feed it the offset and length from `mbr-forensic` / `gpt-forensic`:

```rust
use ntfs_forensic::{NtfsFs, OffsetReader};
use std::fs::File;

let part = OffsetReader::new(File::open("disk.img")?, 1_048_576, 500_000_000)?;
let mut fs = NtfsFs::open(part)?;
# Ok::<(), ntfs_forensic::NtfsError>(())
```

## Built to not break on hostile input

Forensic images are adversarial: corrupt, truncated, and sometimes crafted to crash your tooling. This crate is designed for that.

- **`#![forbid(unsafe_code)]`** across the whole crate.
- **Checked arithmetic, bounded allocations, loop caps** — every length and offset is validated against *both* the structure's declared size and the actual buffer.
- **Fuzzed.** Seven `cargo-fuzz` targets (boot, MFT record + fixup, attributes, runlist, INDX buffers, LZNT1, `$ATTRIBUTE_LIST`) have run **tens of millions of executions**. The one panic they found — an LZNT1 chunk-size overflow — is fixed and pinned as a regression test.

```bash
cargo +nightly fuzz run compress   # reproduce the hardening for yourself
```

## Coverage

Clean-room, spec-first implementation cross-checked against The Sleuth Kit and the `ntfs` / `mft` crates as oracles:

| Layer | Implemented |
|---|---|
| Boot sector / BPB | ✅ |
| MFT records + update-sequence fixup | ✅ |
| Resident & non-resident attributes | ✅ |
| Data runs (runlist VCN→LCN, sparse) | ✅ |
| `$STANDARD_INFORMATION`, `$FILE_NAME` | ✅ |
| Directory indexes (`$INDEX_ROOT` / INDX) | ✅ |
| `$ATTRIBUTE_LIST` (fragmented files) | ✅ |
| LZNT1 decompression | ✅ |
| Path resolution & file read | ✅ |
| Forensic Tier-2 (deleted / timestomp / ADS / slack) | ✅ |

## Architecture

`ntfs-forensic` is the FILESYSTEM layer of a larger forensic stack: it navigates a sector stream by path (`name → MFT record → data runs → bytes`). NTFS on-disk *knowledge* (magic bytes, offsets, type codes) lives in the zero-dependency `forensicnomicon` KNOWLEDGE crate; this crate owns the *parsing algorithms*.

---

[Privacy Policy](https://securityronin.github.io/ntfs-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/ntfs-forensic/terms/) · © 2026 Security Ronin Ltd
