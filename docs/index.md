# ntfs-forensic

**A from-scratch NTFS reader and a graded anomaly auditor — reconstruct full file paths from the `$UsnJrnl:$J` change journal (even for deleted, MFT-reused files), and surface the timestomping, alternate data streams, deleted records, and MFT slack that a "clean" filesystem driver is built to hide.**

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

## `$UsnJrnl:$J`: reconstruct full paths — even for deleted files

The USN change journal records *what* changed and *which* MFT entry — but only the file's **own name**, never its path. `ntfs-core` reconstructs the **full path** of every journal event, including files that were deleted and whose `$MFT` record was later reused, by walking the journal with the *Rewind* algorithm — two passes (reverse, then forward) so a rename or MFT-entry reuse resolves to the correct path at each point in time.

> **Credit:** the journal-`$J` path-reconstruction technique was pioneered by [**CyberCX**](https://cybercx.com/) — see their writeup [*NTFS Usnjrnl Rewind*](https://cybercx.com/blog/ntfs-usnjrnl-rewind/) (April 2024) and the reference tool [`CyberCX-DFIR/usnjrnl_rewind`](https://github.com/CyberCX-DFIR/usnjrnl_rewind). This is an independent, clean-room Rust implementation built on `ntfs-core`'s own parsers; its SQLite export is column-compatible with `usnjrnl_rewind`.

## Trust, but verify

`ntfs-forensic` is built for untrusted disk images from potentially compromised systems:

- **`#![forbid(unsafe_code)]`** across both crates — no C bindings, no FFI.
- **Panic-free on malicious input** — every length and offset is validated against both the structure's declared size and the actual buffer; the workspace denies `clippy::unwrap_used` and `clippy::expect_used` in production code.
- **Fuzzed** — seven `cargo-fuzz` targets (`boot`, `record`, `attributes`, `attribute_list`, `runlist`, `index_buffer`, `compress`); a `fuzz.yml` CI workflow builds and smoke-runs each.
- **Validated on real artifacts** — the boot parser is cross-validated against The Sleuth Kit on a real disk image, and MFT parsing is cross-checked against the `mft` crate as an independent oracle.
- **100% line coverage** enforced in CI (`cargo llvm-cov --lib`, failing on any zero-hit line).

---

[Privacy Policy](privacy.md) · [Terms of Service](terms.md) · © 2026 Security Ronin Ltd
