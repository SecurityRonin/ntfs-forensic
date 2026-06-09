# ntfs-forensic

[![ntfs-forensic](https://img.shields.io/crates/v/ntfs-forensic.svg?label=ntfs-forensic)](https://crates.io/crates/ntfs-forensic)
[![ntfs-core](https://img.shields.io/crates/v/ntfs-core.svg?label=ntfs-core)](https://crates.io/crates/ntfs-core)
[![Docs.rs](https://img.shields.io/docsrs/ntfs-forensic)](https://docs.rs/ntfs-forensic)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/ntfs-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/ntfs-forensic/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Hand it a raw MFT record, get back severity-graded NTFS anomalies — timestomping, alternate data streams, deleted records, and record slack as `forensicnomicon::report::Finding`s.**

```toml
[dependencies]
ntfs-forensic = "0.5"   # pulls in ntfs-core
```

```rust
use ntfs_forensic::audit_record;
use forensicnomicon::report::Source;

let src = Source { analyzer: "ntfs-forensic".into(), scope: "NTFS".into(), version: None };

for anomaly in audit_record(&mft_record_bytes) {
    let finding = anomaly.to_finding(src.clone());
    println!("[{:?}] {} — {}", finding.severity, finding.code, finding.note);
    // e.g. [Some(High)] NTFS-TIMESTOMP — $SI created before $FN …
}
```

`audit_record` parses the record header and attributes, extracts `$STANDARD_INFORMATION`/`$FILE_NAME`, and grades what it finds. A record whose header does not parse yields no anomalies (structural corruption is surfaced by the reader/carver, never a panic). Already have parsed components? Skip the re-parse and call `audit_components(record_number, header, record, attributes, si, fname)`.

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

The first four come from `audit_record` / `audit_components`. The volume-level pair come from `audit_mft_mirror($MFT, $MFTMirr)` and `audit_logfile($LogFile)`, returning `ArtifactAnomaly`s that also convert via `to_finding(source)`.

## The building blocks

`audit_record` is composed from pure, side-effect-free primitives you can call directly:

- `detect_timestomp(si, file_name)` → `TimestompIndicators { si_created_before_fn, created_mismatch, si_whole_second }`
- `alternate_data_streams(attributes)` → the named `$DATA` attributes
- `record_slack(record, header)` → the bytes past the record's used size
- `is_deleted(header)` → record not currently allocated
- `carve_file_records(mft, record_size)` → offsets of `FILE`/`BAAD` records in a raw `$MFT` region

## `$UsnJrnl:$J` change-journal analysis

Beyond MFT-record anomalies, this crate analyses the USN change journal (decoded by `ntfs-core`):

- `rules` — a configurable rule engine (`RuleSet` / `Rule`, glob + regex filename and reason-flag matching) whose hits convert to graded `report::Finding`s via `RuleMatch::to_finding`.
- `analysis` — pattern detectors for secure deletion (SDelete / cipher), USN-journal clearing, ransomware, and timestomping.
- `correlation` — cross-references USN ↔ `$LogFile` ↔ `$MFT` to surface ghost records, coverage gaps, entry reuse, and timestamp conflicts.
- `triage` — a `TriageEngine` with 12 built-in investigative questions over reconstructed records.

The "reconstructed records" these analyse come from `ntfs-core`'s `RewindEngine`, which rebuilds the full path of every journal event — even for deleted, MFT-reused files — via the *Rewind* algorithm pioneered by **CyberCX** ([*NTFS Usnjrnl Rewind*](https://cybercx.com/blog/ntfs-usnjrnl-rewind/) · [`CyberCX-DFIR/usnjrnl_rewind`](https://github.com/CyberCX-DFIR/usnjrnl_rewind)).

These power the thin [`usnjrnl-forensic`](https://github.com/SecurityRonin/usnjrnl-forensic) CLI, which adds output formats (JSON / CSV / SQLite / TLN / body) and live monitoring on top.

## The two-crate split

This crate is the **analyzer**; the **reader** is [`ntfs-core`](https://crates.io/crates/ntfs-core) (`$MFT`, attributes, indexes, data runs, LZNT1, the full `$UsnJrnl:$J` reader stack — streaming reader, carver, `RewindEngine` path reconstruction, `MftData` — and `NtfsFs` path navigation over any `Read + Seek` source). The split mirrors `vmdk-core`/`vmdk-forensic`. Together they back [`issen`](https://github.com/SecurityRonin/issen) and [`usnjrnl-forensic`](https://github.com/SecurityRonin/usnjrnl-forensic).

## Trust, but verify

Built for untrusted disk images from potentially compromised systems: `#![forbid(unsafe_code)]`; panic-free on crafted input (the workspace denies `clippy::unwrap_used` / `expect_used` in production code); `ntfs-core` is fuzzed with seven `cargo-fuzz` targets, cross-validated against The Sleuth Kit and the `mft` crate on real disk images, and held at 100% line coverage in CI.

---

[Privacy Policy](https://securityronin.github.io/ntfs-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/ntfs-forensic/terms/) · © 2026 Security Ronin Ltd
