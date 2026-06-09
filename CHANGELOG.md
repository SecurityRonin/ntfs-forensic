# Changelog

All notable changes to `ntfs-forensic` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [ntfs-core 0.7.1 / ntfs-forensic 0.6.1] — 2026-06-09

### Docs

- Feature `$UsnJrnl:$J` full-path reconstruction (the *Rewind* engine) as the
  headline capability, with a worked example, and credit the technique's
  originator, [CyberCX](https://cybercx.com.au/blog/ntfs-usnjrnl-rewind/)
  ([`CyberCX-DFIR/usnjrnl_rewind`](https://github.com/CyberCX-DFIR/usnjrnl_rewind)).
  Docs-only; no code change.

## [ntfs-core 0.7.0 / ntfs-forensic 0.6.0] — 2026-06-09

Absorbed `usnjrnl-forensic`'s intelligence: all USN-journal reader logic moved
into `ntfs-core`, all USN findings logic into `ntfs-forensic`. `usnjrnl-forensic`
is now a thin CLI shell over these two crates.

### Added — `ntfs-core` (reader)

- `refs` — ReFS USN V3 support: `RefsFileId` (128-bit), `RefsRecord`,
  `RefsAnalyzer` (volume detection, file-id grouping, journal-rewind path
  reconstruction).
- `usn::reader::UsnJournalReader` — streaming, low-memory `$UsnJrnl:$J` iterator
  over any `Read + Seek`.
- `usn::carver::carve_usn_records` — free-space USN record carver (V2/V3,
  timestamp-range gated).
- `rewind::RewindEngine` — CyberCX two-phase (reverse + forward) full-path
  reconstruction with rename/MFT-reuse handling.
- `mft::MftData` / `mft::MftEntry` — high-level `$MFT` aggregator with `$SI`/`$FN`
  timestamps, ADS detection, path resolution, and a `RewindEngine` seed.

### Added — `ntfs-forensic` (analyzer)

- `rules` — USN rule engine (`RuleSet`/`Rule`) emitting graded
  `report::Finding`s via `RuleMatch::to_finding`.
- `analysis` — secure-deletion (SDelete/cipher), USN-journal-clearing,
  ransomware, and timestomping pattern detectors.
- `correlation` — USN ↔ `$LogFile` ↔ `$MFT` correlation: ghost records,
  coverage gaps, entry reuse, timestamp conflicts.
- `triage` — `TriageEngine` plus 12 built-in investigative questions.

## [0.2.0] — 2026-06-07

### Added

- `NtfsFs::read_named_stream(path, stream)` — read a named alternate data stream
  (e.g. `$UsnJrnl:$J`, a file's `Zone.Identifier`), sharing the resident /
  non-resident read path with `read_file`.
- `$ATTRIBUTE_LIST` following: attributes spread across extension MFT records are
  gathered (cycle-broken) so `read_file` works on heavily fragmented files whose
  `$DATA` lives in extension records.
- Assembly of a split non-resident `$DATA` whose runlist spans several `$DATA`
  attributes (different `start_vcn`) across records, via `data::attribute_runlist`.

### Validated

- MFT record/attribute parsing cross-validated against the `mft` crate on a real
  `$MFT` (DEF CON DFIR CTF), 65,528 records — in-use/is-dir/record-number 100%,
  names 100% by membership (dev-only parity gate).

## [0.1.0] — 2026-06-06

Initial crates.io release.

### Added

- From-scratch NTFS reader over any `Read + Seek` source — no third-party NTFS
  parsing dependency.
- Boot sector / BPB parsing (`BootSector::parse`).
- FILE record parsing with update-sequence-array fixup
  (`MftRecordHeader::parse`, `apply_fixup`).
- Resident and non-resident attribute walking (`parse_attributes`,
  `Attribute`, `AttributeBody`).
- `$STANDARD_INFORMATION` and `$FILE_NAME` timestamp decoding.
- Data-run (runlist) decoding with sparse and non-resident reads
  (`decode_runlist`, `read_attribute_value`).
- LZNT1 decompression (`decompress`).
- `$ATTRIBUTE_LIST` following for heavily fragmented files
  (`parse_attribute_list`).
- Directory B-tree traversal (`$INDEX_ROOT` / INDX) (`IndexRoot::parse`,
  `parse_index_buffer`).
- Named alternate-data-stream reads via `read_named_stream`.
- Path and record navigation (`NtfsFs::open`, `read_file`, `read_record`,
  `directory_entries`, `resolve_path`).
- Bounded partition window (`OffsetReader`) — structurally cannot read past the
  partition boundary.
- Forensic Tier-2: `$SI`-vs-`$FN` timestomp detection (`detect_timestomp`),
  alternate-data-stream enumeration (`alternate_data_streams`),
  deleted-record carving (`carve_file_records`, `is_deleted`), and MFT record
  slack extraction (`record_slack`).

### Security

- `#![forbid(unsafe_code)]` across the whole crate.
- Adversarial-input hardening: bounded allocations, loop caps, and fixup
  verification surface malformed input as typed errors rather than panics or
  silently-wrong output.
- Seven `cargo-fuzz` targets (`attribute_list`, `attributes`, `boot`,
  `compress`, `index_buffer`, `record`, `runlist`).

### Testing

- 100% line coverage, enforced in CI.
- Boot parser cross-validated against The Sleuth Kit's `fsstat` on a real disk
  image; MFT parsing cross-validated against the `mft` crate as an independent
  oracle.

[Unreleased]: https://github.com/SecurityRonin/ntfs-forensic/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/SecurityRonin/ntfs-forensic/releases/tag/v0.1.0
