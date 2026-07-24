# 7. Absorb the USN-journal / Rewind stack into `ntfs-core` / `ntfs-forensic`

Date: 2026-07-24

Status: Accepted

## Context

`usnjrnl-forensic` was a separate repository carrying its own NTFS handling: an
in-house MBR/GPT parse, the third-party `ntfs` and `mft` crates, from-scratch
`$MFT` and deleted-record carving, `$MFTMirr`/`$LogFile` handling, and the
`$UsnJrnl:$J` reader plus the CyberCX "Rewind" full-path reconstruction
algorithm. `MIGRATION.md` records the plan: once this workspace reached parity,
`usnjrnl-forensic` would drop its ad-hoc NTFS modules and both third-party NTFS
crates and depend on this one auditable engine.

The `$UsnJrnl:$J` reader logic is NTFS *reader* knowledge (record decode,
streaming, carving, MFT-seeded path reconstruction); the USN *findings* logic
(rule engine, clearing/ransomware/timestomp detectors, correlation, triage) is
*analyzer* knowledge. Under the reader/analyzer split (ADR 0001) they belong in
`ntfs-core` and `ntfs-forensic` respectively — not in a downstream application
crate.

## Decision

Move the USN-journal reader stack into `ntfs-core` and the USN findings stack
into `ntfs-forensic`, leaving `usnjrnl-forensic` a thin CLI shell over the two
(CHANGELOG `ntfs-core 0.7.0 / ntfs-forensic 0.6.0`, commit `3fdce42`
"usnjrnl absorption"). Concretely:

- `ntfs-core` gains `usn` (streaming `UsnJournalReader`, `carve_usn_records`,
  V2/V3 record decode), `rewind::RewindEngine` (two-pass reverse/forward
  path reconstruction), `refs` (ReFS USN V3 128-bit references), and the
  `MftData`/`MftEntry` aggregator that seeds the rewind engine.
- `ntfs-forensic` gains `rules` (USN rule engine → graded findings),
  `analysis` (secure-deletion / journal-clearing / ransomware / timestomp
  detectors), `correlation` (USN ↔ `$LogFile` ↔ `$MFT`), and `triage`.

## Consequences

- One self-owned, fuzzed, independently-validated NTFS engine replaces both
  in-house modules *and* the `ntfs` + `mft` third-party dependencies in
  `usnjrnl-forensic` — the net dependency reduction `MIGRATION.md` targeted.
- The `mft::seed_rewind()` seam is preserved: the rewind engine consumes parsed
  *and* carved (deleted) MFT entries with parent references, so downstream code
  sits on top unchanged.
- The full Rewind capability is now the workspace's headline feature (README),
  reusable by issen directly rather than only through the CLI shell.
- The CyberCX technique is credited in-repo (CHANGELOG 0.7.1, README) as a
  clean-room Rust implementation over `ntfs-core`'s own parsers.
