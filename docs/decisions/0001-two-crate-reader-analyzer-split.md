# 1. Two-crate reader/analyzer split (`ntfs-core` + `ntfs-forensic`)

Date: 2026-07-24

Status: Accepted

## Context

NTFS forensic tooling has two distinct responsibilities that pull the code in
opposite directions. A *reader* is built to interpret valid on-disk structures
robustly and expose a clean navigation API (path → record → attribute → bytes).
An *analyzer* must see exactly the detail a robust reader abstracts away: slack
between records, deleted/overwritten regions, `$SI`-vs-`$FN` timestamp
divergence, torn-write fixups, and other anti-forensic indicators a "clean"
filesystem driver is designed to hide.

The repository began as a single `ntfs-forensic` crate and was split into a
Cargo workspace with two members — `core/` (`ntfs-core`) and `forensic/`
(`ntfs-forensic`) — in commit `112a76a` (`refactor!: split ntfs-forensic into
ntfs-core (reader) + ntfs-forensic (analyzer)`). The SecurityRonin fleet
constitution (`~/src/ronin-issen/CLAUDE.md` → "Crate-structure standard —
reader/analyzer split") makes this the binding standard layout for every
single-format repo (Pattern A), with `ntfs-forensic` named as the reference
implementation.

## Decision

Ship one workspace repository named `ntfs-forensic` with exactly two published
members:

- **`ntfs-core`** — the pure reader/parser. Boot sector, `$MFT` records,
  attributes, indexes, data runs, LZNT1, `$UsnJrnl:$J`, `$LogFile`, and
  `NtfsFs` navigation over any `Read + Seek` source. Emits no findings.
- **`ntfs-forensic`** — the anomaly auditor. Converts parsed structures into
  severity-graded `forensicnomicon::report::Finding`s (timestomping, ADS,
  deleted records, MFT slack) via `audit_record`-style entry points.

`ntfs-forensic` depends on `ntfs-core` by default (`ntfs-core.workspace = true`
in `forensic/Cargo.toml`), but is free to parse raw bytes directly where the
reader's happy-path API would hide an anomaly — several `ntfs-forensic`
primitives take `&[u8]` and re-parse headers in place rather than routing
through `NtfsFs`.

## Consequences

- One versionable reader that third parties can reuse without pulling in the
  analyzer, and one auditor that plugs into the fleet's shared report model.
- The two members version independently (`ntfs-core` 0.9.x, `ntfs-forensic`
  0.8.x) — a reader-only fix does not force an analyzer bump.
- Consumers that only need file extraction (issen, disk4n6) depend on
  `ntfs-core` alone; the correlation/timeline layer additionally depends on
  `ntfs-forensic`.
- The split obliges discipline about which layer owns a given capability;
  auditor code that needs sub-reader detail parses bytes directly rather than
  contorting a reader API (see the `&[u8]` audit entry points).
