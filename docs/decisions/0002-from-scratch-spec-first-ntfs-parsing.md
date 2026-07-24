# 2. From-scratch, spec-first NTFS parsing (no third-party NTFS crate in the shipped graph)

Date: 2026-07-24

Status: Accepted

## Context

Two maintained Rust NTFS crates exist: Colin Finck's `ntfs` (a general-purpose
read-only filesystem crate) and `mft` (an `$MFT` record parser). Reusing one
would have been the DRY default under the fleet's "prefer existing crates"
research discipline.

But both are built to answer "what files are on this volume?" — they normalize
or skip exactly the malformed, deleted, and slack detail a forensic auditor
must observe. A general-purpose reader hides torn-write fixups, unallocated
`FILE`/`BAAD` records, `$SI`-vs-`$FN` divergence, and MFT-record slack; those
are the primary artifacts of this workspace (see the capability matrix in
`README.md` and `core/src/lib.rs`). The research therefore did not merely find
prior art — it established that the existing readers' abstraction is
*unacceptable* for the forensic use case, which is the bar the fleet requires
before choosing to build.

`core/src/lib.rs` states the resulting posture: "a clean, spec-first
implementation (no third-party NTFS parsing dependency)." The commit history
(`MIGRATION.md`, CHANGELOG 0.1.0/0.7.0) records that the workspace was built to
let downstream consumers *drop* both the `ntfs` and `mft` third-party
dependencies.

## Decision

Parse every NTFS structure from scratch against the on-disk specification, with
no third-party NTFS parsing crate in the shipped dependency graph. Keep the
third-party `mft` crate only as a **dev-dependency**, used as an independent
cross-validation oracle in the parity tests (`mft` in `core/Cargo.toml`
`[dev-dependencies]`, driving `tests/parity_mft.rs`). The `ntfs` crate is not a
dependency in any capacity — dev or shipped.

## Consequences

- The reader can surface deleted, slack, and malformed structures a
  happy-path crate would drop — the whole reason the workspace exists.
- Full ownership of the parse path: bounds checks, allocation caps, and fixup
  verification are ours to guarantee (see ADR 0005).
- Correctness must be earned against independent oracles rather than inherited
  from a mature crate. This is done deliberately — the `mft` crate, The Sleuth
  Kit, and LogFileParser serve as Tier-1 oracles (see `docs/validation.md`).
- Format-constant knowledge is *not* re-derived here; it is sourced from the
  `forensicnomicon` KNOWLEDGE leaf (see ADR 0004), so "from scratch" means the
  parsing algorithms, not the magic bytes and field offsets.
