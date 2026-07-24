# 5. Memory-safety and panic-free posture — `forbid(unsafe)` plus bounded byte reads

Date: 2026-07-24

Status: Accepted

## Context

Both crates parse untrusted, attacker-controllable disk images from potentially
compromised systems. Length, offset, and count fields are adversary-controlled,
so a naive `data[off..off+4]` or `try_into().unwrap()` turns a crafted image
into a panic (denial of service) or, worse, silently wrong output. The fleet
"Paranoid Gatekeeper" standard (`~/src/ronin-issen/CLAUDE.md`) requires these
crates to never panic, never read out of bounds, and never trust a length field.

Unlike the fleet's mmap-backed readers (ewf, memory-forensic), an NTFS parser
over a generic `Read + Seek` source needs no `unsafe` at all — so the strongest
posture, `forbid(unsafe_code)`, is achievable rather than a `deny` + bounded
`#[allow]` exception.

## Decision

- Set `unsafe_code = "forbid"` at the workspace level (`Cargo.toml
  [workspace.lints.rust]`) and `#![forbid(unsafe_code)]` in `core/src/lib.rs` —
  no C bindings, no FFI, no per-site unsafe escape hatch.
- Enforce the panic-free lint set fleet-wide: `unwrap_used = "deny"`,
  `expect_used = "deny"`, `correctness`/`suspicious = "deny"`, plus the pedantic
  group at warn (`Cargo.toml [workspace.lints.clippy]`). Tests are exempted via
  `clippy.toml` (`allow-unwrap-in-tests`/`allow-expect-in-tests`) so they still
  fail loudly.
- Route every multi-byte integer field through bounds-checked readers that
  return `0` (or a zero-filled array) when the read would run past the buffer,
  rather than panicking — see `core/src/bytes.rs` (`le_u16`/`le_u32`/`le_u64`/
  `arr`) and the shared `safe-read` crate.
- Prove the posture empirically with `cargo-fuzz`: six in-tree targets (`boot`,
  `record`, `attributes`, `attribute_list`, `runlist`, `index_buffer`) plus a
  `fuzz.yml` CI workflow.

## Consequences

- A provable, badge-able "zero places a crafted input can corrupt memory" —
  `rg forbid` is the complete audit surface, and the README's robustness claim
  leads with *fuzzed* (measured) beside *panic-free by lint* (static), never a
  bare "panic-free" absolute.
- **Partial `safe-read` migration (known debt).** The fleet standard is to route
  all bounded reads through the shared, fuzzed `safe-read` crate and to *not*
  keep a per-crate `bytes.rs`. Here, `safe-read` is used in four modules —
  `core/src/carve.rs` (the first adoption, in `6db1d2e`/`962f5f2` to fix a
  crafted-input OOB panic, `fb289ee`; dependency renamed `forensic-bytes →
  safe-read` in `567ed02` and pinned to the published `0.1` in `fe933ba`),
  `core/src/usn/reader.rs`, `core/src/usn/carver.rs`, and
  `core/src/logfile/usn_extractor.rs`. The remaining modules (`attribute`,
  `boot`, `record`, `index`, `file_name`, `standard_information`,
  `attribute_list`, and `logfile/mod.rs`) still use the local
  `core/src/bytes.rs` copy. Completing the migration to `safe-read` and deleting
  `bytes.rs` is outstanding work, tracked as a follow-up rather than done.
- `bytes.rs`'s `data.get(off..off+N)` form is panic-safe but computes `off+N`
  before the range check, so a near-`usize::MAX` offset could overflow in debug
  builds; `safe-read`'s `checked_add` is the reason the fleet prefers it — a
  further argument for finishing the migration.
