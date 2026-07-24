# 6. Reuse the maintained `lznt1` crate for compressed `$DATA` decompression

Date: 2026-07-24

Status: Accepted

## Context

NTFS stores compressed `$DATA` with the LZNT1 codec. Decompressing it is
required to read the file bytes of any compressed stream. The fleet's global
research discipline (`CLAUDE.core.md`) names LZNT1 explicitly as a case where a
correct, maintained ecosystem crate already exists (`lznt1`) and should be
reused rather than reinvented — a self-encoded round-trip against a home-rolled
decoder is the canonical "LZNT1 trap" (both encoder and decoder wrong, tests
green).

The `lznt1` crate is `no_std`, `forbid(unsafe)`, pure-Rust, validated
byte-for-byte against The Sleuth Kit on real Windows streams, and ships an
encoder too — so it clears both the memory-safety posture (ADR 0005) and the
independent-oracle bar.

## Decision

Depend on the maintained `lznt1` crate (`lznt1 = "0.1"` in
`workspace.dependencies`) and re-export its `decompress` from `ntfs-core`
(`core/src/lib.rs`: `pub use lznt1::decompress;`), rather than carrying a
decode-only implementation of the codec. The `core/Cargo.toml` comment records
the rationale directly: "preferred over re-rolling our own decode-only copy."

## Consequences

- No home-rolled codec to fall into the LZNT1 trap; correctness rides on an
  implementation already validated against TSK on real data.
- One fewer parser surface to fuzz and audit in this workspace; the codec's
  safety posture matches ours (`no_std`, `forbid(unsafe)`).
- The earlier in-tree `compress.rs` module (present at the reader/analyzer split,
  commit `112a76a`) is superseded by the crate re-export.
- This is the fleet-correct application of "prefer our own crates": for solved
  codecs the rule yields to a mature, audited ecosystem crate — the same
  reasoning the constitution applies to crypto primitives.
