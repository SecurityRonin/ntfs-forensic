# 9. Low CI-verified MSRV floor (1.85), decoupled from the pinned dev toolchain

Date: 2026-07-24

Status: Accepted

## Context

The fleet MSRV policy (`~/src/ronin-issen/CLAUDE.md` and `CLAUDE.core.md` →
"Rust MSRV & Toolchain Policy") separates the *dev toolchain* (what contributors
and CI build with) from the *declared MSRV* (`rust-version`, a downstream-facing
promise). Published libraries keep a low, CI-verified MSRV so raising it is
treated as a near-breaking change that narrows the crates.io audience; apps
declare MSRV equal to the pinned toolchain.

Both crates here are published *libraries* (a reader and an analyzer other code
links), so the low-MSRV promise applies. The dev toolchain is pinned to the
current fleet stable in `rust-toolchain.toml` (`channel = "1.96.0"`,
`components = ["clippy", "rustfmt"]`, set in commit `a381b1e`).

## Decision

- Declare `rust-version = "1.85"` once at the workspace level
  (`Cargo.toml [workspace.package]`, inherited by both members via
  `rust-version.workspace = true`) — a deliberate compatibility floor, decoupled
  from the drifting 1.96.0 dev pin.
- Verify the floor in CI with a dedicated MSRV job that pins the toolchain
  *action* to the same version (`.github/workflows/ci.yml`: job `msrv`, name
  "MSRV (1.85)", `dtolnay/rust-toolchain@1.85`), so the promise is a real,
  enforced guarantee rather than an aspiration.

## Consequences

- Downstream consumers can build on Rust 1.85+ regardless of what the fleet dev
  toolchain drifts to; the floor moves only deliberately.
- The MSRV action pin (`@1.85`) is an explicit *version* ref, which — per the
  fleet toolchain gotcha — overrides `rust-toolchain.toml`'s 1.96.0 pin for that
  job via `RUSTUP_TOOLCHAIN`, so the MSRV job genuinely builds on 1.85.
- The exact floor of **1.85** (rather than the fleet's more common 1.75/1.80) is
  not explained in any commit message or comment. Rationale reconstructed from
  structure; original intent not recovered in available history — it is most
  plausibly the minimum a transitive dependency (e.g. `forensic-vfs`,
  `safe-read`, or a `forensicnomicon`/`mft` dependency) compiles under, but that
  was not confirmed from the record and is not asserted here as fact.
