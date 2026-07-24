# 3. Crate naming: `ntfs-core` published, imported as `ntfs_core` (no `ntfs` name hijack)

Date: 2026-07-24

Status: Accepted

## Context

The bare crate name `ntfs` on crates.io belongs to Colin Finck's popular,
maintained general-purpose NTFS crate. The fleet naming grammar
(`~/src/ronin-issen/CLAUDE.md` → "Crate naming grammar") is explicit about this
exact case: when the bare `<x>` name is a *popular* third-party crate, do **not**
hijack the import path via `[lib] name = "<bare>"`; keep the `<x>_core` import
(the constitution cites `ntfs-core imports as ntfs_core` by name).

The reader/analyzer split (ADR 0001) already fixes the two crate roles:
`<x>-core` for the reader, `<x>-forensic` for the analyzer.

## Decision

- Publish the reader as **`ntfs-core`**, imported as **`ntfs_core`** — no
  `[lib] name = "ntfs"` alias, so there is no collision or confusion with the
  third-party `ntfs` crate (`core/Cargo.toml` `name = "ntfs-core"`, no `[lib]`
  rename; consumers write `use ntfs_core::...`).
- Publish the analyzer as **`ntfs-forensic`**, which is also the repository
  name (Pattern A single-format repo).

## Consequences

- The import path `ntfs_core` reads unambiguously and never shadows the popular
  `ntfs` crate for a consumer who depends on both (e.g. during a migration).
- The repo, the analyzer crate, and the reader crate carry the three fleet-
  standard names with zero special-casing.
- Rationale reconstructed from the fleet naming grammar and the `core/Cargo.toml`
  package name; the constitution names `ntfs-core`/`ntfs_core` directly as the
  worked example, so the decision is grounded rather than inferred.
