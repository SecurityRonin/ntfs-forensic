# 8. `forensic-vfs` `FileSystem` adapter behind an optional `vfs` feature

Date: 2026-07-24

Status: Accepted

## Context

The fleet's universal container/filesystem abstraction (`~/src/ronin-issen/
CLAUDE.md` → "VFS & Universal Container Abstraction") lets a consumer read any
evidence image without knowing one filesystem format from another: readers
implement the `forensic-vfs` `FileSystem` contract, and `forensic-vfs-engine`
composes a whole stack (`E01 → GPT → BitLocker → NTFS`) as one
`Arc<dyn ImageSource>` that N workers share and no path can write. For NTFS to
participate, `NtfsFs` must implement that trait.

But `forensic-vfs` is a heavier dependency (with its own churn — the workspace
tracked it across `0.3 → 0.4 → 0.5`, commits `53873c0`, `2d2c38e`, `c4e0e44`).
A third party who wants only the bare NTFS reader over a `Read + Seek` source
should not be forced to pull it in.

## Decision

Implement `impl FileSystem for NtfsFs` in `core/src/vfs.rs` (commit `dd7aed6`),
gated behind an **optional** Cargo feature:

```toml
[dependencies]
forensic-vfs = { version = "0.7", optional = true }

[features]
vfs = ["dep:forensic-vfs"]
```

The default build stays dependency-light (a bare reader); turning on `vfs`
activates the adapter so an NTFS volume composes as `Arc<dyn FileSystem>`
alongside the other fleet filesystems. Supporting the trait drove reader changes
that are valuable independently — interior mutability so all reads go through
`&self` (commit `5294ba6`), `FileId`-addressed reads (`09c1d54`),
`volume_label()` from `$VOLUME_NAME` (`47d35bd`), and `deleted_nodes()` MFT
recovery (`dcdc85a`).

## Consequences

- Third-party consumers get a minimal `ntfs-core`; fleet orchestration enables
  `vfs` to slot NTFS into the universal stack. This is the sanctioned exception
  to "batteries-included": a lean library `default` for outside reuse, with the
  heavier integration opt-in (and fleet binaries turn it on).
- `forensic-vfs` version bumps are absorbed here behind the feature without
  disturbing default-build consumers.
- `NtfsFs`'s shared-`&self` read model (needed for `Arc<dyn FileSystem>` across
  workers) is a permanent API property, not a `vfs`-only concession.
