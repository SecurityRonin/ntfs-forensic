# Migration plan — consolidating NTFS onto `ntfs-forensic`

`ntfs-forensic` is the FILESYSTEM-layer foundation for the SecurityRonin forensic
family (sibling of `ext4fs`, `apfsfs`). It is built so two downstream consumers
can drop their ad-hoc NTFS handling and depend on one self-owned, auditable,
forensic-grade engine:

1. **issen** — VMDK/EWF → partition (`mbr-forensic`/`gpt-forensic`) → NTFS → extract
   arbitrary files by path (`*.evtx`, registry hives, `$MFT`, `$UsnJrnl`).
2. **usnjrnl-forensic** — replace its in-house NTFS modules **and** its two
   third-party NTFS crates with this one.

This document records the `usnjrnl-forensic` migration intent so the gating
conditions and the one design seam don't get lost between TDD increments.

## The parity gate (when, not date)

The swap happens only once `ntfs-forensic` is **mature**, defined as:

- Feature parity with what `usnjrnl-forensic` relies on: allocated MFT record
  parsing, runlist/`$DATA` extraction, path/record extraction, deleted-record
  carving, and `$LogFile` / `$UsnJrnl` extraction.
- **Bit-identical cross-validation** on the real CTF images (DEFCON 2018,
  Magnet 2023, Szechuan Sauce) against The Sleuth Kit (`fls`/`istat`/`icat`) and
  the `ntfs` / `mft` crates.
- `usnjrnl-forensic`'s existing `tests/image_integration.rs` expectations remain
  unchanged across the swap (they become the regression guard).

## What `ntfs-forensic` replaces in `usnjrnl-forensic`

Reflects the `usnjrnl-forensic` layout as of this plan:

| Current module | Today | After migration |
|---|---|---|
| `image/` | own MBR/GPT parse + Colin Finck `ntfs` crate | `ntfs-forensic` container glue + path/record extraction |
| `mft/mod.rs` | omerbenamram `mft` crate | `ntfs-forensic` MFT reader |
| `mft/carver.rs` | from-scratch deleted-record carver | `ntfs-forensic` forensic Tier-2 |
| `mftmirr/`, `logfile/mod.rs` | own | `ntfs-forensic` |

Net effect: drops the `ntfs` **and** `mft` third-party dependencies.

## What stays in `usnjrnl-forensic`

The USN-journal *application* layer: `usn/` (V2/V3/V4 parsing), `rewind/`,
`analysis/`, `correlation/` (TriForce), `monitor/`, `triage/`, `output/`.

## The one design seam to preserve

`mft::seed_rewind()` is the single tight coupling: the rewind engine consumes
parsed **and carved (deleted)** MFT entries, including their parent references.
`ntfs-forensic`'s MFT API must expose exactly that — carved entries + parent
refs — so the rewind engine can sit on top unchanged. Keep this in mind for
increments 4 (`$FILE_NAME` parent ref) and 9 (deleted-record carving).

## Migration discipline

- Do it as its own RED → GREEN change in `usnjrnl-forensic`, with the existing
  image-integration tests as the failing-then-passing regression guard.
- Optionally keep the old `ntfs`/`mft`-crate path behind a feature flag during
  the transition, removing it once parity is proven on all three images.
- The migration both *consumes* and *validates* `ntfs-forensic`: usnjrnl's
  battle-tested expectations are a second oracle for this crate.
