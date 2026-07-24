# ntfs-forensic — Purpose & Scope

**Purpose.** Give the SecurityRonin fleet one self-owned, auditable NTFS engine
that surfaces the deleted, slack, and anti-forensic detail a general-purpose
filesystem driver hides — so downstream tools (issen, disk4n6, usnjrnl-forensic)
can drop their ad-hoc NTFS handling and third-party NTFS crates.

**In scope.**

- **`ntfs-core` (reader):** boot sector / BPB, `$MFT` records + update-sequence
  fixup, resident and non-resident attributes, `$ATTRIBUTE_LIST` for fragmented
  files, data runs (VCN→LCN, sparse), LZNT1 (`$DATA`) via the `lznt1` crate,
  directory indexes (`$INDEX_ROOT` / INDX), named/alternate data streams,
  `$MFTMirr` and `$LogFile` (RCRD decode → LFS redo/undo → transaction
  reconstruction), the `$UsnJrnl:$J` change-journal reader (streaming + slack
  carving), ReFS USN V3, and the *Rewind* full-path reconstruction engine.
  Navigation over any `Read + Seek` source via `NtfsFs`, with a bounded
  partition window (`OffsetReader`) and an optional `forensic-vfs` `FileSystem`
  adapter (feature `vfs`).
- **`ntfs-forensic` (analyzer):** timestomping (`$SI` vs `$FN`), alternate data
  streams, deleted-record carving, MFT-record slack, `$MFTMirr`/`$LogFile`
  tamper checks, and a USN rule engine + correlation + triage — all emitted as
  severity-graded `forensicnomicon::report::Finding`s.

**Out of scope (non-goals).**

- **No end-user binary.** This is a library pair; the CLIs and UX are
  `usnjrnl-forensic`, `disk4n6`, and `issen`. There is no `ntfs4n6`.
- **No container or partition decoding.** Locating the NTFS volume inside an
  image (EWF/VMDK/VHDX → MBR/GPT → offset+length) is the job of the upstream
  crates in *Where this fits*; this workspace starts from a `Read + Seek`.
- **No write path.** The reader is read-only; carving/reconstruction derive new
  artifacts, never mutate the source.
- **No re-derivation of format constants** (they come from `forensicnomicon`)
  and **no third-party NTFS parsing crate** in the shipped graph (`mft` is a
  dev-only validation oracle; the `ntfs` crate is not a dependency at all).

**Artifact family.** NTFS (and ReFS USN V3): `$MFT`, `$LogFile`, `$UsnJrnl:$J`,
`$MFTMirr`, `$INDEX_ROOT`/INDX, alternate data streams, LZNT1-compressed
`$DATA`.

**Validation.** Correctness is earned against independent oracles on real
images, never self-graded fixtures — The Sleuth Kit (`fsstat`/`icat`), the `mft`
crate, and LogFileParser, on the DEF CON 2018 and DFIR Madness "Stolen Szechuan
Sauce" corpora. Full evidence, tiers, and reproduction steps live in
[docs/validation.md](docs/validation.md). The design rationale behind these
choices is recorded as ADRs in [docs/decisions/](docs/decisions/).
