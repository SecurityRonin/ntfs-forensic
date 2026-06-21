# Validation

`ntfs-forensic` parses untrusted NTFS structures from potentially compromised
disk images. Correctness is therefore established the way forensic tooling must
be: against **independent oracles** (a different tool, or a different code path,
that already decodes the same bytes correctly) on **real third-party corpora**
with known ground truth — never against fixtures we hand-encoded and then graded
ourselves.

This page records exactly which oracle and which corpus back each capability, so
the claim is independently re-checkable. Per-file provenance (source, download
URL, hashes, license) lives in [`tests/data/README.md`](https://github.com/SecurityRonin/ntfs-forensic/blob/main/tests/data/README.md);
the fleet-wide machine index is `issen/docs/corpus-catalog.md`. This page
cross-references both rather than duplicating them.

## How to read the evidence tiers

Each validation below is tagged with the trustworthiness of its check, not
whether the data is "synthetic":

- **Tier 1** — an independent third party authored the artifact *and* the answer
  key, or it is real-world data decoded by an independent tool. The strongest claim.
- **Tier 2** — real engine output whose ground truth is derivable from the
  documented construction, or confirmed by an *independent code path* on real
  data. Genuinely checked, but we chose the scenario.
- **Tier 3** — fixture and expected answer both authored here, nothing
  independent vouching. Used only for per-branch coverage, never as a
  correctness claim. (The "LZNT1 trap": a self-encoded round trip passes while
  both encoder and decoder are wrong — see below for why this crate avoids it.)

## Independent oracles

| Oracle | Independent of us? | Validates | Tier |
|---|---|---|---|
| **The Sleuth Kit** (`fsstat`) | Yes — separate C codebase | Boot-sector geometry (sector/cluster size, MFT/MFTMirr LCN, serial) | 1 |
| **The Sleuth Kit** (`icat`, `blkcat`, `istat`) | Yes | LZNT1 plaintext + the raw on-disk compressed stream; `$MFT` / `$LogFile` extraction | 1 |
| **`mft` crate** (omerbenamram) | Yes — independent Rust MFT parser | `$MFT` record in-use / is-directory flags and `$FILE_NAME` set, per record | 1 |
| **LogFileParser** (jschicht, MIT, via Wine) | Yes — separate AutoIt tool | `$LogFile` transaction decode (designated oracle for the in-progress redo/undo work) | 1 |
| **In-test RCRD census** | Independent *code path* (flat page-aligned signature scan, no fixup) | `read_record_pages` recovered exactly the RCRD pages present, each USA-valid | 2 |
| **`lznt1` crate** | Yes — vetted third-party codec we reuse | The LZNT1 decode itself (we did not hand-roll the codec) | 1 |

Two independent *extractors* are also cross-checked against each other: TSK
`icat -o <lba> <image> 2` and `ntfs-forensic`'s own `$LogFile` extraction produce
a **byte-identical** stream (same MD5), so neither extractor's assumptions are
load-bearing alone.

## Independent test corpora

All three are third-party, publicly distributed, and carry independently
established ground truth. Large images are gitignored and fetched manually; the
small MIT volume is committed. Hashes and full provenance are in
[`tests/data/README.md`](https://github.com/SecurityRonin/ntfs-forensic/blob/main/tests/data/README.md).

| Corpus | Source | Used for | License / redistribution |
|---|---|---|---|
| **DEF CON DFIR CTF 2018 — `MaxPowers`** (`MaxPowersCDrive.E01`) | Public CTF image | Boot sector ground truth (vs TSK `fsstat`) | CTF public distribution; first 4 KiB committed |
| **DFIR Madness "Stolen Szechuan Sauce" Case 001 — CITADEL-DC01** (`20200918_0347_CDrive.E01`) | dfirmadness.com (James Smith) | Real LZNT1 stream + plaintext (vs TSK); real `$LogFile` RCRD page + full stream | Educational/research use |
| **SampleTinyNtfsVolume** (`$MFT`/`$LogFile`/`$MFTMirr`) | jschicht/LogFileParser release | Small `$LogFile` / NTFS validation sample for the decoder + oracle harness | **MIT** (committed with attribution) |

## Per-capability validation

### Boot sector — Tier 1

`core/tests/real_image.rs` parses the real NTFS boot sector carved from the DEF
CON 2018 `MaxPowers` image and asserts every field against the values **TSK
`fsstat` derived independently**: 512-byte sectors, 4096-byte clusters, 1024-byte
MFT entries, MFT at LCN 786 432, MFTMirr at LCN 2, serial `326C195B6C191B65`.

### LZNT1 decompression — Tier 1 (the LZNT1 trap, avoided)

`core/tests/lznt1_real.rs` validates the LZNT1 codec against a **real on-disk
compressed `$DATA` stream** (CITADEL-DC01 inode 437) whose plaintext is produced
**by TSK `icat`**, not by us. A self-encoded round trip would pass even with an
inverted bit-split (both sides wrong); decoding a real Windows-written stream and
matching TSK's plaintext byte-for-byte is what actually proves correctness. The
codec is also a vetted third-party crate (`lznt1`), not a hand-rolled decoder.

### `$MFT` record parsing — Tier 1

`core/tests/parity_mft.rs` (env-gated, `NTFS_FORENSIC_MFT`) cross-validates record
parsing against the **`mft` crate** on a real `$MFT`. Records are aligned by
record number; the in-use flag, is-directory flag, and `$FILE_NAME` set are
compared. The gate fails on any flag disagreement, and validates that the
oracle's chosen file name is *among* the names `ntfs-forensic` parsed (a record
may carry Win32 / 8.3 / POSIX / hard-link names).

### `$LogFile` RCRD record pages — Tier 1 input + Tier 2 completeness

`core/tests/logfile_rcrd.rs` validates `read_record_pages` (the RCRD reader +
multi-sector USA fixup) against a **real RCRD page** carved from the CITADEL-DC01
`$LogFile`, extracted with **TSK `icat` as the independent input oracle**
(byte-identical to our own extraction). The env-gated full-stream test
(`NTFS_FORENSIC_LOGFILE`) is a **differential**: it counts raw `RCRD` signatures
via a flat scan independent of the reader and requires the reader to recover
*exactly* that many — on the clean DC01 reference stream that is **4470 of 4470**
pages, each with a valid USA. A torn-sector page is rejected, never returned with
un-fixed bytes. The expected count is derived structurally from the data, not a
hardcoded magic number.

The transaction-level redo/undo decode that consumes these pages uses
**LogFileParser** (via Wine) as its row-level differential oracle; that work is in
progress and is not yet claimed as validated here.

### Robustness — never panic, never over-read

Every parser is fuzzed (seven `cargo-fuzz` targets: `boot`, `record`,
`attributes`, `attribute_list`, `runlist`, `index_buffer`, `compress`; a
`fuzz.yml` CI workflow builds and smoke-runs each), with the invariant "must not
panic." Production code is `#![forbid(unsafe_code)]` and denies
`clippy::unwrap_used` / `clippy::expect_used`; every length and offset is
bounds-checked against both the declared structure size and the actual buffer.

## Reproducing the validation

The committed, always-on tests run with `cargo test`. The env-gated real-corpus
tests need the large images (fetch per `tests/data/README.md`):

```bash
# Boot + LZNT1 (committed fixtures, always run)
cargo test -p ntfs-core --test real_image --test lznt1_real

# $MFT parity vs the mft crate (extract a raw $MFT first, e.g. via TSK icat)
NTFS_FORENSIC_MFT=mft.raw \
  cargo test -p ntfs-core --test parity_mft -- --ignored --nocapture

# Full $LogFile RCRD differential (extract $LogFile = inode 2 via TSK icat)
icat -o <ntfs_partition_lba> disk.E01 2 > DC01_LogFile.bin
NTFS_FORENSIC_LOGFILE=DC01_LogFile.bin \
  cargo test -p ntfs-core --test logfile_rcrd -- --ignored

# Full NTFS volume walk
NTFS_FORENSIC_TEST_IMAGE=/path/to/ntfs.raw \
  cargo test -p ntfs-core --test real_image -- --ignored
```

## Coverage & fuzzing as backstops

100% line coverage is enforced in CI (`cargo llvm-cov --lib`, failing on any
zero-hit line not annotated `// cov:unreachable`). Coverage is a regression
backstop that proves behavior is exercised — it is not the correctness claim. The
oracles above are.
