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
  correctness claim: a self-consistent round trip proves internal consistency,
  not correctness against real-world bytes.

## Independent oracles

| Oracle | Independent of us? | Validates | Tier |
|---|---|---|---|
| **The Sleuth Kit** (`fsstat`) | Yes — separate C codebase | Boot-sector geometry (sector/cluster size, MFT/MFTMirr LCN, serial) | 1 |
| **The Sleuth Kit** (`icat`, `blkcat`, `istat`) | Yes | LZNT1 plaintext + the raw on-disk compressed stream; `$MFT` / `$LogFile` extraction | 1 |
| **`mft` crate** (omerbenamram) | Yes — independent Rust MFT parser | `$MFT` record in-use / is-directory flags and `$FILE_NAME` set, per record | 1 |
| **LogFileParser** (jschicht, MIT, via Wine) | Yes — separate AutoIt tool | The redo/undo **operation-code mapping** (`LogOp`, transcribed verbatim from its `_SolveUndoRedoCodes`); and the full **per-record decode** — its Wine harness emits a `LogFile.csv` (78,765 rows on the DC01 `$LogFile`) reconciled record-for-record against `parse_log_records` | 1 |
| **In-test RCRD census** | Independent *code path* (flat page-aligned signature scan, no fixup) | `read_record_pages` recovered exactly the RCRD pages present, each USA-valid | 2 |
| **`lznt1` crate** | Yes — vetted third-party codec we reuse | The LZNT1 decode itself (a maintained, audited codec) | 1 |

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

### LZNT1 decompression — Tier 1

`core/tests/lznt1_real.rs` validates the LZNT1 codec against a **real on-disk
compressed `$DATA` stream** (CITADEL-DC01 inode 437) whose plaintext is produced
independently **by TSK `icat`**. Decoding a stream that real Windows wrote and
matching TSK's plaintext byte-for-byte establishes correctness against real-world
bytes. The codec itself is the vetted third-party `lznt1` crate.

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

### `$LogFile` redo/undo operation codes (`LogOp`) — Tier 1

`LogOp::from_u16` maps each NTFS Log File Service redo/undo operation code
(`0x00`–`0x22`) to its operation, surfacing anything outside that range verbatim
as `Unknown(u16)`. The mapping is **transcribed verbatim from LogFileParser's own
`_SolveUndoRedoCodes` function** — the exact lookup its GUI runs to label the
RedoOP/UndoOP columns — so the numeric mapping is identical to that tool's by
construction (canonical spelling; the shared invariant is the numeric code, not
the label). The lib test `logop_from_u16_matches_logfileparser_table` asserts the
full table against that reference. This validates the *operation vocabulary*, not
the record parser that extracts the codes (below).

### `$LogFile` redo/undo record decode — Tier 1

`parse_log_records` walks the LFS records in each RCRD page and decodes each
record's LSN, redo/undo `LogOp`, record type, and transaction id. Correctness is
established by a **full-stream row-level differential against LogFileParser's
`LogFile.csv`** — the Wine harness (below) decoded the real CITADEL-DC01
`$LogFile` into 78,765 transaction rows, and `full_logfile_records_match_logfileparser`
(env-gated on `NTFS_FORENSIC_LOGFILE` + `NTFS_FORENSIC_LOGFILE_CSV`) reconciles
every record we decode against them.

**Join on LSN, not byte offset.** Each LFS record's LSN is globally unique in the
log, so it is the record's true identity. LogFileParser reports a *shifted*
`lf_Offset` for records in any page that also carries a **table-dump
pseudo-record** (`OpenAttributeTableDump` / `DirtyPageTableDump` / …): the dump's
row takes the real record's offset and the real record is listed ~0x40 later, at a
byte that holds no record header. Our offsets are the physically-correct ones
(verified against the raw bytes), so joining on LSN isolates genuine decode
disagreements from LogFileParser's offset bookkeeping.

Result on the real stream:

| Bucket | Count | Meaning |
|---|---|---|
| **exact** | 74,754 | byte offset **and** all five fields (LSN, redo, undo, type, txid) match LogFileParser |
| **reported_diff** | 633 | same record by LSN + operation + type; only LogFileParser's offset/tx reporting differs (the table-dump-page bookkeeping above) |
| **op_disagree** | **0** | operation-code or record-type disagreements — none |
| **stale** | 12 | prior-generation residue we recover and LogFileParser filters (see below) |
| **unexplained** | **0** | records inside LogFileParser's LSN window that it does not also carry — none |

The load-bearing assertions are `op_disagree == 0` and `unexplained == 0`: every
record we decode within LogFileParser's window is corroborated by it and agrees on
operation and record type.

**Stale prior-generation residue (a recovery feature, not an error).** The
`$LogFile` is a circular buffer. When the log wraps, a physical RCRD page is
rewritten in place, but a torn/partial rewrite can leave a run of *older*-generation
records in the page's record area. On DC01, page `0x0fb5000` declares an LSN range
near 161,442,724 yet physically retains twelve records with LSNs ~160,484,800 —
**below LogFileParser's oldest tracked LSN (161,226,776)**, i.e. from a generation
that predates its valid restart window. LogFileParser follows the restart/LSN chain
and filters them; `parse_log_records` walks the page bytes and **recovers** them.
The differential classifies any such record (LSN below the oracle's minimum) as
`stale` rather than a disagreement — surfacing recoverable overwritten log records
is a forensic capability, and the test proves these are genuinely pre-window
(not random garbage and not a misparse, since their operation/type still decode
cleanly).

### `$LogFile` file-operation semantics (`FileOperation`) — Tier 2

`classify_log_operation` maps each decoded LFS record's `(redo, undo)`
[`LogOp`] pair to a higher-level [`FileOperation`] — file create, delete,
rename, data-write, attribute create/delete, resize, index insert/delete,
transaction control, table-dump, no-op — surfacing any unmapped pair verbatim as
`Unknown(redo_code, undo_code)`.

**Tier 2 (semantic), not Tier 1.** The mapping is the *general* per-opcode rule
the authoritative LFS references document, transcribed from three independent
primary sources (cited per-pattern in the unit tests and the module docs):

- **msuhanov, [`dfir_ntfs/LogFile.py`](https://github.com/msuhanov/dfir_ntfs/blob/master/dfir_ntfs/LogFile.py)**
  — the maintained NTFS journal parser; its `LOGGED_RESIDENT_UPDATES` /
  `LOGGED_NONRESIDENT_UPDATES` lists and `NTFSOperations` table classify each
  opcode by what it mutates.
- **jschicht, [`LogFileParser`](https://github.com/jschicht/LogFileParser/blob/master/LogFileParser.au3)**
  — `_SanityTest1` enumerates the *valid* `(redo, undo)` pairings
  (`CreateAttribute`↔`DeleteAttribute`,
  `AddIndexEntryAllocation`↔`DeleteIndexEntryAllocation`,
  `UpdateFileNameAllocation`↔self, `SetBits`↔`ClearBits`, …) — the authority for
  how the redo and undo opcodes compose.
- **Brian Carrier, *File System Forensic Analysis* (2005), ch. 13** — the primary
  forensic reference for `InitializeFileRecordSegment` ⇒ creation and
  `DeallocateFileRecordSegment` ⇒ deletion.

It is **Tier 2, not Tier 1**, because there is **no independent *semantic*
oracle** that labels each transaction's file operation to differential against:
`LogFileParser`'s `LogFile.csv` decodes the redo/undo *records* (validated Tier 1
above) but emits no per-transaction file-operation label, and `NTFS-Log-Tracker`
was not available to run on this host. The ground truth is therefore *derivable
from the documented opcode semantics* — genuinely checked against three primary
sources and exercised end-to-end on a real corpus, but the scenario is one we
constructed, so it can miss real-world quirks. The *record decode* feeding the
classifier is independently Tier 1 (the `LogFileParser` row differential).

**Real-corpus characterization (DC01).**
`core/tests/logfile_rcrd.rs::semantic_classification_is_complete_and_sane`
(env-gated on `NTFS_FORENSIC_LOGFILE`) runs the classifier over the whole real
CITADEL-DC01 `$LogFile` and asserts two properties:

1. **Completeness** — no record whose redo *and* undo opcodes are both documented
   (`0x00`–`0x22`, never `LogOp::Unknown`) falls through to
   `FileOperation::Unknown`. A both-known record in `Unknown` would be a hole in
   the general mapping. On DC01 the count is **0**.
2. **Sanity** — a live domain controller's log exercises every major
   file-operation class.

Observed distribution over the **75,399** decoded records (4,470 pages):

| FileOperation | Count | FileOperation | Count |
|---|---|---|---|
| Resize | 20,904 | DataWrite | 18,445 |
| TransactionControl | 16,495 | Rename | 7,373 |
| BitmapAllocation | 3,881 | TableDump | 1,811 |
| IndexInsert | 1,427 | AttributeCreate | 1,254 |
| IndexDelete | 1,159 | Delete | 1,075 |
| AttributeDelete | 852 | Create | 517 |
| Noop | 206 | **Unknown** | **0** |

The load-bearing result is **Unknown = 0**: every redo/undo opcode the real DC01
stream carries is a documented operation that the classifier maps — the mapping
is complete over this corpus.

### `$LogFile` transaction reconstruction — Tier 1 differential (per-txid LSN membership)

`reconstruct_transactions` groups the decoded LFS records into transactions — the
unit a forensic analyst reasons about (one user/OS action = one transaction of
redo/undo records). NTFS keys this grouping on the **`transaction_id`** field
(LFS record header offset `0x24`), which the Microsoft `LFS_RECORD` layout and
the flatcap `linux-ntfs` `$LogFile` docs describe as the field that "groups
related records into a single transaction". Records of concurrent transactions
are *interleaved* in LSN order, so contiguity does not bound a transaction; the
`transaction_id` does (TZWorks `mala` users guide: "each record has a pointer to
the previous record in the chain for its transaction … consecutive records can be
interleaved between multiple transactions"). The `client_previous_lsn` /
`client_undo_next_lsn` back-pointers are the redo/undo *replay* chain, not the
grouping key. Each transaction's state is read from the bounding control opcodes:
`CommitTransaction` (0x1A) / `ForgetTransaction` (0x1B) ⇒ **Committed** (a commit
overrides a compensation), `CompensationLogRecord` (0x01) alone ⇒ **Aborted**,
neither ⇒ **Incomplete**. Sources: Microsoft `LFS_RECORD` / flatcap
[`$LogFile` docs](https://flatcap.github.io/linux-ntfs/ntfs/files/logfile.html);
TZWorks [`mala` users guide](https://tzworks.com/prototypes/mala/mala.users.guide.pdf);
msuhanov [`dfir_ntfs/LogFile.py`](https://github.com/msuhanov/dfir_ntfs/blob/master/dfir_ntfs/LogFile.py);
Brian Carrier, *File System Forensic Analysis* (2005), ch. 13.

**Why Tier 1.** `LogFileParser`'s `LogFile.csv` carries an `lf_transaction_id`
column — an *independent tool's* transaction assignment for the same real stream.
`core/tests/logfile_rcrd.rs::transaction_membership_matches_logfileparser`
(env-gated on `NTFS_FORENSIC_LOGFILE` + `NTFS_FORENSIC_LOGFILE_CSV`) groups the
oracle rows by `lf_transaction_id`, groups our records by `reconstruct_transactions`,
and reconciles the two **per transaction id by the SET of record LSNs** assigned
to it. The comparison joins on LSN (each LSN is the record's globally-unique
identity), so it is immune to the table-dump `lf_Offset` shift documented in the
record differential above — only *which LSNs go in which transaction* is compared,
never byte offsets.

The reconciliation isolates the circular-buffer artifacts from genuine
disagreement, exactly as the record differential does:

- **stale** — records whose LSN is below the oracle's oldest tracked LSN are
  prior-generation residue `LogFileParser` filters and we carve; they are excluded
  from the per-txid set comparison (a recovery capability, not an error — see the
  "Stale prior-generation residue" note above).
- **`oracle_extra`** — an LSN the oracle never lists anywhere is recovery, not a
  grouping error; an LSN the oracle lists under a *different* txid is a genuine
  membership divergence and is the only thing counted against agreement.

The load-bearing assertions are that the grouping **drops no record on the real
stream** (every decoded record lands in exactly one transaction) and that the
in-window per-txid LSN membership agrees with `LogFileParser` for the overwhelming
majority (`> 0.98`). Any residual divergence — transactions whose boundary fell in
an overwritten region of the wrap, or records the two tools window differently — is
printed (`exact` / `divergent` / `absent_txid` / `stale_records` /
`oracle_unseen_extra` counts plus a sample) and characterized, never silently
tolerated. The record decode and LSN identity this reconciliation rests on are
themselves Tier 1 (the `LogFileParser` row differential above).

> Run the differential after extracting the real DC01 `$LogFile` and producing
> `LogFile.csv` per the LogFileParser/Wine recipe under "Reproducing the
> validation":
>
> ```bash
> NTFS_FORENSIC_LOGFILE=DC01_LogFile.bin \
> NTFS_FORENSIC_LOGFILE_CSV=LogFile.csv \
>   cargo test -p ntfs-core --test logfile_rcrd transaction_membership -- --ignored --nocapture
> ```

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

The `$LogFile` transaction oracle is LogFileParser (jschicht) run under Wine — it
emits a per-record `LogFile.csv` that the record parser is reconciled against:

```bash
# Produces LogFile.csv with lf_Offset / lf_LSN / lf_RedoOperation / lf_UndoOperation
# / lf_record_type / lf_transaction_id — the row-level differential ground truth.
WINEPREFIX=~/.wine wine LogFileParser64.exe \
  /LogFileFile:Z:/path/to/DC01_LogFile.bin /OutputPath:Z:/tmp/lfp_out \
  /SkipSqlite3:1 /SectorsPerCluster:8 /MftRecordSize:1024
```

> Gotcha: do not let the host sleep mid-run — the AutoIt GUI's event loop stalls
> and the parse never completes.

## Coverage & fuzzing as backstops

100% line coverage is enforced in CI (`cargo llvm-cov --lib`, failing on any
zero-hit line not annotated `// cov:unreachable`). Coverage is a regression
backstop that proves behavior is exercised — it is not the correctness claim. The
oracles above are.
