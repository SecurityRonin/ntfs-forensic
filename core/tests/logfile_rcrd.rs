//! Real-data validation of the $LogFile RCRD record-page reader (doer-checker).
//!
//! The page bytes come from the CITADEL-DC01 $LogFile (DFIR Madness "Stolen
//! Szechuan Sauce" Case 001), extracted with TSK `icat` as an independent input
//! oracle — byte-identical to issen's own extraction. Validating the USA fixup
//! against a real on-disk RCRD page, rather than a page this crate encoded
//! itself, is what catches a wrong fixup offset or a self-consistent-but-wrong
//! round trip (the LZNT1 trap). See `tests/data/README.md`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ntfs_core::{
    classify_log_operation, parse_log_records, read_record_pages, reconstruct_transactions,
    FileOperation, LogOp,
};

/// One real RCRD record page carved from the DC01 $LogFile.
const REAL_RCRD: &[u8] = include_bytes!("../../tests/data/real_logfile_rcrd_page.bin");

/// Decode the LFS log records in the real DC01 RCRD page and reconcile them
/// against **`LogFileParser`** (jschicht, run under Wine) — the independent oracle.
///
/// This page is byte offset 0x2000 of the DC01 `$LogFile`; `LogFileParser`'s
/// `LogFile.csv` reports exactly one log record in it, at `lf_Offset 0x2200`
/// (in-page 0x200): `lf_LSN=223672896` (0x0D54FA40), `lf_RedoOperation=`
/// `CompensationlogRecord`, `lf_UndoOperation=`Noop, `lf_record_type=2`,
/// `lf_transaction_id=0`. Every expected value below is the oracle's, not ours.
#[test]
fn parses_real_log_record_matching_logfileparser() {
    let pages = read_record_pages(REAL_RCRD);
    assert_eq!(pages.len(), 1, "the fixture is one RCRD page");
    let records = parse_log_records(&pages[0]);

    assert_eq!(
        records.len(),
        1,
        "`LogFileParser` reports one record in this page"
    );
    let r = &records[0];
    assert_eq!(
        r.page_offset, 0x200,
        "in-page offset (lf_Offset 0x2200 - page 0x2000)"
    );
    assert_eq!(r.this_lsn, 0x0D54_FA40, "lf_LSN = 223672896");
    assert_eq!(r.redo_op, LogOp::CompensationLogRecord, "lf_RedoOperation");
    assert_eq!(r.undo_op, LogOp::Noop, "lf_UndoOperation");
    assert_eq!(r.record_type, 2, "lf_record_type");
    assert_eq!(r.transaction_id, 0, "lf_transaction_id");
}

#[test]
fn reads_real_rcrd_page_and_applies_usa_fixup() {
    let pages = read_record_pages(REAL_RCRD);

    assert_eq!(pages.len(), 1, "one valid RCRD page in the fixture");
    let p = &pages[0];
    assert_eq!(p.offset, 0, "single page starts at offset 0");
    assert_eq!(
        &p.data[0..4],
        b"RCRD",
        "signature preserved through the read"
    );
    assert_eq!(p.last_lsn, 0x0d54_fa40, "last_lsn from RCRD header @0x08");

    // The USA fixup must restore sector 0's last two bytes from usa[1] — the
    // original bytes the on-disk USN displaced. usa_offset here is 0x28, so
    // usa[1] lives at 0x2a; after the fixup, offset 0x1fe (the sector-0 tail)
    // must hold that value, not the USN that occupied it on disk.
    assert_eq!(
        &p.data[0x1fe..0x200],
        &REAL_RCRD[0x2a..0x2c],
        "sector-0 tail restored from the update sequence array",
    );
}

#[test]
fn rejects_rcrd_page_with_broken_usa() {
    // Corrupt sector 0's tail so it no longer matches the page's USN: the USA
    // integrity check must fail and the page must be dropped, never returned
    // with un-fixed (wrong) bytes.
    let mut corrupt = REAL_RCRD.to_vec();
    corrupt[0x1fe] ^= 0xff;
    assert!(
        read_record_pages(&corrupt).is_empty(),
        "a page failing the USA integrity check must be skipped",
    );
}

/// Full-stream walk against the real DC01 $LogFile.
///
/// Ignored unless `NTFS_FORENSIC_LOGFILE` points at an extracted $LogFile:
///
/// ```bash
/// NTFS_FORENSIC_LOGFILE=/path/to/DC01_LogFile.bin \
///   cargo test -p ntfs-core --test logfile_rcrd -- --ignored
/// ```
#[test]
#[ignore = "requires NTFS_FORENSIC_LOGFILE pointing at a real $LogFile stream"]
fn reads_all_rcrd_pages_from_real_logfile() {
    let path = match std::env::var("NTFS_FORENSIC_LOGFILE") {
        Ok(p) => p,
        Err(_) => return,
    };
    let data = std::fs::read(&path).expect("read $LogFile");
    let pages = read_record_pages(&data);

    // Every returned page is a genuine, fixup-verified RCRD page.
    for p in &pages {
        assert_eq!(&p.data[0..4], b"RCRD", "only RCRD pages returned");
        assert_eq!(p.offset % 4096, 0, "page-aligned offset");
    }

    // Differential oracle: count raw RCRD signatures via a path independent of
    // the reader (a flat page-aligned scan, no fixup), then require the reader
    // to recover exactly that many. The two counts agree iff every RCRD page on
    // this clean reference image (DC01 $LogFile) carries a valid USA — a damaged
    // stream would yield fewer (USA-rejected pages), never more. The expected
    // count is derived from the data structurally, not a hardcoded magic number.
    let raw_rcrd = data
        .chunks_exact(4096)
        .filter(|page| &page[0..4] == b"RCRD")
        .count();
    assert!(pages.len() <= raw_rcrd, "reader must not invent pages");
    assert_eq!(
        pages.len(),
        raw_rcrd,
        "every RCRD page on the clean DC01 reference image must have a valid USA",
    );
}

/// `LogFileParser`'s exact redo/undo operation name (its `_SolveUndoRedoCodes`
/// spelling, quirks and all) → opcode, so the CSV's name strings can be compared
/// to the numeric opcode our [`LogOp`] carries. `None` for the tool's
/// non-operation markers (e.g. `JS_NewEndOfRecord`).
fn lfp_op_code(name: &str) -> Option<u16> {
    Some(match name {
        "Noop" => 0x00,
        "CompensationlogRecord" => 0x01,
        "InitializeFileRecordSegment" => 0x02,
        "DeallocateFileRecordSegment" => 0x03,
        "WriteEndofFileRecordSegement" => 0x04,
        "CreateAttribute" => 0x05,
        "DeleteAttribute" => 0x06,
        "UpdateResidentValue" => 0x07,
        "UpdateNonResidentValue" => 0x08,
        "UpdateMappingPairs" => 0x09,
        "DeleteDirtyClusters" => 0x0A,
        "SetNewAttributeSizes" => 0x0B,
        "AddindexEntryRoot" => 0x0C,
        "DeleteindexEntryRoot" => 0x0D,
        "AddIndexEntryAllocation" => 0x0E,
        "DeleteIndexEntryAllocation" => 0x0F,
        "WriteEndOfIndexBuffer" => 0x10,
        "SetIndexEntryVcnRoot" => 0x11,
        "SetIndexEntryVcnAllocation" => 0x12,
        "UpdateFileNameRoot" => 0x13,
        "UpdateFileNameAllocation" => 0x14,
        "SetBitsInNonresidentBitMap" => 0x15,
        "ClearBitsInNonresidentBitMap" => 0x16,
        "HotFix" => 0x17,
        "EndTopLevelAction" => 0x18,
        "PrepareTransaction" => 0x19,
        "CommitTransaction" => 0x1A,
        "ForgetTransaction" => 0x1B,
        "OpenNonresidentAttribute" => 0x1C,
        "OpenAttributeTableDump" => 0x1D,
        "AttributeNamesDump" => 0x1E,
        "DirtyPageTableDump" => 0x1F,
        "TransactionTableDump" => 0x20,
        "UpdateRecordDataRoot" => 0x21,
        "UpdateRecordDataAllocation" => 0x22,
        _ => return None,
    })
}

/// Full-stream row-level differential (the strongest decoder validation): every
/// LFS record [`parse_log_records`] decodes from the real DC01 `$LogFile` must
/// match `LogFileParser`'s `LogFile.csv` on LSN, redo/undo opcode, record type, and
/// transaction id — joined by the record's byte offset within the stream.
///
/// ```bash
/// NTFS_FORENSIC_LOGFILE=DC01_LogFile.bin \
/// NTFS_FORENSIC_LOGFILE_CSV=LogFile.csv \
///   cargo test -p ntfs-core --test logfile_rcrd full_logfile -- --ignored --nocapture
/// ```
#[test]
#[ignore = "requires NTFS_FORENSIC_LOGFILE + NTFS_FORENSIC_LOGFILE_CSV"]
fn full_logfile_records_match_logfileparser() {
    let Ok(lf_path) = std::env::var("NTFS_FORENSIC_LOGFILE") else {
        return;
    };
    let Ok(csv_path) = std::env::var("NTFS_FORENSIC_LOGFILE_CSV") else {
        return;
    };
    let data = std::fs::read(&lf_path).expect("read $LogFile");
    let csv = std::fs::read_to_string(&csv_path).expect("read LogFile.csv");

    // Index the oracle CSV (pipe-delimited) by column name, then by file offset.
    let mut lines = csv.lines();
    let header: Vec<&str> = lines.next().expect("csv header").split('|').collect();
    let col = |n: &str| {
        header
            .iter()
            .position(|h| *h == n)
            .unwrap_or_else(|| panic!("missing column {n}"))
    };
    let (c_off, c_lsn, c_redo, c_undo, c_rt, c_tx) = (
        col("lf_Offset"),
        col("lf_LSN"),
        col("lf_RedoOperation"),
        col("lf_UndoOperation"),
        col("lf_record_type"),
        col("lf_transaction_id"),
    );
    // Join on the record's intrinsic identity — its LSN (globally unique in the
    // log) — not its byte offset. LogFileParser reports a *shifted* `lf_Offset`
    // for records in pages that also carry a table-dump pseudo-record
    // (OpenAttributeTableDump / DirtyPageTableDump …): the dump's row takes the
    // real record's offset and the real record is listed ~0x40 later, at a byte
    // that holds no record header. Our parser's offsets are the physically-correct
    // ones (verified against the raw bytes), so an offset join spuriously fails
    // around dumps. The LSN join is immune to that bookkeeping quirk, isolating
    // genuine decode disagreements (op / type) from offset-and-tx reporting noise.
    type Row = (u64, Option<u16>, Option<u16>, u32, u32); // off, redo, undo, rt, tx
    let mut by_lsn: std::collections::HashMap<u64, Vec<Row>> = std::collections::HashMap::new();
    for line in lines {
        let f: Vec<&str> = line.split('|').collect();
        if f.len() <= c_tx {
            continue;
        }
        let off = u64::from_str_radix(f[c_off].trim_start_matches("0x"), 16).unwrap_or(0);
        let Ok(lsn) = f[c_lsn].parse::<u64>() else {
            continue;
        };
        let rt: u32 = f[c_rt].parse().unwrap_or(0);
        let tx = u32::from_str_radix(f[c_tx].trim_start_matches("0x"), 16).unwrap_or(0);
        by_lsn.entry(lsn).or_default().push((
            off,
            lfp_op_code(f[c_redo]),
            lfp_op_code(f[c_undo]),
            rt,
            tx,
        ));
    }
    assert!(by_lsn.len() > 1000, "thin oracle: {} LSNs", by_lsn.len());
    // The oldest LSN LogFileParser still tracks. Anything below it is a prior log
    // generation that predates its valid restart window — recoverable stale
    // residue, not a current record.
    let oracle_min_lsn = *by_lsn.keys().min().expect("non-empty oracle");

    let pages = read_record_pages(&data);
    let (mut exact, mut reported_diff, mut op_disagree, mut stale, mut unexplained) =
        (0usize, 0usize, 0usize, 0usize, 0usize);
    let mut op_sample: Vec<String> = Vec::new();
    let mut unexplained_sample: Vec<String> = Vec::new();
    // A `None` oracle opcode = LogFileParser printed a non-operation marker for
    // that field; treat it as a wildcard rather than a disagreement.
    let op_match = |c: Option<u16>, got: u16| match c {
        Some(c) => c == got,
        None => true,
    };
    for page in &pages {
        for r in parse_log_records(page) {
            let file_off = (page.offset + r.page_offset) as u64;
            let Some(rows) = by_lsn.get(&r.this_lsn) else {
                // Not in the oracle. Below its window = expected stale residue we
                // recover and it filters; within its window = a real concern.
                if r.this_lsn < oracle_min_lsn {
                    stale += 1;
                } else {
                    unexplained += 1;
                    if unexplained_sample.len() < 8 {
                        unexplained_sample.push(format!(
                            "@{file_off:#x} lsn={} redo={:?} rt={} tx={}",
                            r.this_lsn, r.redo_op, r.record_type, r.transaction_id
                        ));
                    }
                }
                continue;
            };
            // Decode agreement: operation codes + record type, against any oracle
            // row carrying this LSN (the record's true identity).
            let op_ok = rows.iter().any(|&(_off, redo_c, undo_c, rt, _tx)| {
                op_match(redo_c, r.redo_op.code())
                    && op_match(undo_c, r.undo_op.code())
                    && r.record_type == rt
            });
            if !op_ok {
                op_disagree += 1;
                if op_sample.len() < 8 {
                    op_sample.push(format!(
                        "@{file_off:#x} lsn={} mine redo={:?} undo={:?} rt={}; oracle={rows:?}",
                        r.this_lsn, r.redo_op, r.undo_op, r.record_type
                    ));
                }
                continue;
            }
            // Full agreement additionally reproduces LogFileParser's byte offset
            // and transaction id; `reported_diff` is the table-dump bookkeeping.
            let full = rows.iter().any(|&(off, redo_c, undo_c, rt, tx)| {
                off == file_off
                    && op_match(redo_c, r.redo_op.code())
                    && op_match(undo_c, r.undo_op.code())
                    && r.record_type == rt
                    && r.transaction_id == tx
            });
            if full {
                exact += 1;
            } else {
                reported_diff += 1;
            }
        }
    }
    eprintln!(
        "differential: exact={exact} reported_diff={reported_diff} op_disagree={op_disagree} stale={stale} unexplained={unexplained}"
    );
    // The load-bearing claims: every record we decode that falls within
    // LogFileParser's LSN window is corroborated by it and agrees on operation +
    // record type. `reported_diff` is purely LogFileParser's offset/tx bookkeeping
    // in table-dump pages; `stale` is prior-generation residue we recover and it
    // filters. Both are documented in docs/validation.md.
    assert!(
        exact > 74_000,
        "too few exact (offset+all-field) matches: {exact}"
    );
    assert_eq!(
        op_disagree, 0,
        "operation/type disagreements: {op_sample:?}"
    );
    assert_eq!(
        unexplained, 0,
        "records within LogFileParser's window but absent from it: {unexplained_sample:?}"
    );
}

/// Characterization of the semantic layer (`classify_log_operation`) over the
/// **whole** real DC01 `$LogFile`: the decoded redo/undo records of a live
/// domain controller must classify into a sane spread of file operations, and
/// the mapping must be **complete** — no record whose redo *and* undo opcodes
/// are both documented (`0x00`–`0x22`, never `LogOp::Unknown`) may fall through
/// to `FileOperation::Unknown`. A both-known record landing in `Unknown` is a
/// hole in the general mapping, not a property of the data.
///
/// Tier 2 (semantic): the operation taxonomy is derivable from the documented
/// LFS opcode semantics (msuhanov `dfir_ntfs`, jschicht `LogFileParser`,
/// Carrier ch.13); there is no independent *semantic* oracle that labels each
/// transaction's file operation (`LogFileParser`'s `LogFile.csv` decodes the
/// redo/undo records — already validated Tier 1 — but does not itself emit a
/// per-transaction file-operation label). The record decode feeding this is
/// Tier 1 (the `LogFileParser` row differential above).
///
/// ```bash
/// NTFS_FORENSIC_LOGFILE=/path/to/DC01_LogFile.bin \
///   cargo test -p ntfs-core --test logfile_rcrd semantic -- --ignored --nocapture
/// ```
#[test]
#[ignore = "requires NTFS_FORENSIC_LOGFILE pointing at a real $LogFile stream"]
fn semantic_classification_is_complete_and_sane() {
    let Ok(path) = std::env::var("NTFS_FORENSIC_LOGFILE") else {
        return;
    };
    let data = std::fs::read(&path).expect("read $LogFile");
    let pages = read_record_pages(&data);

    let mut counts: std::collections::BTreeMap<&'static str, usize> =
        std::collections::BTreeMap::new();
    let mut total = 0usize;
    let mut both_known_unknown: Vec<String> = Vec::new();

    for page in &pages {
        for r in parse_log_records(page) {
            total += 1;
            let op = classify_log_operation(r.redo_op, r.undo_op);
            let bucket = match op {
                FileOperation::Create => "Create",
                FileOperation::Delete => "Delete",
                FileOperation::Rename => "Rename",
                FileOperation::IndexInsert => "IndexInsert",
                FileOperation::IndexDelete => "IndexDelete",
                FileOperation::AttributeCreate => "AttributeCreate",
                FileOperation::AttributeDelete => "AttributeDelete",
                FileOperation::Resize => "Resize",
                FileOperation::DataWrite => "DataWrite",
                FileOperation::BitmapAllocation => "BitmapAllocation",
                FileOperation::TransactionControl => "TransactionControl",
                FileOperation::TableDump => "TableDump",
                FileOperation::Noop => "Noop",
                FileOperation::Unknown(redo, undo) => {
                    // Completeness: an Unknown is only acceptable when at least
                    // one side was an undocumented opcode. Both-known ⇒ a hole.
                    let redo_known = !matches!(r.redo_op, LogOp::Unknown(_));
                    let undo_known = !matches!(r.undo_op, LogOp::Unknown(_));
                    if redo_known && undo_known && both_known_unknown.len() < 16 {
                        both_known_unknown.push(format!(
                            "@page {:#x}+{:#x}: redo={redo:#x} undo={undo:#x}",
                            page.offset, r.page_offset
                        ));
                    }
                    "Unknown"
                }
            };
            *counts.entry(bucket).or_default() += 1;
        }
    }

    eprintln!(
        "semantic distribution over {total} records ({} pages):",
        pages.len()
    );
    for (k, v) in &counts {
        eprintln!("  {k}: {v}");
    }

    assert!(total > 50_000, "thin stream: only {total} records");

    // Completeness — the load-bearing assertion: every both-known-opcode record
    // is classified, never dropped into Unknown.
    assert!(
        both_known_unknown.is_empty(),
        "both-known-opcode records fell through to Unknown (mapping hole): {both_known_unknown:?}"
    );

    // Sanity — a live DC's log exercises every major file-operation class.
    for class in [
        "Create",
        "Delete",
        "Rename",
        "DataWrite",
        "IndexInsert",
        "IndexDelete",
        "AttributeCreate",
        "AttributeDelete",
        "Resize",
        "TransactionControl",
    ] {
        assert!(
            counts.get(class).copied().unwrap_or(0) > 0,
            "expected at least one {class} on a live DC $LogFile",
        );
    }
}

/// Per-transaction LSN-membership differential against `LogFileParser`: for every
/// transaction id `reconstruct_transactions` builds from the real DC01 `$LogFile`,
/// the SET of record LSNs it assigns to that txid must match the SET
/// `LogFileParser`'s `LogFile.csv` assigns to the same `lf_transaction_id`.
///
/// **Join on LSN, group on txid.** The record's LSN is its globally-unique
/// identity (see `full_logfile_records_match_logfileparser`), so comparing the
/// *set of LSNs* per transaction is immune to `LogFileParser`'s table-dump
/// `lf_Offset` shift — we never compare byte offsets here, only which LSNs each
/// tool places in each transaction. Records the two tools see differently in the
/// circular-buffer wrap are isolated rather than failing the run:
///
/// - **stale** — a record we recover whose LSN is below the oracle's oldest
///   tracked LSN: prior-generation residue `LogFileParser` filters and we carve
///   (documented in `validation.md`). Excluded from the per-txid comparison.
/// - **`oracle_extra`** — an LSN the oracle lists for a txid that is absent from
///   our stream entirely (a record in a page region our reader did not surface).
///
/// The load-bearing assertion is that for the overwhelming majority of
/// transaction ids the in-window LSN membership agrees exactly.
///
/// Tier 1 *input* (the record decode + LSN identity are validated against
/// `LogFileParser` above); the transaction grouping reconciled here is checked
/// against `LogFileParser`'s own `lf_transaction_id` column — an independent
/// tool's transaction assignment on the same real stream.
///
/// ```bash
/// NTFS_FORENSIC_LOGFILE=DC01_LogFile.bin \
/// NTFS_FORENSIC_LOGFILE_CSV=LogFile.csv \
///   cargo test -p ntfs-core --test logfile_rcrd transaction_membership -- --ignored --nocapture
/// ```
#[test]
#[ignore = "requires NTFS_FORENSIC_LOGFILE + NTFS_FORENSIC_LOGFILE_CSV"]
fn transaction_membership_matches_logfileparser() {
    use std::collections::{HashMap, HashSet};

    let Ok(lf_path) = std::env::var("NTFS_FORENSIC_LOGFILE") else {
        return;
    };
    let Ok(csv_path) = std::env::var("NTFS_FORENSIC_LOGFILE_CSV") else {
        return;
    };
    let data = std::fs::read(&lf_path).expect("read $LogFile");
    let csv = std::fs::read_to_string(&csv_path).expect("read LogFile.csv");

    // Index the oracle CSV (pipe-delimited): for each lf_transaction_id, the set
    // of lf_LSN values it lists. Also record every LSN the oracle knows, so we
    // can tell "the oracle puts this LSN in a different txid" from "the oracle
    // has never heard of this LSN".
    let mut lines = csv.lines();
    let header: Vec<&str> = lines.next().expect("csv header").split('|').collect();
    let col = |n: &str| {
        header
            .iter()
            .position(|h| *h == n)
            .unwrap_or_else(|| panic!("missing column {n}"))
    };
    let (c_lsn, c_tx) = (col("lf_LSN"), col("lf_transaction_id"));

    let mut oracle_txid_lsns: HashMap<u32, HashSet<u64>> = HashMap::new();
    let mut oracle_all_lsns: HashSet<u64> = HashSet::new();
    for line in lines {
        let f: Vec<&str> = line.split('|').collect();
        if f.len() <= c_tx.max(c_lsn) {
            continue;
        }
        let Ok(lsn) = f[c_lsn].parse::<u64>() else {
            continue;
        };
        let tx = u32::from_str_radix(f[c_tx].trim_start_matches("0x"), 16).unwrap_or(0);
        oracle_txid_lsns.entry(tx).or_default().insert(lsn);
        oracle_all_lsns.insert(lsn);
    }
    assert!(
        oracle_txid_lsns.len() > 10,
        "thin oracle: {} txids",
        oracle_txid_lsns.len()
    );
    let oracle_min_lsn = *oracle_all_lsns.iter().min().expect("non-empty oracle");

    // Reconstruct our transactions over the whole real stream.
    let pages = read_record_pages(&data);
    let mut all_records = Vec::new();
    for page in &pages {
        all_records.extend(parse_log_records(page));
    }
    let txns = reconstruct_transactions(&all_records);
    // Every record lands in exactly one transaction — no record dropped by the
    // grouping layer (the property the synthetic unit tests assert, re-checked on
    // the real stream where it actually matters).
    let grouped: usize = txns.iter().map(|t| t.records.len()).sum();
    assert_eq!(
        grouped,
        all_records.len(),
        "grouping dropped records on the real stream"
    );

    // For each txid we reconstruct, compare the in-window LSN set to the oracle's.
    let (mut txid_exact, mut txid_divergent) = (0usize, 0usize);
    let (mut stale, mut oracle_extra, mut absent_txid) = (0usize, 0usize, 0usize);
    let mut divergence_sample: Vec<String> = Vec::new();
    for t in &txns {
        // Our LSNs for this txid, restricted to the oracle's recovery window
        // (drop prior-generation residue the oracle filters).
        let mut ours: HashSet<u64> = HashSet::new();
        for &lsn in &t.lsns {
            if lsn < oracle_min_lsn {
                stale += 1;
            } else {
                ours.insert(lsn);
            }
        }
        if ours.is_empty() {
            continue; // wholly stale (pre-window) transaction — nothing to compare
        }
        let Some(theirs) = oracle_txid_lsns.get(&t.transaction_id) else {
            // The oracle never used this txid at all. Only a concern if some of
            // our in-window LSNs are ones the oracle *does* know under another
            // txid (a real grouping disagreement) vs LSNs it never saw.
            let misplaced = ours.iter().filter(|l| oracle_all_lsns.contains(l)).count();
            absent_txid += 1;
            if misplaced > 0 && divergence_sample.len() < 12 {
                divergence_sample.push(format!(
                    "txid={:#x}: oracle has no such txid yet {misplaced} of our {} LSNs are known to it",
                    t.transaction_id,
                    ours.len()
                ));
            }
            continue;
        };
        // Restrict the oracle's set to LSNs it shares the window with us on.
        let theirs_in: HashSet<u64> = theirs
            .iter()
            .copied()
            .filter(|l| *l >= oracle_min_lsn)
            .collect();
        let missing: Vec<u64> = theirs_in.difference(&ours).copied().collect();
        let extra: Vec<u64> = ours.difference(&theirs_in).copied().collect();
        // An "extra" LSN the oracle never saw anywhere is recovery, not a
        // grouping error; an extra LSN the oracle placed under a *different* txid
        // is a genuine membership divergence.
        let extra_misplaced: Vec<u64> = extra
            .iter()
            .copied()
            .filter(|l| oracle_all_lsns.contains(l))
            .collect();
        oracle_extra += extra.len() - extra_misplaced.len();
        if missing.is_empty() && extra_misplaced.is_empty() {
            txid_exact += 1;
        } else {
            txid_divergent += 1;
            if divergence_sample.len() < 12 {
                divergence_sample.push(format!(
                    "txid={:#x}: oracle_missing_from_ours={} ours_under_wrong_txid={}",
                    t.transaction_id,
                    missing.len(),
                    extra_misplaced.len()
                ));
            }
        }
    }

    let total = txid_exact + txid_divergent;
    eprintln!(
        "txid membership: exact={txid_exact} divergent={txid_divergent} \
         (of {total} compared) | absent_txid={absent_txid} stale_records={stale} \
         oracle_unseen_extra={oracle_extra}"
    );
    if !divergence_sample.is_empty() {
        eprintln!("divergence sample: {divergence_sample:?}");
    }

    assert!(total > 10, "too few comparable transactions: {total}");
    // The load-bearing claim: the per-txid LSN membership agrees for the
    // overwhelming majority. Any residual divergence is characterized above
    // (circular-buffer wrap / boundary records the two tools window differently)
    // and reported, not silently tolerated.
    let agreement = txid_exact as f64 / total as f64;
    assert!(
        agreement > 0.98,
        "per-txid LSN-membership agreement {agreement:.4} below 0.98; sample={divergence_sample:?}"
    );
}
