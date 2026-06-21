//! Real-data validation of the $LogFile RCRD record-page reader (doer-checker).
//!
//! The page bytes come from the CITADEL-DC01 $LogFile (DFIR Madness "Stolen
//! Szechuan Sauce" Case 001), extracted with TSK `icat` as an independent input
//! oracle — byte-identical to issen's own extraction. Validating the USA fixup
//! against a real on-disk RCRD page, rather than a page this crate encoded
//! itself, is what catches a wrong fixup offset or a self-consistent-but-wrong
//! round trip (the LZNT1 trap). See `tests/data/README.md`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ntfs_core::{parse_log_records, read_record_pages, LogOp};

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
