//! $LogFile parser for gap detection and LSN correlation.
//!
//! The NTFS $LogFile records transaction log entries. By analyzing restart
//! areas and record pages, we can detect gaps that indicate journal clearing
//! or corruption.

pub mod usn_extractor;

pub use usn_extractor::{extract_usn_from_logfile, LogFileRecordSource, LogFileUsnRecord};

use crate::error::Result;

// ─── Constants ───────────────────────────────────────────────────────────────

/// NTFS $LogFile restart area signature "RSTR".
const RSTR_SIGNATURE: &[u8; 4] = b"RSTR";

/// NTFS $LogFile record page signature "RCRD".
const RCRD_SIGNATURE: &[u8; 4] = b"RCRD";

/// Default NTFS $LogFile page size.
const LOG_PAGE_SIZE: usize = 0x1000; // 4096 bytes

// ─── Parsed structures ──────────────────────────────────────────────────────

/// Parsed NTFS $LogFile restart area.
#[derive(Debug, Clone)]
pub struct RestartArea {
    pub offset: usize,
    pub current_lsn: u64,
    pub log_clients: u16,
    pub system_page_size: u32,
    pub log_page_size: u32,
}

/// Summary of $LogFile analysis.
#[derive(Debug, Clone)]
pub struct LogFileSummary {
    pub restart_areas: Vec<RestartArea>,
    pub record_page_count: usize,
    pub has_gaps: bool,
    pub highest_lsn: u64,
}

/// An NTFS $LogFile (LFS) redo/undo operation code.
///
/// These are the NTFS log-file-service operations (Brian Carrier, *File System
/// Forensic Analysis*). The code→operation mapping is transcribed verbatim from
/// the `_SolveUndoRedoCodes` function in jschicht's `LogFileParser` — the exact
/// lookup its GUI runs to label the `RedoOP`/`UndoOP` columns — so this enum's
/// mapping is identical to that tool's by construction. Names use the canonical
/// spelling (`LogFileParser` carries a few typos, e.g. "Segement"); the invariant
/// shared with the tool is the numeric code, not the label. A code outside the
/// documented `0x00..=0x22` range is surfaced verbatim via [`LogOp::Unknown`],
/// never silently mapped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogOp {
    Noop,
    CompensationLogRecord,
    InitializeFileRecordSegment,
    DeallocateFileRecordSegment,
    WriteEndOfFileRecordSegment,
    CreateAttribute,
    DeleteAttribute,
    UpdateResidentValue,
    UpdateNonResidentValue,
    UpdateMappingPairs,
    DeleteDirtyClusters,
    SetNewAttributeSizes,
    AddIndexEntryRoot,
    DeleteIndexEntryRoot,
    AddIndexEntryAllocation,
    DeleteIndexEntryAllocation,
    WriteEndOfIndexBuffer,
    SetIndexEntryVcnRoot,
    SetIndexEntryVcnAllocation,
    UpdateFileNameRoot,
    UpdateFileNameAllocation,
    SetBitsInNonResidentBitMap,
    ClearBitsInNonResidentBitMap,
    HotFix,
    EndTopLevelAction,
    PrepareTransaction,
    CommitTransaction,
    ForgetTransaction,
    OpenNonResidentAttribute,
    OpenAttributeTableDump,
    AttributeNamesDump,
    DirtyPageTableDump,
    TransactionTableDump,
    UpdateRecordDataRoot,
    UpdateRecordDataAllocation,
    /// A code outside the documented `0x00..=0x22` range, surfaced verbatim.
    Unknown(u16),
}

impl LogOp {
    /// Map a raw 16-bit redo/undo operation code to its operation.
    #[must_use]
    pub fn from_u16(code: u16) -> Self {
        use LogOp::{
            AddIndexEntryAllocation, AddIndexEntryRoot, AttributeNamesDump,
            ClearBitsInNonResidentBitMap, CommitTransaction, CompensationLogRecord,
            CreateAttribute, DeallocateFileRecordSegment, DeleteAttribute, DeleteDirtyClusters,
            DeleteIndexEntryAllocation, DeleteIndexEntryRoot, DirtyPageTableDump,
            EndTopLevelAction, ForgetTransaction, HotFix, InitializeFileRecordSegment, Noop,
            OpenAttributeTableDump, OpenNonResidentAttribute, PrepareTransaction,
            SetBitsInNonResidentBitMap, SetIndexEntryVcnAllocation, SetIndexEntryVcnRoot,
            SetNewAttributeSizes, TransactionTableDump, Unknown, UpdateFileNameAllocation,
            UpdateFileNameRoot, UpdateMappingPairs, UpdateNonResidentValue,
            UpdateRecordDataAllocation, UpdateRecordDataRoot, UpdateResidentValue,
            WriteEndOfFileRecordSegment, WriteEndOfIndexBuffer,
        };
        match code {
            0x00 => Noop,
            0x01 => CompensationLogRecord,
            0x02 => InitializeFileRecordSegment,
            0x03 => DeallocateFileRecordSegment,
            0x04 => WriteEndOfFileRecordSegment,
            0x05 => CreateAttribute,
            0x06 => DeleteAttribute,
            0x07 => UpdateResidentValue,
            0x08 => UpdateNonResidentValue,
            0x09 => UpdateMappingPairs,
            0x0A => DeleteDirtyClusters,
            0x0B => SetNewAttributeSizes,
            0x0C => AddIndexEntryRoot,
            0x0D => DeleteIndexEntryRoot,
            0x0E => AddIndexEntryAllocation,
            0x0F => DeleteIndexEntryAllocation,
            0x10 => WriteEndOfIndexBuffer,
            0x11 => SetIndexEntryVcnRoot,
            0x12 => SetIndexEntryVcnAllocation,
            0x13 => UpdateFileNameRoot,
            0x14 => UpdateFileNameAllocation,
            0x15 => SetBitsInNonResidentBitMap,
            0x16 => ClearBitsInNonResidentBitMap,
            0x17 => HotFix,
            0x18 => EndTopLevelAction,
            0x19 => PrepareTransaction,
            0x1A => CommitTransaction,
            0x1B => ForgetTransaction,
            0x1C => OpenNonResidentAttribute,
            0x1D => OpenAttributeTableDump,
            0x1E => AttributeNamesDump,
            0x1F => DirtyPageTableDump,
            0x20 => TransactionTableDump,
            0x21 => UpdateRecordDataRoot,
            0x22 => UpdateRecordDataAllocation,
            other => Unknown(other),
        }
    }

    /// The raw 16-bit operation code (inverse of [`LogOp::from_u16`]).
    #[must_use]
    pub fn code(self) -> u16 {
        use LogOp::{
            AddIndexEntryAllocation, AddIndexEntryRoot, AttributeNamesDump,
            ClearBitsInNonResidentBitMap, CommitTransaction, CompensationLogRecord,
            CreateAttribute, DeallocateFileRecordSegment, DeleteAttribute, DeleteDirtyClusters,
            DeleteIndexEntryAllocation, DeleteIndexEntryRoot, DirtyPageTableDump,
            EndTopLevelAction, ForgetTransaction, HotFix, InitializeFileRecordSegment, Noop,
            OpenAttributeTableDump, OpenNonResidentAttribute, PrepareTransaction,
            SetBitsInNonResidentBitMap, SetIndexEntryVcnAllocation, SetIndexEntryVcnRoot,
            SetNewAttributeSizes, TransactionTableDump, Unknown, UpdateFileNameAllocation,
            UpdateFileNameRoot, UpdateMappingPairs, UpdateNonResidentValue,
            UpdateRecordDataAllocation, UpdateRecordDataRoot, UpdateResidentValue,
            WriteEndOfFileRecordSegment, WriteEndOfIndexBuffer,
        };
        match self {
            Noop => 0x00,
            CompensationLogRecord => 0x01,
            InitializeFileRecordSegment => 0x02,
            DeallocateFileRecordSegment => 0x03,
            WriteEndOfFileRecordSegment => 0x04,
            CreateAttribute => 0x05,
            DeleteAttribute => 0x06,
            UpdateResidentValue => 0x07,
            UpdateNonResidentValue => 0x08,
            UpdateMappingPairs => 0x09,
            DeleteDirtyClusters => 0x0A,
            SetNewAttributeSizes => 0x0B,
            AddIndexEntryRoot => 0x0C,
            DeleteIndexEntryRoot => 0x0D,
            AddIndexEntryAllocation => 0x0E,
            DeleteIndexEntryAllocation => 0x0F,
            WriteEndOfIndexBuffer => 0x10,
            SetIndexEntryVcnRoot => 0x11,
            SetIndexEntryVcnAllocation => 0x12,
            UpdateFileNameRoot => 0x13,
            UpdateFileNameAllocation => 0x14,
            SetBitsInNonResidentBitMap => 0x15,
            ClearBitsInNonResidentBitMap => 0x16,
            HotFix => 0x17,
            EndTopLevelAction => 0x18,
            PrepareTransaction => 0x19,
            CommitTransaction => 0x1A,
            ForgetTransaction => 0x1B,
            OpenNonResidentAttribute => 0x1C,
            OpenAttributeTableDump => 0x1D,
            AttributeNamesDump => 0x1E,
            DirtyPageTableDump => 0x1F,
            TransactionTableDump => 0x20,
            UpdateRecordDataRoot => 0x21,
            UpdateRecordDataAllocation => 0x22,
            Unknown(c) => c,
        }
    }
}

/// One RCRD record page from $LogFile with its multi-sector USA fixup applied.
///
/// `data` holds the page exactly as it was in memory before NTFS wrote the
/// update sequence number (USN) into each 512-byte sector tail — i.e. the
/// displaced original bytes have been restored from the update-sequence array,
/// so the log-record stream within the page can be read directly. Pages whose
/// USA integrity check fails are not represented here (see [`read_record_pages`]).
#[derive(Debug, Clone)]
pub struct RecordPage {
    /// Byte offset of this page within the $LogFile stream.
    pub offset: usize,
    /// `last_lsn` from the RCRD header (offset 0x08): the LSN of the last log
    /// record that ends on this page.
    pub last_lsn: u64,
    /// Page bytes with the USA fixup applied (sector tails restored).
    pub data: Vec<u8>,
}

/// Read every RCRD record page from a $LogFile, applying the multi-sector USA
/// fixup to each page in turn.
///
/// Only pages beginning with the `RCRD` signature are returned; RSTR restart
/// pages and zeroed/garbage pages are skipped. A page whose USA integrity check
/// fails — a sector tail on disk does not match the page's USN (torn write,
/// corruption, or tampering) — is also skipped, because its record bytes cannot
/// be trusted. The fixup reuses [`crate::record::apply_fixup`], which is
/// signature-agnostic (it reads `usa_offset`/`usa_count` from the shared
/// multi-sector header that RCRD pages and FILE records both carry).
pub fn read_record_pages(data: &[u8]) -> Vec<RecordPage> {
    let mut pages = Vec::new();
    let page_count = data.len() / LOG_PAGE_SIZE;

    for page_idx in 0..page_count {
        let offset = page_idx * LOG_PAGE_SIZE;

        // page_count = data.len() / LOG_PAGE_SIZE guarantees a full page here.
        let page = &data[offset..offset + LOG_PAGE_SIZE];
        if &page[0..4] != RCRD_SIGNATURE {
            continue;
        }

        // Apply the multi-sector USA fixup on a private copy. The on-disk page
        // has the USN written into each 512-byte sector tail; apply_fixup
        // verifies every tail matches the USN, then restores the displaced
        // originals from the update sequence array. A mismatch (torn write /
        // corruption / tampering) means the record bytes cannot be trusted, so
        // the page is skipped rather than returned with un-fixed bytes.
        let mut buf = page.to_vec();
        if crate::record::apply_fixup(&mut buf, 512).is_err() {
            continue;
        }

        let last_lsn = u64::from_le_bytes(buf[0x08..0x10].try_into().unwrap_or([0; 8]));

        pages.push(RecordPage {
            offset,
            last_lsn,
            data: buf,
        });
    }

    pages
}

/// Parse NTFS $LogFile data.
///
/// Scans for restart areas (RSTR) and record pages (RCRD) to build
/// a summary. Detects gaps in the log sequence.
pub fn parse_logfile(data: &[u8]) -> Result<LogFileSummary> {
    let mut restart_areas = Vec::new();
    let mut record_page_count = 0;
    let mut highest_lsn: u64 = 0;
    let mut has_gaps = false;
    let mut last_page_had_rcrd = false;

    let page_count = data.len() / LOG_PAGE_SIZE;

    for page_idx in 0..page_count {
        let page_offset = page_idx * LOG_PAGE_SIZE;

        // page_count = data.len() / LOG_PAGE_SIZE guarantees a full page fits here.
        let sig = &data[page_offset..page_offset + 4];

        if sig == RSTR_SIGNATURE {
            if page_offset + 0x28 <= data.len() {
                let current_lsn = u64::from_le_bytes(
                    data[page_offset + 0x08..page_offset + 0x10]
                        .try_into()
                        .unwrap_or([0; 8]),
                );
                let log_clients = u16::from_le_bytes(
                    data[page_offset + 0x10..page_offset + 0x12]
                        .try_into()
                        .unwrap_or([0; 2]),
                );
                let system_page_size = u32::from_le_bytes(
                    data[page_offset + 0x20..page_offset + 0x24]
                        .try_into()
                        .unwrap_or([0; 4]),
                );
                let log_page_size = u32::from_le_bytes(
                    data[page_offset + 0x24..page_offset + 0x28]
                        .try_into()
                        .unwrap_or([0; 4]),
                );

                if current_lsn > highest_lsn {
                    highest_lsn = current_lsn;
                }

                restart_areas.push(RestartArea {
                    offset: page_offset,
                    current_lsn,
                    log_clients,
                    system_page_size,
                    log_page_size,
                });
            } // cov:unreachable: page_count = data.len() / LOG_PAGE_SIZE (0x1000) ⇒ each page is a full 4096 bytes, so page_offset + 0x28 always fits; the false-branch is unreachable
            last_page_had_rcrd = false;
        } else if sig == RCRD_SIGNATURE {
            record_page_count += 1;

            // Extract last_end_lsn from RCRD header (offset 0x18)
            if page_offset + 0x20 <= data.len() {
                let page_lsn = u64::from_le_bytes(
                    data[page_offset + 0x18..page_offset + 0x20]
                        .try_into()
                        .unwrap_or([0; 8]),
                );
                if page_lsn > highest_lsn {
                    highest_lsn = page_lsn;
                }
            } // cov:unreachable: page_count = data.len() / LOG_PAGE_SIZE (0x1000) ⇒ each page is a full 4096 bytes, so page_offset + 0x20 always fits; the false-branch is unreachable

            last_page_had_rcrd = true;
        } else {
            // Neither RSTR nor RCRD - could be a gap
            if last_page_had_rcrd && page_idx > 2 {
                // If we had RCRD pages and now see something else, that's a gap
                let is_zeroed = data[page_offset..page_offset + 4] == [0, 0, 0, 0];
                if !is_zeroed {
                    has_gaps = true;
                }
            }
            last_page_had_rcrd = false;
        }
    }

    Ok(LogFileSummary {
        restart_areas,
        record_page_count,
        has_gaps,
        highest_lsn,
    })
}

/// Correlate $LogFile LSN with USN Journal entries.
///
/// The USN (Update Sequence Number) in journal records corresponds to
/// byte offsets in the journal. $LogFile LSNs are separate but can help
/// detect if the journal was cleared (LSN continuity break).
pub fn detect_journal_clearing(logfile_summary: &LogFileSummary) -> bool {
    // Journal clearing indicators:
    // 1. Gaps in $LogFile record pages
    // 2. Very few restart areas (should have exactly 2 normally)
    // 3. LSN discontinuities

    if logfile_summary.has_gaps {
        return true;
    }

    if logfile_summary.restart_areas.len() != 2 {
        return logfile_summary.restart_areas.is_empty();
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The complete code→operation mapping, transcribed verbatim from
    /// `LogFileParser`'s `_SolveUndoRedoCodes` (the function its GUI runs). Index =
    /// the raw opcode; this is the authoritative reference `LogOp::from_u16` must
    /// reproduce exactly. Canonical spelling differs from `LogFileParser`'s typos
    /// (e.g. its "Segement"); the shared invariant is the numeric code, asserted
    /// here as the variant identity.
    const LFP_OPS: [LogOp; 35] = [
        LogOp::Noop,                         // 0x00
        LogOp::CompensationLogRecord,        // 0x01
        LogOp::InitializeFileRecordSegment,  // 0x02
        LogOp::DeallocateFileRecordSegment,  // 0x03
        LogOp::WriteEndOfFileRecordSegment,  // 0x04
        LogOp::CreateAttribute,              // 0x05
        LogOp::DeleteAttribute,              // 0x06
        LogOp::UpdateResidentValue,          // 0x07
        LogOp::UpdateNonResidentValue,       // 0x08
        LogOp::UpdateMappingPairs,           // 0x09
        LogOp::DeleteDirtyClusters,          // 0x0A
        LogOp::SetNewAttributeSizes,         // 0x0B
        LogOp::AddIndexEntryRoot,            // 0x0C
        LogOp::DeleteIndexEntryRoot,         // 0x0D
        LogOp::AddIndexEntryAllocation,      // 0x0E
        LogOp::DeleteIndexEntryAllocation,   // 0x0F
        LogOp::WriteEndOfIndexBuffer,        // 0x10
        LogOp::SetIndexEntryVcnRoot,         // 0x11
        LogOp::SetIndexEntryVcnAllocation,   // 0x12
        LogOp::UpdateFileNameRoot,           // 0x13
        LogOp::UpdateFileNameAllocation,     // 0x14
        LogOp::SetBitsInNonResidentBitMap,   // 0x15
        LogOp::ClearBitsInNonResidentBitMap, // 0x16
        LogOp::HotFix,                       // 0x17
        LogOp::EndTopLevelAction,            // 0x18
        LogOp::PrepareTransaction,           // 0x19
        LogOp::CommitTransaction,            // 0x1A
        LogOp::ForgetTransaction,            // 0x1B
        LogOp::OpenNonResidentAttribute,     // 0x1C
        LogOp::OpenAttributeTableDump,       // 0x1D
        LogOp::AttributeNamesDump,           // 0x1E
        LogOp::DirtyPageTableDump,           // 0x1F
        LogOp::TransactionTableDump,         // 0x20
        LogOp::UpdateRecordDataRoot,         // 0x21
        LogOp::UpdateRecordDataAllocation,   // 0x22
    ];

    #[test]
    fn logop_from_u16_matches_logfileparser_table() {
        for (code, &expected) in LFP_OPS.iter().enumerate() {
            assert_eq!(
                LogOp::from_u16(code as u16),
                expected,
                "opcode {code:#04x} must map to `LogFileParser`'s operation"
            );
        }
    }

    #[test]
    fn logop_unknown_surfaces_the_raw_code() {
        // 0x23 is `LogFileParser`'s internal "JS_NewEndOfRecord" marker, not a real
        // NTFS operation; it and anything above the documented range are Unknown.
        assert_eq!(LogOp::from_u16(0x23), LogOp::Unknown(0x23));
        assert_eq!(LogOp::from_u16(0xFFFF), LogOp::Unknown(0xFFFF));
    }

    #[test]
    fn logop_code_round_trips() {
        for code in 0u16..=0x22 {
            assert_eq!(LogOp::from_u16(code).code(), code, "round-trip {code:#04x}");
        }
        assert_eq!(LogOp::Unknown(0x99).code(), 0x99);
    }

    fn make_rstr_page(lsn: u64) -> Vec<u8> {
        let mut page = vec![0u8; LOG_PAGE_SIZE];
        page[0..4].copy_from_slice(RSTR_SIGNATURE);
        page[0x08..0x10].copy_from_slice(&lsn.to_le_bytes());
        page[0x10..0x12].copy_from_slice(&1u16.to_le_bytes()); // 1 client
        page[0x20..0x24].copy_from_slice(&4096u32.to_le_bytes());
        page[0x24..0x28].copy_from_slice(&4096u32.to_le_bytes());
        page
    }

    fn make_rcrd_page(lsn: u64) -> Vec<u8> {
        let mut page = vec![0u8; LOG_PAGE_SIZE];
        page[0..4].copy_from_slice(RCRD_SIGNATURE);
        page[0x18..0x20].copy_from_slice(&lsn.to_le_bytes());
        page
    }

    /// Build an RCRD page with a well-formed update sequence array, in the
    /// on-disk form `apply_fixup` accepts: `usa_offset` 0x28, `usa_count` 9 (1 USN +
    /// 8 protected 512-byte sectors), the USN written into each sector tail, and
    /// distinct original values held in usa[1..9]. (The real-data equivalent is
    /// exercised by `core/tests/logfile_rcrd.rs`; this synthetic page is for
    /// per-branch lib coverage.)
    fn make_rcrd_page_with_usa(last_lsn: u64) -> Vec<u8> {
        let mut page = vec![0u8; LOG_PAGE_SIZE];
        page[0..4].copy_from_slice(RCRD_SIGNATURE);
        page[0x04..0x06].copy_from_slice(&0x28u16.to_le_bytes()); // usa_offset
        page[0x06..0x08].copy_from_slice(&9u16.to_le_bytes()); // usa_count
        page[0x08..0x10].copy_from_slice(&last_lsn.to_le_bytes()); // last_lsn @0x08
        let usn: u16 = 0x0007;
        page[0x28..0x2a].copy_from_slice(&usn.to_le_bytes()); // usa[0] = USN
        for i in 0..8usize {
            let original: u16 = 0xAA00 | i as u16;
            let usa_slot = 0x2a + i * 2;
            page[usa_slot..usa_slot + 2].copy_from_slice(&original.to_le_bytes());
            let tail = (i + 1) * 512 - 2;
            page[tail..tail + 2].copy_from_slice(&usn.to_le_bytes()); // USN in tail
        }
        page
    }

    #[test]
    fn read_record_pages_accepts_valid_usa_page() {
        let pages = read_record_pages(&make_rcrd_page_with_usa(0x1234));
        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].offset, 0);
        assert_eq!(pages[0].last_lsn, 0x1234);
        // Sector-0 tail (0x1fe) restored from usa[1] = 0xAA00.
        assert_eq!(&pages[0].data[0x1fe..0x200], &0xAA00u16.to_le_bytes());
    }

    #[test]
    fn read_record_pages_skips_non_rcrd_pages() {
        // RSTR and zeroed pages are not record pages → continue branch.
        let mut data = make_rstr_page(1000);
        data.extend_from_slice(&vec![0u8; LOG_PAGE_SIZE]);
        assert!(read_record_pages(&data).is_empty());
    }

    #[test]
    fn read_record_pages_skips_page_with_invalid_usa() {
        // RCRD signature but usa_count is 0 → apply_fixup errors → page skipped.
        let pages = read_record_pages(&make_rcrd_page(5000));
        assert!(pages.is_empty());
    }

    #[test]
    fn read_record_pages_empty_input() {
        assert!(read_record_pages(&[]).is_empty());
    }

    #[test]
    fn read_record_pages_returns_only_valid_pages_in_mixed_stream() {
        // RSTR, valid-USA RCRD, invalid-USA RCRD, zeroed → exactly one recovered.
        let mut data = make_rstr_page(1000);
        data.extend_from_slice(&make_rcrd_page_with_usa(0xBEEF));
        data.extend_from_slice(&make_rcrd_page(2000)); // usa_count 0 → rejected
        data.extend_from_slice(&vec![0u8; LOG_PAGE_SIZE]);
        let pages = read_record_pages(&data);
        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].offset, LOG_PAGE_SIZE);
        assert_eq!(pages[0].last_lsn, 0xBEEF);
    }

    #[test]
    fn test_parse_logfile_with_restart_areas() {
        let mut data = Vec::new();
        data.extend_from_slice(&make_rstr_page(1000));
        data.extend_from_slice(&make_rstr_page(2000));
        data.extend_from_slice(&make_rcrd_page(3000));

        let summary = parse_logfile(&data).unwrap();
        assert_eq!(summary.restart_areas.len(), 2);
        assert_eq!(summary.record_page_count, 1);
        assert_eq!(summary.highest_lsn, 3000);
        assert!(!summary.has_gaps);
    }

    #[test]
    fn test_detect_journal_clearing_with_gaps() {
        let summary = LogFileSummary {
            restart_areas: vec![],
            record_page_count: 0,
            has_gaps: true,
            highest_lsn: 0,
        };
        assert!(detect_journal_clearing(&summary));
    }

    #[test]
    fn test_normal_logfile_no_clearing() {
        let summary = LogFileSummary {
            restart_areas: vec![
                RestartArea {
                    offset: 0,
                    current_lsn: 1000,
                    log_clients: 1,
                    system_page_size: 4096,
                    log_page_size: 4096,
                },
                RestartArea {
                    offset: 4096,
                    current_lsn: 2000,
                    log_clients: 1,
                    system_page_size: 4096,
                    log_page_size: 4096,
                },
            ],
            record_page_count: 100,
            has_gaps: false,
            highest_lsn: 5000,
        };
        assert!(!detect_journal_clearing(&summary));
    }

    #[test]
    fn test_detect_journal_clearing_empty_restart_areas() {
        let summary = LogFileSummary {
            restart_areas: vec![],
            record_page_count: 0,
            has_gaps: false,
            highest_lsn: 0,
        };
        assert!(detect_journal_clearing(&summary));
    }

    #[test]
    fn test_detect_journal_clearing_one_restart_area() {
        // 1 restart area (not 2) but no gaps - not detected as clearing
        let summary = LogFileSummary {
            restart_areas: vec![RestartArea {
                offset: 0,
                current_lsn: 1000,
                log_clients: 1,
                system_page_size: 4096,
                log_page_size: 4096,
            }],
            record_page_count: 50,
            has_gaps: false,
            highest_lsn: 5000,
        };
        assert!(!detect_journal_clearing(&summary));
    }

    #[test]
    fn test_detect_journal_clearing_three_restart_areas() {
        // 3 restart areas (not 2) but no gaps
        let summary = LogFileSummary {
            restart_areas: vec![
                RestartArea {
                    offset: 0,
                    current_lsn: 1000,
                    log_clients: 1,
                    system_page_size: 4096,
                    log_page_size: 4096,
                },
                RestartArea {
                    offset: 4096,
                    current_lsn: 2000,
                    log_clients: 1,
                    system_page_size: 4096,
                    log_page_size: 4096,
                },
                RestartArea {
                    offset: 8192,
                    current_lsn: 3000,
                    log_clients: 1,
                    system_page_size: 4096,
                    log_page_size: 4096,
                },
            ],
            record_page_count: 50,
            has_gaps: false,
            highest_lsn: 5000,
        };
        assert!(!detect_journal_clearing(&summary));
    }

    #[test]
    fn test_parse_logfile_empty() {
        let summary = parse_logfile(&[]).unwrap();
        assert_eq!(summary.restart_areas.len(), 0);
        assert_eq!(summary.record_page_count, 0);
        assert!(!summary.has_gaps);
        assert_eq!(summary.highest_lsn, 0);
    }

    #[test]
    fn test_parse_logfile_only_rcrd_pages() {
        let mut data = Vec::new();
        data.extend_from_slice(&make_rcrd_page(1000));
        data.extend_from_slice(&make_rcrd_page(2000));
        data.extend_from_slice(&make_rcrd_page(3000));

        let summary = parse_logfile(&data).unwrap();
        assert_eq!(summary.restart_areas.len(), 0);
        assert_eq!(summary.record_page_count, 3);
        assert_eq!(summary.highest_lsn, 3000);
    }

    #[test]
    fn test_parse_logfile_gap_detection() {
        // RSTR, RSTR, RCRD, RCRD, non-RCRD/non-zero page, RCRD
        // Gap should be detected at the non-RCRD page
        let mut data = Vec::new();
        data.extend_from_slice(&make_rstr_page(1000));
        data.extend_from_slice(&make_rstr_page(2000));
        data.extend_from_slice(&make_rcrd_page(3000));

        // Create a non-zero, non-RCRD, non-RSTR page (looks like corruption)
        let mut garbage_page = vec![0xDEu8; LOG_PAGE_SIZE];
        garbage_page[0..4].copy_from_slice(b"JUNK");
        data.extend_from_slice(&garbage_page);

        data.extend_from_slice(&make_rcrd_page(5000));

        let summary = parse_logfile(&data).unwrap();
        assert!(summary.has_gaps);
    }

    #[test]
    fn test_parse_logfile_no_gap_for_zeroed_page() {
        // Zeroed pages after RCRD pages should NOT be treated as gaps
        let mut data = Vec::new();
        data.extend_from_slice(&make_rstr_page(1000));
        data.extend_from_slice(&make_rstr_page(2000));
        data.extend_from_slice(&make_rcrd_page(3000));
        data.extend_from_slice(&vec![0u8; LOG_PAGE_SIZE]); // zeroed page

        let summary = parse_logfile(&data).unwrap();
        assert!(!summary.has_gaps);
    }

    #[test]
    fn test_parse_logfile_restart_area_lsn_tracking() {
        let mut data = Vec::new();
        data.extend_from_slice(&make_rstr_page(5000));
        data.extend_from_slice(&make_rstr_page(3000));
        data.extend_from_slice(&make_rcrd_page(4000));

        let summary = parse_logfile(&data).unwrap();
        assert_eq!(summary.highest_lsn, 5000);
        assert_eq!(summary.restart_areas.len(), 2);
        assert_eq!(summary.restart_areas[0].current_lsn, 5000);
        assert_eq!(summary.restart_areas[1].current_lsn, 3000);
    }

    #[test]
    fn test_parse_logfile_short_rstr_page() {
        // A page with RSTR signature but too small for full header
        let mut data = vec![0u8; LOG_PAGE_SIZE];
        data[0..4].copy_from_slice(RSTR_SIGNATURE);
        // Only write signature, not enough data for header fields at 0x08..0x28
        // But we set the full page so offset + 0x28 <= data.len() is true
        // The actual data at those offsets will be zeros, which is still valid

        let summary = parse_logfile(&data).unwrap();
        assert_eq!(summary.restart_areas.len(), 1);
        assert_eq!(summary.restart_areas[0].current_lsn, 0);
    }

    #[test]
    fn test_parse_logfile_page_offset_boundary() {
        // Line 61: page_offset + 4 > data.len() break condition
        // This is tricky because page_count = data.len() / LOG_PAGE_SIZE,
        // so page_offset = page_idx * LOG_PAGE_SIZE is always <= data.len() - LOG_PAGE_SIZE.
        // For page_offset + 4 > data.len(), we'd need data.len() < page_offset + 4.
        // Since page_offset < data.len() (because page_idx < page_count and
        // page_count = data.len() / LOG_PAGE_SIZE), page_offset is at most
        // data.len() - LOG_PAGE_SIZE. And LOG_PAGE_SIZE (4096) >> 4.
        // So line 61 is effectively unreachable with the current loop bounds.
        // Still, let's add a test for the edge case of exactly one page.
        let data = make_rcrd_page(5000);
        assert_eq!(data.len(), LOG_PAGE_SIZE);
        let summary = parse_logfile(&data).unwrap();
        assert_eq!(summary.record_page_count, 1);
        assert_eq!(summary.highest_lsn, 5000);
    }

    #[test]
    fn test_parse_logfile_data_smaller_than_page() {
        // Data that's not a full page
        let data = vec![0xAAu8; 100];
        let summary = parse_logfile(&data).unwrap();
        assert_eq!(summary.restart_areas.len(), 0);
        assert_eq!(summary.record_page_count, 0);
    }

    #[test]
    fn test_parse_logfile_boundary_check_line_61() {
        // Line 61: page_offset + 4 > data.len() break
        // This line is unreachable with current loop bounds because:
        //   page_count = data.len() / LOG_PAGE_SIZE
        //   page_offset = page_idx * LOG_PAGE_SIZE (max = (page_count-1) * LOG_PAGE_SIZE)
        //   So page_offset <= data.len() - LOG_PAGE_SIZE, and LOG_PAGE_SIZE (4096) >> 4.
        // Exercise the closest boundary: data.len() exactly equals one page.
        let data = vec![0u8; LOG_PAGE_SIZE];
        let summary = parse_logfile(&data).unwrap();
        // All zeros -> no RSTR or RCRD signatures
        assert_eq!(summary.restart_areas.len(), 0);
        assert_eq!(summary.record_page_count, 0);
        assert!(!summary.has_gaps);
    }

    #[test]
    fn test_parse_logfile_gap_not_flagged_early_pages() {
        // Covers line 120: the condition page_idx > 2 prevents false gap detection
        // for the very first pages. Build data: RCRD page 0, then garbage page 1.
        // Since page_idx=1 which is <= 2, no gap should be flagged.
        let mut data = Vec::new();
        data.extend_from_slice(&make_rcrd_page(1000)); // page 0
        let mut garbage = vec![0xDEu8; LOG_PAGE_SIZE];
        garbage[0..4].copy_from_slice(b"JUNK");
        data.extend_from_slice(&garbage); // page 1

        let summary = parse_logfile(&data).unwrap();
        assert!(!summary.has_gaps);
    }

    #[test]
    fn test_parse_logfile_rstr_too_short_for_header() {
        // Test RSTR page where page_offset + 0x28 > data.len() is false
        // but then we need the opposite: page_offset + 0x28 > data.len()
        // This can't happen with full pages since LOG_PAGE_SIZE (4096) >> 0x28.
        // Exercise: a full RSTR page that has a zero LSN.
        let mut data = make_rstr_page(0);
        // Override the LSN to zero - should track as highest_lsn = 0
        data[0x08..0x10].copy_from_slice(&0u64.to_le_bytes());

        let summary = parse_logfile(&data).unwrap();
        assert_eq!(summary.restart_areas.len(), 1);
        assert_eq!(summary.restart_areas[0].current_lsn, 0);
        assert_eq!(summary.highest_lsn, 0);
    }
}
