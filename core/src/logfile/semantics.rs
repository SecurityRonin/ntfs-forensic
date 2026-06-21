//! Semantic interpretation of `$LogFile` LFS records as file operations.
//!
//! [`parse_log_records`](super::parse_log_records) decodes the raw redo/undo
//! [`LogOp`](super::LogOp) vocabulary; this layer maps each record's
//! `(redo, undo)` operation pair to the higher-level **file operation** it
//! effects — file creation, deletion, rename, data write, attribute change,
//! index change, or transaction control.
//!
//! ## Why the mapping is per-opcode, not fixture-keyed
//!
//! In the NTFS Log File Service every redo opcode names a *structural* mutation
//! of an on-disk object (an FRS, an attribute, an index entry, a bitmap), and
//! the undo opcode names its inverse. The operation class is therefore intrinsic
//! to the opcode pair, independent of which file or image produced it. The
//! groupings below are transcribed from two independent references:
//!
//! - **msuhanov, `dfir_ntfs/LogFile.py`** — the maintained NTFS journal parser
//!   used in DFIR. Its `LOGGED_RESIDENT_UPDATES` / `LOGGED_NONRESIDENT_UPDATES`
//!   lists and `NTFSOperations` table classify each opcode by what it mutates.
//!   <https://github.com/msuhanov/dfir_ntfs/blob/master/dfir_ntfs/LogFile.py>
//! - **jschicht, `LogFileParser`** — `_SanityTest1` enumerates the *valid*
//!   `(redo, undo)` pairings (e.g. `CreateAttribute`↔`DeleteAttribute`,
//!   `AddIndexEntryAllocation`↔`DeleteIndexEntryAllocation`,
//!   `UpdateFileNameAllocation`↔self), which is the authority for how the redo
//!   and undo opcodes compose.
//!   <https://github.com/jschicht/LogFileParser/blob/master/LogFileParser.au3>
//! - **Brian Carrier, *File System Forensic Analysis* (2005), ch. 13 "NTFS
//!   Application Category" / the `$LogFile` redo/undo discussion** — the primary
//!   forensic reference for `InitializeFileRecordSegment` ⇒ file creation and
//!   `DeallocateFileRecordSegment` ⇒ file deletion.
//!
//! A record whose redo *and* undo opcodes are both documented but whose pair is
//! not a recognised file operation surfaces the raw `(redo_code, undo_code)`
//! verbatim via [`FileOperation::Unknown`] — the bytes are never dropped.

use super::{LogOp, LogRecord};

/// A higher-level file operation reconstructed from a `$LogFile` LFS record's
/// `(redo, undo)` operation pair.
///
/// The taxonomy follows the structural mutation each redo opcode performs (see
/// the module docs for the per-opcode source citations). It is deliberately
/// coarse: one variant per class of on-disk effect a forensic timeline cares
/// about, not one per raw opcode (that vocabulary is [`LogOp`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileOperation {
    /// A file record segment was initialized — a new MFT entry, i.e. file/dir
    /// **creation** (`InitializeFileRecordSegment`, redo 0x02).
    Create,
    /// A file record segment was freed — file/dir **deletion**
    /// (`DeallocateFileRecordSegment`, redo 0x03).
    Delete,
    /// A `$FILE_NAME` in a directory index was updated in place — a **rename /
    /// move** (or an in-index timestamp/size update). `UpdateFileNameRoot`
    /// (0x13) / `UpdateFileNameAllocation` (0x14), each self-paired.
    Rename,
    /// A name was **inserted** into a directory index — the create side of a
    /// link/rename. `AddIndexEntryRoot` (0x0C) / `AddIndexEntryAllocation`
    /// (0x0E).
    IndexInsert,
    /// A name was **removed** from a directory index — the delete side of an
    /// unlink/rename. `DeleteIndexEntryRoot` (0x0D) /
    /// `DeleteIndexEntryAllocation` (0x0F).
    IndexDelete,
    /// A new attribute was added to a file record (`CreateAttribute`, 0x05).
    AttributeCreate,
    /// An attribute was removed from a file record (`DeleteAttribute`, 0x06).
    AttributeDelete,
    /// An attribute's logical/allocated/initialized sizes changed — a file
    /// **resize** (`SetNewAttributeSizes`, 0x0B).
    Resize,
    /// Attribute **data** (resident or non-resident) was written: a content
    /// update, run-list / VCN mapping change, or index-buffer write.
    /// `UpdateResidentValue` (0x07), `UpdateNonResidentValue` (0x08),
    /// `UpdateMappingPairs` (0x09), `WriteEndOfFileRecordSegment` (0x04),
    /// `WriteEndOfIndexBuffer` (0x10), `SetIndexEntryVcnRoot` (0x11),
    /// `SetIndexEntryVcnAllocation` (0x12), `UpdateRecordDataRoot` (0x21),
    /// `UpdateRecordDataAllocation` (0x22).
    DataWrite,
    /// A cluster/MFT-allocation **bitmap** bit was set, cleared, or clusters
    /// marked dirty — space (de)allocation. `SetBitsInNonResidentBitMap`
    /// (0x15), `ClearBitsInNonResidentBitMap` (0x16), `DeleteDirtyClusters`
    /// (0x0A).
    BitmapAllocation,
    /// Transaction-boundary control, not an on-disk file mutation:
    /// `EndTopLevelAction` (0x18), `PrepareTransaction` (0x19),
    /// `CommitTransaction` (0x1A), `ForgetTransaction` (0x1B),
    /// `CompensationLogRecord` (0x01).
    TransactionControl,
    /// A restart-area / open-attribute-table / dirty-page / transaction-table
    /// **dump** or hot-fix — log housekeeping that records no file change.
    /// `HotFix` (0x17), `OpenNonResidentAttribute` (0x1C),
    /// `OpenAttributeTableDump` (0x1D), `AttributeNamesDump` (0x1E),
    /// `DirtyPageTableDump` (0x1F), `TransactionTableDump` (0x20).
    TableDump,
    /// A no-op log record (`Noop`, redo 0x00 with no undo effect).
    Noop,
    /// The `(redo, undo)` opcode pair is not a recognised file operation. The
    /// raw codes are surfaced verbatim — `(redo_code, undo_code)` — so an
    /// investigator can identify the operation themselves (never dropped).
    Unknown(u16, u16),
}

impl FileOperation {
    /// Classify a single decoded LFS [`LogRecord`] into its file operation.
    ///
    /// The redo opcode names the operation; the undo opcode is the inverse the
    /// recovery pass would apply. A `Noop` redo paired with a substantive undo
    /// (the form NTFS uses to log a pure deallocation) is classified by the
    /// undo. Any pair outside the documented map yields
    /// [`FileOperation::Unknown`] carrying both raw codes.
    #[must_use]
    pub fn classify(record: &LogRecord) -> Self {
        classify(record.redo_op, record.undo_op)
    }
}

/// Core `(redo, undo)` → [`FileOperation`] map. Separated from
/// [`FileOperation::classify`] so it can be unit-tested on bare opcode pairs
/// without constructing a full [`LogRecord`].
#[must_use]
pub fn classify(redo: LogOp, undo: LogOp) -> FileOperation {
    let _ = (redo, undo);
    unimplemented!("RED: semantic (redo,undo) -> FileOperation mapping not yet written")
}

#[cfg(any())]
#[must_use]
fn classify_impl(redo: LogOp, undo: LogOp) -> FileOperation {
    use FileOperation as F;
    use LogOp as O;

    match redo {
        O::InitializeFileRecordSegment => F::Create,
        O::DeallocateFileRecordSegment => F::Delete,

        O::UpdateFileNameRoot | O::UpdateFileNameAllocation => F::Rename,

        O::AddIndexEntryRoot | O::AddIndexEntryAllocation => F::IndexInsert,
        O::DeleteIndexEntryRoot | O::DeleteIndexEntryAllocation => F::IndexDelete,

        O::CreateAttribute => F::AttributeCreate,
        O::DeleteAttribute => F::AttributeDelete,
        O::SetNewAttributeSizes => F::Resize,

        O::UpdateResidentValue
        | O::UpdateNonResidentValue
        | O::UpdateMappingPairs
        | O::WriteEndOfFileRecordSegment
        | O::WriteEndOfIndexBuffer
        | O::SetIndexEntryVcnRoot
        | O::SetIndexEntryVcnAllocation
        | O::UpdateRecordDataRoot
        | O::UpdateRecordDataAllocation => F::DataWrite,

        O::SetBitsInNonResidentBitMap
        | O::ClearBitsInNonResidentBitMap
        | O::DeleteDirtyClusters => F::BitmapAllocation,

        O::EndTopLevelAction
        | O::PrepareTransaction
        | O::CommitTransaction
        | O::ForgetTransaction
        | O::CompensationLogRecord => F::TransactionControl,

        O::HotFix
        | O::OpenNonResidentAttribute
        | O::OpenAttributeTableDump
        | O::AttributeNamesDump
        | O::DirtyPageTableDump
        | O::TransactionTableDump => F::TableDump,

        // A bare `Noop` redo with a substantive undo is how NTFS logs a pure
        // deallocation (LogFileParser `_SanityTest1`: `Undo =
        // DeallocateFileRecordSegment` requires `Redo = Noop`). Classify by the
        // undo so the deletion is not lost as a Noop.
        O::Noop => match undo {
            O::Noop => F::Noop,
            O::DeallocateFileRecordSegment => F::Delete,
            O::DeleteIndexEntryRoot | O::DeleteIndexEntryAllocation => F::IndexDelete,
            O::DeleteAttribute => F::AttributeDelete,
            O::Unknown(u) => F::Unknown(0x00, u),
            other => F::Unknown(0x00, other.code()),
        },

        O::Unknown(r) => F::Unknown(r, undo.code()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logfile::RecordPage;

    // Each test cites the authoritative source for the (redo, undo) → operation
    // mapping it asserts. Sources: msuhanov dfir_ntfs/LogFile.py (LOGGED_*_UPDATES,
    // NTFSOperations); jschicht LogFileParser _SanityTest1 (valid redo/undo pairs);
    // Carrier, File System Forensic Analysis ch. 13 (Init/Dealloc ⇒ create/delete).

    /// Carrier ch.13: `InitializeFileRecordSegment` allocates and initializes a
    /// new FRS ⇒ file creation. dfir_ntfs lists it in LOGGED_RESIDENT_UPDATES.
    #[test]
    fn initialize_file_record_segment_is_create() {
        assert_eq!(
            classify(LogOp::InitializeFileRecordSegment, LogOp::Noop),
            FileOperation::Create
        );
    }

    /// Carrier ch.13: `DeallocateFileRecordSegment` frees an FRS ⇒ file deletion.
    #[test]
    fn deallocate_file_record_segment_is_delete() {
        assert_eq!(
            classify(LogOp::DeallocateFileRecordSegment, LogOp::Noop),
            FileOperation::Delete
        );
    }

    /// LogFileParser `_SanityTest1`: a pure deallocation is logged as
    /// `Redo = Noop`, `Undo = DeallocateFileRecordSegment` — classified by undo.
    #[test]
    fn noop_redo_dealloc_undo_is_delete() {
        assert_eq!(
            classify(LogOp::Noop, LogOp::DeallocateFileRecordSegment),
            FileOperation::Delete
        );
    }

    /// LogFileParser `_SanityTest1` (#13/#14): UpdateFileName{Root,Allocation}
    /// are self-paired and update the `$FILE_NAME` held in a directory index ⇒
    /// rename / move.
    #[test]
    fn update_file_name_is_rename() {
        assert_eq!(
            classify(LogOp::UpdateFileNameRoot, LogOp::UpdateFileNameRoot),
            FileOperation::Rename
        );
        assert_eq!(
            classify(
                LogOp::UpdateFileNameAllocation,
                LogOp::UpdateFileNameAllocation
            ),
            FileOperation::Rename
        );
    }

    /// LogFileParser `_SanityTest1` (#4/#5): AddIndexEntry{Root,Allocation} pair
    /// with the corresponding Delete; the redo inserts a name into a directory
    /// index.
    #[test]
    fn add_index_entry_is_index_insert() {
        assert_eq!(
            classify(LogOp::AddIndexEntryRoot, LogOp::DeleteIndexEntryRoot),
            FileOperation::IndexInsert
        );
        assert_eq!(
            classify(
                LogOp::AddIndexEntryAllocation,
                LogOp::DeleteIndexEntryAllocation
            ),
            FileOperation::IndexInsert
        );
    }

    /// LogFileParser `_SanityTest1` (#4/#5): DeleteIndexEntry{Root,Allocation}
    /// remove a name from a directory index.
    #[test]
    fn delete_index_entry_is_index_delete() {
        assert_eq!(
            classify(LogOp::DeleteIndexEntryRoot, LogOp::AddIndexEntryRoot),
            FileOperation::IndexDelete
        );
        assert_eq!(
            classify(
                LogOp::DeleteIndexEntryAllocation,
                LogOp::AddIndexEntryAllocation
            ),
            FileOperation::IndexDelete
        );
    }

    /// LogFileParser `_SanityTest1` (#6): CreateAttribute ↔ DeleteAttribute.
    #[test]
    fn create_and_delete_attribute() {
        assert_eq!(
            classify(LogOp::CreateAttribute, LogOp::DeleteAttribute),
            FileOperation::AttributeCreate
        );
        assert_eq!(
            classify(LogOp::DeleteAttribute, LogOp::CreateAttribute),
            FileOperation::AttributeDelete
        );
    }

    /// dfir_ntfs `_Decode_SetNewAttributeSize`: SetNewAttributeSizes carries the
    /// new alloc/real/initialized sizes ⇒ a resize.
    #[test]
    fn set_new_attribute_sizes_is_resize() {
        assert_eq!(
            classify(LogOp::SetNewAttributeSizes, LogOp::SetNewAttributeSizes),
            FileOperation::Resize
        );
    }

    /// dfir_ntfs LOGGED_RESIDENT_UPDATES / LOGGED_NONRESIDENT_UPDATES: these
    /// opcodes write attribute data (resident $MFT bytes or nonresident clusters)
    /// or index-buffer content ⇒ data write.
    #[test]
    fn value_and_mapping_updates_are_data_write() {
        for redo in [
            LogOp::UpdateResidentValue,
            LogOp::UpdateNonResidentValue,
            LogOp::UpdateMappingPairs,
            LogOp::WriteEndOfFileRecordSegment,
            LogOp::WriteEndOfIndexBuffer,
            LogOp::SetIndexEntryVcnRoot,
            LogOp::SetIndexEntryVcnAllocation,
            LogOp::UpdateRecordDataRoot,
            LogOp::UpdateRecordDataAllocation,
        ] {
            assert_eq!(classify(redo, redo), FileOperation::DataWrite, "{redo:?}");
        }
    }

    /// LogFileParser `_SanityTest1` (#7): SetBits ↔ ClearBits in the nonresident
    /// bitmap; DeleteDirtyClusters marks clusters dirty. All are space
    /// (de)allocation, not a file-content change.
    #[test]
    fn bitmap_and_dirty_clusters_are_bitmap_allocation() {
        assert_eq!(
            classify(
                LogOp::SetBitsInNonResidentBitMap,
                LogOp::ClearBitsInNonResidentBitMap
            ),
            FileOperation::BitmapAllocation
        );
        assert_eq!(
            classify(
                LogOp::ClearBitsInNonResidentBitMap,
                LogOp::SetBitsInNonResidentBitMap
            ),
            FileOperation::BitmapAllocation
        );
        assert_eq!(
            classify(LogOp::DeleteDirtyClusters, LogOp::Noop),
            FileOperation::BitmapAllocation
        );
    }

    /// flatcap NTFS recovery doc + LogFileParser: these mark transaction
    /// boundaries (prepare/commit/forget/end-top-level) or an undo
    /// (CompensationLogRecord), not an on-disk file mutation.
    #[test]
    fn transaction_boundaries_are_transaction_control() {
        for redo in [
            LogOp::EndTopLevelAction,
            LogOp::PrepareTransaction,
            LogOp::CommitTransaction,
            LogOp::ForgetTransaction,
            LogOp::CompensationLogRecord,
        ] {
            assert_eq!(
                classify(redo, LogOp::Noop),
                FileOperation::TransactionControl,
                "{redo:?}"
            );
        }
    }

    /// dfir_ntfs NTFSOperations: the *Dump and HotFix opcodes are log
    /// housekeeping (restart-area / table snapshots) recording no file change.
    #[test]
    fn dumps_and_hotfix_are_table_dump() {
        for redo in [
            LogOp::HotFix,
            LogOp::OpenNonResidentAttribute,
            LogOp::OpenAttributeTableDump,
            LogOp::AttributeNamesDump,
            LogOp::DirtyPageTableDump,
            LogOp::TransactionTableDump,
        ] {
            assert_eq!(
                classify(redo, LogOp::Noop),
                FileOperation::TableDump,
                "{redo:?}"
            );
        }
    }

    /// A `Noop`/`Noop` record is a genuine no-op.
    #[test]
    fn noop_pair_is_noop() {
        assert_eq!(classify(LogOp::Noop, LogOp::Noop), FileOperation::Noop);
    }

    /// Show-the-unrecognized-value: an undocumented redo opcode surfaces both raw
    /// codes verbatim, never silently dropped.
    #[test]
    fn unknown_redo_surfaces_both_raw_codes() {
        assert_eq!(
            classify(LogOp::Unknown(0x40), LogOp::CommitTransaction),
            FileOperation::Unknown(0x40, 0x1A)
        );
    }

    /// A `Noop` redo paired with an *undocumented* undo also surfaces both codes.
    #[test]
    fn noop_redo_unknown_undo_surfaces_codes() {
        assert_eq!(
            classify(LogOp::Noop, LogOp::Unknown(0x55)),
            FileOperation::Unknown(0x00, 0x55)
        );
    }

    /// A `Noop` redo paired with a documented-but-unmapped undo (e.g. an
    /// UpdateResidentValue undo with a Noop redo, which NTFS does not emit)
    /// surfaces both real codes rather than misclassifying.
    #[test]
    fn noop_redo_unmapped_known_undo_surfaces_codes() {
        assert_eq!(
            classify(LogOp::Noop, LogOp::UpdateResidentValue),
            FileOperation::Unknown(0x00, 0x07)
        );
    }

    /// The `FileOperation::classify` convenience wraps a full `LogRecord`.
    #[test]
    fn classify_over_log_record() {
        let rec = LogRecord {
            page_offset: 0x40,
            this_lsn: 1,
            client_previous_lsn: 0,
            client_undo_next_lsn: 0,
            record_type: 1,
            transaction_id: 0,
            redo_op: LogOp::InitializeFileRecordSegment,
            undo_op: LogOp::Noop,
            target_attribute: 0,
            mft_cluster_index: 0,
            target_vcn: 0,
        };
        assert_eq!(FileOperation::classify(&rec), FileOperation::Create);
        // The record is unused beyond its op pair; touch a field so the borrow is
        // meaningful and the helper is exercised end-to-end.
        let _ = RecordPage {
            offset: 0,
            last_lsn: 1,
            data: vec![],
        };
    }
}
