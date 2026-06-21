//! Transaction reconstruction over decoded `$LogFile` LFS records.
//!
//! [`parse_log_records`](super::parse_log_records) decodes individual redo/undo
//! records; [`classify`](super::classify) labels each record's file operation.
//! This layer groups those records into the unit a forensic analyst actually
//! reasons about: a **transaction** — a single user/OS action whose redo/undo
//! records are committed (and applied) or rolled back as one atom.
//!
//! ## `transaction_id` is a reused table slot, not a unique id
//!
//! Every LFS client record carries a 4-byte field at offset `0x24` of the record
//! header that the Microsoft `LFS_RECORD` layout labels `TransactionId`. It is
//! tempting to read this as a unique per-transaction identifier and group on it
//! directly — but on real volumes it is **low-cardinality and reused**: it is the
//! index of the transaction's entry in NTFS's in-memory *open transaction table*,
//! and that slot is recycled as transactions commit and new ones begin. On the
//! real CITADEL-DC01 `$LogFile` there are only **8 distinct values** across 78,765
//! records (the busiest slot holds 26,274), so a single value spans thousands of
//! distinct logical transactions. Grouping purely on `transaction_id` therefore
//! yields a handful of giant *slot* groups, not transactions.
//!
//! The correct model is two-level:
//!
//! 1. **Slot** — partition records by `transaction_id` (the table slot). This is
//!    exactly what `LogFileParser`'s `lf_transaction_id` column reports, and the
//!    slot grouping is validated Tier-1 against it (per-slot LSN membership).
//! 2. **Transaction** — *within* each slot, in LSN order, a transaction is the run
//!    of records up to and including a **terminal**: `CommitTransaction` (0x1A) or
//!    `ForgetTransaction` (0x1B). A new run begins after each terminal (the slot is
//!    reused). A `CompensationLogRecord` (0x01) seen as a redo within a run marks
//!    that transaction [`TransactionState::Aborted`]; a run sealed by a terminal is
//!    [`TransactionState::Committed`] (a terminal wins over a compensation); a
//!    trailing run with no terminal is [`TransactionState::Incomplete`].
//!
//! Records of concurrent transactions are interleaved in LSN order across slots,
//! so contiguity in the global stream does not bound a transaction; the slot plus
//! the terminal does. The `client_previous_lsn` / `client_undo_next_lsn`
//! back-pointers are the redo/undo *replay* chain, not the grouping key.
//!
//! Sources for the model:
//!
//! - **Microsoft `LFS_RECORD` / flatcap `linux-ntfs` `$LogFile` docs** —
//!   `TransactionId` at offset `0x24`; the open-transaction-table / restart model.
//!   <https://flatcap.github.io/linux-ntfs/ntfs/files/logfile.html>
//! - **`TZWorks` `mala` users guide** — records of concurrent transactions are
//!   interleaved; the previous-record pointer chains a transaction but adjacency
//!   does not bound it.
//!   <https://tzworks.com/prototypes/mala/mala.users.guide.pdf>
//! - **msuhanov `dfir_ntfs/LogFile.py`** — `get_transaction_id()` is the table
//!   slot; the transaction table is implied from the log records, not a unique id.
//!   <https://github.com/msuhanov/dfir_ntfs/blob/master/dfir_ntfs/LogFile.py>
//! - **Brian Carrier, *File System Forensic Analysis* (2005), ch. 13** — the
//!   redo/undo transaction model and commit/abort recovery passes.
//!
//! ## Why the terminal is read on the *redo* opcode
//!
//! NTFS writes a `ForgetTransaction` record with `undo = CompensationLogRecord`
//! (its inverse). Terminal/abort detection therefore reads the **redo** opcode —
//! the operation the record performs — never the undo field, or every
//! Forget-sealed transaction would falsely look aborted.

use super::{LogOp, LogRecord};

/// The recovery disposition of a reconstructed [`Transaction`], derived from the
/// terminal / compensation opcode that bounds its run within a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionState {
    /// A `CommitTransaction` (0x1A) or `ForgetTransaction` (0x1B) record sealed
    /// the run — its redo records were applied (or are replayable). A terminal
    /// seal wins even if the run also carried a compensation (sub-action undo).
    Committed,
    /// A `CompensationLogRecord` (0x01) redo appeared in the run with no
    /// terminal — the transaction was rolled back, its effects undone.
    Aborted,
    /// The trailing run of a slot ended without a terminal: the records exist but
    /// the commit/forget that would seal them was not recovered (e.g. the log
    /// wrapped over it in the circular buffer). The final disposition is unknown.
    Incomplete,
}

/// One terminal-bounded run of `$LogFile` LFS records within a transaction-table
/// slot — a single logical transaction (one user/OS action) NTFS commits or rolls
/// back as a whole.
///
/// `transaction_id` is the *slot* the run occupied (the reused
/// open-transaction-table index, LFS header offset `0x24`); many [`Transaction`]s
/// can share one `transaction_id`. `records` holds **indices into the slice passed
/// to [`reconstruct_transactions`]**, ascending by LSN (replay order); `lsns`
/// carries each record's `this_lsn` (the run's LSN set, comparable against an
/// oracle without re-indexing); `operations` is the parallel
/// [`FileOperation`](super::FileOperation) classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// The transaction-table **slot** this run occupied (LFS header offset
    /// `0x24`). Reused across transactions — not a unique transaction id.
    pub transaction_id: u32,
    /// Indices into the source record slice, ascending by LSN.
    pub records: Vec<usize>,
    /// Each member record's `this_lsn`, ascending — the run's LSN set.
    pub lsns: Vec<u64>,
    /// Per-record file-operation classification, parallel to `records`.
    pub operations: Vec<super::FileOperation>,
    /// Recovery disposition derived from the terminal / compensation opcode.
    pub state: TransactionState,
}

/// Reconstruct individual transactions from decoded LFS [`LogRecord`]s.
///
/// Partitions records by `transaction_id` (the transaction-table slot), then
/// within each slot — in ascending `this_lsn` (replay) order — splits the stream
/// into transactions at each terminal (`CommitTransaction` 0x1A /
/// `ForgetTransaction` 0x1B). Each emitted [`Transaction`] is one terminal-bounded
/// run (or the trailing un-terminated run), classified [`TransactionState`] from
/// its terminal / `CompensationLogRecord` (0x01) redo.
///
/// Returned transactions are ordered by the lowest LSN they contain, so the
/// output reads in log order. Every input record lands in exactly one
/// transaction — none is dropped, including transaction-control records and
/// records whose opcode is [`LogOp::Unknown`].
#[must_use]
pub fn reconstruct_transactions(records: &[LogRecord]) -> Vec<Transaction> {
    use std::collections::HashMap;

    // Level 1 — partition record indices by transaction-table slot.
    let mut slots: HashMap<u32, Vec<usize>> = HashMap::new();
    for (idx, rec) in records.iter().enumerate() {
        slots.entry(rec.transaction_id).or_default().push(idx);
    }

    let mut txns: Vec<Transaction> = Vec::new();
    for (transaction_id, mut indices) in slots {
        // Replay order within the slot.
        indices.sort_by_key(|&i| records[i].this_lsn);
        // RED placeholder: whole-slot grouping (the flawed model) — does not split
        // at terminals, so the split tests fail until GREEN.
        txns.push(build_transaction(
            transaction_id,
            indices,
            records,
            TransactionState::Committed,
        ));
    }

    // Log order: by the lowest LSN each transaction owns. Every run is non-empty
    // by construction, so `first` is always present.
    txns.sort_by_key(|t| t.lsns.first().copied().unwrap_or(u64::MAX));
    txns
}

/// Assemble a [`Transaction`] from an LSN-ordered run of record indices.
fn build_transaction(
    transaction_id: u32,
    records_idx: Vec<usize>,
    all: &[LogRecord],
    state: TransactionState,
) -> Transaction {
    let mut lsns = Vec::with_capacity(records_idx.len());
    let mut operations = Vec::with_capacity(records_idx.len());
    for &i in &records_idx {
        lsns.push(all[i].this_lsn);
        operations.push(super::classify(all[i].redo_op, all[i].undo_op));
    }
    Transaction {
        transaction_id,
        records: records_idx,
        lsns,
        operations,
        state,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logfile::FileOperation;

    /// Build a minimal [`LogRecord`] carrying just the fields transaction
    /// reconstruction reads: LSN, transaction-table slot, redo/undo opcodes.
    fn rec(this_lsn: u64, slot: u32, redo: LogOp, undo: LogOp) -> LogRecord {
        LogRecord {
            page_offset: 0,
            this_lsn,
            client_previous_lsn: 0,
            client_undo_next_lsn: 0,
            record_type: 1,
            transaction_id: slot,
            redo_op: redo,
            undo_op: undo,
            target_attribute: 0,
            mft_cluster_index: 0,
            target_vcn: 0,
        }
    }

    // ── terminal split (the corrected model) ─────────────────────────────────

    // A slot reused across two committed transactions splits into TWO
    // transactions at each ForgetTransaction terminal, NOT one slot-group.
    #[test]
    fn reused_slot_splits_into_two_transactions() {
        let recs = vec![
            rec(10, 0x40, LogOp::InitializeFileRecordSegment, LogOp::Noop),
            rec(
                11,
                0x40,
                LogOp::ForgetTransaction,
                LogOp::CompensationLogRecord,
            ),
            rec(12, 0x40, LogOp::CreateAttribute, LogOp::DeleteAttribute),
            rec(
                13,
                0x40,
                LogOp::ForgetTransaction,
                LogOp::CompensationLogRecord,
            ),
        ];
        let txns = reconstruct_transactions(&recs);
        assert_eq!(txns.len(), 2, "one slot, two terminals => two transactions");
        assert_eq!(txns[0].lsns, vec![10, 11]);
        assert_eq!(txns[0].state, TransactionState::Committed);
        assert_eq!(txns[1].lsns, vec![12, 13]);
        assert_eq!(txns[1].state, TransactionState::Committed);
        // Both carry the same reused slot.
        assert_eq!(txns[0].transaction_id, 0x40);
        assert_eq!(txns[1].transaction_id, 0x40);
    }

    // CommitTransaction (0x1A) is also a terminal.
    #[test]
    fn commit_is_a_terminal() {
        let recs = vec![
            rec(1, 5, LogOp::InitializeFileRecordSegment, LogOp::Noop),
            rec(2, 5, LogOp::CommitTransaction, LogOp::Noop),
            rec(3, 5, LogOp::CreateAttribute, LogOp::DeleteAttribute),
            rec(4, 5, LogOp::CommitTransaction, LogOp::Noop),
        ];
        let txns = reconstruct_transactions(&recs);
        assert_eq!(txns.len(), 2);
        assert!(txns.iter().all(|t| t.state == TransactionState::Committed));
    }

    // A Forget record's undo field is CompensationLogRecord by construction; it
    // must be read as Committed, NOT Aborted (terminal read on redo only).
    #[test]
    fn forget_with_compensation_undo_is_committed_not_aborted() {
        let recs = vec![rec(
            1,
            7,
            LogOp::ForgetTransaction,
            LogOp::CompensationLogRecord,
        )];
        let txns = reconstruct_transactions(&recs);
        assert_eq!(txns.len(), 1);
        assert_eq!(txns[0].state, TransactionState::Committed);
    }

    // A CompensationLogRecord redo with no terminal => Aborted.
    #[test]
    fn compensation_redo_without_terminal_is_aborted() {
        let recs = vec![
            rec(1, 9, LogOp::InitializeFileRecordSegment, LogOp::Noop),
            rec(2, 9, LogOp::CompensationLogRecord, LogOp::Noop),
        ];
        let txns = reconstruct_transactions(&recs);
        assert_eq!(txns.len(), 1);
        assert_eq!(txns[0].state, TransactionState::Aborted);
    }

    // A run that compensates a sub-action then commits is Committed (terminal
    // wins), and the compensation flag does not leak into the NEXT run.
    #[test]
    fn terminal_wins_over_compensation_and_flag_resets() {
        let recs = vec![
            rec(1, 3, LogOp::InitializeFileRecordSegment, LogOp::Noop),
            rec(2, 3, LogOp::CompensationLogRecord, LogOp::Noop),
            rec(3, 3, LogOp::CommitTransaction, LogOp::Noop),
            // Next run in the same slot: a clean incomplete trailing run.
            rec(4, 3, LogOp::CreateAttribute, LogOp::DeleteAttribute),
        ];
        let txns = reconstruct_transactions(&recs);
        assert_eq!(txns.len(), 2);
        assert_eq!(txns[0].lsns, vec![1, 2, 3]);
        assert_eq!(txns[0].state, TransactionState::Committed);
        // The trailing run must NOT inherit the previous run's compensation.
        assert_eq!(txns[1].lsns, vec![4]);
        assert_eq!(txns[1].state, TransactionState::Incomplete);
    }

    // Trailing records after the last terminal, with no compensation => Incomplete.
    #[test]
    fn trailing_run_without_terminal_is_incomplete() {
        let recs = vec![
            rec(1, 1, LogOp::InitializeFileRecordSegment, LogOp::Noop),
            rec(2, 1, LogOp::ForgetTransaction, LogOp::CompensationLogRecord),
            rec(3, 1, LogOp::CreateAttribute, LogOp::DeleteAttribute),
        ];
        let txns = reconstruct_transactions(&recs);
        assert_eq!(txns.len(), 2);
        assert_eq!(txns[1].lsns, vec![3]);
        assert_eq!(txns[1].state, TransactionState::Incomplete);
    }

    // ── slot grouping + interleaving ─────────────────────────────────────────

    // Records of two concurrent slots interleaved in LSN order split into the
    // correct per-slot transactions (the mala example, slot-keyed).
    #[test]
    fn separates_interleaved_slots() {
        let recs = vec![
            rec(21, 1, LogOp::InitializeFileRecordSegment, LogOp::Noop),
            rec(22, 1, LogOp::CreateAttribute, LogOp::DeleteAttribute),
            rec(23, 2, LogOp::InitializeFileRecordSegment, LogOp::Noop),
            rec(24, 1, LogOp::CommitTransaction, LogOp::Noop),
            rec(25, 2, LogOp::CreateAttribute, LogOp::DeleteAttribute),
            rec(26, 2, LogOp::CommitTransaction, LogOp::Noop),
        ];
        let txns = reconstruct_transactions(&recs);
        assert_eq!(txns.len(), 2);
        // Ordered by lowest LSN: slot 1's transaction first.
        assert_eq!(txns[0].transaction_id, 1);
        assert_eq!(txns[0].lsns, vec![21, 22, 24]);
        assert_eq!(txns[1].transaction_id, 2);
        assert_eq!(txns[1].lsns, vec![23, 25, 26]);
    }

    // Records must be held in ascending LSN order within a transaction even when
    // the source slice presents the slot's records out of order.
    #[test]
    fn orders_records_by_lsn_within_slot() {
        let recs = vec![
            rec(30, 5, LogOp::CommitTransaction, LogOp::Noop),
            rec(28, 5, LogOp::InitializeFileRecordSegment, LogOp::Noop),
            rec(29, 5, LogOp::CreateAttribute, LogOp::DeleteAttribute),
        ];
        let txns = reconstruct_transactions(&recs);
        assert_eq!(txns.len(), 1);
        assert_eq!(txns[0].lsns, vec![28, 29, 30]);
        assert_eq!(txns[0].records, vec![1, 2, 0]);
    }

    // Every input record lands in exactly one transaction — none dropped.
    #[test]
    fn assigns_every_record_exactly_once() {
        let recs = vec![
            rec(1, 1, LogOp::InitializeFileRecordSegment, LogOp::Noop),
            rec(2, 2, LogOp::InitializeFileRecordSegment, LogOp::Noop),
            rec(3, 1, LogOp::CommitTransaction, LogOp::Noop),
            rec(4, 3, LogOp::InitializeFileRecordSegment, LogOp::Noop),
        ];
        let txns = reconstruct_transactions(&recs);
        let total: usize = txns.iter().map(|t| t.records.len()).sum();
        assert_eq!(total, recs.len(), "no record dropped");
        let mut seen: Vec<usize> = txns
            .iter()
            .flat_map(|t| t.records.iter().copied())
            .collect();
        seen.sort_unstable();
        assert_eq!(seen, vec![0, 1, 2, 3], "each index assigned exactly once");
    }

    // operations is parallel to records and carries the classification.
    #[test]
    fn operations_parallel_records() {
        let recs = vec![
            rec(1, 9, LogOp::InitializeFileRecordSegment, LogOp::Noop),
            rec(2, 9, LogOp::CommitTransaction, LogOp::Noop),
        ];
        let txns = reconstruct_transactions(&recs);
        assert_eq!(
            txns[0].operations,
            vec![FileOperation::Create, FileOperation::TransactionControl]
        );
    }

    // An unrecognized opcode must not silently drop the record: a record with an
    // Unknown opcode is still grouped and counted.
    #[test]
    fn unknown_opcode_record_is_retained() {
        let recs = vec![
            rec(1, 6, LogOp::Unknown(0x40), LogOp::Unknown(0x41)),
            rec(2, 6, LogOp::CommitTransaction, LogOp::Noop),
        ];
        let txns = reconstruct_transactions(&recs);
        assert_eq!(txns.len(), 1);
        assert_eq!(txns[0].records.len(), 2);
        assert_eq!(txns[0].operations[0], FileOperation::Unknown(0x40, 0x41));
        assert_eq!(txns[0].state, TransactionState::Committed);
    }

    // EndTopLevelAction / PrepareTransaction are NOT terminals — a run carrying
    // only those is the trailing Incomplete run (no commit/forget/compensation).
    #[test]
    fn prepare_and_end_top_level_are_not_terminals() {
        let recs = vec![
            rec(1, 4, LogOp::PrepareTransaction, LogOp::Noop),
            rec(2, 4, LogOp::EndTopLevelAction, LogOp::Noop),
        ];
        let txns = reconstruct_transactions(&recs);
        assert_eq!(txns.len(), 1, "no terminal => single trailing run");
        assert_eq!(txns[0].state, TransactionState::Incomplete);
        assert_eq!(txns[0].records.len(), 2);
    }

    #[test]
    fn empty_input_yields_no_transactions() {
        assert!(reconstruct_transactions(&[]).is_empty());
    }
}
