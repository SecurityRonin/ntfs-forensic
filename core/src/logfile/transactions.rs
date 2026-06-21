//! Transaction reconstruction over decoded `$LogFile` LFS records.
//!
//! [`parse_log_records`](super::parse_log_records) decodes individual redo/undo
//! records; [`classify`](super::classify) labels each record's file operation.
//! This layer groups those records into the unit a forensic analyst actually
//! reasons about: a **transaction** — a single user/OS action whose redo/undo
//! records are committed (and applied) or rolled back as one atom.
//!
//! ## How NTFS groups records into a transaction
//!
//! Every LFS client record carries a 4-byte **`TransactionId`** at offset `0x24`
//! of the LFS record header, and per the Microsoft `LFS_RECORD` layout this field
//! "groups related records into a single transaction". A logical operation —
//! say a rename — emits several records (delete old index entry, delete old
//! `$FILE_NAME`, create new `$FILE_NAME`, add new index entry), all sharing one
//! `TransactionId`. Records for different concurrent transactions are
//! **interleaved** in LSN order, so contiguity does not bound a transaction;
//! the `TransactionId` does. Each record additionally back-chains to the
//! previous record of the same client via `ClientPreviousLsn` (offset `0x08`),
//! but that pointer is monotonic across *all* clients, not a per-transaction
//! delimiter — it is the redo/undo replay chain, not the grouping key.
//!
//! The grouping is therefore keyed on `transaction_id`, exactly as the
//! authoritative references describe:
//!
//! - **Microsoft `LFS_RECORD` / flatcap `linux-ntfs` `$LogFile` docs** —
//!   `TransactionId` (offset `0x24`, 4 bytes) "groups related records into a
//!   single transaction"; `ClientPreviousLsn`/`ClientUndoNextLsn` form the
//!   redo/undo replay chain.
//!   <https://flatcap.github.io/linux-ntfs/ntfs/files/logfile.html>
//! - **`TZWorks` `mala` users guide** — "each record has a pointer to the previous
//!   record in the chain for its transaction … consecutive records can be
//!   interleaved between multiple transactions"; the tool "groups the
//!   appropriate operations into their own separate transactions".
//!   <https://tzworks.com/prototypes/mala/mala.users.guide.pdf>
//! - **msuhanov `dfir_ntfs/LogFile.py`** — exposes `get_transaction_id()` and the
//!   `client_previous_lsn` / `client_undo_next_lsn` accessors; transactions are
//!   keyed by client id + transaction id.
//!   <https://github.com/msuhanov/dfir_ntfs/blob/master/dfir_ntfs/LogFile.py>
//! - **Brian Carrier, *File System Forensic Analysis* (2005), ch. 13** — the
//!   redo/undo transaction model and the commit/abort recovery passes.
//!
//! ## Transaction state
//!
//! NTFS's recovery distinguishes committed transactions (replay redo) from
//! uncommitted ones (replay undo / compensation). The bounding control opcodes
//! (no redo/undo payload of their own) are the state evidence in the log:
//!
//! - **`CommitTransaction` (0x1A)** seals the transaction; **`ForgetTransaction`
//!   (0x1B)** marks it fully complete and removable from the transaction table.
//!   Either ⇒ [`TransactionState::Committed`].
//! - **`CompensationLogRecord` (0x01)** is an undo/abort record written while
//!   rolling a transaction back. Present without a commit ⇒
//!   [`TransactionState::Aborted`].
//! - Neither seen ⇒ [`TransactionState::Incomplete`] — the records are present in
//!   the recovered log window but no commit/forget/compensation bounds them
//!   (e.g. a transaction whose boundary fell in an overwritten region of the
//!   circular buffer).
//!
//! `EndTopLevelAction` (0x18) and `PrepareTransaction` (0x19) are sub-action /
//! two-phase markers that do **not** by themselves decide the final state; a
//! commit/forget still seals it, and their absence does not abort it. They are
//! retained in the transaction's record list (never dropped) but are not treated
//! as terminal.

use super::{LogOp, LogRecord};

/// The recovery disposition of a reconstructed [`Transaction`], derived from the
/// transaction-control opcodes present among its records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionState {
    /// A `CommitTransaction` (0x1A) or `ForgetTransaction` (0x1B) record sealed
    /// the transaction — its redo records were applied (or are replayable).
    Committed,
    /// A `CompensationLogRecord` (0x01) rolled the transaction back without a
    /// commit — its effects were (or would be) undone.
    Aborted,
    /// No commit / forget / compensation record bounds the transaction within the
    /// recovered log window. The records exist but the boundary that would seal
    /// or roll them back was not recovered (e.g. overwritten in the circular
    /// buffer). Forensically the operation's final disposition is unknown.
    Incomplete,
}

/// A group of `$LogFile` LFS records that share one `transaction_id` — the
/// atomic unit (one user/OS action) NTFS commits or rolls back as a whole.
///
/// `records` holds **indices into the slice passed to
/// [`reconstruct_transactions`]**, in ascending LSN order (the order NTFS would
/// replay them). `operations` is the parallel [`FileOperation`](super::FileOperation)
/// classification of each record, same order. `lsns` carries each record's
/// `this_lsn` so the set of LSNs a transaction owns can be compared against an
/// oracle without re-indexing into the source slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// The shared `transaction_id` (LFS header offset `0x24`).
    pub transaction_id: u32,
    /// Indices into the source record slice, ascending by LSN.
    pub records: Vec<usize>,
    /// Each member record's `this_lsn`, ascending — the transaction's LSN set.
    pub lsns: Vec<u64>,
    /// Per-record file-operation classification, parallel to `records`.
    pub operations: Vec<super::FileOperation>,
    /// Recovery disposition derived from the control opcodes present.
    pub state: TransactionState,
}

/// Group decoded LFS [`LogRecord`]s into [`Transaction`]s by `transaction_id`.
///
/// Records are grouped on their `transaction_id` (the NTFS grouping key, see the
/// module docs), each transaction's records sorted ascending by `this_lsn`
/// (replay order), and a [`TransactionState`] derived from the commit / forget /
/// compensation opcodes among its records.
///
/// Returned transactions are ordered by the lowest LSN they contain, so the
/// output reads in log order. Every input record lands in exactly one
/// transaction — none is dropped, including transaction-control records and
/// records whose opcode is [`LogOp::Unknown`].
#[must_use]
pub fn reconstruct_transactions(records: &[LogRecord]) -> Vec<Transaction> {
    use std::collections::HashMap;

    // Group record indices by transaction_id. A Vec per txid preserves the
    // source order; we sort each group by LSN below.
    let mut groups: HashMap<u32, Vec<usize>> = HashMap::new();
    for (idx, rec) in records.iter().enumerate() {
        groups.entry(rec.transaction_id).or_default().push(idx);
    }

    let mut txns: Vec<Transaction> = Vec::with_capacity(groups.len());
    for (transaction_id, mut indices) in groups {
        // Replay order is ascending LSN within the transaction.
        indices.sort_by_key(|&i| records[i].this_lsn);

        let mut lsns = Vec::with_capacity(indices.len());
        let mut operations = Vec::with_capacity(indices.len());
        // Final state is decided by the terminal control opcode present: a
        // commit/forget seals (Committed) and overrides a compensation; a
        // compensation alone aborts; neither is Incomplete. EndTopLevelAction
        // and PrepareTransaction are sub-action markers, not terminal.
        let mut committed = false;
        let mut compensated = false;
        for &i in &indices {
            let rec = &records[i];
            lsns.push(rec.this_lsn);
            operations.push(super::classify(rec.redo_op, rec.undo_op));
            // A control opcode can appear on either the redo or the undo side.
            for op in [rec.redo_op, rec.undo_op] {
                match op {
                    LogOp::CommitTransaction | LogOp::ForgetTransaction => committed = true,
                    LogOp::CompensationLogRecord => compensated = true,
                    _ => {}
                }
            }
        }

        let state = if committed {
            TransactionState::Committed
        } else if compensated {
            TransactionState::Aborted
        } else {
            TransactionState::Incomplete
        };

        txns.push(Transaction {
            transaction_id,
            records: indices,
            lsns,
            operations,
            state,
        });
    }

    // Output in log order: by the lowest LSN each transaction owns. Every group
    // has at least one record (it was created from a record), so `first` is
    // always present.
    txns.sort_by_key(|t| t.lsns.first().copied().unwrap_or(u64::MAX));
    txns
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logfile::FileOperation;

    /// Build a minimal [`LogRecord`] carrying just the fields transaction
    /// reconstruction reads: LSN, transaction id, redo/undo opcodes.
    fn rec(this_lsn: u64, transaction_id: u32, redo: LogOp, undo: LogOp) -> LogRecord {
        LogRecord {
            page_offset: 0,
            this_lsn,
            client_previous_lsn: 0,
            client_undo_next_lsn: 0,
            record_type: 1,
            transaction_id,
            redo_op: redo,
            undo_op: undo,
            target_attribute: 0,
            mft_cluster_index: 0,
            target_vcn: 0,
        }
    }

    // ── grouping ────────────────────────────────────────────────────────────

    // Microsoft LFS_RECORD / flatcap: TransactionId groups related records into
    // a single transaction. Two records sharing a txid form one transaction.
    #[test]
    fn groups_records_by_transaction_id() {
        let recs = vec![
            rec(10, 7, LogOp::InitializeFileRecordSegment, LogOp::Noop),
            rec(11, 7, LogOp::CreateAttribute, LogOp::DeleteAttribute),
        ];
        let txns = reconstruct_transactions(&recs);
        assert_eq!(txns.len(), 1);
        assert_eq!(txns[0].transaction_id, 7);
        assert_eq!(txns[0].records, vec![0, 1]);
        assert_eq!(txns[0].lsns, vec![10, 11]);
    }

    // TZWorks mala: records for concurrent transactions are interleaved in LSN
    // order; the txid — not contiguity — bounds each transaction.
    #[test]
    fn separates_interleaved_transactions() {
        // tx 1: LSNs 21,22,24 ; tx 2: LSNs 23,25,26 (the mala example)
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
        // Ordered by lowest LSN: tx 1 first.
        assert_eq!(txns[0].transaction_id, 1);
        assert_eq!(txns[0].lsns, vec![21, 22, 24]);
        assert_eq!(txns[1].transaction_id, 2);
        assert_eq!(txns[1].lsns, vec![23, 25, 26]);
    }

    // Records must be held in ascending LSN order within a transaction even when
    // the source slice presents them out of order.
    #[test]
    fn orders_records_by_lsn_within_transaction() {
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

    // ── state ───────────────────────────────────────────────────────────────

    // CommitTransaction (0x1A) seals the transaction => Committed.
    #[test]
    fn commit_record_is_committed() {
        let recs = vec![
            rec(1, 1, LogOp::InitializeFileRecordSegment, LogOp::Noop),
            rec(2, 1, LogOp::CommitTransaction, LogOp::Noop),
        ];
        let txns = reconstruct_transactions(&recs);
        assert_eq!(txns[0].state, TransactionState::Committed);
    }

    // ForgetTransaction (0x1B) marks the transaction fully complete => Committed.
    #[test]
    fn forget_record_is_committed() {
        let recs = vec![
            rec(1, 1, LogOp::InitializeFileRecordSegment, LogOp::Noop),
            rec(2, 1, LogOp::ForgetTransaction, LogOp::Noop),
        ];
        let txns = reconstruct_transactions(&recs);
        assert_eq!(txns[0].state, TransactionState::Committed);
    }

    // CompensationLogRecord (0x01) without a commit => Aborted (rolled back).
    #[test]
    fn compensation_without_commit_is_aborted() {
        let recs = vec![
            rec(1, 1, LogOp::InitializeFileRecordSegment, LogOp::Noop),
            rec(2, 1, LogOp::CompensationLogRecord, LogOp::Noop),
        ];
        let txns = reconstruct_transactions(&recs);
        assert_eq!(txns[0].state, TransactionState::Aborted);
    }

    // A commit takes precedence over a compensation record: a transaction that
    // both rolled back a sub-action and then committed is Committed (the commit
    // is the terminal seal).
    #[test]
    fn commit_takes_precedence_over_compensation() {
        let recs = vec![
            rec(1, 1, LogOp::InitializeFileRecordSegment, LogOp::Noop),
            rec(2, 1, LogOp::CompensationLogRecord, LogOp::Noop),
            rec(3, 1, LogOp::CommitTransaction, LogOp::Noop),
        ];
        let txns = reconstruct_transactions(&recs);
        assert_eq!(txns[0].state, TransactionState::Committed);
    }

    // No commit/forget/compensation bounds the records => Incomplete.
    #[test]
    fn no_boundary_is_incomplete() {
        let recs = vec![
            rec(1, 1, LogOp::InitializeFileRecordSegment, LogOp::Noop),
            rec(2, 1, LogOp::CreateAttribute, LogOp::DeleteAttribute),
        ];
        let txns = reconstruct_transactions(&recs);
        assert_eq!(txns[0].state, TransactionState::Incomplete);
    }

    // EndTopLevelAction / PrepareTransaction are NOT terminal — a transaction
    // carrying only those is still Incomplete (no commit/forget/compensation).
    #[test]
    fn prepare_and_end_top_level_alone_are_incomplete() {
        let recs = vec![
            rec(1, 4, LogOp::PrepareTransaction, LogOp::Noop),
            rec(2, 4, LogOp::EndTopLevelAction, LogOp::Noop),
        ];
        let txns = reconstruct_transactions(&recs);
        assert_eq!(txns[0].state, TransactionState::Incomplete);
        // But they are retained, never dropped.
        assert_eq!(txns[0].records.len(), 2);
    }

    // An unrecognized control opcode must not silently drop the record: a record
    // with an Unknown opcode is still grouped and counted.
    #[test]
    fn unknown_opcode_record_is_retained() {
        let recs = vec![
            rec(1, 6, LogOp::Unknown(0x40), LogOp::Unknown(0x41)),
            rec(2, 6, LogOp::CommitTransaction, LogOp::Noop),
        ];
        let txns = reconstruct_transactions(&recs);
        assert_eq!(txns[0].records.len(), 2);
        assert_eq!(txns[0].operations[0], FileOperation::Unknown(0x40, 0x41));
        assert_eq!(txns[0].state, TransactionState::Committed);
    }

    #[test]
    fn empty_input_yields_no_transactions() {
        assert!(reconstruct_transactions(&[]).is_empty());
    }
}
