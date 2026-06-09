//! TriForce correlation engine: MFT + $LogFile + $UsnJrnl.
//!
//! Cross-correlates three NTFS artifacts to produce a unified timeline
//! and detect evidence of anti-forensic activity (journal clearing,
//! timestomping, phantom file operations).

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::DateTime;
    use ntfs_core::logfile::usn_extractor::{LogFileRecordSource, LogFileUsnRecord};
    use ntfs_core::mft::MftEntry;
    use ntfs_core::usn::{FileAttributes, UsnReason, UsnRecord};

    /// Helper: build a minimal UsnRecord for testing.
    fn usn(
        entry: u64,
        seq: u16,
        parent: u64,
        usn_offset: i64,
        ts_secs: i64,
        name: &str,
        reason: UsnReason,
    ) -> UsnRecord {
        UsnRecord {
            mft_entry: entry,
            mft_sequence: seq,
            parent_mft_entry: parent,
            parent_mft_sequence: 1,
            usn: usn_offset,
            timestamp: DateTime::from_timestamp(ts_secs, 0).unwrap(),
            reason,
            filename: name.into(),
            file_attributes: FileAttributes::ARCHIVE,
            source_info: 0,
            security_id: 0,
            major_version: 2,
        }
    }

    /// Helper: wrap a UsnRecord into a LogFileUsnRecord.
    fn logfile_usn(record: UsnRecord, lsn: u64) -> LogFileUsnRecord {
        LogFileUsnRecord {
            lsn,
            page_offset: 0,
            source: LogFileRecordSource::RedoData,
            record,
        }
    }

    /// Helper: build a minimal MftEntry for testing.
    fn mft_entry(entry: u64, seq: u16, parent: u64, name: &str, is_dir: bool) -> MftEntry {
        MftEntry {
            entry_number: entry,
            sequence_number: seq,
            filename: name.into(),
            parent_entry: parent,
            parent_sequence: 1,
            is_directory: is_dir,
            is_in_use: true,
            si_created: None,
            si_modified: None,
            si_mft_modified: None,
            si_accessed: None,
            fn_created: None,
            fn_modified: None,
            fn_mft_modified: None,
            fn_accessed: None,
            full_path: format!(".\\{name}"),
            file_size: 0,
            has_ads: false,
        }
    }

    // ─── Test 1: Create engine and build unified timeline ────────────────

    #[test]
    fn test_unified_timeline_from_usn_only() {
        let records = vec![
            usn(
                100,
                1,
                50,
                1000,
                1700000000,
                "file1.txt",
                UsnReason::FILE_CREATE,
            ),
            usn(
                101,
                1,
                50,
                2000,
                1700000100,
                "file2.txt",
                UsnReason::FILE_CREATE,
            ),
        ];

        let engine = CorrelationEngine::new();
        let timeline = engine.build_timeline(&records, &[], &[]);

        assert_eq!(timeline.len(), 2);
        assert_eq!(timeline[0].source, EventSource::UsnJournal);
        assert_eq!(timeline[1].source, EventSource::UsnJournal);
        // Timeline is sorted by timestamp
        assert!(timeline[0].record.timestamp <= timeline[1].record.timestamp);
    }

    // ─── Test 2: Merge LogFile USN records into timeline ─────────────────

    #[test]
    fn test_unified_timeline_merges_logfile_records() {
        let usn_records = vec![usn(
            100,
            1,
            50,
            2000,
            1700000200,
            "file1.txt",
            UsnReason::DATA_EXTEND,
        )];
        let logfile_records = vec![logfile_usn(
            usn(
                100,
                1,
                50,
                1000,
                1700000100,
                "file1.txt",
                UsnReason::FILE_CREATE,
            ),
            500,
        )];

        let engine = CorrelationEngine::new();
        let timeline = engine.build_timeline(&usn_records, &logfile_records, &[]);

        assert_eq!(timeline.len(), 2);
        // LogFile record came first chronologically
        assert_eq!(timeline[0].source, EventSource::LogFile);
        assert_eq!(timeline[1].source, EventSource::UsnJournal);
    }

    // ─── Test 3: Deduplicate records present in both sources ─────────────

    #[test]
    fn test_deduplication_when_record_in_both_sources() {
        // Same USN offset + same entry + same timestamp = duplicate
        let record = usn(
            100,
            1,
            50,
            1000,
            1700000100,
            "file1.txt",
            UsnReason::FILE_CREATE,
        );
        let usn_records = vec![record.clone()];
        let logfile_records = vec![logfile_usn(record.clone(), 500)];

        let engine = CorrelationEngine::new();
        let timeline = engine.build_timeline(&usn_records, &logfile_records, &[]);

        // Should deduplicate into a single event marked as Both
        assert_eq!(timeline.len(), 1);
        assert_eq!(timeline[0].source, EventSource::Both);
    }

    // ─── Test 4: Ghost records (in LogFile but not UsnJrnl) ──────────────

    #[test]
    fn test_ghost_records_detected() {
        // UsnJrnl starts at USN 5000 (journal was cleared/wrapped)
        let usn_records = vec![usn(
            200,
            1,
            50,
            5000,
            1700001000,
            "after.txt",
            UsnReason::FILE_CREATE,
        )];
        // LogFile has older records with USN < 5000
        let logfile_records = vec![
            logfile_usn(
                usn(
                    100,
                    1,
                    50,
                    1000,
                    1700000100,
                    "deleted_evidence.txt",
                    UsnReason::FILE_CREATE,
                ),
                300,
            ),
            logfile_usn(
                usn(
                    101,
                    1,
                    50,
                    2000,
                    1700000200,
                    "wiped.exe",
                    UsnReason::FILE_DELETE | UsnReason::CLOSE,
                ),
                400,
            ),
        ];

        let engine = CorrelationEngine::new();
        let ghosts = engine.find_ghost_records(&usn_records, &logfile_records);

        assert_eq!(ghosts.len(), 2);
        assert_eq!(ghosts[0].record.filename, "deleted_evidence.txt");
        assert_eq!(ghosts[1].record.filename, "wiped.exe");
    }

    // ─── Test 5: No ghosts when all LogFile records also in UsnJrnl ──────

    #[test]
    fn test_no_ghosts_when_fully_covered() {
        let record = usn(
            100,
            1,
            50,
            1000,
            1700000100,
            "file1.txt",
            UsnReason::FILE_CREATE,
        );
        let usn_records = vec![record.clone()];
        let logfile_records = vec![logfile_usn(record, 500)];

        let engine = CorrelationEngine::new();
        let ghosts = engine.find_ghost_records(&usn_records, &logfile_records);

        assert_eq!(ghosts.len(), 0);
    }

    // ─── Test 6: Coverage analysis ───────────────────────────────────────

    #[test]
    fn test_coverage_analysis() {
        let usn_records = vec![
            usn(
                100,
                1,
                50,
                1000,
                1700000100,
                "a.txt",
                UsnReason::FILE_CREATE,
            ),
            usn(
                101,
                1,
                50,
                5000,
                1700000500,
                "b.txt",
                UsnReason::FILE_CREATE,
            ),
        ];
        let logfile_records = vec![logfile_usn(
            usn(
                99,
                1,
                50,
                500,
                1700000050,
                "early.txt",
                UsnReason::FILE_CREATE,
            ),
            100,
        )];

        let engine = CorrelationEngine::new();
        let coverage = engine.analyze_coverage(&usn_records, &logfile_records);

        // UsnJrnl range
        assert_eq!(coverage.usn_earliest_ts.timestamp(), 1700000100);
        assert_eq!(coverage.usn_latest_ts.timestamp(), 1700000500);
        assert_eq!(coverage.usn_record_count, 2);

        // LogFile range
        assert_eq!(
            coverage.logfile_earliest_ts.unwrap().timestamp(),
            1700000050
        );
        assert_eq!(coverage.logfile_record_count, 1);

        // LogFile extends before UsnJrnl = evidence of clearing
        assert!(coverage.logfile_extends_before_usn);
    }

    // ─── Test 7: MFT cross-validation (timestomping detection) ──────────

    #[test]
    fn test_mft_usn_timestamp_conflicts() {
        // MFT says file was created at ts=1700000100
        let mut entry = mft_entry(100, 1, 50, "suspicious.exe", false);
        entry.si_created = Some(DateTime::from_timestamp(1700000100, 0).unwrap());
        entry.fn_created = Some(DateTime::from_timestamp(1700000500, 0).unwrap());

        // USN Journal says file was created at ts=1700000500
        let usn_records = vec![usn(
            100,
            1,
            50,
            1000,
            1700000500,
            "suspicious.exe",
            UsnReason::FILE_CREATE,
        )];

        let engine = CorrelationEngine::new();
        let conflicts = engine.find_timestamp_conflicts(&usn_records, &[entry]);

        // SI_Created (1700000100) predates the USN FILE_CREATE (1700000500) = timestomped
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].mft_entry, 100);
        assert_eq!(
            conflicts[0].conflict_type,
            TimestampConflictType::SiPredatesUsnCreate
        );
    }

    #[test]
    fn test_timestamp_conflicts_keeps_earliest_create() {
        // Two FILE_CREATE records for entry 100; the second is earlier, exercising
        // the and_modify path that keeps the earliest USN create timestamp.
        let mut entry = mft_entry(100, 1, 50, "evil.exe", false);
        entry.si_created = Some(DateTime::from_timestamp(1700000000, 0).unwrap());
        let usn_records = vec![
            usn(
                100,
                1,
                50,
                2000,
                1700000500,
                "evil.exe",
                UsnReason::FILE_CREATE,
            ),
            usn(
                100,
                1,
                50,
                1000,
                1700000300,
                "evil.exe",
                UsnReason::FILE_CREATE,
            ),
        ];
        let engine = CorrelationEngine::new();
        let conflicts = engine.find_timestamp_conflicts(&usn_records, &[entry]);
        // Earliest create (1700000300) is used; si_created (1700000000) predates it.
        assert_eq!(conflicts.len(), 1);
        assert_eq!(
            conflicts[0].usn_timestamp,
            DateTime::from_timestamp(1700000300, 0).unwrap()
        );
    }

    #[test]
    fn test_timestamp_conflicts_skip_paths() {
        // Exercises the non-conflict skip branches: a non-FILE_CREATE record, an
        // entry whose si_created is None, and an entry with no matching USN create.
        let mut e_no_si = mft_entry(100, 1, 50, "a.txt", false);
        e_no_si.si_created = None;
        let e_no_create = mft_entry(200, 1, 50, "b.txt", false); // si_created None, entry 200 has no USN create
        let usn_records = vec![
            usn(
                100,
                1,
                50,
                1000,
                1700000500,
                "a.txt",
                UsnReason::FILE_CREATE,
            ),
            usn(100, 1, 50, 1100, 1700000600, "a.txt", UsnReason::CLOSE),
        ];
        let engine = CorrelationEngine::new();
        let conflicts = engine.find_timestamp_conflicts(&usn_records, &[e_no_si, e_no_create]);
        assert_eq!(conflicts.len(), 0);
    }

    // ─── Test 8: No conflict when timestamps are consistent ──────────────

    #[test]
    fn test_no_conflict_when_timestamps_consistent() {
        let mut entry = mft_entry(100, 1, 50, "normal.txt", false);
        let ts = DateTime::from_timestamp(1700000500, 0).unwrap();
        entry.si_created = Some(ts);
        entry.fn_created = Some(ts);

        let usn_records = vec![usn(
            100,
            1,
            50,
            1000,
            1700000500,
            "normal.txt",
            UsnReason::FILE_CREATE,
        )];

        let engine = CorrelationEngine::new();
        let conflicts = engine.find_timestamp_conflicts(&usn_records, &[entry]);

        assert_eq!(conflicts.len(), 0);
    }

    // ─── Test 9: File activity summary per MFT entry ─────────────────────

    #[test]
    fn test_file_activity_summary() {
        let usn_records = vec![
            usn(
                100,
                1,
                50,
                1000,
                1700000100,
                "report.docx",
                UsnReason::FILE_CREATE,
            ),
            usn(
                100,
                1,
                50,
                2000,
                1700000200,
                "report.docx",
                UsnReason::DATA_EXTEND,
            ),
            usn(
                100,
                1,
                50,
                3000,
                1700000300,
                "report.docx",
                UsnReason::CLOSE,
            ),
            usn(
                100,
                1,
                50,
                4000,
                1700000400,
                "report.docx",
                UsnReason::DATA_EXTEND,
            ),
            usn(
                100,
                1,
                50,
                5000,
                1700000500,
                "report.docx",
                UsnReason::CLOSE,
            ),
        ];

        let engine = CorrelationEngine::new();
        let summaries = engine.summarize_file_activity(&usn_records);

        assert_eq!(summaries.len(), 1);
        let summary = &summaries[0];
        assert_eq!(summary.mft_entry, 100);
        assert_eq!(summary.filename, "report.docx");
        assert_eq!(summary.event_count, 5);
        assert_eq!(summary.first_seen.timestamp(), 1700000100);
        assert_eq!(summary.last_seen.timestamp(), 1700000500);
        assert!(summary.reasons.contains(UsnReason::FILE_CREATE));
        assert!(summary.reasons.contains(UsnReason::DATA_EXTEND));
        assert!(summary.reasons.contains(UsnReason::CLOSE));
    }

    // ─── Test 10: Empty inputs produce empty results ─────────────────────

    #[test]
    fn test_empty_inputs() {
        let engine = CorrelationEngine::new();

        let timeline = engine.build_timeline(&[], &[], &[]);
        assert!(timeline.is_empty());

        let ghosts = engine.find_ghost_records(&[], &[]);
        assert!(ghosts.is_empty());

        let coverage = engine.analyze_coverage(&[], &[]);
        assert_eq!(coverage.usn_record_count, 0);
        assert_eq!(coverage.logfile_record_count, 0);
        assert!(!coverage.logfile_extends_before_usn);
    }

    // ─── Test 11: Detect MFT entry reuse across USN records ─────────────

    #[test]
    fn test_detect_entry_reuse() {
        // Same MFT entry 100, but different sequence numbers = reused
        let usn_records = vec![
            usn(
                100,
                3,
                50,
                1000,
                1700000100,
                "old_file.txt",
                UsnReason::FILE_DELETE | UsnReason::CLOSE,
            ),
            usn(
                100,
                4,
                60,
                2000,
                1700000200,
                "new_file.exe",
                UsnReason::FILE_CREATE,
            ),
        ];

        let engine = CorrelationEngine::new();
        let reuses = engine.detect_entry_reuse(&usn_records);

        assert_eq!(reuses.len(), 1);
        assert_eq!(reuses[0].mft_entry, 100);
        assert_eq!(reuses[0].old_sequence, 3);
        assert_eq!(reuses[0].new_sequence, 4);
        assert_eq!(reuses[0].old_filename, "old_file.txt");
        assert_eq!(reuses[0].new_filename, "new_file.exe");
    }

    // ─── Test 12: No reuse when sequence stays the same ──────────────────

    #[test]
    fn test_no_reuse_same_sequence() {
        let usn_records = vec![
            usn(
                100,
                3,
                50,
                1000,
                1700000100,
                "file.txt",
                UsnReason::FILE_CREATE,
            ),
            usn(
                100,
                3,
                50,
                2000,
                1700000200,
                "file.txt",
                UsnReason::DATA_EXTEND,
            ),
        ];

        let engine = CorrelationEngine::new();
        let reuses = engine.detect_entry_reuse(&usn_records);
        assert!(reuses.is_empty());
    }

    // ─── Test 13: Full TriForce report ───────────────────────────────────

    #[test]
    fn test_triforce_report() {
        let usn_records = vec![usn(
            100,
            1,
            50,
            5000,
            1700001000,
            "current.txt",
            UsnReason::FILE_CREATE,
        )];
        let logfile_records = vec![logfile_usn(
            usn(
                99,
                1,
                50,
                1000,
                1700000100,
                "ghost.exe",
                UsnReason::FILE_CREATE,
            ),
            200,
        )];
        let mut entry = mft_entry(100, 1, 50, "current.txt", false);
        entry.si_created = Some(DateTime::from_timestamp(1700000500, 0).unwrap());

        let engine = CorrelationEngine::new();
        let report = engine.generate_report(&usn_records, &logfile_records, &[entry]);

        assert_eq!(report.timeline_event_count, 2);
        assert_eq!(report.ghost_record_count, 1);
        assert!(report.journal_clearing_suspected);
        assert_eq!(report.timestamp_conflict_count, 1);
    }

    // ─── Test 14: Multiple files activity summary is separated ───────────

    #[test]
    fn test_activity_summary_multiple_files() {
        let usn_records = vec![
            usn(
                100,
                1,
                50,
                1000,
                1700000100,
                "a.txt",
                UsnReason::FILE_CREATE,
            ),
            usn(
                101,
                1,
                50,
                2000,
                1700000200,
                "b.txt",
                UsnReason::FILE_CREATE,
            ),
            usn(100, 1, 50, 3000, 1700000300, "a.txt", UsnReason::CLOSE),
        ];

        let engine = CorrelationEngine::new();
        let summaries = engine.summarize_file_activity(&usn_records);

        assert_eq!(summaries.len(), 2);
        // Sorted by first_seen
        assert_eq!(summaries[0].mft_entry, 100);
        assert_eq!(summaries[0].event_count, 2);
        assert_eq!(summaries[1].mft_entry, 101);
        assert_eq!(summaries[1].event_count, 1);
    }

    // ─── Test 15: Timeline preserves LSN for LogFile records ─────────────

    // ─── Test 16: Multiple FILE_CREATE for same entry picks earliest ─────

    #[test]
    fn test_timestamp_conflict_multiple_creates_picks_earliest() {
        // Lines 242-243: and_modify branch in find_timestamp_conflicts
        // When the same MFT entry has multiple FILE_CREATE events,
        // the earliest timestamp should be stored.
        let usn_records = vec![
            usn(
                100,
                1,
                50,
                1000,
                1700000300,
                "file.exe",
                UsnReason::FILE_CREATE,
            ),
            usn(
                100,
                1,
                50,
                2000,
                1700000100,
                "file.exe",
                UsnReason::FILE_CREATE,
            ), // earlier
            usn(
                100,
                1,
                50,
                3000,
                1700000200,
                "file.exe",
                UsnReason::FILE_CREATE,
            ),
        ];

        // MFT says SI_Created is way before the earliest USN create -> conflict
        let mut entry = mft_entry(100, 1, 50, "file.exe", false);
        entry.si_created = Some(DateTime::from_timestamp(1699999000, 0).unwrap());

        let engine = CorrelationEngine::new();
        let conflicts = engine.find_timestamp_conflicts(&usn_records, &[entry]);

        assert_eq!(conflicts.len(), 1);
        // The USN timestamp used should be the earliest (1700000100)
        assert_eq!(conflicts[0].usn_timestamp.timestamp(), 1700000100);
    }

    // ─── Test 17: File activity summary first_seen/last_seen update ──────

    #[test]
    fn test_activity_summary_first_seen_last_seen_update() {
        // Line 336: first_seen update when r.timestamp < s.first_seen
        // Also tests last_seen update and reason accumulation
        let usn_records = vec![
            // First record seen: ts=200
            usn(
                100,
                1,
                50,
                1000,
                1700000200,
                "data.txt",
                UsnReason::FILE_CREATE,
            ),
            // Earlier timestamp: ts=100 -> should update first_seen
            usn(
                100,
                1,
                50,
                2000,
                1700000100,
                "data.txt",
                UsnReason::DATA_EXTEND,
            ),
            // Latest timestamp: ts=300 -> should update last_seen
            usn(
                100,
                1,
                50,
                3000,
                1700000300,
                "data_renamed.txt",
                UsnReason::RENAME_NEW_NAME,
            ),
        ];

        let engine = CorrelationEngine::new();
        let summaries = engine.summarize_file_activity(&usn_records);

        assert_eq!(summaries.len(), 1);
        let s = &summaries[0];
        assert_eq!(s.mft_entry, 100);
        assert_eq!(s.event_count, 3);
        assert_eq!(s.first_seen.timestamp(), 1700000100);
        assert_eq!(s.last_seen.timestamp(), 1700000300);
        assert_eq!(s.filename, "data_renamed.txt"); // latest filename used
                                                    // All reasons accumulated
        assert!(s.reasons.contains(UsnReason::FILE_CREATE));
        assert!(s.reasons.contains(UsnReason::DATA_EXTEND));
        assert!(s.reasons.contains(UsnReason::RENAME_NEW_NAME));
    }

    #[test]
    fn test_timeline_preserves_lsn() {
        let logfile_records = vec![logfile_usn(
            usn(
                100,
                1,
                50,
                1000,
                1700000100,
                "file.txt",
                UsnReason::FILE_CREATE,
            ),
            42_000,
        )];

        let engine = CorrelationEngine::new();
        let timeline = engine.build_timeline(&[], &logfile_records, &[]);

        assert_eq!(timeline.len(), 1);
        assert_eq!(timeline[0].lsn, Some(42_000));
    }

    #[test]
    fn test_correlation_engine_default() {
        // Cover lines 118-119: Default impl for CorrelationEngine.
        #[allow(clippy::default_constructed_unit_structs)]
        let engine = CorrelationEngine::default();
        // Default-constructed engine should work identically to new().
        let timeline = engine.build_timeline(&[], &[], &[]);
        assert!(timeline.is_empty());
    }
}
