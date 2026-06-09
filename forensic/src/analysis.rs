//! Anti-forensics and threat detection from USN Journal records.
//!
//! Provides heuristic detectors for:
//! - Secure deletion tool artifacts (SDelete, CCleaner, cipher /w)
//! - USN journal clearing / tampering
//! - Ransomware-like mass rename/encrypt patterns
//! - Timestamp manipulation (timestomping)

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Duration, Utc};
    use ntfs_core::usn::{FileAttributes, UsnReason, UsnRecord};

    /// Helper to build a synthetic UsnRecord for testing.
    fn make_record(
        mft_entry: u64,
        filename: &str,
        reason: UsnReason,
        timestamp: DateTime<Utc>,
        usn: i64,
    ) -> UsnRecord {
        UsnRecord {
            mft_entry,
            mft_sequence: 1,
            parent_mft_entry: 5,
            parent_mft_sequence: 1,
            usn,
            timestamp,
            reason,
            filename: filename.to_string(),
            file_attributes: FileAttributes::ARCHIVE,
            source_info: 0,
            security_id: 0,
            major_version: 2,
        }
    }

    fn ts(secs_offset: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000 + secs_offset, 0).unwrap()
    }

    // ─── Secure Deletion Tests ───────────────────────────────────────────

    #[test]
    fn test_detect_sdelete_pattern() {
        let records = vec![
            make_record(100, "AAAAAAA", UsnReason::FILE_CREATE, ts(0), 1000),
            make_record(100, "AAAAAAA", UsnReason::FILE_DELETE, ts(1), 1100),
            make_record(101, "ZZZZZZZ", UsnReason::FILE_CREATE, ts(2), 1200),
            make_record(101, "ZZZZZZZ", UsnReason::FILE_DELETE, ts(3), 1300),
            make_record(102, "0000000", UsnReason::FILE_CREATE, ts(4), 1400),
            make_record(102, "0000000", UsnReason::FILE_DELETE, ts(5), 1500),
        ];

        let indicators = detect_secure_deletion(&records);
        assert!(!indicators.is_empty());
        assert_eq!(indicators[0].pattern, SecureDeletionPattern::SDelete);
        assert!(indicators[0].confidence >= 0.9);
    }

    #[test]
    fn test_sdelete_not_triggered_by_normal_files() {
        let records = vec![
            make_record(100, "document.docx", UsnReason::FILE_CREATE, ts(0), 1000),
            make_record(101, "report.pdf", UsnReason::FILE_CREATE, ts(1), 1100),
            make_record(102, "image.png", UsnReason::FILE_DELETE, ts(2), 1200),
        ];

        let indicators = detect_secure_deletion(&records);
        assert!(indicators.is_empty());
    }

    #[test]
    fn test_detect_bulk_temp_deletion() {
        let mut records = Vec::new();
        for i in 0..15 {
            records.push(make_record(
                100 + i,
                &format!("tmp{i:04}.tmp"),
                UsnReason::FILE_DELETE,
                ts(i as i64),
                1000 + (i as i64) * 100,
            ));
        }

        let indicators = detect_secure_deletion(&records);
        assert!(!indicators.is_empty());
        assert_eq!(
            indicators[0].pattern,
            SecureDeletionPattern::BulkTempDeletion
        );
    }

    #[test]
    fn test_no_bulk_temp_with_few_files() {
        let records = vec![
            make_record(100, "tmp001.tmp", UsnReason::FILE_DELETE, ts(0), 1000),
            make_record(101, "tmp002.tmp", UsnReason::FILE_DELETE, ts(1), 1100),
        ];

        let indicators = detect_secure_deletion(&records);
        assert!(indicators.is_empty());
    }

    // ─── Journal Clearing Tests ──────────────────────────────────────────

    #[test]
    fn test_detect_high_starting_usn() {
        let records = vec![
            make_record(
                100,
                "file.txt",
                UsnReason::FILE_CREATE,
                ts(0),
                2_000_000_000, // 2GB - way above threshold
            ),
            make_record(
                101,
                "file2.txt",
                UsnReason::FILE_CREATE,
                ts(1),
                2_000_001_000,
            ),
        ];

        let result = detect_journal_clearing(&records);
        assert!(result.clearing_detected);
        assert!(result.confidence >= 0.4);
        assert_eq!(result.first_usn, Some(2_000_000_000));
    }

    #[test]
    fn test_detect_timestamp_gap() {
        let records = vec![
            make_record(100, "before.txt", UsnReason::FILE_CREATE, ts(0), 1000),
            // 48-hour gap
            make_record(
                101,
                "after.txt",
                UsnReason::FILE_CREATE,
                ts(48 * 3600),
                1100,
            ),
        ];

        let result = detect_journal_clearing(&records);
        assert!(!result.timestamp_gaps.is_empty());
        assert!(result.timestamp_gaps[0].gap_duration > Duration::hours(24));
    }

    #[test]
    fn test_no_clearing_for_normal_journal() {
        let records = vec![
            make_record(100, "a.txt", UsnReason::FILE_CREATE, ts(0), 100),
            make_record(101, "b.txt", UsnReason::FILE_CREATE, ts(60), 200),
            make_record(102, "c.txt", UsnReason::FILE_CREATE, ts(120), 300),
        ];

        let result = detect_journal_clearing(&records);
        assert!(!result.clearing_detected);
        assert!(result.timestamp_gaps.is_empty());
    }

    #[test]
    fn test_clearing_empty_records() {
        let result = detect_journal_clearing(&[]);
        assert!(!result.clearing_detected);
        assert!(result.first_usn.is_none());
    }

    // ─── Ransomware Detection Tests ──────────────────────────────────────

    #[test]
    fn test_detect_known_ransomware_extension() {
        let mut records = Vec::new();
        for i in 0..5 {
            records.push(make_record(
                100 + i,
                &format!("document{i}.docx.encrypted"),
                UsnReason::RENAME_NEW_NAME,
                ts(i as i64),
                1000 + (i as i64) * 100,
            ));
        }

        let indicators = detect_ransomware_patterns(&records);
        assert!(!indicators.is_empty());
        assert_eq!(indicators[0].extension, ".encrypted");
        assert_eq!(indicators[0].affected_count, 5);
    }

    #[test]
    fn test_detect_mass_rename_unknown_extension() {
        let mut records = Vec::new();
        for i in 0..25 {
            records.push(make_record(
                100 + i,
                &format!("file{i}.xyz_ransom"),
                UsnReason::RENAME_NEW_NAME,
                ts(i as i64),
                1000 + (i as i64) * 100,
            ));
        }

        let indicators = detect_ransomware_patterns(&records);
        assert!(!indicators.is_empty());
    }

    #[test]
    fn test_no_ransomware_for_normal_renames() {
        let records = vec![
            make_record(100, "doc1.docx", UsnReason::RENAME_NEW_NAME, ts(0), 1000),
            make_record(101, "image.png", UsnReason::RENAME_NEW_NAME, ts(100), 1100),
            make_record(102, "report.pdf", UsnReason::RENAME_NEW_NAME, ts(200), 1200),
        ];

        let indicators = detect_ransomware_patterns(&records);
        assert!(indicators.is_empty());
    }

    #[test]
    fn test_ransomware_multiple_known_extensions() {
        let mut records = Vec::new();
        // .locked files
        for i in 0..5 {
            records.push(make_record(
                100 + i,
                &format!("file{i}.locked"),
                UsnReason::RENAME_NEW_NAME,
                ts(i as i64),
                1000 + (i as i64) * 100,
            ));
        }
        // .crypto files
        for i in 0..4 {
            records.push(make_record(
                200 + i,
                &format!("photo{i}.crypto"),
                UsnReason::RENAME_NEW_NAME,
                ts(100 + i as i64),
                2000 + (i as i64) * 100,
            ));
        }

        let indicators = detect_ransomware_patterns(&records);
        // Should detect at least the .locked group (5 >= 3 threshold)
        let locked_indicators: Vec<_> = indicators
            .iter()
            .filter(|i| i.extension == ".locked")
            .collect();
        assert!(!locked_indicators.is_empty());
    }

    // ─── Timestomping Detection Tests ────────────────────────────────────

    #[test]
    fn test_detect_isolated_basic_info_change() {
        let records = vec![make_record(
            100,
            "suspicious.exe",
            UsnReason::BASIC_INFO_CHANGE,
            ts(1000),
            5000,
        )];

        let indicators = detect_timestomping(&records);
        assert!(!indicators.is_empty());
        assert_eq!(indicators[0].filename, "suspicious.exe");
        assert!(!indicators[0].has_nearby_data_change);
        assert!(indicators[0].confidence >= 0.7);
    }

    #[test]
    fn test_no_timestomp_with_data_change() {
        let records = vec![
            make_record(100, "normal.docx", UsnReason::DATA_OVERWRITE, ts(999), 4900),
            make_record(
                100,
                "normal.docx",
                UsnReason::BASIC_INFO_CHANGE,
                ts(1000),
                5000,
            ),
        ];

        let indicators = detect_timestomping(&records);
        assert!(indicators.is_empty());
    }

    #[test]
    fn test_timestomp_with_distant_data_change() {
        // Data change is > 60 seconds away, so BASIC_INFO_CHANGE is still suspicious
        let records = vec![
            make_record(
                100,
                "suspicious.exe",
                UsnReason::DATA_OVERWRITE,
                ts(0),
                1000,
            ),
            make_record(
                100,
                "suspicious.exe",
                UsnReason::BASIC_INFO_CHANGE,
                ts(120), // 2 minutes later
                5000,
            ),
        ];

        let indicators = detect_timestomping(&records);
        assert!(!indicators.is_empty());
    }

    #[test]
    fn test_timestomp_multiple_files() {
        let records = vec![
            make_record(
                100,
                "malware1.exe",
                UsnReason::BASIC_INFO_CHANGE,
                ts(0),
                1000,
            ),
            make_record(
                200,
                "malware2.dll",
                UsnReason::BASIC_INFO_CHANGE,
                ts(5),
                1500,
            ),
            make_record(300, "normal.txt", UsnReason::DATA_OVERWRITE, ts(10), 2000),
            make_record(
                300,
                "normal.txt",
                UsnReason::BASIC_INFO_CHANGE,
                ts(11),
                2100,
            ),
        ];

        let indicators = detect_timestomping(&records);
        // malware1.exe and malware2.dll should be flagged, normal.txt should not
        let flagged_files: Vec<&str> = indicators.iter().map(|i| i.filename.as_str()).collect();
        assert!(flagged_files.contains(&"malware1.exe"));
        assert!(flagged_files.contains(&"malware2.dll"));
        assert!(!flagged_files.contains(&"normal.txt"));
    }

    #[test]
    fn test_no_timestomp_on_create() {
        // FILE_CREATE is a legitimate reason for BASIC_INFO_CHANGE
        let records = vec![
            make_record(100, "newfile.txt", UsnReason::FILE_CREATE, ts(0), 1000),
            make_record(
                100,
                "newfile.txt",
                UsnReason::BASIC_INFO_CHANGE,
                ts(1),
                1100,
            ),
        ];

        let indicators = detect_timestomping(&records);
        assert!(indicators.is_empty());
    }

    // ─── Additional coverage tests ──────────────────────────────────────

    #[test]
    fn test_is_sdelete_filename_short() {
        assert!(!is_sdelete_filename("AB"));
        assert!(!is_sdelete_filename("A"));
        assert!(!is_sdelete_filename(""));
    }

    #[test]
    fn test_is_sdelete_filename_mixed_chars() {
        assert!(!is_sdelete_filename("ABCDEF"));
        assert!(!is_sdelete_filename("aaaaaa")); // lowercase not matched
    }

    #[test]
    fn test_is_sdelete_filename_with_extension() {
        assert!(is_sdelete_filename("AAAA.txt"));
        assert!(is_sdelete_filename("ZZZZZ.dat"));
        assert!(is_sdelete_filename("00000.bin"));
    }

    #[test]
    fn test_is_common_extension() {
        assert!(is_common_extension(".txt"));
        assert!(is_common_extension(".exe"));
        assert!(is_common_extension(".dll"));
        assert!(is_common_extension(".pdf"));
        assert!(!is_common_extension(".xyz_ransom"));
        assert!(!is_common_extension(".custom"));
    }

    #[test]
    fn test_sdelete_only_creates_lower_confidence() {
        // Only create events, no deletes -> lower confidence
        let records = vec![
            make_record(100, "AAAAAAA", UsnReason::FILE_CREATE, ts(0), 1000),
            make_record(101, "BBBBBBB", UsnReason::FILE_CREATE, ts(1), 1100),
            make_record(102, "CCCCCCC", UsnReason::FILE_CREATE, ts(2), 1200),
        ];

        let indicators = detect_secure_deletion(&records);
        assert!(!indicators.is_empty());
        assert!(indicators[0].confidence < 0.9);
    }

    #[test]
    fn test_sdelete_events_spread_over_time() {
        // Events more than 60 seconds apart should be separate groups
        let records = vec![
            make_record(100, "AAAAAAA", UsnReason::FILE_CREATE, ts(0), 1000),
            make_record(101, "AAAAAAA", UsnReason::FILE_DELETE, ts(1), 1100),
            // Gap > 60 seconds
            make_record(102, "BBBBBBB", UsnReason::FILE_CREATE, ts(120), 1200),
            make_record(103, "BBBBBBB", UsnReason::FILE_DELETE, ts(121), 1300),
        ];

        // Each pair has only 2 events, below the threshold of 3
        let indicators = detect_secure_deletion(&records);
        let sdelete_indicators: Vec<_> = indicators
            .iter()
            .filter(|i| i.pattern == SecureDeletionPattern::SDelete)
            .collect();
        assert!(sdelete_indicators.is_empty());
    }

    #[test]
    fn test_bulk_temp_deletion_spread_over_time() {
        // .tmp deletes more than 30 seconds apart should form separate groups
        let mut records = Vec::new();
        for i in 0..5 {
            records.push(make_record(
                100 + i,
                &format!("tmp{i:04}.tmp"),
                UsnReason::FILE_DELETE,
                ts(i as i64),
                1000 + (i as i64) * 100,
            ));
        }
        // Gap > 30 seconds
        for i in 0..5 {
            let n = 100 + i;
            records.push(make_record(
                200 + i,
                &format!("tmp{n:04}.tmp"),
                UsnReason::FILE_DELETE,
                ts(60 + i as i64),
                2000 + (i as i64) * 100,
            ));
        }

        let indicators = detect_secure_deletion(&records);
        let bulk = indicators
            .iter()
            .filter(|i| i.pattern == SecureDeletionPattern::BulkTempDeletion)
            .count();
        assert_eq!(bulk, 0);
    }

    #[test]
    fn test_mass_rename_with_common_extension_ignored() {
        // Mass renames to .txt should NOT trigger ransomware detection
        let mut records = Vec::new();
        for i in 0..25 {
            records.push(make_record(
                100 + i,
                &format!("file{i}.txt"),
                UsnReason::RENAME_NEW_NAME,
                ts(i as i64),
                1000 + (i as i64) * 100,
            ));
        }

        let indicators = detect_ransomware_patterns(&records);
        assert!(indicators.is_empty());
    }

    #[test]
    fn test_ransomware_high_count_high_confidence() {
        // 20+ renames to known extension should have 0.95 confidence
        let mut records = Vec::new();
        for i in 0..25 {
            records.push(make_record(
                100 + i,
                &format!("document{i}.docx.encrypted"),
                UsnReason::RENAME_NEW_NAME,
                ts(i as i64),
                1000 + (i as i64) * 100,
            ));
        }

        let indicators = detect_ransomware_patterns(&records);
        assert!(!indicators.is_empty());
        let encrypted_ind = indicators
            .iter()
            .find(|i| i.extension == ".encrypted")
            .unwrap();
        assert!(encrypted_ind.confidence >= 0.95);
    }

    #[test]
    fn test_ransomware_medium_count_medium_confidence() {
        // 10-19 renames should have 0.85 confidence
        let mut records = Vec::new();
        for i in 0..12 {
            records.push(make_record(
                100 + i,
                &format!("file{i}.locked"),
                UsnReason::RENAME_NEW_NAME,
                ts(i as i64),
                1000 + (i as i64) * 100,
            ));
        }

        let indicators = detect_ransomware_patterns(&records);
        let locked = indicators
            .iter()
            .find(|i| i.extension == ".locked")
            .unwrap();
        assert!((locked.confidence - 0.85).abs() < 0.01);
    }

    #[test]
    fn test_mass_rename_over_long_time_not_ransomware() {
        // Mass renames to same unknown extension but spread over > 10 minutes
        let mut records = Vec::new();
        for i in 0..25 {
            records.push(make_record(
                100 + i,
                &format!("file{i}.xyz_spread"),
                UsnReason::RENAME_NEW_NAME,
                ts(i as i64 * 60), // 1 minute apart, total > 10 min
                1000 + (i as i64) * 100,
            ));
        }

        let indicators = detect_ransomware_patterns(&records);
        let spread = indicators
            .iter()
            .filter(|i| i.extension == ".xyz_spread")
            .count();
        assert_eq!(spread, 0);
    }

    #[test]
    fn test_detect_journal_clearing_multiple_gaps() {
        // Multiple 24+ hour gaps increase confidence
        let records = vec![
            make_record(100, "a.txt", UsnReason::FILE_CREATE, ts(0), 100),
            make_record(101, "b.txt", UsnReason::FILE_CREATE, ts(25 * 3600), 200),
            make_record(102, "c.txt", UsnReason::FILE_CREATE, ts(50 * 3600), 300),
            make_record(103, "d.txt", UsnReason::FILE_CREATE, ts(75 * 3600), 400),
        ];

        let result = detect_journal_clearing(&records);
        assert_eq!(result.timestamp_gaps.len(), 3);
        assert!(result.confidence > 0.0);
    }

    #[test]
    fn test_timestomp_basic_info_change_with_close() {
        // BASIC_INFO_CHANGE | CLOSE (not isolated) should have lower confidence
        let records = vec![make_record(
            100,
            "stomped.exe",
            UsnReason::BASIC_INFO_CHANGE | UsnReason::CLOSE | UsnReason::SECURITY_CHANGE,
            ts(1000),
            5000,
        )];

        let indicators = detect_timestomping(&records);
        if !indicators.is_empty() {
            // If detected, confidence should be lower (0.5) because reason is not isolated
            assert!(indicators[0].confidence <= 0.5);
        }
    }

    #[test]
    fn test_sdelete_grouping_splits_on_time_gap() {
        // Line 96: groups.push when a group of >= 3 SDelete events is followed
        // by a time gap > 60 seconds, then more events start a new group.
        let mut records = Vec::new();

        // First group: 4 SDelete events within 60 seconds
        for i in 0..4u64 {
            records.push(make_record(
                100 + i,
                &"A".repeat(7),
                UsnReason::FILE_CREATE,
                ts(i as i64),
                1000 + (i as i64) * 100,
            ));
        }

        // Time gap of 120 seconds (> 60s threshold)
        // Small group of 2 SDelete events (< 3, should be cleared not pushed)
        records.push(make_record(
            200,
            &"B".repeat(7),
            UsnReason::FILE_DELETE,
            ts(124),
            2000,
        ));
        records.push(make_record(
            201,
            &"B".repeat(7),
            UsnReason::FILE_DELETE,
            ts(125),
            2100,
        ));

        // Another time gap
        // Third group: 3 more SDelete events
        for i in 0..3u64 {
            records.push(make_record(
                300 + i,
                &"C".repeat(7),
                UsnReason::FILE_CREATE,
                ts(300 + i as i64),
                3000 + (i as i64) * 100,
            ));
        }

        let indicators = detect_secure_deletion(&records);
        // Should detect at least the first group (4 events) and third group (3 events)
        let sdelete_indicators: Vec<_> = indicators
            .iter()
            .filter(|i| i.pattern == SecureDeletionPattern::SDelete)
            .collect();
        assert!(!sdelete_indicators.is_empty());
    }

    #[test]
    fn test_bulk_temp_deletion_grouping_splits_on_time_gap() {
        // Line 173: groups.push when a group of >= 10 .tmp deletions is followed
        // by a time gap > 30 seconds, then more events.
        let mut records = Vec::new();

        // First group: 12 tmp file deletions within 30 seconds
        for i in 0..12u64 {
            records.push(make_record(
                100 + i,
                &format!("tmp{i:04}.tmp"),
                UsnReason::FILE_DELETE,
                ts(i as i64),
                1000 + (i as i64) * 100,
            ));
        }

        // Time gap of 60 seconds (> 30s threshold)
        // Small group of 5 tmp deletions (< 10, should be cleared)
        for i in 0..5u64 {
            records.push(make_record(
                200 + i,
                &format!("tmpB{i:04}.tmp"),
                UsnReason::FILE_DELETE,
                ts(72 + i as i64),
                2000 + (i as i64) * 100,
            ));
        }

        // Another time gap, then another group of 10
        for i in 0..10u64 {
            records.push(make_record(
                300 + i,
                &format!("tmpC{i:04}.tmp"),
                UsnReason::FILE_DELETE,
                ts(200 + i as i64),
                3000 + (i as i64) * 100,
            ));
        }

        let indicators = detect_secure_deletion(&records);
        let bulk_indicators: Vec<_> = indicators
            .iter()
            .filter(|i| i.pattern == SecureDeletionPattern::BulkTempDeletion)
            .collect();
        assert!(!bulk_indicators.is_empty());
    }

    #[test]
    fn test_timestomping_other_before_event() {
        // Line 532: other.timestamp - event.timestamp path
        // when other event happens BEFORE the BASIC_INFO_CHANGE event
        // This tests the branch where other.timestamp < event.timestamp
        // so the abs difference is event.timestamp - other.timestamp.
        // Wait, line 531-532 actually is:
        //   let time_diff = if other.timestamp >= event.timestamp {
        //       other.timestamp - event.timestamp    // line 532
        //   } else {
        //       event.timestamp - other.timestamp
        //   };
        // Line 532 fires when other.timestamp >= event.timestamp.
        // The existing tests have nearby data changes AFTER the BASIC_INFO_CHANGE.
        // We need a test where the data change is AT or AFTER the event.
        // Actually, we need an ISOLATED BASIC_INFO_CHANGE where nearby events
        // DON'T have data changes but DO have timestamps >= event.timestamp.

        let records = vec![
            // A BASIC_INFO_CHANGE event (possible timestomping)
            make_record(
                100,
                "stomped.exe",
                UsnReason::BASIC_INFO_CHANGE,
                ts(1000),
                5000,
            ),
            // A nearby event AFTER the BASIC_INFO_CHANGE (> its timestamp)
            // but with SECURITY_CHANGE (not a data change), so it doesn't
            // suppress the timestomping detection
            make_record(
                101,
                "other.txt",
                UsnReason::SECURITY_CHANGE,
                ts(1010), // 10 seconds after, within 60s window
                5100,
            ),
        ];

        let indicators = detect_timestomping(&records);
        assert!(!indicators.is_empty());
        assert_eq!(indicators[0].filename, "stomped.exe");
    }

    #[test]
    fn test_ransomware_renames_without_extension() {
        // Renames with no extension should not cause issues
        let mut records = Vec::new();
        for i in 0..25 {
            records.push(make_record(
                100 + i,
                &format!("file{i}"), // No extension
                UsnReason::RENAME_NEW_NAME,
                ts(i as i64),
                1000 + (i as i64) * 100,
            ));
        }

        let indicators = detect_ransomware_patterns(&records);
        // Should not crash, and no indicator for files without extensions
        assert!(indicators.is_empty());
    }

    #[test]
    fn test_timestomp_other_timestamp_after_event() {
        // Cover line 557: `other.timestamp - event.timestamp` branch.
        // Create a BASIC_INFO_CHANGE event with a DATA_OVERWRITE event that occurs
        // AFTER it (within 60 seconds). This exercises the `other.timestamp >= event.timestamp`
        // path where `time_diff = other.timestamp - event.timestamp`.
        let records = vec![
            make_record(100, "file.exe", UsnReason::BASIC_INFO_CHANGE, ts(100), 5000),
            make_record(
                100,
                "file.exe",
                UsnReason::DATA_OVERWRITE,
                ts(110), // 10 seconds AFTER the BASIC_INFO_CHANGE
                5100,
            ),
        ];

        let indicators = detect_timestomping(&records);
        // The DATA_OVERWRITE is within 60 seconds and after the BASIC_INFO_CHANGE,
        // so it should NOT be flagged as timestomping.
        assert!(indicators.is_empty());
    }
}
