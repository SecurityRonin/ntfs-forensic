//! Journal Rewind engine for complete path reconstruction.
//!
//! Implements the CyberCX "Rewind" algorithm: processes USN journal entries
//! in reverse chronological order to reconstruct full paths even when MFT
//! entries have been reallocated multiple times.
//!
//! ## Algorithm
//!
//! Traditional tools resolve USN parent references against the *current* `$MFT`
//! state. When an MFT entry has been reused (sequence number changed), the
//! parent can't be found and the path is marked "UNKNOWN".
//!
//! The rewind approach:
//! 1. Seed a lookup table from the current `$MFT` state (entry -> name + parent)
//! 2. Process USN records from newest to oldest
//! 3. For each record, track the (entry, sequence) -> (name, `parent_entry`, `parent_seq`) mapping
//! 4. Handle renames by restoring old names when seeing `RENAME_OLD_NAME` events
//! 5. Recursively resolve paths through the lookup table
//!
//! This guarantees complete path resolution for every journal entry.

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usn::{FileAttributes, UsnReason};
    use chrono::DateTime;

    fn make_record(
        entry: u64,
        seq: u16,
        parent_entry: u64,
        parent_seq: u16,
        reason: UsnReason,
        filename: &str,
        usn: i64,
    ) -> UsnRecord {
        UsnRecord {
            mft_entry: entry,
            mft_sequence: seq,
            parent_mft_entry: parent_entry,
            parent_mft_sequence: parent_seq,
            usn,
            timestamp: DateTime::from_timestamp(1700000000, 0).unwrap(),
            reason,
            filename: filename.to_string(),
            file_attributes: FileAttributes::ARCHIVE,
            source_info: 0,
            security_id: 0,
            major_version: 2,
        }
    }

    #[test]
    fn test_entry_key_root() {
        let root = EntryKey::root();
        assert!(root.is_root());
        assert_eq!(root.entry, 5);
    }

    #[test]
    fn test_resolve_path_simple() {
        // MFT has: entry 100 "Users" -> root, entry 200 "admin" -> 100
        let engine = RewindEngine::from_mft(vec![
            (100, 1, "Users".into(), 5, 5),
            (200, 1, "admin".into(), 100, 1),
        ]);

        let path = engine.resolve_path(&EntryKey::new(200, 1));
        assert_eq!(path, ".\\Users\\admin");
    }

    #[test]
    fn test_resolve_path_root() {
        let engine = RewindEngine::new();
        let path = engine.resolve_path(&EntryKey::root());
        assert_eq!(path, ".");
    }

    #[test]
    fn test_resolve_path_unknown_entry() {
        let engine = RewindEngine::new();
        let path = engine.resolve_path(&EntryKey::new(999, 1));
        assert!(path.contains("UNKNOWN"));
    }

    #[test]
    fn test_rewind_simple_create() {
        // Scenario: file created at .\temp\malware.exe
        let mut engine = RewindEngine::from_mft(vec![(50, 1, "temp".into(), 5, 5)]);

        let records = vec![make_record(
            100,
            1,
            50,
            1,
            UsnReason::FILE_CREATE,
            "malware.exe",
            100,
        )];

        let resolved = engine.rewind(&records);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].full_path, ".\\temp\\malware.exe");
        assert_eq!(resolved[0].parent_path, ".\\temp");
    }

    #[test]
    fn test_rewind_resolves_unknown_parent_via_journal() {
        // Scenario from CyberCX blog:
        // MFT entry 983 was reused. Current state has seq=6, but the journal
        // record refers to parent 983 with seq=4 (the old allocation).
        // The journal itself contains events that tell us entry 983 seq 4
        // was a folder named "ip_scanner" under entry 500 "Drivers".
        //
        // Without rewind, parent 983:4 would be UNKNOWN.
        // With rewind, we should resolve it to .\Intel\Drivers\ip_scanner

        let mut engine = RewindEngine::from_mft(vec![(30, 1, "Intel".into(), 5, 5)]);

        // Journal records (oldest to newest):
        // 1. Folder "Drivers" created at entry 500, seq 1, parent 30:1 (Intel)
        // 2. Folder "ip_scanner" created at entry 983, seq 4, parent 500:1 (Drivers)
        // 3. File "data.txt" created at entry 1500, seq 1, parent 983:4 (ip_scanner)
        // 4. File "data.txt" deleted
        // 5. Folder "ip_scanner" deleted
        // 6. Entry 983 reused as seq 6 for something else
        let records = vec![
            make_record(500, 1, 30, 1, UsnReason::FILE_CREATE, "Drivers", 10),
            make_record(983, 4, 500, 1, UsnReason::FILE_CREATE, "ip_scanner", 20),
            make_record(1500, 1, 983, 4, UsnReason::FILE_CREATE, "data.txt", 30),
            make_record(1500, 1, 983, 4, UsnReason::FILE_DELETE, "data.txt", 40),
            make_record(983, 4, 500, 1, UsnReason::FILE_DELETE, "ip_scanner", 50),
            make_record(983, 6, 5, 5, UsnReason::FILE_CREATE, "NewFolder", 60),
        ];

        let resolved = engine.rewind(&records);

        // The data.txt create should resolve to .\Intel\Drivers\ip_scanner\data.txt
        assert_eq!(
            resolved[2].full_path,
            ".\\Intel\\Drivers\\ip_scanner\\data.txt"
        );
        // The new folder at entry 983 seq 6 should be .\NewFolder
        assert_eq!(resolved[5].full_path, ".\\NewFolder");
    }

    #[test]
    fn test_rewind_handles_rename() {
        // Scenario: folder renamed from "old_name" to "new_name"
        // Files created under the folder should show correct name at each point.

        let mut engine = RewindEngine::from_mft(vec![]);

        let records = vec![
            // Folder created as "old_name"
            make_record(100, 1, 5, 5, UsnReason::FILE_CREATE, "old_name", 10),
            // File created under old_name
            make_record(200, 1, 100, 1, UsnReason::FILE_CREATE, "before.txt", 20),
            // Folder renamed: old_name -> new_name
            make_record(100, 1, 5, 5, UsnReason::RENAME_OLD_NAME, "old_name", 30),
            make_record(100, 1, 5, 5, UsnReason::RENAME_NEW_NAME, "new_name", 31),
            // File created under new_name
            make_record(300, 1, 100, 1, UsnReason::FILE_CREATE, "after.txt", 40),
        ];

        let resolved = engine.rewind(&records);

        // before.txt should be under old_name at the time it was created
        assert_eq!(resolved[1].full_path, ".\\old_name\\before.txt");
        // after.txt should be under new_name
        assert_eq!(resolved[4].full_path, ".\\new_name\\after.txt");
    }

    #[test]
    fn test_rewind_multiple_reuse() {
        // Entry 50 is reused 3 times with different sequence numbers
        let mut engine = RewindEngine::from_mft(vec![]);

        let records = vec![
            make_record(50, 2, 5, 5, UsnReason::FILE_CREATE, "first_life", 10),
            make_record(50, 2, 5, 5, UsnReason::FILE_DELETE, "first_life", 20),
            make_record(50, 4, 5, 5, UsnReason::FILE_CREATE, "second_life", 30),
            make_record(50, 4, 5, 5, UsnReason::FILE_DELETE, "second_life", 40),
            make_record(50, 6, 5, 5, UsnReason::FILE_CREATE, "third_life", 50),
        ];

        let resolved = engine.rewind(&records);
        assert_eq!(resolved[0].full_path, ".\\first_life");
        assert_eq!(resolved[2].full_path, ".\\second_life");
        assert_eq!(resolved[4].full_path, ".\\third_life");
    }

    #[test]
    fn test_rewind_deep_path_reconstruction() {
        // Deep path: .\A\B\C\D\file.txt where all are created in journal
        let mut engine = RewindEngine::from_mft(vec![]);

        let records = vec![
            make_record(10, 1, 5, 5, UsnReason::FILE_CREATE, "A", 10),
            make_record(20, 1, 10, 1, UsnReason::FILE_CREATE, "B", 20),
            make_record(30, 1, 20, 1, UsnReason::FILE_CREATE, "C", 30),
            make_record(40, 1, 30, 1, UsnReason::FILE_CREATE, "D", 40),
            make_record(50, 1, 40, 1, UsnReason::FILE_CREATE, "file.txt", 50),
        ];

        let resolved = engine.rewind(&records);
        assert_eq!(resolved[4].full_path, ".\\A\\B\\C\\D\\file.txt");
    }

    #[test]
    fn test_from_mft_seeding() {
        let engine = RewindEngine::from_mft(vec![
            (100, 1, "Users".into(), 5, 5),
            (200, 1, "admin".into(), 100, 1),
            (300, 1, "Desktop".into(), 200, 1),
        ]);
        assert_eq!(engine.lookup_len(), 3);
        let path = engine.resolve_path(&EntryKey::new(300, 1));
        assert_eq!(path, ".\\Users\\admin\\Desktop");
    }

    #[test]
    fn test_rewind_engine_default() {
        let engine = RewindEngine::default();
        assert_eq!(engine.lookup_len(), 0);
    }

    #[test]
    fn test_rewind_engine_insert() {
        let mut engine = RewindEngine::new();
        engine.insert(
            EntryKey::new(100, 1),
            EntryInfo {
                name: "inserted.txt".to_string(),
                parent: EntryKey::root(),
            },
        );
        assert_eq!(engine.lookup_len(), 1);
        let path = engine.resolve_path(&EntryKey::new(100, 1));
        assert_eq!(path, ".\\inserted.txt");
    }

    #[test]
    fn test_resolve_path_circular_reference() {
        // Create circular parent references: A -> B -> A
        let mut engine = RewindEngine::new();
        engine.insert(
            EntryKey::new(100, 1),
            EntryInfo {
                name: "A".to_string(),
                parent: EntryKey::new(200, 1),
            },
        );
        engine.insert(
            EntryKey::new(200, 1),
            EntryInfo {
                name: "B".to_string(),
                parent: EntryKey::new(100, 1),
            },
        );

        let path = engine.resolve_path(&EntryKey::new(100, 1));
        // Should hit depth limit and return UNRESOLVED
        assert!(path.contains("UNRESOLVED"));
    }

    #[test]
    fn test_entry_key_not_root() {
        let key = EntryKey::new(100, 1);
        assert!(!key.is_root());
    }

    #[test]
    fn test_rewind_empty_records() {
        let mut engine = RewindEngine::new();
        let resolved = engine.rewind(&[]);
        assert!(resolved.is_empty());
    }

    #[test]
    fn test_rewind_data_extend_and_truncation() {
        let mut engine = RewindEngine::from_mft(vec![(50, 1, "data".into(), 5, 5)]);

        let records = vec![
            make_record(100, 1, 50, 1, UsnReason::FILE_CREATE, "log.txt", 10),
            make_record(100, 1, 50, 1, UsnReason::DATA_EXTEND, "log.txt", 20),
            make_record(100, 1, 50, 1, UsnReason::DATA_TRUNCATION, "log.txt", 30),
        ];

        let resolved = engine.rewind(&records);
        assert_eq!(resolved.len(), 3);
        assert_eq!(resolved[0].full_path, ".\\data\\log.txt");
        assert_eq!(resolved[1].full_path, ".\\data\\log.txt");
        assert_eq!(resolved[2].full_path, ".\\data\\log.txt");
    }

    #[test]
    fn test_resolve_path_hits_depth_limit_linear_chain() {
        // Create a chain of 258 entries (> 256 depth limit) that is NOT circular
        // but exceeds the depth guard. Entry 1000 -> 1001 -> 1002 -> ... -> 1257
        // None of them point to root, so path resolution will recurse 257+ times.
        let mut engine = RewindEngine::new();
        let chain_length = 258;
        for i in 0..chain_length {
            let entry_num = 1000 + i as u64;
            let parent_num = 1001 + i as u64; // Points to next in chain
            engine.insert(
                EntryKey::new(entry_num, 1),
                EntryInfo {
                    name: format!("dir_{i}"),
                    parent: EntryKey::new(parent_num, 1),
                },
            );
        }

        // Resolving from the start of the chain should hit depth limit
        let path = engine.resolve_path(&EntryKey::new(1000, 1));
        assert!(path.contains("UNRESOLVED") || path.contains("UNKNOWN"));
    }

    #[test]
    fn test_resolve_path_from_hits_depth_limit_in_rewind() {
        // Create a circular reference that will hit the depth limit in the
        // resolve_path_from function (used in the forward pass of rewind).
        // Build entries: A -> B -> C -> A (cycle)
        let mut engine = RewindEngine::new();
        engine.insert(
            EntryKey::new(100, 1),
            EntryInfo {
                name: "A".to_string(),
                parent: EntryKey::new(200, 1),
            },
        );
        engine.insert(
            EntryKey::new(200, 1),
            EntryInfo {
                name: "B".to_string(),
                parent: EntryKey::new(300, 1),
            },
        );
        engine.insert(
            EntryKey::new(300, 1),
            EntryInfo {
                name: "C".to_string(),
                parent: EntryKey::new(100, 1),
            },
        );

        // Process a record whose parent is in the cycle
        let records = vec![make_record(
            400,
            1,
            100,
            1,
            UsnReason::FILE_CREATE,
            "trapped.txt",
            10,
        )];

        let resolved = engine.rewind(&records);
        assert_eq!(resolved.len(), 1);
        // The parent path should contain UNRESOLVED due to the circular chain
        assert!(resolved[0].parent_path.contains("UNRESOLVED"));
    }

    #[test]
    fn test_rewind_forward_pass_unseen_entry() {
        // Test lines 204-206: forward_lookup doesn't have the key yet,
        // and the record is not a RENAME_NEW_NAME or FILE_CREATE.
        // This exercises the else branch in the forward pass.
        let mut engine = RewindEngine::from_mft(vec![(50, 1, "data".into(), 5, 5)]);

        let records = vec![
            // DATA_EXTEND is not RENAME_NEW_NAME nor FILE_CREATE
            // And entry 100:1 is not in the lookup initially
            make_record(100, 1, 50, 1, UsnReason::DATA_EXTEND, "log.txt", 10),
        ];

        let resolved = engine.rewind(&records);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].full_path, ".\\data\\log.txt");
    }

    #[test]
    fn test_resolve_path_from_unknown_parent_in_forward() {
        // Test line 245: resolve_path_from returns UNKNOWN for unknown key
        // This happens during rewind's forward pass when the parent key
        // is not in the forward_lookup and is not root.
        let mut engine = RewindEngine::new();

        let records = vec![
            // Parent 999:1 is not in any lookup and is not root
            make_record(100, 1, 999, 1, UsnReason::FILE_CREATE, "orphan.txt", 10),
        ];

        let resolved = engine.rewind(&records);
        assert_eq!(resolved.len(), 1);
        assert!(resolved[0].parent_path.contains("UNKNOWN(999:1)"));
    }

    #[test]
    fn test_seed_from_carved_adds_entries() {
        use crate::carve::CarvedMftEntry;

        let mut engine = RewindEngine::from_mft(vec![
            (5, 5, ".".into(), 5, 5), // root
            (10, 1, "Users".into(), 5, 5),
        ]);
        assert_eq!(engine.lookup_len(), 2);

        let carved = vec![
            CarvedMftEntry {
                offset: 0,
                entry_number: 20,
                sequence_number: 1,
                filename: "admin".to_string(),
                parent_entry: 10,
                parent_sequence: 1,
                is_directory: true,
                is_in_use: false, // deleted — carved from unallocated
            },
            CarvedMftEntry {
                offset: 1024,
                entry_number: 30,
                sequence_number: 1,
                filename: "Desktop".to_string(),
                parent_entry: 20,
                parent_sequence: 1,
                is_directory: true,
                is_in_use: false,
            },
        ];

        engine.seed_from_carved(&carved);

        assert_eq!(engine.lookup_len(), 4);
        let path = engine.resolve_path(&EntryKey::new(30, 1));
        assert_eq!(path, ".\\Users\\admin\\Desktop");
    }

    #[test]
    fn test_seed_from_carved_does_not_overwrite_allocated() {
        use crate::carve::CarvedMftEntry;

        // Allocated MFT says entry 100 seq 1 = "current.txt"
        let mut engine = RewindEngine::from_mft(vec![(100, 1, "current.txt".into(), 5, 5)]);

        // Carved data also has entry 100 seq 1 but with old name
        let carved = vec![CarvedMftEntry {
            offset: 0,
            entry_number: 100,
            sequence_number: 1,
            filename: "old_name.txt".to_string(),
            parent_entry: 5,
            parent_sequence: 5,
            is_directory: false,
            is_in_use: false,
        }];

        engine.seed_from_carved(&carved);

        // Allocated entry should win — carved should not overwrite
        assert_eq!(engine.lookup_len(), 1);
        let path = engine.resolve_path(&EntryKey::new(100, 1));
        assert_eq!(path, ".\\current.txt");
    }

    #[test]
    fn test_seed_from_carved_adds_historical_sequence() {
        use crate::carve::CarvedMftEntry;

        // Allocated MFT has entry 100 seq 3 (current)
        let mut engine = RewindEngine::from_mft(vec![(100, 3, "new_file.txt".into(), 5, 5)]);

        // Carved: entry 100 seq 1 (historical, different sequence)
        let carved = vec![CarvedMftEntry {
            offset: 0,
            entry_number: 100,
            sequence_number: 1,
            filename: "old_file.txt".to_string(),
            parent_entry: 5,
            parent_sequence: 5,
            is_directory: false,
            is_in_use: false,
        }];

        engine.seed_from_carved(&carved);

        // Both should exist — different sequence numbers
        assert_eq!(engine.lookup_len(), 2);
        assert_eq!(
            engine.resolve_path(&EntryKey::new(100, 3)),
            ".\\new_file.txt"
        );
        assert_eq!(
            engine.resolve_path(&EntryKey::new(100, 1)),
            ".\\old_file.txt"
        );
    }

    #[test]
    fn test_resolve_path_from_standalone() {
        // Test the resolve_path_from function directly via rewind behavior
        let mut engine = RewindEngine::new();
        let records = vec![make_record(
            10,
            1,
            5,
            5,
            UsnReason::FILE_CREATE,
            "root_file.txt",
            10,
        )];

        let resolved = engine.rewind(&records);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].parent_path, ".");
        assert_eq!(resolved[0].full_path, ".\\root_file.txt");
    }

    // ─── Carving pipeline integration tests ──────────────────────────────────

    #[test]
    fn test_carved_records_resolve_paths_via_carved_mft() {
        use crate::carve::CarvedMftEntry;
        use crate::usn::CarvedRecord;

        // Simulate: allocated MFT only has root (entry 5).
        // Carved MFT recovers a deleted directory tree: Users/admin/Temp
        // Carved USN records reference files under that deleted tree.

        let mut engine = RewindEngine::from_mft(vec![]);

        let carved_mft = vec![
            CarvedMftEntry {
                offset: 0,
                entry_number: 10,
                sequence_number: 1,
                filename: "Users".to_string(),
                parent_entry: 5,
                parent_sequence: 5,
                is_directory: true,
                is_in_use: false,
            },
            CarvedMftEntry {
                offset: 1024,
                entry_number: 20,
                sequence_number: 1,
                filename: "admin".to_string(),
                parent_entry: 10,
                parent_sequence: 1,
                is_directory: true,
                is_in_use: false,
            },
            CarvedMftEntry {
                offset: 2048,
                entry_number: 30,
                sequence_number: 1,
                filename: "Temp".to_string(),
                parent_entry: 20,
                parent_sequence: 1,
                is_directory: true,
                is_in_use: false,
            },
        ];

        engine.seed_from_carved(&carved_mft);

        // Carved USN records: malware.exe created under the deleted Temp dir
        let carved_usn = vec![CarvedRecord {
            offset: 50000,
            record: make_record(500, 1, 30, 1, UsnReason::FILE_CREATE, "malware.exe", 99999),
        }];

        // Merge carved USN records into the record list (simulating main.rs logic)
        let mut all_records: Vec<UsnRecord> = Vec::new();
        all_records.extend(carved_usn.into_iter().map(|c| c.record));

        let resolved = engine.rewind(&all_records);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].full_path, ".\\Users\\admin\\Temp\\malware.exe");
    }

    #[test]
    fn test_carved_and_allocated_records_merge_in_pipeline() {
        use crate::carve::CarvedMftEntry;
        use crate::usn::CarvedRecord;

        // Allocated: MFT has current tree, USN has recent records
        let mut engine = RewindEngine::from_mft(vec![
            (10, 1, "Windows".into(), 5, 5),
            (20, 1, "System32".into(), 10, 1),
        ]);

        // Carved: historical MFT directory that was deleted
        let carved_mft = vec![CarvedMftEntry {
            offset: 0,
            entry_number: 50,
            sequence_number: 2,
            filename: "HackTools".to_string(),
            parent_entry: 5,
            parent_sequence: 5,
            is_directory: true,
            is_in_use: false,
        }];
        engine.seed_from_carved(&carved_mft);

        // Allocated USN records
        let allocated = vec![make_record(
            100,
            1,
            20,
            1,
            UsnReason::FILE_CREATE,
            "cmd.exe",
            1000,
        )];

        // Carved USN records
        let carved_usn = vec![CarvedRecord {
            offset: 80000,
            record: make_record(
                200,
                1,
                50,
                2,
                UsnReason::FILE_CREATE,
                "mimikatz.exe",
                500, // older USN offset
            ),
        }];

        // Merge: allocated + carved, sorted by USN
        let mut all_records = allocated;
        all_records.extend(carved_usn.into_iter().map(|c| c.record));
        all_records.sort_by_key(|r| r.usn);

        let resolved = engine.rewind(&all_records);
        assert_eq!(resolved.len(), 2);

        // Carved record (lower USN) comes first after sorting
        assert_eq!(resolved[0].full_path, ".\\HackTools\\mimikatz.exe");
        assert_eq!(resolved[1].full_path, ".\\Windows\\System32\\cmd.exe");
    }
}
