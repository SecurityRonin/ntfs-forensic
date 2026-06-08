//! NTFS metadata-artifact parsers live in ntfs-core: $MFTMirr, $LogFile, and
//! MFT-entry carving all decode NTFS on-disk structures, so they belong with
//! the reader (detection/correlation is layered on top, elsewhere).

use ntfs_core::carve::{carve_mft_entries, CarvedMftEntry, MftCarvingStats};
use ntfs_core::logfile::{detect_journal_clearing, extract_usn_from_logfile, parse_logfile};
use ntfs_core::mftmirr::compare_mft_mirror;

#[test]
fn ntfs_metadata_artifact_parsers_are_exposed_and_handle_empty_input() {
    // Every parser must degrade gracefully on empty input — never panic.
    let _ = compare_mft_mirror(&[], &[]);
    if let Ok(summary) = parse_logfile(&[]) {
        let _: bool = detect_journal_clearing(&summary);
    }
    assert!(extract_usn_from_logfile(&[]).is_empty());

    let (entries, stats): (Vec<CarvedMftEntry>, MftCarvingStats) = carve_mft_entries(&[]);
    assert!(entries.is_empty());
    let _ = stats;
}
