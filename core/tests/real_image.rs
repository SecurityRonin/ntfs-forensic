//! Real-data validation (doer-checker).
//!
//! Synthetic fixtures inherit the author's blind spots, so the boot parser is
//! also checked against a real NTFS boot sector — the first 4 KiB of the NTFS
//! partition from the publicly-distributed DEF CON DFIR CTF 2018 `MaxPowers`
//! disk image. The expected values are the *independent* ground truth reported
//! by The Sleuth Kit's `fsstat`, not by this crate:
//!
//! ```text
//! $ fsstat -o 1026048 MaxPowersCDrive.E01
//! OEM Name: NTFS
//! First Cluster of MFT: 786432
//! First Cluster of MFT Mirror: 2
//! Size of MFT Entries: 1024 bytes
//! Size of Index Records: 4096 bytes
//! Volume Serial Number: 326C195B6C191B65
//! Sector Size: 512
//! Cluster Size: 4096
//! ```
//!
//! The full-image walk (open → read MFT → list directories → read files) needs
//! the EWF container layer, which lives in the orchestration crate; that path
//! is exercised by [`opens_raw_partition_image`] whenever a raw NTFS stream is
//! supplied via `NTFS_FORENSIC_TEST_IMAGE`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ntfs_core::BootSector;

/// The real boot sector carved from the DEF CON 2018 CTF image.
const REAL_BOOT: &[u8] = include_bytes!("data/defcon2018_cdrive_boot.bin");

#[test]
fn parses_real_ntfs_boot_sector_matching_tsk() {
    let boot = BootSector::parse(REAL_BOOT).expect("real NTFS boot sector must parse");

    // Every value below is what TSK fsstat derived independently of this crate.
    assert_eq!(boot.bytes_per_sector, 512, "sector size");
    assert_eq!(boot.cluster_size(), 4096, "cluster size");
    assert_eq!(boot.sectors_per_cluster, 8, "4096 / 512");
    assert_eq!(boot.mft_record_size, 1024, "MFT entry size");
    assert_eq!(boot.index_record_size, 4096, "index record size");
    assert_eq!(boot.mft_lcn, 786_432, "first cluster of $MFT");
    assert_eq!(boot.mftmirr_lcn, 2, "first cluster of $MFTMirr");
    assert_eq!(boot.volume_serial, 0x326C_195B_6C19_1B65, "volume serial");

    // The byte offset of $MFT must follow from cluster × cluster_size.
    assert_eq!(boot.mft_byte_offset(), 786_432 * 4096);
}

/// Full-image smoke test against a raw NTFS partition stream.
///
/// Ignored by default; run with a raw image (a single NTFS partition, offset 0
/// at the volume boot record) via:
///
/// ```bash
/// NTFS_FORENSIC_TEST_IMAGE=/path/to/ntfs.raw cargo test --test real_image -- --ignored
/// ```
#[test]
#[ignore = "requires NTFS_FORENSIC_TEST_IMAGE pointing at a raw NTFS partition"]
fn opens_raw_partition_image() {
    use ntfs_core::NtfsFs;
    use std::fs::File;

    let path = match std::env::var("NTFS_FORENSIC_TEST_IMAGE") {
        Ok(p) => p,
        Err(_) => return,
    };
    let mut fs = NtfsFs::open(File::open(&path).expect("open image")).expect("parse NTFS volume");

    // Record 0 is $MFT itself and must be an in-use base record.
    let mft = fs.read_record(0).expect("read $MFT record");
    let hdr = ntfs_core::MftRecordHeader::parse(&mft).expect("parse $MFT header");
    assert!(hdr.is_in_use(), "$MFT must be in use");
    assert!(hdr.is_base_record(), "$MFT must be a base record");

    // The root directory (record 5) must enumerate without panicking.
    let root = fs.read_record(5).expect("read root record");
    let entries = fs.directory_entries(&root).expect("list root directory");
    assert!(!entries.is_empty(), "root directory should not be empty");

    // Every record in the low MFT range either parses or returns a forensic
    // error — never a panic.
    for n in 0..64 {
        if let Ok(buf) = fs.read_record(n) {
            let _ = ntfs_core::MftRecordHeader::parse(&buf);
        }
    }
}
