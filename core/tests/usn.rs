//! The USN journal parser core lives in ntfs-core: $UsnJrnl:$J records are an
//! NTFS metadata artifact, so decoding them belongs with the NTFS reader.

use ntfs_core::usn::{parse_usn_record_v2, FileAttributes, UsnReason, UsnRecord};

#[test]
fn usn_parser_core_is_exposed_and_rejects_short_input() {
    // Too-short input must degrade to an Err, never panic.
    assert!(parse_usn_record_v2(&[]).is_err());
    assert!(parse_usn_record_v2(&[0u8; 8]).is_err());

    // The flag types and record struct are part of the public surface.
    let _ = (FileAttributes::empty(), UsnReason::empty());
    fn _accepts_record(_: &UsnRecord) {}
}
