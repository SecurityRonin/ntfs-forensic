#![no_main]
//! MFT record header parse + update-sequence fixup over arbitrary bytes.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ntfs_forensic::MftRecordHeader::parse(data);
    // Fixup mutates in place; exercise it over a few plausible sector sizes.
    for &sector in &[512usize, 4096] {
        let mut buf = data.to_vec();
        let _ = ntfs_forensic::apply_fixup(&mut buf, sector);
    }
});
