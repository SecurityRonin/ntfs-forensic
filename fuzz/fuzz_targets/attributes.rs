#![no_main]
//! Attribute-chain walking over arbitrary record bytes from arbitrary offsets.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // First byte selects a starting offset so the fuzzer can probe alignment.
    let (off, rec) = match data.split_first() {
        Some((o, r)) => (*o as usize, r),
        None => return,
    };
    let _ = ntfs_forensic::parse_attributes(rec, off);
});
