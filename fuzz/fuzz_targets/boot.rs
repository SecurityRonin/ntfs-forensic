#![no_main]
//! The volume boot record is fully attacker-controlled — parse must never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ntfs_forensic::BootSector::parse(data);
});
