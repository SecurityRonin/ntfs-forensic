#![no_main]
//! Data-run decoding over arbitrary bytes.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(runs) = ntfs_core::decode_runlist(data) {
        // total_clusters must also stay panic-free on whatever decoded.
        let _ = ntfs_core::runlist::total_clusters(&runs);
    }
});
