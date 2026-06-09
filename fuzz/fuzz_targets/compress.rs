#![no_main]
//! LZNT1 decompression — the highest-risk surface (loops + back-references).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ntfs_core::decompress(data);
});
