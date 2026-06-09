#![no_main]
//! INDX index-buffer parsing (signature, fixup, entries) over arbitrary bytes.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut buf = data.to_vec();
    let _ = ntfs_core::parse_index_buffer(&mut buf, 4096, 512);
});
