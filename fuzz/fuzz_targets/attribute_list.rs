#![no_main]
//! $ATTRIBUTE_LIST entry parsing over arbitrary bytes.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ntfs_core::parse_attribute_list(data);
});
