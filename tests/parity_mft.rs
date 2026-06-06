//! Parity gate (doer-checker): cross-validate ntfs-forensic's record parsing
//! against the battle-tested `mft` crate on a **real** `$MFT`.
//!
//! Run against a raw `$MFT` extracted from a real image, e.g. via TSK:
//!
//! ```bash
//! icat -o <ntfs_partition_lba> disk.E01 0 | head -c 64M > mft.raw
//! NTFS_FORENSIC_MFT=mft.raw cargo test --test parity_mft -- --ignored --nocapture
//! ```
//!
//! The mft crate is the independent oracle. Records are aligned by physical
//! position in the `$MFT` (which equals the record number on a contiguous MFT),
//! and the in-use / is-directory flags and the best Win32 file name are
//! compared. The gate fails on any flag disagreement.

use std::collections::HashMap;

use ntfs_forensic::{apply_fixup, parse_attributes, FileName, MftRecordHeader};

const FILE_NAME: u32 = 0x30;

/// Every `$FILE_NAME` ntfs-forensic parses for a record. A file may carry
/// several (hard links / 8.3-DOS / Win32 / POSIX), so the parity check validates
/// that the oracle's chosen name is *among* these — i.e. that ntfs-forensic
/// parsed it — rather than that both tools picked the same "best" one.
fn names(record: &[u8], first_attr_off: usize) -> Vec<String> {
    let Ok(attrs) = parse_attributes(record, first_attr_off) else {
        return Vec::new();
    };
    attrs
        .iter()
        .filter(|a| a.type_code == FILE_NAME)
        .filter_map(|a| a.resident_content(record))
        .filter_map(|content| FileName::parse(content).ok())
        .map(|fnm| fnm.name)
        .collect()
}

#[test]
#[ignore = "requires NTFS_FORENSIC_MFT pointing at a raw $MFT"]
fn parity_with_mft_crate() {
    let Ok(path) = std::env::var("NTFS_FORENSIC_MFT") else {
        return;
    };
    let data = std::fs::read(&path).expect("read $MFT");

    // Oracle: the mft crate, keyed by record number.
    let mut parser = mft::MftParser::from_buffer(data.clone()).expect("mft parser");
    let mut oracle: HashMap<u64, (bool, bool, Option<String>)> = HashMap::new();
    for entry in parser.iter_entries().flatten() {
        let name = entry.find_best_name_attribute().map(|n| n.name);
        // First occurrence wins: iteration is in physical order, so position N
        // (record number N on a contiguous MFT) is seen before any stray later
        // record that reuses the same number.
        oracle
            .entry(entry.header.record_number)
            .or_insert((entry.is_allocated(), entry.is_dir(), name));
    }

    // Subject: ntfs-forensic over the same 1024-byte records, aligned by position.
    let rec_size = 1024usize;
    let (mut compared, mut flag_mismatch, mut recnum_mismatch) = (0u64, 0u64, 0u64);
    let (mut name_match, mut name_total) = (0u64, 0u64);
    let mut samples: Vec<String> = Vec::new();

    for (i, chunk) in data.chunks(rec_size).enumerate() {
        if chunk.len() < rec_size || &chunk[0..4] != b"FILE" {
            continue;
        }
        let Some((o_alloc, o_dir, o_name)) = oracle.get(&(i as u64)) else {
            continue;
        };
        let mut buf = chunk.to_vec();
        if apply_fixup(&mut buf, 512).is_err() {
            continue;
        }
        let Ok(header) = MftRecordHeader::parse(&buf) else {
            continue;
        };
        compared += 1;

        if u64::from(header.record_number) != i as u64 {
            recnum_mismatch += 1;
        }
        if header.is_in_use() != *o_alloc || header.is_directory() != *o_dir {
            flag_mismatch += 1;
            if samples.len() < 25 {
                samples.push(format!(
                    "rec {i}: ntfs(use={}, dir={}) vs mft(alloc={}, dir={})",
                    header.is_in_use(),
                    header.is_directory(),
                    o_alloc,
                    o_dir
                ));
            }
        }
        if let Some(on) = o_name {
            name_total += 1;
            let ntfs_names = names(&buf, header.first_attribute_offset as usize);
            if ntfs_names.iter().any(|n| n == on) {
                name_match += 1;
            } else if samples.len() < 25 {
                samples.push(format!("rec {i} name: mft={on:?} not in ntfs {ntfs_names:?}"));
            }
        }
    }

    println!("── parity vs mft crate ──────────────────────────────");
    println!("records compared        : {compared}");
    println!("in-use/is-dir mismatches: {flag_mismatch}");
    println!("record-number mismatches: {recnum_mismatch}");
    println!(
        "name agreement          : {name_match}/{name_total} ({:.3}%)",
        if name_total == 0 {
            100.0
        } else {
            name_match as f64 * 100.0 / name_total as f64
        }
    );
    for s in &samples {
        println!("  {s}");
    }

    assert!(compared > 1000, "too few records compared: {compared}");
    assert_eq!(flag_mismatch, 0, "in-use/is-dir must match the mft crate");
    assert_eq!(recnum_mismatch, 0, "record numbers must match the mft crate");
    assert_eq!(
        name_match, name_total,
        "every name the oracle reports must be parsed by ntfs-forensic"
    );
}
