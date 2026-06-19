//! Real-data LZNT1 regression (doer-checker).
//!
//! Synthetic round-trips validate only the author's own encoding assumptions —
//! they pass while the codec is wrong (the LZNT1 inverted bit-split once shipped
//! green against a fixture encoded *to* the bug). So the codec is also pinned to
//! a genuine on-disk NTFS-compressed stream, with The Sleuth Kit as the
//! independent oracle for the plaintext.
//!
//! Provenance (see `tests/data/README.md`): DFIR Madness "Stolen Szechuan Sauce"
//! CITADEL-DC01 C: drive (Windows Server 2012 R2), NTFS partition at sector
//! offset 718848, cluster size 4096.
//!
//! `C:\ProgramData\Microsoft\Windows\WER\ReportArchive\...\Report.wer`,
//! MFT inode 437 — a `$DATA Non-Resident, Compressed` stream of actual size
//! 1832 bytes occupying a single allocated cluster (LCN 291553): one 16-cluster
//! LZNT1 compression unit, so the cluster holds the entire compressed stream and
//! `icat` returns the whole plaintext.
//!
//! ```text
//! $ istat  -o 718848 <E01> 437      # $DATA Non-Resident, Compressed  size: 1832  → LCN 291553
//! $ icat   -o 718848 <E01> 437      > lznt1_real.expected   # TSK-decompressed plaintext (oracle)
//! $ blkcat -o 718848 <E01> 291553 1 > lznt1_real.bin        # raw on-disk LZNT1 stream (one cluster)
//! ```
//!
//! The assertion is that our codec (`lznt1::decompress`, re-exported by
//! `ntfs_core`) reproduces TSK's plaintext byte-for-byte.

#![allow(clippy::unwrap_used, clippy::expect_used)]

/// The raw on-disk LZNT1 stream: the single allocated cluster (LCN 291553) of
/// `Report.wer`'s compressed `$DATA`, carved with `blkcat`.
const REAL_COMPRESSED: &[u8] = include_bytes!("../../tests/data/lznt1_real.bin");

/// The independent oracle: TSK `icat`'s decompression of the same `$DATA`.
const TSK_PLAINTEXT: &[u8] = include_bytes!("../../tests/data/lznt1_real.expected");

#[test]
fn decompresses_real_ntfs_stream_matching_tsk() {
    let mut out = Vec::new();
    ntfs_core::decompress(REAL_COMPRESSED, &mut out).expect("real LZNT1 stream must decode");

    // A unit decodes to at most its full size; `ntfs_core::data` truncates to the
    // file's real size, so the regression mirrors that and compares against the
    // oracle's 1832-byte plaintext.
    out.truncate(TSK_PLAINTEXT.len());

    assert_eq!(
        out, TSK_PLAINTEXT,
        "LZNT1 decode must match TSK icat plaintext byte-for-byte"
    );
}
