//! `impl FileSystem for NtfsFs`, driven as `Arc<dyn FileSystem>` over a REAL
//! third-party NTFS volume (doer-checker).
//!
//! The fixture is `partition.dd` inside the committed `SampleTinyNtfsVolume.zip`
//! (Joakim Schicht's `LogFileParser` sample, MIT). Every asserted value is what
//! **The Sleuth Kit** (`fls` / `istat` / `fsstat`) reports independently of this
//! crate — the tool is the oracle, not our own reader:
//!
//! ```text
//! $ fsstat -f ntfs partition.dd    # Sector 512, Cluster 512
//! $ fls    -f ntfs partition.dd    # root (rec 5) → file1.txt=37 … file8.txt=32
//! $ istat  -f ntfs partition.dd 37 # file1.txt: $DATA Resident size 408, links 1
//! $ istat  -f ntfs partition.dd 0  # $MFT: $DATA Non-Resident size 262144, LCN 4778
//! ```

#![cfg(feature = "vfs")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Cursor, Read};
use std::sync::Arc;

use forensic_vfs::{
    Allocation, FileId, FileSystem, FsKind, NodeKind, ResidencyKind, SectorSizes, StreamId,
    TimeZonePolicy,
};
use ntfs_core::NtfsFs;

/// The committed `LogFileParser` sample volume — a 7 MiB deflated raw NTFS
/// partition. `tests/` is excluded from the published tarball, so `include_bytes!`
/// of the repo-root fixture is safe here (matches `parity_mft.rs` / `real_image.rs`).
const SAMPLE_ZIP: &[u8] = include_bytes!("../../tests/data/SampleTinyNtfsVolume.zip");

/// Extract `partition.dd` from the zip in memory and open it as an
/// `Arc<dyn FileSystem>` — proving `NtfsFs` composes object-safely.
fn open_real_volume() -> Arc<dyn FileSystem> {
    let mut archive = zip::ZipArchive::new(Cursor::new(SAMPLE_ZIP)).expect("open sample zip");
    let mut dd = Vec::new();
    archive
        .by_name("SampleTinyNtfsVolume/partition.dd")
        .expect("partition.dd present")
        .read_to_end(&mut dd)
        .expect("read partition.dd");
    let fs = NtfsFs::open(Cursor::new(dd)).expect("open NTFS volume");
    Arc::new(fs)
}

#[test]
fn identity_matches_tsk_geometry() {
    let fs = open_real_volume();
    assert_eq!(fs.kind(), FsKind::NTFS);
    assert_eq!(fs.timestamp_zone(), TimeZonePolicy::Utc);
    // fsstat: sector 512, cluster 512.
    assert_eq!(
        fs.sector_sizes(),
        SectorSizes {
            logical: 512,
            physical: 512,
            cluster_or_block: 512,
        }
    );
    // The NTFS root directory is record 5; istat reports its sequence as 5.
    assert_eq!(fs.root(), FileId::NtfsRef { entry: 5, seq: 5 });
}

#[test]
fn volume_label_matches_tsk() {
    // TSK `fsstat -f ntfs partition.dd` reports `Volume Name: New Volume` —
    // the $VOLUME_NAME attribute of the $Volume metafile (MFT record 3),
    // stored UTF-16LE. The tool is the oracle, not our own reader.
    let fs = open_real_volume();
    assert_eq!(fs.volume_label(), Some("New Volume".to_string()));
}

#[test]
fn read_dir_lists_real_root_entries() {
    let fs = open_real_volume();
    let entries: Vec<_> = fs
        .read_dir(fs.root())
        .unwrap()
        .map(Result::unwrap)
        .collect();

    // fls: file1.txt is inode 37, a regular file.
    let file1 = entries
        .iter()
        .find(|e| e.name == b"file1.txt")
        .expect("file1.txt in root");
    assert_eq!(file1.id, FileId::NtfsRef { entry: 37, seq: 1 });
    assert_eq!(file1.kind, NodeKind::File);

    // All eight user files are enumerated.
    for n in 1..=8 {
        let name = format!("file{n}.txt");
        assert!(
            entries.iter().any(|e| e.name == name.as_bytes()),
            "root should list {name}"
        );
    }
}

#[test]
fn lookup_finds_a_known_file() {
    let fs = open_real_volume();
    assert_eq!(
        fs.lookup(fs.root(), b"file1.txt").unwrap(),
        Some(FileId::NtfsRef { entry: 37, seq: 1 })
    );
    assert_eq!(fs.lookup(fs.root(), b"no-such-file").unwrap(), None);
}

#[test]
fn meta_matches_istat() {
    let fs = open_real_volume();
    let m = fs.meta(FileId::NtfsRef { entry: 37, seq: 1 }).unwrap();

    assert_eq!(m.ino, 37);
    assert_eq!(m.kind, NodeKind::File);
    assert_eq!(m.nlink, 1); // istat: Links: 1
                            // istat: $DATA Resident, size 408.
    assert_eq!(m.size, 408);
    assert_eq!(m.residency, ResidencyKind::Resident { inline_len: 408 });

    // istat SI times: Created 2013-05-01, Modified 2013-04-28 — created is later,
    // proving born/modified map to the correct (distinct) $SI fields.
    let born = m.times.born.expect("born present");
    let modified = m.times.modified.expect("modified present");
    assert!(
        born.unix_nanos > modified.unix_nanos,
        "created (2013-05-01) is later than modified (2013-04-28)"
    );
}

#[test]
fn read_at_returns_file_bytes() {
    let fs = open_real_volume();
    let id = FileId::NtfsRef { entry: 37, seq: 1 };

    // icat: file1.txt is 408 bytes beginning "Just some bogus text".
    let mut buf = [0u8; 1024];
    let n = fs.read_at(id, StreamId::Default, 0, &mut buf).unwrap();
    assert_eq!(n, 408);
    assert_eq!(&buf[..15], b"Just some bogus");

    // A non-zero offset returns the windowed suffix.
    let mut win = [0u8; 16];
    let n = fs.read_at(id, StreamId::Default, 5, &mut win).unwrap();
    assert_eq!(&win[..n], b"some bogus text ");

    // Reading past the end yields zero bytes, not an error.
    assert_eq!(
        fs.read_at(id, StreamId::Default, 10_000, &mut buf).unwrap(),
        0
    );
}

/// The committed volume with MFT record 32 (`file8.txt`) marked deleted exactly
/// as NTFS does it: the record-header `IN_USE` flag (bit `0x0001` of the `flags`
/// field at record offset `0x16`) cleared, while its `$STANDARD_INFORMATION` and
/// `$FILE_NAME` bytes stay intact. That is a genuine deleted MFT record — not a
/// mock — so `deleted_nodes()` recovers the file's real name, parent, and MACB
/// times. (Record 32 is located by its self-identifying header record-number
/// field at offset `0x2C`; only the true record 32 carries that number — the
/// `$MFTMirr` mirrors records 0-3 only and index buffers use the `INDX`
/// signature — so the scan is unambiguous and survives fixture drift.)
fn open_with_deleted_file8() -> Arc<dyn FileSystem> {
    let mut archive = zip::ZipArchive::new(Cursor::new(SAMPLE_ZIP)).expect("open sample zip");
    let mut dd = Vec::new();
    archive
        .by_name("SampleTinyNtfsVolume/partition.dd")
        .expect("partition.dd present")
        .read_to_end(&mut dd)
        .expect("read partition.dd");

    let mut rec_off = None;
    let mut off = 0usize;
    while off + 0x30 <= dd.len() {
        if &dd[off..off + 4] == b"FILE" {
            let recnum = u32::from_le_bytes([
                dd[off + 0x2c],
                dd[off + 0x2d],
                dd[off + 0x2e],
                dd[off + 0x2f],
            ]);
            if recnum == 32 {
                rec_off = Some(off);
                break;
            }
        }
        off += 512;
    }
    let rec_off = rec_off.expect("MFT record 32 (file8.txt) present in sample volume");

    // The record must start allocated, or the "deletion" would be a no-op.
    let flags_lo = rec_off + 0x16;
    assert_eq!(
        dd[flags_lo] & 0x01,
        0x01,
        "record 32 must be in-use before deletion"
    );
    dd[flags_lo] &= !0x01; // clear IN_USE — the exact bit NTFS flips on delete

    let fs = NtfsFs::open(Cursor::new(dd)).expect("open NTFS volume");
    Arc::new(fs)
}

#[test]
fn deleted_nodes_recovers_deleted_file_name_and_parent() {
    let fs = open_with_deleted_file8();
    let deleted: Vec<_> = fs.deleted_nodes().unwrap().map(Result::unwrap).collect();

    let node = deleted
        .iter()
        .find(|d| d.name == b"file8.txt")
        .expect("deleted_nodes must recover file8.txt");

    // Identity: MFT record 32, sequence 3 — a readable FileId::NtfsRef.
    assert_eq!(node.id, FileId::NtfsRef { entry: 32, seq: 3 });
    // Parent is the NTFS root directory (record 5, sequence 5).
    assert_eq!(node.parent, Some(FileId::NtfsRef { entry: 5, seq: 5 }));
    // Name-layer status is Deleted; it is a regular file.
    assert_eq!(node.meta.allocated, Allocation::Deleted);
    assert_eq!(node.meta.kind, NodeKind::File);
    // MACB times survive the delete ($SI-sourced).
    assert!(
        node.meta.times.born.is_some(),
        "born time recovered from $SI"
    );

    // The recovered id is genuinely readable — its resident $DATA reads back.
    let mut buf = [0u8; 512];
    let n = fs.read_at(node.id, StreamId::Default, 0, &mut buf).unwrap();
    assert!(
        n > 0,
        "deleted file8.txt $DATA is readable via its recovered id"
    );
}

#[test]
fn unallocated_reports_free_clusters_consistent_with_bitmap() {
    // `unallocated()` reads the volume's real `$Bitmap` (MFT record 6) and emits
    // each maximal run of free clusters. The independent cross-check (no external
    // tool): the $MFT's own clusters are allocated, so none of them may appear in
    // an unallocated run. We compare against the $MFT extent the reader reports
    // for record 0 — a different code path — so agreement is not self-referential.
    let fs = open_real_volume();

    let free: Vec<_> = fs.unallocated().unwrap().map(Result::unwrap).collect();
    assert!(
        !free.is_empty(),
        "a real volume with slack space has free clusters"
    );

    // Runs are ordered, non-empty, and non-overlapping (maximal spans).
    let mut prev_end = 0u64;
    for r in &free {
        assert!(r.run.len > 0, "a free run is never zero-length");
        assert!(
            r.run.image_offset >= prev_end,
            "free runs are ordered and disjoint"
        );
        prev_end = r.run.image_offset + r.run.len;
    }

    // No free run overlaps the (allocated) $MFT $DATA.
    let mft: Vec<_> = fs
        .extents(FileId::NtfsRef { entry: 0, seq: 1 }, StreamId::Default)
        .unwrap()
        .map(Result::unwrap)
        .collect();
    for m in &mft {
        let m_start = m.run.image_offset;
        let m_end = m_start + m.run.len;
        for r in &free {
            let r_start = r.run.image_offset;
            let r_end = r_start + r.run.len;
            assert!(
                r_end <= m_start || r_start >= m_end,
                "free run [{r_start},{r_end}) overlaps allocated $MFT [{m_start},{m_end})"
            );
        }
    }
}

#[test]
fn extents_returns_mft_runs() {
    let fs = open_real_volume();
    // $MFT (record 0): istat → $DATA Non-Resident, size 262144, first LCN 4778.
    let runs: Vec<_> = fs
        .extents(FileId::NtfsRef { entry: 0, seq: 1 }, StreamId::Default)
        .unwrap()
        .map(Result::unwrap)
        .collect();

    assert!(!runs.is_empty(), "$MFT $DATA is non-resident");
    // First run starts at the first MFT cluster: 4778 * 512 bytes.
    assert_eq!(runs[0].run.image_offset, 4778 * 512);
    assert!(!runs[0].run.flags.sparse);
    // The runs cover the whole (fully-allocated) 262144-byte $MFT $DATA.
    let total: u64 = runs.iter().map(|r| r.run.len).sum();
    assert_eq!(total, 262_144);
}
