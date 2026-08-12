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
    Allocation, DirEntry, FileId, FileSystem, FsKind, NodeKind, ResidencyKind, RunAlloc,
    SectorSizes, StreamId, TimeZonePolicy,
};
use ntfs_core::NtfsFs;

/// The committed `LogFileParser` sample volume — a 7 MiB deflated raw NTFS
/// partition. `tests/` is excluded from the published tarball, so `include_bytes!`
/// of the repo-root fixture is safe here (matches `parity_mft.rs` / `real_image.rs`).
const SAMPLE_ZIP: &[u8] = include_bytes!("../../tests/data/SampleTinyNtfsVolume.zip");

/// The committed tiny NTFS volume with an ntfs-3g `IntxLNK` symlink (provenance
/// in `tests/data/README.md`).
const TINY_ZIP: &[u8] = include_bytes!("../../tests/data/tiny.zip");

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

/// The raw `partition.dd` bytes, so a test can mutate a real volume rather than
/// invent one from scratch.
fn raw_volume() -> Vec<u8> {
    let mut archive = zip::ZipArchive::new(Cursor::new(SAMPLE_ZIP)).expect("open sample zip");
    let mut dd = Vec::new();
    archive
        .by_name("SampleTinyNtfsVolume/partition.dd")
        .expect("partition.dd present")
        .read_to_end(&mut dd)
        .expect("read partition.dd");
    dd
}

/// Walks `fs` recursively and returns the entry whose path is `rel` (joined
/// with `/`), if present.
fn find_entry(fs: &dyn FileSystem, rel: &str) -> Option<DirEntry> {
    // Cycle-guarded like the engine's own walker: NTFS emits `.`/`..`-style
    // FILE_NAME entries that carry the directory flag, so a naive walk of a
    // real volume would loop forever on the parent reference.
    let mut visited = std::collections::HashSet::new();
    let mut stack = vec![(fs.root(), String::new())];
    while let Some((id, prefix)) = stack.pop() {
        if !visited.insert(id) {
            continue;
        }
        for e in fs.read_dir(id).ok()?.collect::<Result<Vec<_>, _>>().ok()? {
            let name = String::from_utf8_lossy(&e.name).into_owned();
            let path = if prefix.is_empty() { name.clone() } else { format!("{prefix}/{name}") };
            if path == rel {
                return Some(e);
            }
            if e.kind == NodeKind::Dir {
                stack.push((e.id, path));
            }
        }
    }
    None
}

#[test]
fn symlink_surfaces_as_symlink_with_target() {
    // The committed tiny.zip volume carries an ntfs-3g-authored `IntxLNK`
    // symlink; the patched adapter must classify it and decode the target
    // exactly as ntfs-3g's own mount does (../README.txt).
    let mut archive = zip::ZipArchive::new(Cursor::new(TINY_ZIP)).expect("open tiny zip");
    let mut dd = Vec::new();
    archive
        .by_name("tiny.img")
        .expect("tiny.img present")
        .read_to_end(&mut dd)
        .expect("read tiny.img");
    let fs = NtfsFs::open(Cursor::new(dd)).expect("open NTFS volume");

    let link = find_entry(&fs, "nested/readme-link.txt").expect("readme-link.txt present");
    assert_eq!(link.kind, NodeKind::Symlink, "the adapter must classify the IntxLNK record as a symlink");
    assert_eq!(
        fs.read_link(link.id, 4096).expect("read_link"),
        b"../README.txt",
        "the decoded target must match ntfs-3g's own resolution"
    );
    let meta = fs.meta(link.id).expect("symlink meta");
    assert_eq!(meta.kind, NodeKind::Symlink);

    // A regular file is not a link and reads an empty target, not an error.
    let readme = find_entry(&fs, "README.txt").expect("README.txt present");
    assert_eq!(readme.kind, NodeKind::File);
    assert_eq!(fs.read_link(readme.id, 4096).expect("read_link regular file"), b"");
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

/// **Tier-1 (independent-oracle) validation of `unallocated()`.**
///
/// The Sleuth Kit is the oracle. On the committed sample volume:
///
/// ```text
/// $ fsstat -f ntfs partition.dd
///   Sector Size: 512
///   Cluster Size: 512
///   Total Cluster Range: 0 - 14334        # 14335 clusters total
/// $ blkls   -f ntfs partition.dd | wc -c   # unallocated clusters, concatenated
///   3503616                                # 3503616 / 512 = 6843 free clusters
/// $ blkls -e -f ntfs partition.dd | wc -c  # every cluster (sanity)
///   7339520                                # 7339520 / 512 = 14335 == total
/// ```
///
/// `blkls` (default) extracts exactly the `$Bitmap`-unallocated clusters, so its
/// byte count IS the free-space oracle: **6843 free clusters × 512 = 3 503 616
/// bytes**. This test sums the `len` of every extent `unallocated()` emits and
/// asserts it equals that number — reconciling our `$Bitmap` walk against TSK's,
/// not against ourselves. It is env-gated (`NTFS_TIER1=1`) like the crate's other
/// real-artifact checks so the default `cargo test` stays hermetic.
#[test]
fn unallocated_total_matches_tsk_blkls_free_clusters() {
    if std::env::var("NTFS_TIER1").is_err() {
        return; // Tier-1 oracle reconciliation — opt in with NTFS_TIER1=1.
    }

    // Independent ground truth from `blkls` (see doc comment above).
    const CLUSTER_SIZE: u64 = 512;
    const TSK_FREE_CLUSTERS: u64 = 6843;
    const TSK_FREE_BYTES: u64 = TSK_FREE_CLUSTERS * CLUSTER_SIZE; // 3_503_616

    let fs = open_real_volume();
    let free: Vec<_> = fs.unallocated().unwrap().map(Result::unwrap).collect();
    assert!(!free.is_empty(), "the volume has free clusters");

    let mut total_free_bytes = 0u64;
    for r in &free {
        // Every extent is a genuine unallocated run …
        assert_eq!(r.alloc, RunAlloc::Unallocated);
        // … and cluster-aligned in both offset and length.
        assert_eq!(
            r.run.image_offset % CLUSTER_SIZE,
            0,
            "free run offset {} is cluster-aligned",
            r.run.image_offset
        );
        assert_eq!(
            r.run.len % CLUSTER_SIZE,
            0,
            "free run length {} is a whole number of clusters",
            r.run.len
        );
        total_free_bytes += r.run.len;
    }

    // The reconciliation: our summed free space == TSK's free-cluster count × size.
    assert_eq!(
        total_free_bytes,
        TSK_FREE_BYTES,
        "sum of unallocated() extents ({total_free_bytes} B = {} clusters) must equal \
         TSK blkls free space ({TSK_FREE_BYTES} B = {TSK_FREE_CLUSTERS} clusters)",
        total_free_bytes / CLUSTER_SIZE
    );
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

// ---------------------------------------------------------------------------
// Refusals on a real volume.
//
// The tests above all address the filesystem correctly, so they only ever walk
// the happy path. These drive the same entry points with an identity from
// another filesystem and with a named stream, on a volume that is genuinely
// mounted — so a refusal here is the adapter's decision, not a failure to open
// the image.
//
// This matters more than coverage arithmetic. `FileId` is a fleet-wide union:
// an ext4 inode, an APFS oid and an NTFS reference are all just integers in a
// struct. If the NTFS adapter coerced `ExtInode { ino: 5 }` into MFT record 5,
// it would return real bytes from the wrong object under a request that looks
// entirely valid — a wrong answer rather than an error.
// ---------------------------------------------------------------------------

/// An identity belonging to another filesystem, structurally valid but not NTFS.
fn foreign_id() -> FileId {
    FileId::ExtInode { ino: 5, gen: 1 }
}

#[test]
fn every_entry_point_refuses_a_foreign_file_id() {
    let fs = open_real_volume();
    let bad = foreign_id();

    assert!(
        fs.read_dir(bad).is_err(),
        "read_dir must refuse a non-NTFS id"
    );
    assert!(fs.meta(bad).is_err(), "meta must refuse a non-NTFS id");
    assert!(
        fs.lookup(bad, b"anything").is_err(),
        "lookup must refuse a non-NTFS parent id"
    );
    assert!(
        fs.extents(bad, StreamId::Default).is_err(),
        "extents must refuse a non-NTFS id"
    );
    let mut buf = [0u8; 16];
    assert!(
        fs.read_at(bad, StreamId::Default, 0, &mut buf).is_err(),
        "read_at must refuse a non-NTFS id"
    );
}

#[test]
fn byte_paths_refuse_a_named_stream_rather_than_serving_the_default() {
    // A named-stream id cannot be mapped back to its ADS name. Serving $DATA
    // instead would hand back the wrong stream's bytes for an ADS request —
    // silently, and with no way for the caller to tell.
    let fs = open_real_volume();
    let root = FileId::NtfsRef { entry: 5, seq: 5 };

    assert!(
        fs.extents(root, StreamId::Named(1)).is_err(),
        "extents must refuse a named stream"
    );
    let mut buf = [0u8; 16];
    assert!(
        fs.read_at(root, StreamId::Named(1), 0, &mut buf).is_err(),
        "read_at must refuse a named stream"
    );
}

#[test]
fn a_valid_ntfs_id_still_works_after_the_refusals() {
    // Control for the two tests above: they must fail because the identity is
    // foreign, not because this volume rejects everything. The root directory
    // resolves on the same handle.
    let fs = open_real_volume();
    let root = FileId::NtfsRef { entry: 5, seq: 5 };
    assert!(
        fs.meta(root).is_ok(),
        "the root record must still resolve — otherwise the refusals prove nothing"
    );
}

#[test]
fn an_out_of_range_record_is_an_error_not_a_panic_or_fabricated_metadata() {
    // The identity is well-formed NTFS — it just points past the end of this
    // volume's $MFT. That is what a corrupt index entry or a carved reference
    // looks like, and it must surface as a typed error on every entry point
    // rather than panicking or returning default-looking metadata that an
    // examiner would read as fact.
    let fs = open_real_volume();
    let far = FileId::NtfsRef {
        entry: u64::MAX / 2,
        seq: 1,
    };

    assert!(
        fs.meta(far).is_err(),
        "meta must reject a record past the MFT"
    );
    assert!(
        fs.read_dir(far).is_err(),
        "read_dir must reject a record past the MFT"
    );
    assert!(
        fs.lookup(far, b"x").is_err(),
        "lookup must reject a parent past the MFT"
    );
    assert!(
        fs.extents(far, StreamId::Default).is_err(),
        "extents must reject a record past the MFT"
    );
    let mut buf = [0u8; 16];
    assert!(
        fs.read_at(far, StreamId::Default, 0, &mut buf).is_err(),
        "read_at must reject a record past the MFT"
    );
}

// ---------------------------------------------------------------------------
// Degradation on a damaged volume (T2 — real image, documented mutation).
//
// These are not synthetic volumes invented wholesale. Each starts from the same
// real partition.dd the tests above validate against TSK, and applies one
// mutation stated in the test. The expected outcome follows from the
// construction — "the image now ends at byte N, so any record stored past N
// cannot be read" — rather than from an expected-answer chosen by the author.
//
// What they assert is the property that matters for a forensic reader: damage
// must surface as a typed error or an absent value. It must never panic, and it
// must never degrade into a confident-looking empty answer, because a report
// cannot tell the difference between "no label" and "could not read the label".
// ---------------------------------------------------------------------------

/// Truncate the volume to `keep` bytes: the boot sector and the start of $MFT
/// survive, so the filesystem still mounts, but records stored beyond the cut
/// are unreadable. This is what a partial image or a bad-sector run looks like.
fn truncated_volume(keep: usize) -> Option<NtfsFs<Cursor<Vec<u8>>>> {
    let mut dd = raw_volume();
    dd.truncate(keep);
    NtfsFs::open(Cursor::new(dd)).ok()
}

#[test]
fn a_truncated_volume_either_refuses_to_mount_or_degrades_without_panicking() {
    // Sweep the cut point across the image. Every outcome is acceptable except a
    // panic: NtfsFs::open may reject the volume outright, or it may mount and
    // then fail per-record. What must not happen is an unwind, and what must not
    // happen is a fabricated answer.
    for keep in [512usize, 4096, 65_536, 1 << 20, 3 << 20] {
        let Some(fs) = truncated_volume(keep) else {
            continue; // refused at mount time — the loud path, also fine
        };

        // A label that cannot be read is None, never a placeholder string.
        if let Some(label) = fs.volume_label() {
            assert!(
                !label.is_empty(),
                "an unreadable $Volume must yield None, not an empty label at keep={keep}"
            );
        }

        // Walk records well past the surviving bytes. Each entry point must
        // return Ok or Err — the assertion is that control returns at all.
        for entry in [5u64, 64, 4096, 65_536] {
            let id = FileId::NtfsRef { entry, seq: 1 };
            let _ = fs.meta(id);
            let _ = fs.read_dir(id);
            let _ = fs.lookup(id, b"probe");
            let _ = fs.extents(id, StreamId::Default);
            let mut buf = [0u8; 32];
            let _ = fs.read_at(id, StreamId::Default, 0, &mut buf);
        }
    }
}

#[test]
fn truncation_actually_removes_readable_records() {
    // Control for the sweep above. If every truncation still mounted a fully
    // readable volume, the test would pass while exercising nothing — the
    // "green over work never performed" failure mode. At least one cut point
    // must produce a volume where a record the intact image serves is no longer
    // readable.
    let intact = open_real_volume();
    let root = FileId::NtfsRef { entry: 5, seq: 5 };
    assert!(
        intact.meta(root).is_ok(),
        "precondition: the intact volume serves its root record"
    );

    let damaged_somewhere =
        [512usize, 4096, 65_536, 1 << 20]
            .into_iter()
            .any(|keep| match truncated_volume(keep) {
                None => true, // refused to mount: damage observed
                Some(fs) => (0..4096u64)
                    .step_by(64)
                    .any(|entry| fs.meta(FileId::NtfsRef { entry, seq: 1 }).is_err()),
            });
    assert!(
        damaged_somewhere,
        "no truncation produced an unreadable record — the mutation is not biting, \
         so the degradation sweep proves nothing"
    );
}

/// Offsets of every copy of MFT record `n` in this sample volume, found by
/// scanning rather than assumed.
///
/// The image carries both $MFT and its $MFTMirr, so record 3 exists twice. A
/// mutation that damages only one copy leaves the reader a good one to fall back
/// on — which is exactly what the first version of this test got wrong, and why
/// the offsets are derived from the image instead of hard-coded to one location.
fn mft_record_offsets(dd: &[u8], n: u32) -> Vec<usize> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while let Some(rel) = dd[i..].windows(4).position(|w| w == b"FILE") {
        let at = i + rel;
        if at % 512 == 0 && at + 0x30 <= dd.len() {
            let recno =
                u32::from_le_bytes([dd[at + 0x2C], dd[at + 0x2D], dd[at + 0x2E], dd[at + 0x2F]]);
            if recno == n {
                out.push(at);
            }
        }
        i = at + 4;
    }
    out
}

#[test]
fn an_unreadable_volume_record_yields_no_label_rather_than_a_placeholder() {
    // Documented mutation of the real image: overwrite the "FILE" signature on
    // EVERY copy of MFT record 3 ($Volume) so its header will not parse, in both
    // $MFT and $MFTMirr. $MFT's own record 0 is untouched, so the volume still
    // mounts and the only thing lost is the label.
    //
    // The expected result follows from the construction rather than a chosen
    // answer: with no readable $Volume there is no label, so the only honest
    // output is None. A placeholder or empty string would be indistinguishable,
    // in a report, from a volume genuinely named "".
    let mut dd = raw_volume();
    let offsets = mft_record_offsets(&dd, 3);
    assert!(
        !offsets.is_empty(),
        "precondition: the sample volume contains a $Volume record to damage"
    );
    for off in &offsets {
        dd[*off..*off + 4].copy_from_slice(b"XXXX");
    }
    let fs = NtfsFs::open(Cursor::new(dd)).expect("volume still mounts; only $Volume was damaged");

    assert_eq!(
        fs.volume_label(),
        None,
        "an unparseable $Volume record must produce no label at all"
    );
}

#[test]
fn the_intact_volume_does_report_a_label() {
    // Control for the mutation above. Without it, `volume_label() == None` would
    // pass equally well if this volume simply had no label, and the test would
    // prove nothing about the damage.
    let fs = open_real_volume();
    assert!(
        fs.volume_label().is_some(),
        "precondition: the intact sample volume carries a label"
    );
}
