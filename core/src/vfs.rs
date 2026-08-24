//! `impl FileSystem for NtfsFs` — the forensic-vfs adapter (behind the `vfs`
//! feature).
//!
//! [`NtfsFs`] already serves every read through a shared `&self` over a
//! `Mutex`-guarded source, so one mounted handle backs N workers. This module
//! maps that reader onto the [`forensic_vfs::FileSystem`] contract: NTFS nodes
//! are addressed by [`FileId::NtfsRef`] (MFT record + sequence), directory and
//! run enumerations are owned `Send` streams, and every fallible ntfs-core call
//! is translated to a typed [`VfsError`] — never an `unwrap`/panic
//! (Paranoid Gatekeeper).

use std::io::{Read, Seek};

use forensic_vfs::{
    Allocation, ByteRun, DeletedNode, DeletedStream, DirEntry, DirStream, ExtentStream, FileId,
    FileSystem, FsKind, FsMeta, MacbTimes, NodeKind, NodeStream, ResidencyKind, RunAlloc, RunFlags,
    RunInfo, SectorSizes, SmallHex, StreamId, TimeResolution, TimeSource, TimeStamp,
    TimeZonePolicy, VfsError, VfsResult,
};
use forensicnomicon::ntfs::{attr_types, filename_namespace, mft_records};

use crate::attribute::{Attribute, AttributeBody};
use crate::error::NtfsError;
use crate::file_name::FileName;
use crate::fs::NtfsFs;
use crate::parse_attributes;
use crate::record::MftRecordHeader;
use crate::standard_information::StandardInformation;
use crate::time::Filetime;

/// `$FILE_NAME` flag bit marking a directory (its record carries a `$I30`
/// index). NTFS stores this in the name attribute's `flags` field as
/// `FILE_ATTRIBUTE_DIRECTORY`/index-present; it is *not* the DOS `0x10`
/// directory bit.
const FN_FLAG_DIRECTORY: u32 = 0x1000_0000;

/// `$REPARSE_POINT` attribute type (Windows symlinks and junctions).
const ATTR_REPARSE_POINT: u32 = 0xC0;

/// Windows reparse tag for a symbolic link.
const REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;

/// Windows reparse tag for a mount point (junction).
const REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;

/// WSL reparse tag for a symbolic link (`ntfs-3g` `-o special_files=wsl`, and
/// the Windows Subsystem for Linux itself). Distinct from the classic
/// `0xA000000C`: the payload is a version word plus a **UTF-8** target, not a
/// `SubstituteName`/`PrintName` pair.
const REPARSE_TAG_LX_SYMLINK: u32 = 0xA000_001D;

/// WSL reparse tag for a unix-domain socket. Carries no payload — the tag is
/// the whole statement.
const REPARSE_TAG_AF_UNIX: u32 = 0x8000_0023;

/// WSL reparse tag for a FIFO / named pipe. No payload.
const REPARSE_TAG_LX_FIFO: u32 = 0x8000_0024;

/// WSL reparse tag for a character device. The major/minor pair lives in an
/// `$EA`, not in the reparse point.
const REPARSE_TAG_LX_CHR: u32 = 0x8000_0025;

/// WSL reparse tag for a block device. Major/minor in an `$EA`, as for
/// [`REPARSE_TAG_LX_CHR`].
const REPARSE_TAG_LX_BLK: u32 = 0x8000_0026;

/// ntfs-3g (Linux) stores symlinks as a resident unnamed `$DATA` whose content
/// starts with this 7-byte magic (followed by a version byte and a UTF-16LE
/// target path). Windows-created symlinks instead carry a `$REPARSE_POINT`
/// attribute; both forms are recognized.
const NTFS_3G_SYMLINK_MAGIC: &[u8] = b"IntxLNK";

/// ntfs-3g's Interix encoding for a character device: the magic is followed by
/// a 64-bit major/minor pair rather than a path.
const NTFS_3G_CHR_MAGIC: &[u8] = b"IntxCHR";

/// ntfs-3g's Interix encoding for a block device.
const NTFS_3G_BLK_MAGIC: &[u8] = b"IntxBLK";

fn utf16le(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect()
}

/// Decode a `$REPARSE_POINT` value for a symlink or mount point: the
/// substitute name (the on-disk truth, usually `\??\C:\…`), UTF-16LE.
/// `None` for an unrecognized tag or a malformed buffer — never a fabricated
/// target.
fn decode_reparse_buffer(content: &[u8]) -> Option<String> {
    if content.len() < 8 {
        return None;
    }
    let tag = u32::from_le_bytes(content[0..4].try_into().ok()?);
    if tag != REPARSE_TAG_SYMLINK && tag != REPARSE_TAG_MOUNT_POINT {
        return None;
    }
    let data_len = usize::from(u16::from_le_bytes(content[4..6].try_into().ok()?));
    let data = content.get(8..8 + data_len)?;
    // The two buffers do NOT share a layout: a symlink carries a 4-byte `Flags`
    // field that a junction does not, so its PathBuffer starts four bytes later
    // (Wine include/ddk/ntifs.h:160; MS-FSCC 2.1.2.4 vs 2.1.2.5).
    //
    //   both:     SubstituteNameOffset(2) SubstituteNameLength(2)
    //             PrintNameOffset(2) PrintNameLength(2)
    //   symlink:  Flags(4)
    //   both:     PathBuffer[…]
    //
    // SubstituteNameOffset is relative to the start of PathBuffer, so the
    // substitute name begins at `data + path_base + SubstituteNameOffset`.
    // Reading a symlink at +8 lands inside Flags and truncates the target.
    let path_base = if tag == REPARSE_TAG_SYMLINK { 12 } else { 8 };
    if data.len() < path_base {
        return None;
    }
    let sub_off = usize::from(u16::from_le_bytes(data[0..2].try_into().ok()?));
    let sub_len = usize::from(u16::from_le_bytes(data[2..4].try_into().ok()?));
    let path = data.get(path_base + sub_off..path_base + sub_off + sub_len)?;
    Some(String::from_utf16_lossy(&utf16le(path)))
}

/// Decode the ntfs-3g `IntxLNK` `$DATA` payload: the 7-byte magic (the
/// version byte is not validated — matching ntfs-3g and 7-Zip, which accept
/// any version), then the UTF-16LE target path.
fn decode_ntfs3g_symlink(data: &[u8]) -> Option<String> {
    if data.len() >= 8 && data.starts_with(NTFS_3G_SYMLINK_MAGIC) {
        Some(String::from_utf16_lossy(&utf16le(&data[8..])))
    } else {
        None
    }
}

/// The symlink target of an MFT record, when it is one: the `$REPARSE_POINT`
/// substitute name (Windows) or the ntfs-3g `IntxLNK` `$DATA` payload (Linux).
/// `None` for a regular file or directory.
fn reparse_target(rec: &[u8], attrs: &[Attribute]) -> Option<String> {
    if let Some(content) = attrs
        .iter()
        .find(|a| a.type_code == ATTR_REPARSE_POINT)
        .and_then(|a| a.resident_content(rec))
    {
        return decode_reparse_buffer(content);
    }
    let data = attrs
        .iter()
        .find(|a| a.type_code == attr_types::DATA && a.name.is_none())?
        .resident_content(rec)?;
    decode_ntfs3g_symlink(data)
}

/// The node kind a `$REPARSE_POINT` tag denotes, for the tags that describe a
/// POSIX node type. `None` for a tag this reader does not model (a dedup
/// pointer, a cloud placeholder, an unknown vendor tag) — those are not node
/// types and must not be reported as one.
fn kind_of_reparse_tag(tag: u32) -> Option<NodeKind> {
    match tag {
        REPARSE_TAG_SYMLINK | REPARSE_TAG_MOUNT_POINT | REPARSE_TAG_LX_SYMLINK => {
            Some(NodeKind::Symlink)
        }
        REPARSE_TAG_LX_CHR => Some(NodeKind::CharDevice),
        REPARSE_TAG_LX_BLK => Some(NodeKind::BlockDevice),
        REPARSE_TAG_LX_FIFO => Some(NodeKind::Fifo),
        REPARSE_TAG_AF_UNIX => Some(NodeKind::Socket),
        _ => None,
    }
}

/// Classify a non-directory MFT record that carries a POSIX node type, in
/// either encoding a Linux driver writes.
///
/// Returns `None` when the record states no such type — an ordinary file, or a
/// reparse point of a kind this reader does not model.
///
/// **Not every type survives every encoding.** ntfs-3g's Interix mode stores a
/// FIFO as a zero-length `$DATA` and a socket as a one-byte `$DATA`, neither
/// carrying a magic (`libntfs-3g/dir.c`). Those are indistinguishable from
/// ordinary files on disk, so they are not classified here — inferring a FIFO
/// from "empty file" would fabricate an observation the volume never made.
fn special_kind(rec: &[u8], attrs: &[Attribute]) -> Option<NodeKind> {
    if let Some(content) = attrs
        .iter()
        .find(|a| a.type_code == ATTR_REPARSE_POINT)
        .and_then(|a| a.resident_content(rec))
    {
        if content.len() >= 4 {
            let tag = u32::from_le_bytes(content[0..4].try_into().ok()?);
            return kind_of_reparse_tag(tag);
        }
        return None;
    }
    // Interix: the type is the first 7 bytes of the unnamed resident $DATA.
    let data = attrs
        .iter()
        .find(|a| a.type_code == attr_types::DATA && a.name.is_none())?
        .resident_content(rec)?;
    if data.len() < 8 {
        return None;
    }
    if data.starts_with(NTFS_3G_SYMLINK_MAGIC) {
        Some(NodeKind::Symlink)
    } else if data.starts_with(NTFS_3G_CHR_MAGIC) {
        Some(NodeKind::CharDevice)
    } else if data.starts_with(NTFS_3G_BLK_MAGIC) {
        Some(NodeKind::BlockDevice)
    } else {
        None
    }
}

/// The MFT record number carried by a [`FileId`]. Only NTFS references address
/// this filesystem; any other identity domain is a caller error, surfaced loud.
fn entry_of(id: FileId) -> VfsResult<u64> {
    match id {
        FileId::NtfsRef { entry, .. } => Ok(entry),
        other => Err(VfsError::Unsupported {
            layer: "ntfs file-id",
            scheme: format!("{other:?}"),
        }),
    }
}

/// The ntfs-core stream name for a [`StreamId`]. The default `$DATA` is `None`;
/// a named-stream id cannot be mapped back to its ADS name, so it is refused
/// loud rather than silently read as the default stream.
fn stream_name(stream: StreamId) -> VfsResult<Option<&'static str>> {
    match stream {
        StreamId::Default => Ok(None),
        other => Err(VfsError::Unsupported {
            layer: "ntfs stream",
            scheme: format!("{other:?}"),
        }),
    }
}

/// Translate an ntfs-core error into the VFS error type, keeping I/O distinct
/// from a structural decode failure (bootstrap fails loud; a per-node miss maps
/// to `Decode`, carrying the original message).
fn map_err(e: NtfsError) -> VfsError {
    match e {
        NtfsError::Io(source) => VfsError::Io {
            op: "ntfs read",
            source,
        },
        other => VfsError::Decode {
            layer: "ntfs",
            offset: 0,
            detail: other.to_string(),
            bytes: SmallHex::new(&[]),
        },
    }
}

/// Assemble the unified [`FsMeta`] for a record whose raw bytes are `rec`.
fn build_meta(entry: u64, rec: &[u8]) -> VfsResult<FsMeta> {
    let header = MftRecordHeader::parse(rec).map_err(map_err)?;
    let attrs = parse_attributes(rec, header.first_attribute_offset as usize).map_err(map_err)?;

    // MAC(B) times from $STANDARD_INFORMATION (the primary set). A missing or
    // malformed $SI leaves the times empty rather than fabricating zeros.
    let mut times = MacbTimes::default();
    if let Some(content) = attrs
        .iter()
        .find(|a| a.type_code == attr_types::STANDARD_INFORMATION)
        .and_then(|a| a.resident_content(rec))
    {
        if let Ok(si) = StandardInformation::parse(content) {
            let ts = |ft: Filetime| TimeStamp {
                unix_nanos: ft.to_unix_nanos(),
                source: TimeSource::Si,
                resolution: TimeResolution::WinFileTime,
            };
            times = MacbTimes {
                born: Some(ts(si.created)),
                modified: Some(ts(si.modified)),
                changed: Some(ts(si.mft_modified)),
                accessed: Some(ts(si.accessed)),
            };
        }
    }

    // Size + residency come from the unnamed $DATA, which is authoritative:
    // the $FILE_NAME sizes are updated lazily and are routinely zero on a
    // real volume. A directory has no $DATA (size 0, trivially resident).
    let data = attrs
        .iter()
        .find(|a| a.type_code == attr_types::DATA && a.name.is_none());
    let (size, residency) = match data.map(|a| &a.body) {
        Some(AttributeBody::Resident { content_length, .. }) => (
            u64::from(*content_length),
            ResidencyKind::Resident {
                inline_len: *content_length,
            },
        ),
        Some(AttributeBody::NonResident { real_size, .. }) => {
            (*real_size, ResidencyKind::NonResident)
        }
        None => (0, ResidencyKind::Resident { inline_len: 0 }),
    };

    Ok(FsMeta {
        ino: entry,
        kind: if header.is_directory() {
            NodeKind::Dir
        } else {
            special_kind(rec, &attrs).unwrap_or(NodeKind::File)
        },
        allocated: if header.is_in_use() {
            Allocation::Allocated
        } else {
            Allocation::Deleted
        },
        size,
        nlink: u32::from(header.hard_link_count),
        uid: None,
        gid: None,
        mode: None,
        times,
        streams: Vec::new(),
        residency,
        link_target: None,
    })
}

/// Namespace preference when a record carries several `$FILE_NAME` links: pick
/// the human name over the 8.3 short name. Win32/DOS combined > Win32 > POSIX >
/// DOS, so a DOS-only short name is used only when nothing better exists.
fn namespace_rank(ns: u8) -> u8 {
    match ns {
        filename_namespace::WIN32_AND_DOS => 3,
        filename_namespace::WIN32 => 2,
        filename_namespace::POSIX => 1,
        _ => 0, // DOS (or unknown): the least-preferred short name
    }
}

/// The best `$FILE_NAME` for a record — the highest-ranked namespace among all
/// name links (Win32 over 8.3 DOS). `None` when the record has no parseable
/// `$FILE_NAME`, so the caller never fabricates a name.
fn best_file_name(rec: &[u8]) -> Option<FileName> {
    let header = MftRecordHeader::parse(rec).ok()?;
    let attrs = parse_attributes(rec, header.first_attribute_offset as usize).ok()?;
    attrs
        .iter()
        .filter(|a| a.type_code == attr_types::FILE_NAME)
        .filter_map(|a| a.resident_content(rec))
        .filter_map(|c| FileName::parse(c).ok())
        .max_by_key(|fnm| namespace_rank(fnm.namespace))
}

/// Number of `$MFT` records = the unnamed `$DATA` real size / the record size.
/// A record read past this bound is rejected by `read_record`, so the walk is
/// bounded to the real MFT rather than scanning arbitrary image bytes.
fn mft_record_count<R: Read + Seek + Send>(fs: &NtfsFs<R>) -> VfsResult<u64> {
    let rec0 = fs.read_record(mft_records::MFT).map_err(map_err)?;
    let meta = build_meta(mft_records::MFT, &rec0)?;
    let rec_size = fs.boot().mft_record_size;
    if rec_size == 0 {
        return Ok(0); // cov:unreachable: a mounted volume always has a non-zero record size
    }
    Ok(meta.size / rec_size)
}

/// Maximal runs of free (unallocated) clusters in an NTFS `$Bitmap`.
///
/// `$Bitmap` stores one bit per cluster, **LSB-first** within each byte: a set
/// bit marks the cluster allocated, a clear bit marks it free. Bits past
/// `total_clusters` are padding in the final byte (the bitmap length is rounded
/// up to a whole byte) and are ignored — the `total_clusters` bound is
/// authoritative, so a crafted padding bit cannot invent or hide a cluster.
///
/// Each maximal span of free clusters is returned as `(start_cluster, length)`.
/// A byte the bitmap does not contain (a short/truncated bitmap) reads as
/// **allocated**, so free space is never fabricated past the described data; the
/// caller (`unallocated`) separately rejects a bitmap too short to cover the
/// volume, so that arm is a defensive floor, not the normal path.
fn free_runs(bitmap: &[u8], total_clusters: u64) -> Vec<(u64, u64)> {
    let mut runs: Vec<(u64, u64)> = Vec::new();
    let mut run_start: Option<u64> = None;
    for cluster in 0..total_clusters {
        let byte_idx = usize::try_from(cluster / 8).unwrap_or(usize::MAX);
        let bit = (cluster % 8) as u8;
        let allocated = bitmap.get(byte_idx).is_none_or(|b| (b >> bit) & 1 == 1);
        if allocated {
            if let Some(start) = run_start.take() {
                runs.push((start, cluster - start));
            }
        } else if run_start.is_none() {
            run_start = Some(cluster);
        }
    }
    if let Some(start) = run_start {
        runs.push((start, total_clusters - start));
    }
    runs
}

/// Core of [`FileSystem::unallocated`]: map an NTFS `$Bitmap`'s free clusters to
/// image-relative [`RunInfo`] extents. Factored out of the trait method so it is
/// unit-tested directly over synthetic bitmap bytes; the method itself is the
/// thin `$Bitmap`-reading wrapper. `base_offset` is added to every run so an
/// extent addresses the enclosing image/partition (0 here, matching the
/// volume-relative offsets [`FileSystem::extents`] reports).
fn unallocated_runs(
    bitmap: &[u8],
    cluster_size: u64,
    total_clusters: u64,
    base_offset: u64,
) -> Vec<RunInfo> {
    free_runs(bitmap, total_clusters)
        .into_iter()
        .map(|(start, len)| RunInfo {
            run: ByteRun {
                image_offset: base_offset.saturating_add(start.saturating_mul(cluster_size)),
                len: len.saturating_mul(cluster_size),
                flags: RunFlags::default(),
            },
            alloc: RunAlloc::Unallocated,
        })
        .collect()
}

impl<R: Read + Seek + Send> NtfsFs<R> {
    /// The POSIX node kind the MFT record at `entry` states, in either encoding
    /// a Linux driver writes (Windows/WSL `$REPARSE_POINT` tags, or the ntfs-3g
    /// Interix `$DATA` magics). `None` for an ordinary file.
    ///
    /// A read/parse miss degrades to `None` — the entry then reads as a regular
    /// file rather than failing the whole listing.
    fn special_kind_of_record(&self, entry: u64) -> Option<NodeKind> {
        let rec = self.read_record(entry).ok()?;
        let header = MftRecordHeader::parse(&rec).ok()?;
        let attrs = parse_attributes(&rec, header.first_attribute_offset as usize).ok()?;
        special_kind(&rec, &attrs)
    }
}

impl<R: Read + Seek + Send> FileSystem for NtfsFs<R> {
    fn kind(&self) -> FsKind {
        FsKind::NTFS
    }

    fn root(&self) -> FileId {
        // The NTFS root directory is record 5. Read its header for the sequence;
        // if the record cannot be read (never true on a valid volume this was
        // opened from), degrade to sequence 0 rather than panic.
        let seq = self
            .read_record(mft_records::ROOT)
            .ok()
            .and_then(|rec| MftRecordHeader::parse(&rec).ok())
            .map_or(0, |h| h.sequence_number);
        FileId::NtfsRef {
            entry: mft_records::ROOT,
            seq,
        }
    }

    fn sector_sizes(&self) -> SectorSizes {
        let boot = self.boot();
        SectorSizes {
            logical: u32::from(boot.bytes_per_sector),
            physical: u32::from(boot.bytes_per_sector),
            cluster_or_block: boot.cluster_size() as u32,
        }
    }

    fn timestamp_zone(&self) -> TimeZonePolicy {
        TimeZonePolicy::Utc
    }

    /// The NTFS volume label from the `$Volume` metafile (MFT record 3): its
    /// `$VOLUME_NAME` attribute (type `0x60`) is resident and holds the label in
    /// UTF-16LE. `None` when `$Volume`/the attribute is absent or the label is
    /// empty — never a fabricated name. A per-record read/parse miss degrades to
    /// `None` (a missing label is not a bootstrap failure).
    fn volume_label(&self) -> Option<String> {
        let rec = self.read_record(mft_records::VOLUME).ok()?;
        let header = MftRecordHeader::parse(&rec).ok()?;
        let attrs = parse_attributes(&rec, header.first_attribute_offset as usize).ok()?;
        let content = attrs
            .iter()
            .find(|a| a.type_code == attr_types::VOLUME_NAME)
            .and_then(|a| a.resident_content(&rec))?;
        // $VOLUME_NAME is UTF-16LE; an odd trailing byte cannot form a code unit
        // and is dropped by `chunks_exact`.
        let units: Vec<u16> = content
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let label: String = char::decode_utf16(units)
            .map(|r| r.unwrap_or('\u{FFFD}'))
            .collect();
        if label.is_empty() {
            None
        } else {
            Some(label)
        }
    }

    fn read_dir(&self, ino: FileId) -> VfsResult<DirStream> {
        let entry = entry_of(ino)?;
        let rec = self.read_record(entry).map_err(map_err)?;
        let entries = self.directory_entries(&rec).map_err(map_err)?;
        let out: Vec<VfsResult<DirEntry>> = entries
            .into_iter()
            .filter_map(|e| {
                let file_ref = e.file_reference;
                e.file_name.map(|fnm| {
                    let kind = if fnm.flags & FN_FLAG_DIRECTORY != 0 {
                        NodeKind::Dir
                    } else {
                        self.special_kind_of_record(file_ref.record_number)
                            .unwrap_or(NodeKind::File)
                    };
                    Ok(DirEntry {
                        name: fnm.name.into_bytes(),
                        id: FileId::NtfsRef {
                            entry: file_ref.record_number,
                            seq: file_ref.sequence,
                        },
                        kind,
                    })
                })
            })
            .collect();
        Ok(DirStream::new(out.into_iter()))
    }

    fn extents(&self, ino: FileId, stream: StreamId) -> VfsResult<ExtentStream> {
        let entry = entry_of(ino)?;
        let name = stream_name(stream)?;
        let runs = self.runs_by_record(entry, name).map_err(map_err)?;
        let cluster = self.boot().cluster_size();
        let out: Vec<VfsResult<RunInfo>> = runs
            .into_iter()
            .map(|r| {
                let image_offset = r.lcn.unwrap_or(0).saturating_mul(cluster);
                let len = r.length.saturating_mul(cluster);
                Ok(RunInfo {
                    run: ByteRun {
                        image_offset,
                        len,
                        flags: RunFlags {
                            sparse: r.lcn.is_none(),
                            ..RunFlags::default()
                        },
                    },
                    alloc: RunAlloc::Allocated,
                })
            })
            .collect();
        Ok(ExtentStream::new(out.into_iter()))
    }

    fn lookup(&self, parent: FileId, name: &[u8]) -> VfsResult<Option<FileId>> {
        let entry = entry_of(parent)?;
        let rec = self.read_record(entry).map_err(map_err)?;
        for e in self.directory_entries(&rec).map_err(map_err)? {
            if let Some(fnm) = &e.file_name {
                if fnm.name.as_bytes() == name {
                    return Ok(Some(FileId::NtfsRef {
                        entry: e.file_reference.record_number,
                        seq: e.file_reference.sequence,
                    }));
                }
            }
        }
        Ok(None)
    }

    fn meta(&self, ino: FileId) -> VfsResult<FsMeta> {
        let entry = entry_of(ino)?;
        let rec = self.read_record(entry).map_err(map_err)?;
        build_meta(entry, &rec)
    }

    fn read_at(&self, ino: FileId, stream: StreamId, off: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let entry = entry_of(ino)?;
        let name = stream_name(stream)?;
        // Cap the materialized read at the window end, so a huge stream is never
        // pulled wholesale to satisfy a small windowed read.
        let cap = off.saturating_add(buf.len() as u64);
        let data = self
            .read_data_by_record(entry, name, cap)
            .map_err(map_err)?;
        let start = usize::try_from(off).unwrap_or(usize::MAX);
        if start >= data.len() {
            return Ok(0);
        }
        let n = buf.len().min(data.len() - start);
        buf[..n].copy_from_slice(&data[start..start + n]);
        Ok(n)
    }

    fn read_link(&self, ino: FileId, cap: usize) -> VfsResult<Vec<u8>> {
        let entry = entry_of(ino)?;
        let rec = self.read_record(entry).map_err(map_err)?;
        let header = MftRecordHeader::parse(&rec).map_err(map_err)?;
        let attrs =
            parse_attributes(&rec, header.first_attribute_offset as usize).map_err(map_err)?;
        // A non-link node reads as an empty target, not a per-node error.
        let mut target = reparse_target(&rec, &attrs)
            .unwrap_or_default()
            .into_bytes();
        // Both name fields of a reparse buffer are image-controlled u16s, so a
        // hostile symlink must not allocate past what the caller asked for
        // (matches the ext4/xfs/ufs/btrfs/zfs adapters).
        target.truncate(cap);
        Ok(target)
    }

    fn deleted(&self) -> VfsResult<NodeStream> {
        // The bare-`FsMeta` surface stays empty; the rich identity-carrying
        // surface is `deleted_nodes` below.
        Ok(NodeStream::empty())
    }

    /// Recover deleted MFT records: walk the `$MFT`, and for every record whose
    /// header parses but whose `IN_USE` flag is clear, recover the file's name +
    /// parent from `$FILE_NAME` and its MACB times from `$STANDARD_INFORMATION`.
    /// A record with no parseable `$FILE_NAME` is skipped (no name to recover),
    /// never fabricated. Only the recovered nodes are collected — a small subset
    /// of the MFT, not the whole table — so the returned stream stays bounded.
    fn deleted_nodes(&self) -> VfsResult<DeletedStream> {
        let count = mft_record_count(self)?;
        let mut out: Vec<VfsResult<DeletedNode>> = Vec::new();
        for entry in 0..count {
            // A per-record read/parse miss is not a bootstrap failure: an
            // unused/zeroed record fails the FILE-signature check and is skipped.
            let Ok(rec) = self.read_record(entry) else {
                continue;
            };
            let Ok(header) = MftRecordHeader::parse(&rec) else {
                continue;
            };
            if header.is_in_use() {
                continue;
            }
            let Some(fnm) = best_file_name(&rec) else {
                continue; // no $FILE_NAME → nothing to recover, do not fabricate
            };
            let Ok(meta) = build_meta(entry, &rec) else {
                continue;
            };
            // Parent record 0 ($MFT self) is never a real directory: treat it as
            // an orphan (unrecoverable parent) rather than a bogus reference.
            let parent = if fnm.parent.record_number == 0 {
                None
            } else {
                Some(FileId::NtfsRef {
                    entry: fnm.parent.record_number,
                    seq: fnm.parent.sequence,
                })
            };
            out.push(Ok(DeletedNode {
                id: FileId::NtfsRef {
                    entry,
                    seq: header.sequence_number,
                },
                name: fnm.name.into_bytes(),
                parent,
                meta,
            }));
        }
        Ok(DeletedStream::new(out.into_iter()))
    }

    /// Enumerate the volume's unallocated (free) clusters as image extents.
    ///
    /// Reads `$Bitmap` (MFT record 6) — the cluster allocation bitmap, 1 bit per
    /// cluster — and emits each maximal run of free clusters as a
    /// [`RunAlloc::Unallocated`] [`RunInfo`], byte offsets volume-relative (base
    /// 0) to match [`extents`](FileSystem::extents). A `$Bitmap` too short to
    /// describe every cluster fails **loud** ([`VfsError::Decode`]) rather than
    /// silently reporting the volume as fully allocated.
    fn unallocated(&self) -> VfsResult<ExtentStream> {
        let boot = self.boot();
        let cluster_size = boot.cluster_size();
        let total_clusters = if boot.sectors_per_cluster == 0 {
            0 // cov:unreachable: BootSector::parse rejects a zero sectors_per_cluster
        } else {
            boot.total_sectors / u64::from(boot.sectors_per_cluster)
        };

        // The whole bitmap is total_clusters/8 bytes — bounded and small (~32 MiB
        // for a 1 TiB volume at 4 KiB clusters), so materialising it is safe.
        let bitmap = self
            .read_data_by_record(mft_records::BITMAP, None, u64::MAX)
            .map_err(map_err)?;

        // Fail loud on a truncated bitmap: it cannot describe the whole volume, so
        // the missing bytes would masquerade as "all allocated" — a silent wrong
        // answer. `div_ceil` rounds the bit count up to whole bytes.
        let needed = usize::try_from(total_clusters.div_ceil(8)).unwrap_or(usize::MAX);
        if bitmap.len() < needed {
            return Err(VfsError::Decode {
                layer: "ntfs $Bitmap",
                offset: 0,
                detail: format!(
                    "$Bitmap is {} bytes but {total_clusters} clusters need {needed}",
                    bitmap.len()
                ),
                bytes: SmallHex::new(&[]),
            });
        }

        let runs = unallocated_runs(&bitmap, cluster_size, total_clusters, 0);
        Ok(ExtentStream::new(runs.into_iter().map(Ok)))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        best_file_name, build_meta, decode_ntfs3g_symlink, decode_reparse_buffer, entry_of,
        free_runs, map_err, namespace_rank, reparse_target, stream_name, unallocated_runs,
    };
    use crate::attribute::{Attribute, AttributeBody};
    use crate::error::NtfsError;
    use forensic_vfs::{FileId, RunAlloc, StreamId, VfsError};
    use forensicnomicon::ntfs::filename_namespace;

    // ---- identity and stream translation -------------------------------------
    //
    // The happy-path tests run against a real volume, so they only ever pass a
    // well-formed NtfsRef and the default stream. These cover the refusals: the
    // adapter must reject an identity it cannot address rather than coerce it
    // into a plausible-looking record number.

    #[test]
    fn reparse_buffer_honors_substitute_name_offset_and_ignores_flags() {
        // A relative symlink (`mklink /D dir ..\target.txt`), which exercises
        // two things a zero-offset fixture cannot: a non-zero
        // SubstituteNameOffset, and a non-zero Flags word that must not leak
        // into the decoded target.
        //
        // PathBuffer holds the print name first, then the substitute name:
        //   [0 .. 20)  "target.txt"      <- PrintName
        //   [20 .. 46) "..\target.txt"   <- SubstituteName
        let print_bytes: Vec<u8> = "target.txt"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let sub_bytes: Vec<u8> = "..\\target.txt"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let print_len = print_bytes.len() as u16;
        let sub_len = sub_bytes.len() as u16;
        let mut buf = Vec::new();
        buf.extend_from_slice(&0xA000_000Cu32.to_le_bytes()); // ReparseTag
        buf.extend_from_slice(&(12 + print_len + sub_len).to_le_bytes()); // ReparseDataLength
        buf.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        buf.extend_from_slice(&print_len.to_le_bytes()); // SubstituteNameOffset
        buf.extend_from_slice(&sub_len.to_le_bytes()); // SubstituteNameLength
        buf.extend_from_slice(&0u16.to_le_bytes()); // PrintNameOffset
        buf.extend_from_slice(&print_len.to_le_bytes()); // PrintNameLength
        buf.extend_from_slice(&1u32.to_le_bytes()); // Flags = SYMLINK_FLAG_RELATIVE
        buf.extend_from_slice(&print_bytes);
        buf.extend_from_slice(&sub_bytes);
        assert_eq!(
            decode_reparse_buffer(&buf).as_deref(),
            Some("..\\target.txt"),
            "SubstituteNameOffset is relative to PathBuffer, past Flags"
        );
    }

    #[test]
    fn reparse_buffer_decodes_a_spec_conforming_windows_symlink() {
        // A SymbolicLinkReparseBuffer carries a 4-byte `Flags` field that a
        // MountPointReparseBuffer does not, so its PathBuffer begins 12 bytes
        // into the data — not 8 (Wine include/ddk/ntifs.h:160; MS-FSCC
        // 2.1.2.4 vs 2.1.2.5). This is the buffer Windows actually emits:
        //
        //   SubstituteNameOffset(2) SubstituteNameLength(2)
        //   PrintNameOffset(2) PrintNameLength(2) Flags(4) PathBuffer[…]
        //
        // ReparseDataLength is therefore 12 + the path bytes, and the
        // substitute name is offset from the start of PathBuffer (data + 12).
        let path_bytes: Vec<u8> = "\\??\\C:\\link"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let len = path_bytes.len() as u16;
        let mut buf = Vec::new();
        buf.extend_from_slice(&0xA000_000Cu32.to_le_bytes()); // ReparseTag
        buf.extend_from_slice(&(12 + len).to_le_bytes()); // ReparseDataLength
        buf.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        buf.extend_from_slice(&0u16.to_le_bytes()); // SubstituteNameOffset
        buf.extend_from_slice(&len.to_le_bytes()); // SubstituteNameLength
        buf.extend_from_slice(&len.to_le_bytes()); // PrintNameOffset (end)
        buf.extend_from_slice(&0u16.to_le_bytes()); // PrintNameLength
        buf.extend_from_slice(&0u32.to_le_bytes()); // Flags (SYMLINK_FLAG_ABSOLUTE)
        buf.extend_from_slice(&path_bytes); // PathBuffer
        assert_eq!(
            decode_reparse_buffer(&buf).as_deref(),
            Some("\\??\\C:\\link"),
            "a symlink's PathBuffer starts after Flags, at data + 12"
        );
    }

    #[test]
    fn reparse_buffer_accepts_mount_point_and_rejects_others() {
        // Mount point (junction) tag 0xA0000003, substitute "\\??\\C:\\mount"
        // (22 UTF-16LE bytes; ReparseDataLength = 8 + 22 = 30).
        let path_bytes: Vec<u8> = "\\??\\C:\\mount"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let mut buf = Vec::new();
        buf.extend_from_slice(&0xA000_0003u32.to_le_bytes());
        buf.extend_from_slice(&(8 + path_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&path_bytes);
        assert_eq!(
            decode_reparse_buffer(&buf).as_deref(),
            Some("\\??\\C:\\mount")
        );
        // An unrelated tag (OneDrive placeholder 0x80000018) is not a link.
        buf[0..4].copy_from_slice(&0x8000_0018u32.to_le_bytes());
        assert_eq!(decode_reparse_buffer(&buf), None);
        // Truncated buffers decode to None, never panic.
        assert_eq!(decode_reparse_buffer(&buf[..7]), None);
        assert_eq!(decode_reparse_buffer(b"short"), None);
        assert_eq!(decode_reparse_buffer(&[]), None);
    }

    #[test]
    fn ntfs3g_intxlnk_decodes_utf16_target() {
        let mut data = Vec::new();
        data.extend_from_slice(b"IntxLNK");
        data.push(0x01);
        for u in "../README.txt".encode_utf16() {
            data.extend_from_slice(&u.to_le_bytes());
        }
        assert_eq!(
            decode_ntfs3g_symlink(&data).as_deref(),
            Some("../README.txt")
        );
        // A plain file's data is not a link.
        assert_eq!(decode_ntfs3g_symlink(b"README.txt"), None);
        assert_eq!(decode_ntfs3g_symlink(b""), None);
    }

    /// Build a minimal synthetic MFT record carrying one resident attribute
    /// whose content sits at `content_offset`, and the matching [`Attribute`]
    /// descriptor — enough for the `reparse_target` classifier.
    fn crafted_record(attrs: &[(u32, &[u8])]) -> (Vec<u8>, Vec<Attribute>) {
        let mut rec = vec![0u8; 256];
        let mut out = Vec::new();
        let mut offset = 64usize;
        for (type_code, content) in attrs {
            rec[offset..offset + content.len()].copy_from_slice(content);
            out.push(Attribute {
                type_code: *type_code,
                length: 0,
                non_resident: false,
                name: None,
                flags: 0,
                attribute_id: 0,
                offset: 0,
                body: AttributeBody::Resident {
                    content_offset: offset as u16,
                    content_length: content.len() as u32,
                },
            });
            offset += content.len() + 16;
        }
        (rec, out)
    }

    #[test]
    fn reparse_target_windows_reparse_attribute_decodes_substitute_name() {
        // A Windows-created symlink: the $REPARSE_POINT (0xC0) attribute holds
        // a symlink reparse buffer whose substitute name is the on-disk truth.
        let path_bytes: Vec<u8> = "\\??\\C:\\link"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let mut buf = Vec::new();
        let len = path_bytes.len() as u16;
        buf.extend_from_slice(&0xA000_000Cu32.to_le_bytes()); // tag: symlink
        buf.extend_from_slice(&(12 + len).to_le_bytes()); // ReparseDataLength (incl. Flags)
        buf.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        buf.extend_from_slice(&0u16.to_le_bytes()); // SubstituteNameOffset
        buf.extend_from_slice(&len.to_le_bytes()); // SubstituteNameLength
        buf.extend_from_slice(&len.to_le_bytes()); // PrintNameOffset (end)
        buf.extend_from_slice(&0u16.to_le_bytes()); // PrintNameLength
        buf.extend_from_slice(&0u32.to_le_bytes()); // Flags (symlink-only field)
        buf.extend_from_slice(&path_bytes);
        let (rec, attrs) = crafted_record(&[(0xC0, &buf)]);
        assert_eq!(
            reparse_target(&rec, &attrs).as_deref(),
            Some("\\??\\C:\\link")
        );
    }

    #[test]
    fn reparse_target_ntfs3g_intxlnk_data_decodes_target() {
        let mut data = Vec::new();
        data.extend_from_slice(b"IntxLNK");
        data.push(0x01);
        for u in "../README.txt".encode_utf16() {
            data.extend_from_slice(&u.to_le_bytes());
        }
        let (rec, attrs) = crafted_record(&[(0x80, &data)]);
        assert_eq!(
            reparse_target(&rec, &attrs).as_deref(),
            Some("../README.txt")
        );
    }

    #[test]
    fn reparse_target_plain_file_and_unknown_tags_are_not_links() {
        // A plain file: regular $DATA without the magic → None.
        let (rec, attrs) = crafted_record(&[(0x80, b"README.txt")]);
        assert_eq!(reparse_target(&rec, &attrs), None);
        // A $REPARSE_POINT with an unrelated tag (OneDrive placeholder) → None.
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x8000_0018u32.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        let (rec, attrs) = crafted_record(&[(0xC0, &buf)]);
        assert_eq!(reparse_target(&rec, &attrs), None);
        // A record with no $DATA and no reparse attribute → None.
        let (rec, attrs) = crafted_record(&[]);
        assert_eq!(reparse_target(&rec, &attrs), None);
        // The IntxLNK magic alone (without the version byte + target) → None.
        let (rec, attrs) = crafted_record(&[(0x80, b"IntxLNK")]);
        assert_eq!(reparse_target(&rec, &attrs), None);
    }

    #[test]
    fn reparse_buffer_and_intxlnk_decoders_are_bounds_safe() {
        assert_eq!(decode_reparse_buffer(&[]), None);
        assert_eq!(decode_reparse_buffer(&[0u8; 7]), None);
        // ReparseDataLength larger than the buffer → None, never a panic.
        let mut buf = vec![0u8; 16];
        buf[0..4].copy_from_slice(&0xA000_000Cu32.to_le_bytes());
        buf[4..6].copy_from_slice(&0xFFFFu16.to_le_bytes());
        assert_eq!(decode_reparse_buffer(&buf), None);
        assert_eq!(decode_ntfs3g_symlink(b""), None);
        assert_eq!(decode_ntfs3g_symlink(b"IntxLNK"), None);
    }

    #[test]
    fn entry_of_rejects_a_non_ntfs_identity() {
        // An ext4 inode is a different identity domain entirely. Silently reading
        // MFT record 42 because the number happens to fit would fabricate a result.
        let err = entry_of(FileId::ExtInode { ino: 42, gen: 1 })
            .expect_err("non-NTFS id must be refused");
        match err {
            VfsError::Unsupported { layer, scheme } => {
                assert_eq!(layer, "ntfs file-id");
                assert!(
                    scheme.contains("42"),
                    "the refusal must show the offending value, got {scheme:?}"
                );
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn entry_of_accepts_an_ntfs_reference() {
        assert_eq!(
            entry_of(FileId::NtfsRef { entry: 5, seq: 1 }).expect("NtfsRef is addressable"),
            5
        );
    }

    #[test]
    fn stream_name_refuses_a_named_stream_rather_than_reading_the_default() {
        // A named-stream id cannot be mapped back to its ADS name. Falling back to
        // the default $DATA would return the wrong bytes under a right-looking
        // request — the failure mode this refusal exists to prevent.
        let err = stream_name(StreamId::Named(7)).expect_err("named stream must be refused");
        assert!(
            matches!(err, VfsError::Unsupported { layer, .. } if layer == "ntfs stream"),
            "expected an ntfs stream refusal"
        );
    }

    #[test]
    fn stream_name_maps_the_default_stream_to_none() {
        assert_eq!(
            stream_name(StreamId::Default).expect("default stream is addressable"),
            None
        );
    }

    // ---- error translation ---------------------------------------------------

    #[test]
    fn map_err_keeps_io_distinct_from_decode() {
        // The distinction is load-bearing: an I/O failure means the evidence could
        // not be read (a bootstrap problem), while a decode failure means the bytes
        // were read and are malformed. Collapsing them would let a failed read
        // masquerade as a corrupt filesystem.
        let io = map_err(NtfsError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "short read",
        )));
        assert!(
            matches!(io, VfsError::Io { op, .. } if op == "ntfs read"),
            "an NtfsError::Io must stay an I/O error"
        );
    }

    #[test]
    fn map_err_carries_the_original_message_into_decode() {
        let decoded = map_err(NtfsError::BadRecordSignature(*b"BAAD"));
        match decoded {
            VfsError::Decode { layer, detail, .. } => {
                assert_eq!(layer, "ntfs");
                assert!(
                    !detail.is_empty(),
                    "the original ntfs-core message must survive, not be dropped"
                );
            }
            other => panic!("expected Decode, got {other:?}"),
        }
    }

    // ---- name-link ranking ---------------------------------------------------

    #[test]
    fn namespace_rank_prefers_the_human_name_over_the_8_3_short_name() {
        // A record commonly carries both a Win32 name and a DOS 8.3 name. Ranking
        // decides which one an examiner sees, so the ordering is asserted whole
        // rather than one arm at a time.
        let dos = namespace_rank(filename_namespace::DOS);
        assert!(
            namespace_rank(filename_namespace::WIN32_AND_DOS)
                > namespace_rank(filename_namespace::WIN32)
                && namespace_rank(filename_namespace::WIN32)
                    > namespace_rank(filename_namespace::POSIX)
                && namespace_rank(filename_namespace::POSIX) > dos,
            "ranking must be WIN32_AND_DOS > WIN32 > POSIX > DOS"
        );
    }

    #[test]
    fn namespace_rank_treats_an_unknown_namespace_as_least_preferred() {
        // An unrecognised namespace byte must never outrank a real Win32 name.
        assert!(namespace_rank(0xAB) < namespace_rank(filename_namespace::WIN32));
    }

    // ---- refusing to fabricate on malformed records --------------------------

    #[test]
    fn best_file_name_returns_none_on_a_record_that_does_not_parse() {
        // Not a panic and not an invented name: a record whose header will not
        // parse yields no name, so the caller cannot present a fabricated one.
        assert!(best_file_name(&[0u8; 64]).is_none());
        assert!(best_file_name(&[]).is_none());
        assert!(best_file_name(&[0xFF; 1024]).is_none());
    }

    /// A record whose header parses but whose attribute offset points outside
    /// the buffer — the shape a corrupt or carved record actually has.
    fn header_valid_attrs_broken() -> Vec<u8> {
        let mut rec = vec![0u8; 1024];
        rec[..4].copy_from_slice(b"FILE");
        // mft_offsets::FIRST_ATTRIBUTE (0x14): past the end of the record.
        rec[0x14..0x16].copy_from_slice(&0xFFF0u16.to_le_bytes());
        rec
    }

    #[test]
    fn build_meta_on_a_broken_attribute_list_fabricates_no_timestamps() {
        // Documents observed behaviour, which is NOT what I first assumed: an
        // attribute offset pointing past the record does not produce an error.
        // parse_attributes degrades to an empty list, so build_meta returns Ok.
        //
        // What must hold is that the degradation stays honest — no panic, and no
        // invented facts. Every MAC(B) time is None rather than a zeroed
        // FILETIME, because "1601-01-01" rendered in a timeline is a claim about
        // the evidence that nothing in the record supports.
        let meta = build_meta(7, &header_valid_attrs_broken())
            .expect("an empty attribute list degrades rather than erroring");
        assert_eq!(meta.ino, 7);
        assert!(
            meta.times.born.is_none()
                && meta.times.modified.is_none()
                && meta.times.changed.is_none()
                && meta.times.accessed.is_none(),
            "a record whose attributes did not parse must carry no timestamps at all"
        );
        assert_eq!(meta.size, 0, "no $DATA means no size, not a guess");
    }

    #[test]
    fn best_file_name_yields_none_when_attributes_do_not_parse() {
        // Same record shape through the naming path: no name is better than a
        // name recovered from an attribute list that did not parse.
        assert!(best_file_name(&header_valid_attrs_broken()).is_none());
    }

    #[test]
    fn build_meta_surfaces_a_malformed_record_as_an_error() {
        // build_meta must not return a default-looking FsMeta for bytes it could
        // not parse — an all-zero record is exactly what carving hands it.
        assert!(
            build_meta(0, &[0u8; 1024]).is_err(),
            "a record with no valid header must be an error, not empty metadata"
        );
    }

    #[test]
    fn free_runs_finds_maximal_zero_bit_runs() {
        // Bits are LSB-first within each byte. 0xFF = clusters 0..=7 allocated;
        // 0x00 = clusters 8..=15 free; 0x0F = clusters 16..=19 allocated (bits
        // 0..=3 set), bits 4..=7 are padding past total=20 and ignored. So the
        // only free span is clusters 8..=15.
        assert_eq!(free_runs(&[0xFF, 0x00, 0x0F], 20), vec![(8, 8)]);
    }

    #[test]
    fn free_runs_alternating_bits_yield_single_cluster_runs() {
        // 0b1010_1010: bit0=0 (free), bit1=1 (alloc), … → clusters 0,2,4,6 free.
        assert_eq!(
            free_runs(&[0b1010_1010], 8),
            vec![(0, 1), (2, 1), (4, 1), (6, 1)]
        );
    }

    #[test]
    fn free_runs_trailing_run_to_total_ignores_padding_bits() {
        // 0x00 marks bits 0..=7 free, but total is 5 — bits 5..=7 are padding and
        // must not extend the run. The run closes at the total-cluster boundary.
        assert_eq!(free_runs(&[0x00], 5), vec![(0, 5)]);
    }

    #[test]
    fn free_runs_all_allocated_is_empty() {
        assert!(free_runs(&[0xFF], 8).is_empty());
    }

    #[test]
    fn free_runs_short_bitmap_does_not_fabricate_free_space() {
        // A bitmap too short to cover total_clusters must not invent free clusters
        // for the bytes it lacks — a missing byte reads as allocated.
        assert!(free_runs(&[], 4).is_empty());
        // Only the described first byte contributes; clusters 8..=11 (no byte) are
        // treated as allocated, so the run stops at 8.
        assert_eq!(free_runs(&[0x00], 12), vec![(0, 8)]);
    }

    #[test]
    fn unallocated_runs_maps_free_clusters_to_image_offsets() {
        // Free span clusters 8..=15 over 512-byte clusters, base offset 0 → one
        // Unallocated run at byte 8*512 for 8*512 bytes.
        let runs = unallocated_runs(&[0xFF, 0x00, 0x0F], 512, 20, 0);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].run.image_offset, 8 * 512);
        assert_eq!(runs[0].run.len, 8 * 512);
        assert_eq!(runs[0].alloc, RunAlloc::Unallocated);
        assert!(!runs[0].run.flags.sparse);
    }

    #[test]
    fn unallocated_runs_applies_base_offset() {
        // base_offset shifts every run into the enclosing image/partition.
        let base = 1_048_576u64;
        let runs = unallocated_runs(&[0x00], 4096, 5, base);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].run.image_offset, base);
        assert_eq!(runs[0].run.len, 5 * 4096);
    }
}
