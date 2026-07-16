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
    Allocation, ByteRun, DirEntry, DirStream, ExtentStream, FileId, FileSystem, FsKind, FsMeta,
    MacbTimes, NodeKind, NodeStream, ResidencyKind, RunAlloc, RunFlags, RunInfo, SectorSizes,
    SmallHex, StreamId, TimeResolution, TimeSource, TimeStamp, TimeZonePolicy, VfsError, VfsResult,
};
use forensicnomicon::ntfs::{attr_types, mft_records};

use crate::attribute::AttributeBody;
use crate::error::NtfsError;
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
            NodeKind::File
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
                        NodeKind::File
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

    fn read_link(&self, _ino: FileId, _cap: usize) -> VfsResult<Vec<u8>> {
        // NTFS reparse points (symlinks/junctions) are out of scope for this
        // adapter; a node with none reads as an empty target.
        Ok(Vec::new())
    }

    fn deleted(&self) -> VfsResult<NodeStream> {
        // MFT carving of deleted records is a follow-up; the default surface is
        // an empty stream, not a bootstrap failure.
        Ok(NodeStream::empty())
    }

    fn unallocated(&self) -> VfsResult<ExtentStream> {
        Ok(ExtentStream::empty())
    }
}
