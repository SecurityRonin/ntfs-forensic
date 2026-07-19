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

use crate::attribute::AttributeBody;
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

    fn unallocated(&self) -> VfsResult<ExtentStream> {
        Ok(ExtentStream::empty())
    }
}
