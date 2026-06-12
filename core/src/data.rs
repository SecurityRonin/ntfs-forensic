//! Reconstructing an attribute's bytes — resident inline, or non-resident by
//! following its runlist across the volume.
//!
//! Sparse runs yield zeroes without touching the disk; real runs are read at
//! `lcn × cluster_size`. The output is bounded by the attribute's real size and
//! by the bytes its runs actually allocate, and every size is checked — a
//! crafted runlist cannot trigger an unbounded allocation or an out-of-range
//! seek.

use std::io::{Read, Seek, SeekFrom};

use crate::attribute::{Attribute, AttributeBody};
use crate::error::{NtfsError, Result};
use crate::runlist::{self, Run};

/// Hard ceiling on a single reconstructed value (1 TiB) — far above any real
/// artifact, but stops an allocation bomb from a crafted size.
const MAX_VALUE_BYTES: u64 = 1 << 40;

/// Read `real_size` bytes of a file described by `runs`, from `reader`.
///
/// The result is `min(real_size, bytes the runs allocate)` bytes long; sparse
/// runs contribute zeroes.
///
/// # Errors
///
/// [`NtfsError::BadRunlist`] on arithmetic overflow, [`NtfsError::TooLarge`]
/// when the requested size is implausible, or [`NtfsError::Io`] on read failure.
pub fn read_runs<R: Read + Seek>(
    reader: &mut R,
    runs: &[Run],
    cluster_size: u64,
    real_size: u64,
) -> Result<Vec<u8>> {
    // Bytes the runs allocate (checked); the value can't exceed this.
    let mut allocated = 0u64;
    for r in runs {
        let run_bytes = r
            .length
            .checked_mul(cluster_size)
            .ok_or(NtfsError::BadRunlist("run byte length overflow"))?;
        allocated = allocated
            .checked_add(run_bytes)
            .ok_or(NtfsError::BadRunlist("allocation overflow"))?;
    }

    let want = real_size.min(allocated);
    if want > MAX_VALUE_BYTES {
        return Err(NtfsError::TooLarge { bytes: want });
    }
    let want_usize = usize::try_from(want).map_err(|_| NtfsError::TooLarge { bytes: want })?;

    let mut out: Vec<u8> = Vec::new();
    out.try_reserve_exact(want_usize)
        .map_err(|_| NtfsError::TooLarge { bytes: want })?;

    let mut remaining = want;
    for r in runs {
        if remaining == 0 {
            break;
        }
        let run_bytes = r.length * cluster_size; // already checked above
        let take = run_bytes.min(remaining);
        let take_usize = take as usize; // ≤ want ≤ MAX_VALUE_BYTES, fits usize

        match r.lcn {
            None => out.resize(out.len() + take_usize, 0), // sparse hole → zeroes
            Some(lcn) => {
                let byte_off = lcn
                    .checked_mul(cluster_size)
                    .ok_or(NtfsError::BadRunlist("LCN byte offset overflow"))?;
                reader.seek(SeekFrom::Start(byte_off))?;
                let start = out.len();
                out.resize(start + take_usize, 0);
                reader.read_exact(&mut out[start..])?;
            }
        }
        remaining -= take;
    }

    Ok(out)
}

/// Read an attribute's value, dispatching on resident vs non-resident.
///
/// `record` is the (fixed-up) MFT record the attribute lives in; `reader` is the
/// volume; `cluster_size` is from the boot sector.
///
/// # Errors
///
/// As [`read_runs`], plus [`NtfsError::BadAttribute`] when a resident value or
/// the runlist slice is out of bounds.
pub fn read_attribute_value<R: Read + Seek>(
    reader: &mut R,
    record: &[u8],
    attribute: &Attribute,
    cluster_size: u64,
) -> Result<Vec<u8>> {
    match attribute.body {
        AttributeBody::Resident { .. } => attribute
            .resident_content(record)
            .map(<[u8]>::to_vec)
            .ok_or(NtfsError::BadAttribute {
                offset: attribute.offset,
                detail: "resident content out of bounds",
            }),
        AttributeBody::NonResident { real_size, .. } => {
            let runs = attribute_runlist(record, attribute)?;
            let cu = attribute.compression_unit();
            if attribute.is_compressed() && cu != 0 {
                // Compressed `$DATA` stores data in 2^cu-cluster units. checked_shl
                // rejects an implausible (crafted) unit shift before it overflows.
                let unit_clusters = 1u64.checked_shl(u32::from(cu)).ok_or(
                    NtfsError::BadAttribute {
                        offset: attribute.offset,
                        detail: "implausible compression unit",
                    },
                )?;
                read_compressed_runs(reader, &runs, cluster_size, real_size, unit_clusters)
            } else {
                read_runs(reader, &runs, cluster_size, real_size)
            }
        }
    }
}

/// Read a COMPRESSED non-resident attribute, LZNT1-decompressing each
/// compression unit. NTFS stores a compressed file in `unit_clusters`-cluster
/// units; within a unit the data is either: fully allocated (stored
/// uncompressed → copied verbatim), partially allocated then sparse-padded (the
/// allocated clusters hold the LZNT1 stream → decompressed), or fully sparse (a
/// unit of zeroes). The result is truncated to `real_size`.
///
/// # Errors
///
/// [`NtfsError::TooLarge`] for an implausible size, [`NtfsError::BadRunlist`] on
/// arithmetic overflow, [`NtfsError::BadCompression`] on a malformed LZNT1
/// stream, or [`NtfsError::Io`] on read failure.
fn read_compressed_runs<R: Read + Seek>(
    reader: &mut R,
    runs: &[Run],
    cluster_size: u64,
    real_size: u64,
    unit_clusters: u64,
) -> Result<Vec<u8>> {
    if real_size > MAX_VALUE_BYTES {
        return Err(NtfsError::TooLarge { bytes: real_size });
    }
    let unit_bytes = unit_clusters
        .checked_mul(cluster_size)
        .ok_or(NtfsError::BadRunlist("compression unit byte size overflow"))?;

    // Run cursor: (lcn, remaining_clusters), mutated as clusters are consumed.
    let mut queue: std::collections::VecDeque<(Option<u64>, u64)> =
        runs.iter().map(|r| (r.lcn, r.length)).collect();
    let real_size_usize =
        usize::try_from(real_size).map_err(|_| NtfsError::TooLarge { bytes: real_size })?;
    let mut out: Vec<u8> = Vec::new();

    while (out.len() as u64) < real_size {
        // Gather exactly one compression unit (`unit_clusters` of VCN) from the
        // runlist; the leading allocated clusters (if any) hold the unit's bytes.
        let mut real_bytes: Vec<u8> = Vec::new();
        let mut real_clusters = 0u64;
        let mut got = 0u64;
        while got < unit_clusters {
            let Some((lcn, avail)) = queue.front_mut() else {
                break;
            };
            let take = (unit_clusters - got).min(*avail);
            if let Some(l) = *lcn {
                let byte_off = l
                    .checked_mul(cluster_size)
                    .ok_or(NtfsError::BadRunlist("LCN byte offset overflow"))?;
                let nbytes = usize::try_from(take * cluster_size)
                    .map_err(|_| NtfsError::TooLarge { bytes: take * cluster_size })?;
                reader.seek(SeekFrom::Start(byte_off))?;
                let start = real_bytes.len();
                real_bytes.resize(start + nbytes, 0);
                reader.read_exact(&mut real_bytes[start..])?;
                real_clusters += take;
                *lcn = Some(l + take); // advance the LCN within this run
            }
            *avail -= take;
            if *avail == 0 {
                queue.pop_front();
            }
            got += take;
        }
        if got == 0 {
            break; // runlist exhausted
        }

        if real_clusters == 0 {
            // Fully sparse unit → a unit of zeroes (bounded by the file tail).
            let want = unit_bytes.min(real_size - out.len() as u64);
            let want = usize::try_from(want).map_err(|_| NtfsError::TooLarge { bytes: want })?;
            out.resize(out.len() + want, 0);
        } else if real_clusters == unit_clusters {
            // Fully allocated → stored uncompressed; append verbatim.
            out.extend_from_slice(&real_bytes);
        } else {
            // Partially allocated → the allocated clusters hold the LZNT1 stream.
            let decompressed = crate::compress::decompress(&real_bytes)?;
            out.extend_from_slice(&decompressed);
        }
    }

    out.truncate(real_size_usize);
    Ok(out)
}

/// Decode the data-run list of a non-resident attribute from its (fixed-up)
/// record bytes.
///
/// Reused to assemble a split `$DATA` whose runlist spans several `$DATA`
/// attributes in different MFT records (via `$ATTRIBUTE_LIST`).
///
/// # Errors
///
/// [`NtfsError::BadAttribute`] for a resident attribute or an out-of-bounds
/// runlist; [`NtfsError::BadRunlist`] for a malformed runlist.
pub fn attribute_runlist(record: &[u8], attribute: &Attribute) -> Result<Vec<Run>> {
    let AttributeBody::NonResident { runs_offset, .. } = attribute.body else {
        return Err(NtfsError::BadAttribute {
            offset: attribute.offset,
            detail: "attribute is resident (no runlist)",
        });
    };
    let attr_end = attribute
        .offset
        .checked_add(attribute.length as usize)
        .ok_or(NtfsError::BadAttribute {
            offset: attribute.offset,
            detail: "attribute length overflow",
        })?;
    let runs_start =
        attribute
            .offset
            .checked_add(runs_offset as usize)
            .ok_or(NtfsError::BadAttribute {
                offset: attribute.offset,
                detail: "runs offset overflow",
            })?;
    let runs_bytes = record
        .get(runs_start..attr_end)
        .ok_or(NtfsError::BadAttribute {
            offset: attribute.offset,
            detail: "runlist out of bounds",
        })?;
    runlist::decode(runs_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A volume where cluster `c` is filled with byte value `c as u8`.
    fn volume(clusters: usize, cluster_size: usize) -> Cursor<Vec<u8>> {
        let mut v = vec![0u8; clusters * cluster_size];
        for c in 0..clusters {
            let b = c as u8;
            for x in &mut v[c * cluster_size..(c + 1) * cluster_size] {
                *x = b;
            }
        }
        Cursor::new(v)
    }

    #[test]
    fn reads_single_run() {
        let mut vol = volume(4, 512);
        // One run: 2 clusters starting at LCN 1.
        let runs = [Run {
            length: 2,
            lcn: Some(1),
        }];
        let out = read_runs(&mut vol, &runs, 512, 1024).unwrap();
        assert_eq!(out.len(), 1024);
        assert!(out[..512].iter().all(|&b| b == 1));
        assert!(out[512..].iter().all(|&b| b == 2));
    }

    #[test]
    fn sparse_run_yields_zeroes_without_reading() {
        let mut vol = volume(1, 512); // too small to read 2 clusters — proves no read
        let runs = [Run {
            length: 2,
            lcn: None,
        }];
        let out = read_runs(&mut vol, &runs, 512, 1024).unwrap();
        assert_eq!(out.len(), 1024);
        assert!(out.iter().all(|&b| b == 0));
    }

    #[test]
    fn truncates_to_real_size() {
        let mut vol = volume(4, 512);
        let runs = [Run {
            length: 2,
            lcn: Some(0),
        }]; // 1024 allocated
        let out = read_runs(&mut vol, &runs, 512, 600).unwrap();
        assert_eq!(out.len(), 600);
    }

    #[test]
    fn mixed_data_and_sparse() {
        let mut vol = volume(4, 512);
        let runs = [
            Run {
                length: 1,
                lcn: Some(3),
            }, // cluster 3 → all 3s
            Run {
                length: 1,
                lcn: None,
            }, // sparse → zeros
        ];
        let out = read_runs(&mut vol, &runs, 512, 1024).unwrap();
        assert!(out[..512].iter().all(|&b| b == 3));
        assert!(out[512..].iter().all(|&b| b == 0));
    }

    #[test]
    fn refuses_implausible_size() {
        // A crafted runlist that *allocates* far more than the ceiling — a
        // single sparse run of 2^40 clusters. (A huge real_size alone is
        // harmless: it is clamped to what the runs actually allocate.)
        let mut vol = volume(1, 512);
        let runs = [Run {
            length: 1 << 40,
            lcn: None,
        }];
        assert!(matches!(
            read_runs(&mut vol, &runs, 512, u64::MAX),
            Err(NtfsError::TooLarge { .. })
        ));
    }

    #[test]
    fn rejects_cluster_size_overflow() {
        let mut vol = volume(1, 512);
        let runs = [Run {
            length: u64::MAX,
            lcn: Some(0),
        }];
        assert!(matches!(
            read_runs(&mut vol, &runs, 512, 1024),
            Err(NtfsError::BadRunlist(_))
        ));
    }

    // ── read_attribute_value dispatch ─────────────────────────────────────────

    #[test]
    fn reads_resident_value() {
        use forensicnomicon::ntfs::attr_types;
        // Build a one-attribute record with resident $DATA content "hello".
        let content = b"hello";
        // Minimal resident attribute laid out by hand at record offset 0x10.
        let attr_off = 0x10usize;
        let mut record = vec![0u8; attr_off];
        // header: type, length, resident, name_len 0, name_off, flags, id
        let name_offset = 0x18u16;
        let content_offset = 0x18u16;
        let length = (content_offset as usize + content.len() + 7) & !7;
        let mut a = vec![0u8; length];
        a[0x00..0x04].copy_from_slice(&attr_types::DATA.to_le_bytes());
        a[0x04..0x08].copy_from_slice(&(length as u32).to_le_bytes());
        a[0x0A..0x0C].copy_from_slice(&name_offset.to_le_bytes());
        a[0x10..0x14].copy_from_slice(&(content.len() as u32).to_le_bytes());
        a[0x14..0x16].copy_from_slice(&content_offset.to_le_bytes());
        a[content_offset as usize..content_offset as usize + content.len()]
            .copy_from_slice(content);
        record.extend_from_slice(&a);
        record.extend_from_slice(&attr_types::END.to_le_bytes());

        let attrs = crate::attribute::parse_attributes(&record, attr_off).unwrap();
        let mut vol = volume(1, 512);
        let out = read_attribute_value(&mut vol, &record, &attrs[0], 512).unwrap();
        assert_eq!(out, b"hello");
    }

    #[test]
    fn reads_nonresident_value_via_runlist() {
        use forensicnomicon::ntfs::attr_types;
        // Non-resident $DATA: runlist of 1 cluster @ LCN 2, real size 512.
        let runs_bytes = [0x11u8, 0x01, 0x02, 0x00]; // len 1, lcn delta +2
        let attr_off = 0x10usize;
        let mut record = vec![0u8; attr_off];
        let runs_offset = 0x40u16;
        let length = ((runs_offset as usize + runs_bytes.len()) + 7) & !7;
        let mut a = vec![0u8; length];
        a[0x00..0x04].copy_from_slice(&attr_types::DATA.to_le_bytes());
        a[0x04..0x08].copy_from_slice(&(length as u32).to_le_bytes());
        a[0x08] = 1; // non-resident
        a[0x0A..0x0C].copy_from_slice(&runs_offset.to_le_bytes()); // name offset (no name)
        a[0x20..0x22].copy_from_slice(&runs_offset.to_le_bytes()); // runs offset
        a[0x28..0x30].copy_from_slice(&512u64.to_le_bytes()); // allocated
        a[0x30..0x38].copy_from_slice(&512u64.to_le_bytes()); // real size
        a[runs_offset as usize..runs_offset as usize + runs_bytes.len()]
            .copy_from_slice(&runs_bytes);
        record.extend_from_slice(&a);
        record.extend_from_slice(&attr_types::END.to_le_bytes());

        let attrs = crate::attribute::parse_attributes(&record, attr_off).unwrap();
        let mut vol = volume(4, 512); // cluster 2 → all 2s
        let out = read_attribute_value(&mut vol, &record, &attrs[0], 512).unwrap();
        assert_eq!(out.len(), 512);
        assert!(out.iter().all(|&b| b == 2));
    }

    #[test]
    fn reads_compressed_nonresident_value() {
        use forensicnomicon::ntfs::attr_types;
        // A COMPRESSED $DATA: one 16-cluster compression unit made of 1 real
        // cluster (the LZNT1 stream) + 15 sparse clusters. real_size = 100 bytes.
        // The stream is a single *uncompressed* LZNT1 chunk (header bit15=0,
        // low-12 = size-1), which is valid LZNT1 the decompressor copies verbatim
        // — lets us build a real compressed-unit fixture without a compressor.
        let content = vec![0xABu8; 100];
        let mut stream = Vec::new();
        stream.extend_from_slice(&(content.len() as u16 - 1).to_le_bytes()); // 0x0063
        stream.extend_from_slice(&content);

        // runlist: 0x11 len=1 lcn+2 | 0x01 len=15 sparse | 0x00 end
        let runs_bytes = [0x11u8, 0x01, 0x02, 0x01, 0x0F, 0x00];
        let attr_off = 0x10usize;
        let mut record = vec![0u8; attr_off];
        let runs_offset = 0x40u16;
        let length = ((runs_offset as usize + runs_bytes.len()) + 7) & !7;
        let mut a = vec![0u8; length];
        a[0x00..0x04].copy_from_slice(&attr_types::DATA.to_le_bytes());
        a[0x04..0x08].copy_from_slice(&(length as u32).to_le_bytes());
        a[0x08] = 1; // non-resident
        a[0x0A..0x0C].copy_from_slice(&runs_offset.to_le_bytes()); // name offset (no name)
        a[0x0C..0x0E].copy_from_slice(&0x0001u16.to_le_bytes()); // flags: COMPRESSED
        a[0x20..0x22].copy_from_slice(&runs_offset.to_le_bytes()); // runs offset
        a[0x22..0x24].copy_from_slice(&4u16.to_le_bytes()); // compression_unit = 4 → 16 clusters
        a[0x28..0x30].copy_from_slice(&(16u64 * 512).to_le_bytes()); // allocated 8192
        a[0x30..0x38].copy_from_slice(&(content.len() as u64).to_le_bytes()); // real size 100
        a[runs_offset as usize..runs_offset as usize + runs_bytes.len()]
            .copy_from_slice(&runs_bytes);
        record.extend_from_slice(&a);
        record.extend_from_slice(&attr_types::END.to_le_bytes());

        let cluster_size = 512usize;
        let mut disk = vec![0u8; 16 * cluster_size];
        disk[2 * cluster_size..2 * cluster_size + stream.len()].copy_from_slice(&stream);
        let mut vol = std::io::Cursor::new(disk);

        let attrs = crate::attribute::parse_attributes(&record, attr_off).unwrap();
        let out = read_attribute_value(&mut vol, &record, &attrs[0], 512).unwrap();
        assert_eq!(
            out, content,
            "compressed $DATA must be LZNT1-decompressed, not returned raw"
        );
    }

    #[test]
    fn stops_reading_once_real_size_is_met() {
        // real_size covers only the first run; the second run must not be read.
        let mut vol = volume(4, 512);
        let runs = [
            Run {
                length: 1,
                lcn: Some(0),
            },
            Run {
                length: 1,
                lcn: Some(1),
            },
        ];
        let out = read_runs(&mut vol, &runs, 512, 512).unwrap();
        assert_eq!(out.len(), 512); // only the first run's worth
    }

    #[test]
    fn rejects_runlist_region_out_of_bounds() {
        use crate::attribute::{Attribute, AttributeBody};
        // runs_offset points past the attribute, so the runlist slice is invalid.
        let attr = Attribute {
            type_code: forensicnomicon::ntfs::attr_types::DATA,
            length: 0x48,
            non_resident: true,
            name: None,
            flags: 0,
            attribute_id: 0,
            offset: 0,
            body: AttributeBody::NonResident {
                start_vcn: 0,
                last_vcn: 0,
                runs_offset: 0xFFFF,
                compression_unit: 0,
                allocated_size: 512,
                real_size: 512,
                initialized_size: 512,
            },
        };
        let record = vec![0u8; 0x48];
        let mut vol = volume(1, 512);
        assert!(matches!(
            read_attribute_value(&mut vol, &record, &attr, 512),
            Err(NtfsError::BadAttribute { detail, .. }) if detail == "runlist out of bounds"
        ));
    }

    #[test]
    fn rejects_runs_offset_overflow() {
        use crate::attribute::{Attribute, AttributeBody};
        // offset + length stays in range, but offset + runs_offset overflows.
        let attr = Attribute {
            type_code: forensicnomicon::ntfs::attr_types::DATA,
            length: 0x48,
            non_resident: true,
            name: None,
            flags: 0,
            attribute_id: 0,
            offset: usize::MAX - 0x48,
            body: AttributeBody::NonResident {
                start_vcn: 0,
                last_vcn: 0,
                runs_offset: 0x49,
                compression_unit: 0,
                allocated_size: 512,
                real_size: 512,
                initialized_size: 512,
            },
        };
        let record = vec![0u8; 1];
        let mut vol = volume(1, 512);
        assert!(matches!(
            read_attribute_value(&mut vol, &record, &attr, 512),
            Err(NtfsError::BadAttribute { detail, .. }) if detail == "runs offset overflow"
        ));
    }

    #[test]
    fn attribute_runlist_rejects_resident_attribute() {
        let attr = Attribute {
            type_code: forensicnomicon::ntfs::attr_types::DATA,
            length: 0x20,
            non_resident: false,
            name: None,
            flags: 0,
            attribute_id: 0,
            offset: 0,
            body: AttributeBody::Resident {
                content_offset: 0x18,
                content_length: 4,
            },
        };
        assert!(matches!(
            attribute_runlist(&[0u8; 0x20], &attr),
            Err(NtfsError::BadAttribute { detail, .. }) if detail.contains("resident")
        ));
    }
}
