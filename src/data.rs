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
        AttributeBody::NonResident {
            runs_offset,
            real_size,
            ..
        } => {
            let attr_end = attribute
                .offset
                .checked_add(attribute.length as usize)
                .ok_or(NtfsError::BadAttribute {
                    offset: attribute.offset,
                    detail: "attribute length overflow",
                })?;
            let runs_start = attribute.offset.checked_add(runs_offset as usize).ok_or(
                NtfsError::BadAttribute {
                    offset: attribute.offset,
                    detail: "runs offset overflow",
                },
            )?;
            let runs_bytes = record
                .get(runs_start..attr_end)
                .ok_or(NtfsError::BadAttribute {
                    offset: attribute.offset,
                    detail: "runlist out of bounds",
                })?;
            let runs = runlist::decode(runs_bytes)?;
            read_runs(reader, &runs, cluster_size, real_size)
        }
    }
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
}
