//! MFT attribute walking: the common attribute header plus the resident and
//! non-resident bodies.
//!
//! After the record header, attributes are laid out back-to-back, each starting
//! with a common header (type, length, resident flag, optional name, flags),
//! terminated by an end marker (`0xFFFF_FFFF`). Resident attributes store their
//! value inline; non-resident attributes store a *runlist* mapping the file's
//! virtual clusters to on-disk clusters.
//!
//! Every field is bounds-checked against the record and the attribute's own
//! declared length: a crafted record can never drive an out-of-bounds read or
//! an unbounded loop.
//!
//! Type codes, names, attribute-header field offsets, and flags all come from
//! the [`forensicnomicon::ntfs`] KNOWLEDGE layer.

use forensicnomicon::ntfs::{
    attr_flags as flag, attr_offsets as o, attr_types, attribute_type_name,
};

use crate::bytes::{le_u16, le_u32, le_u64};
use crate::error::{NtfsError, Result};

/// Minimum bytes of a common attribute header (through attribute id).
const HEADER_MIN: usize = 0x10;
/// Minimum bytes of a resident attribute header (through content offset + pad).
const RESIDENT_MIN: usize = 0x18;
/// Minimum bytes of a non-resident attribute header (through initialized size).
const NONRESIDENT_MIN: usize = 0x40;
/// Hard cap on attributes per record — belt-and-suspenders against crafted input.
const MAX_ATTRIBUTES: usize = 4096;

/// A parsed MFT attribute (common header + body discriminant).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    /// Attribute type code (e.g. `0x80` for `$DATA`).
    pub type_code: u32,
    /// Total on-disk length of this attribute, including its header.
    pub length: u32,
    /// `true` when the value is stored out-of-line via a runlist.
    pub non_resident: bool,
    /// Decoded attribute name (e.g. an ADS stream name), or `None` when unnamed.
    pub name: Option<String>,
    /// Attribute flags (compressed / encrypted / sparse).
    pub flags: u16,
    /// Attribute id, unique within the record.
    pub attribute_id: u16,
    /// Byte offset of this attribute within the record.
    pub offset: usize,
    /// Resident or non-resident body.
    pub body: AttributeBody,
}

/// The resident/non-resident discriminant of an attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributeBody {
    /// The value is stored inline within the record.
    Resident {
        content_offset: u16,
        content_length: u32,
    },
    /// The value is stored in clusters described by a runlist.
    NonResident {
        start_vcn: u64,
        last_vcn: u64,
        runs_offset: u16,
        compression_unit: u16,
        allocated_size: u64,
        real_size: u64,
        initialized_size: u64,
    },
}

impl Attribute {
    /// `true` if the attribute is compressed.
    #[must_use]
    pub fn is_compressed(&self) -> bool {
        self.flags & flag::COMPRESSED != 0
    }

    /// The compression-unit size as a power of two clusters (NTFS `2^n`; `0`
    /// means no compression unit / resident). A compressed `$DATA` stores its
    /// data in `2^compression_unit`-cluster units.
    #[must_use]
    pub fn compression_unit(&self) -> u16 {
        match self.body {
            AttributeBody::NonResident {
                compression_unit, ..
            } => compression_unit,
            AttributeBody::Resident { .. } => 0,
        }
    }

    /// `true` if the attribute is encrypted (EFS).
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.flags & flag::ENCRYPTED != 0
    }

    /// `true` if the attribute is sparse.
    #[must_use]
    pub fn is_sparse(&self) -> bool {
        self.flags & flag::SPARSE != 0
    }

    /// Canonical `$NAME` of this attribute type, if known.
    #[must_use]
    pub fn type_name(&self) -> Option<&'static str> {
        attribute_type_name(self.type_code)
    }

    /// For a resident attribute, its value bytes within `record`. Returns `None`
    /// for non-resident attributes or if the slice is out of bounds.
    #[must_use]
    pub fn resident_content<'a>(&self, record: &'a [u8]) -> Option<&'a [u8]> {
        if let AttributeBody::Resident {
            content_offset,
            content_length,
        } = self.body
        {
            let start = self.offset.checked_add(content_offset as usize)?;
            let end = start.checked_add(content_length as usize)?;
            record.get(start..end)
        } else {
            None
        }
    }
}

/// Walk the attribute chain of a (fixed-up) record, starting at
/// `first_attr_offset`, until the end marker.
///
/// # Errors
///
/// [`NtfsError::BadAttribute`] for any attribute that is undersized, declares a
/// length that wouldn't advance the cursor, or whose name/body would read
/// outside the record.
pub fn parse_attributes(record: &[u8], first_attr_offset: usize) -> Result<Vec<Attribute>> {
    let mut attrs = Vec::new();
    let mut pos = first_attr_offset;

    let bad = |offset: usize, detail: &'static str| NtfsError::BadAttribute { offset, detail };

    for _ in 0..MAX_ATTRIBUTES {
        // Need 4 bytes to read the type / end marker; run-off-the-end stops cleanly.
        if record.get(pos + o::TYPE..pos + o::TYPE + 4).is_none() {
            break;
        }
        let type_code = le_u32(record, pos + o::TYPE);
        if type_code == attr_types::END {
            break;
        }

        if pos + HEADER_MIN > record.len() {
            return Err(bad(pos, "header runs past record"));
        }

        let length = le_u32(record, pos + o::LENGTH);
        if (length as usize) < HEADER_MIN {
            return Err(bad(pos, "length below header minimum"));
        }
        let end = pos
            .checked_add(length as usize)
            .ok_or_else(|| bad(pos, "length overflow"))?;
        if end > record.len() {
            return Err(bad(pos, "attribute extends past record"));
        }

        let non_resident = record[pos + o::NON_RESIDENT] != 0;
        let name_length = record[pos + o::NAME_LENGTH] as usize;
        let name_offset = le_u16(record, pos + o::NAME_OFFSET) as usize;
        let flags = le_u16(record, pos + o::FLAGS);
        let attribute_id = le_u16(record, pos + o::ATTRIBUTE_ID);

        // Optional name, bounded by both the attribute's length and the record.
        let name = if name_length == 0 {
            None
        } else {
            let nbytes = name_length
                .checked_mul(2)
                .ok_or_else(|| bad(pos, "name length overflow"))?;
            let nstart = pos
                .checked_add(name_offset)
                .ok_or_else(|| bad(pos, "name offset overflow"))?;
            let nend = nstart
                .checked_add(nbytes)
                .ok_or_else(|| bad(pos, "name overflow"))?;
            if nend > end || nend > record.len() {
                return Err(bad(pos, "name out of bounds"));
            }
            let units: Vec<u16> = record[nstart..nend]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            Some(
                char::decode_utf16(units)
                    .map(|r| r.unwrap_or('\u{FFFD}'))
                    .collect(),
            )
        };

        let body = if non_resident {
            if pos + NONRESIDENT_MIN > end {
                return Err(bad(pos, "non-resident header runs past attribute"));
            }
            let u64at = |rel: usize| le_u64(record, pos + rel);
            let u16at = |rel: usize| le_u16(record, pos + rel);
            AttributeBody::NonResident {
                start_vcn: u64at(o::NR_START_VCN),
                last_vcn: u64at(o::NR_LAST_VCN),
                runs_offset: u16at(o::NR_RUNS_OFFSET),
                compression_unit: u16at(o::NR_COMPRESSION_UNIT),
                allocated_size: u64at(o::NR_ALLOCATED_SIZE),
                real_size: u64at(o::NR_REAL_SIZE),
                initialized_size: u64at(o::NR_INITIALIZED_SIZE),
            }
        } else {
            if pos + RESIDENT_MIN > end {
                return Err(bad(pos, "resident header runs past attribute"));
            }
            let content_length = le_u32(record, pos + o::RES_CONTENT_LENGTH);
            let content_offset = le_u16(record, pos + o::RES_CONTENT_OFFSET);
            let cstart = pos
                .checked_add(content_offset as usize)
                .ok_or_else(|| bad(pos, "content offset overflow"))?;
            let cend = cstart
                .checked_add(content_length as usize)
                .ok_or_else(|| bad(pos, "content overflow"))?;
            if cend > end || cend > record.len() {
                return Err(bad(pos, "resident content out of bounds"));
            }
            AttributeBody::Resident {
                content_offset,
                content_length,
            }
        };

        attrs.push(Attribute {
            type_code,
            length,
            non_resident,
            name,
            flags,
            attribute_id,
            offset: pos,
            body,
        });

        pos = end;
    }

    Ok(attrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn align8(n: usize) -> usize {
        (n + 7) & !7
    }

    /// Build one resident attribute.
    fn resident(type_code: u32, name: Option<&str>, flags: u16, content: &[u8]) -> Vec<u8> {
        let name_chars: Vec<u16> = name.map(|n| n.encode_utf16().collect()).unwrap_or_default();
        let name_offset = RESIDENT_MIN;
        let content_offset = align8(name_offset + name_chars.len() * 2);
        let length = align8(content_offset + content.len());
        let mut a = vec![0u8; length];
        a[o::TYPE..o::TYPE + 4].copy_from_slice(&type_code.to_le_bytes());
        a[o::LENGTH..o::LENGTH + 4].copy_from_slice(&(length as u32).to_le_bytes());
        a[o::NON_RESIDENT] = 0;
        a[o::NAME_LENGTH] = name_chars.len() as u8;
        a[o::NAME_OFFSET..o::NAME_OFFSET + 2].copy_from_slice(&(name_offset as u16).to_le_bytes());
        a[o::FLAGS..o::FLAGS + 2].copy_from_slice(&flags.to_le_bytes());
        a[o::ATTRIBUTE_ID..o::ATTRIBUTE_ID + 2].copy_from_slice(&1u16.to_le_bytes());
        a[o::RES_CONTENT_LENGTH..o::RES_CONTENT_LENGTH + 4]
            .copy_from_slice(&(content.len() as u32).to_le_bytes());
        a[o::RES_CONTENT_OFFSET..o::RES_CONTENT_OFFSET + 2]
            .copy_from_slice(&(content_offset as u16).to_le_bytes());
        for (i, ch) in name_chars.iter().enumerate() {
            let p = name_offset + i * 2;
            a[p..p + 2].copy_from_slice(&ch.to_le_bytes());
        }
        a[content_offset..content_offset + content.len()].copy_from_slice(content);
        a
    }

    /// Build one non-resident attribute with the given runlist bytes.
    #[allow(clippy::too_many_arguments)]
    fn nonresident(
        type_code: u32,
        name: Option<&str>,
        flags: u16,
        start_vcn: u64,
        last_vcn: u64,
        allocated: u64,
        real: u64,
        initialized: u64,
        runs: &[u8],
    ) -> Vec<u8> {
        let name_chars: Vec<u16> = name.map(|n| n.encode_utf16().collect()).unwrap_or_default();
        let name_offset = NONRESIDENT_MIN;
        let runs_offset = align8(name_offset + name_chars.len() * 2);
        let length = align8(runs_offset + runs.len());
        let mut a = vec![0u8; length];
        a[o::TYPE..o::TYPE + 4].copy_from_slice(&type_code.to_le_bytes());
        a[o::LENGTH..o::LENGTH + 4].copy_from_slice(&(length as u32).to_le_bytes());
        a[o::NON_RESIDENT] = 1;
        a[o::NAME_LENGTH] = name_chars.len() as u8;
        a[o::NAME_OFFSET..o::NAME_OFFSET + 2].copy_from_slice(&(name_offset as u16).to_le_bytes());
        a[o::FLAGS..o::FLAGS + 2].copy_from_slice(&flags.to_le_bytes());
        a[o::ATTRIBUTE_ID..o::ATTRIBUTE_ID + 2].copy_from_slice(&2u16.to_le_bytes());
        a[o::NR_START_VCN..o::NR_START_VCN + 8].copy_from_slice(&start_vcn.to_le_bytes());
        a[o::NR_LAST_VCN..o::NR_LAST_VCN + 8].copy_from_slice(&last_vcn.to_le_bytes());
        a[o::NR_RUNS_OFFSET..o::NR_RUNS_OFFSET + 2]
            .copy_from_slice(&(runs_offset as u16).to_le_bytes());
        a[o::NR_COMPRESSION_UNIT..o::NR_COMPRESSION_UNIT + 2].copy_from_slice(&0u16.to_le_bytes());
        a[o::NR_ALLOCATED_SIZE..o::NR_ALLOCATED_SIZE + 8].copy_from_slice(&allocated.to_le_bytes());
        a[o::NR_REAL_SIZE..o::NR_REAL_SIZE + 8].copy_from_slice(&real.to_le_bytes());
        a[o::NR_INITIALIZED_SIZE..o::NR_INITIALIZED_SIZE + 8]
            .copy_from_slice(&initialized.to_le_bytes());
        for (i, ch) in name_chars.iter().enumerate() {
            let p = name_offset + i * 2;
            a[p..p + 2].copy_from_slice(&ch.to_le_bytes());
        }
        a[runs_offset..runs_offset + runs.len()].copy_from_slice(runs);
        a
    }

    /// Assemble a record: zeroed up to `first`, the attributes, then the end marker.
    fn record_with(first: usize, attrs: &[Vec<u8>]) -> Vec<u8> {
        let mut rec = vec![0u8; first];
        for a in attrs {
            rec.extend_from_slice(a);
        }
        rec.extend_from_slice(&attr_types::END.to_le_bytes());
        rec
    }

    #[test]
    fn parses_resident_attribute() {
        let content = b"\x10\x00\x00\x00hello"; // arbitrary $STANDARD_INFORMATION-ish bytes
        let attr = resident(attr_types::STANDARD_INFORMATION, None, 0, content);
        let rec = record_with(0x38, &[attr]);
        let attrs = parse_attributes(&rec, 0x38).expect("walk");
        assert_eq!(attrs.len(), 1);
        let a = &attrs[0];
        assert_eq!(a.type_code, attr_types::STANDARD_INFORMATION);
        assert!(!a.non_resident);
        assert_eq!(a.name, None);
        assert_eq!(a.type_name(), Some("$STANDARD_INFORMATION"));
        assert_eq!(a.resident_content(&rec), Some(&content[..]));
    }

    #[test]
    fn parses_nonresident_attribute() {
        // A trivial single-run runlist: header 0x21, 1 length byte, 2 offset bytes.
        // Named, so the name-encoding path is exercised too.
        let runs = [0x21u8, 0x08, 0x00, 0x10, 0x00];
        let attr = nonresident(
            attr_types::DATA,
            Some("ads"),
            0,
            0,
            7,
            0x8000,
            0x7A00,
            0x7A00,
            &runs,
        );
        let rec = record_with(0x38, &[attr]);
        let attrs = parse_attributes(&rec, 0x38).unwrap();
        let a = &attrs[0];
        assert!(a.non_resident);
        assert_eq!(a.name.as_deref(), Some("ads"));
        assert_eq!(
            a.body,
            AttributeBody::NonResident {
                start_vcn: 0,
                last_vcn: 7,
                runs_offset: 0x48,
                compression_unit: 0,
                allocated_size: 0x8000,
                real_size: 0x7A00,
                initialized_size: 0x7A00,
            }
        );
    }

    /// A 16-byte header with a custom declared `length` and resident flag, used
    /// to drive the bounds-check error branches.
    fn header(type_code: u32, length: u32, non_resident: bool) -> Vec<u8> {
        let mut a = vec![0u8; length.max(HEADER_MIN as u32) as usize];
        a[o::TYPE..o::TYPE + 4].copy_from_slice(&type_code.to_le_bytes());
        a[o::LENGTH..o::LENGTH + 4].copy_from_slice(&length.to_le_bytes());
        a[o::NON_RESIDENT] = u8::from(non_resident);
        a
    }

    #[test]
    fn resident_content_is_none_for_non_resident() {
        let runs = [0x21u8, 0x08, 0x00, 0x10, 0x00];
        let attr = nonresident(
            attr_types::DATA,
            None,
            0,
            0,
            7,
            0x8000,
            0x7A00,
            0x7A00,
            &runs,
        );
        let rec = record_with(0x38, &[attr]);
        let attrs = parse_attributes(&rec, 0x38).unwrap();
        assert_eq!(attrs[0].resident_content(&rec), None);
    }

    #[test]
    fn rejects_header_running_past_record() {
        // 4 valid type bytes (DATA), but no room for the rest of the header.
        let rec = attr_types::DATA.to_le_bytes().to_vec();
        assert!(matches!(
            parse_attributes(&rec, 0),
            Err(NtfsError::BadAttribute { detail, .. }) if detail == "header runs past record"
        ));
    }

    #[test]
    fn rejects_nonresident_header_past_attribute() {
        // non-resident flag set but length < NONRESIDENT_MIN.
        let attr = header(attr_types::DATA, 0x20, true);
        let rec = record_with(0, &[attr]);
        assert!(matches!(
            parse_attributes(&rec, 0),
            Err(NtfsError::BadAttribute { detail, .. })
                if detail == "non-resident header runs past attribute"
        ));
    }

    #[test]
    fn rejects_resident_header_past_attribute() {
        // resident, length in [HEADER_MIN, RESIDENT_MIN).
        let attr = header(attr_types::DATA, 0x10, false);
        let rec = record_with(0, &[attr]);
        assert!(matches!(
            parse_attributes(&rec, 0),
            Err(NtfsError::BadAttribute { detail, .. })
                if detail == "resident header runs past attribute"
        ));
    }

    #[test]
    fn rejects_resident_content_out_of_bounds() {
        // resident header, but content_offset + content_length exceeds the attr.
        let mut attr = header(attr_types::DATA, 0x18, false);
        attr[o::RES_CONTENT_LENGTH..o::RES_CONTENT_LENGTH + 4]
            .copy_from_slice(&0xFFFFu32.to_le_bytes());
        attr[o::RES_CONTENT_OFFSET..o::RES_CONTENT_OFFSET + 2]
            .copy_from_slice(&0x18u16.to_le_bytes());
        let rec = record_with(0, &[attr]);
        assert!(matches!(
            parse_attributes(&rec, 0),
            Err(NtfsError::BadAttribute { detail, .. })
                if detail == "resident content out of bounds"
        ));
    }

    #[test]
    fn decodes_named_ads_attribute() {
        let attr = resident(
            attr_types::DATA,
            Some("Zone.Identifier"),
            0,
            b"[ZoneTransfer]",
        );
        let rec = record_with(0x38, &[attr]);
        let attrs = parse_attributes(&rec, 0x38).unwrap();
        assert_eq!(attrs[0].name.as_deref(), Some("Zone.Identifier"));
    }

    #[test]
    fn walks_multiple_attributes_until_end() {
        let si = resident(attr_types::STANDARD_INFORMATION, None, 0, &[0u8; 48]);
        let fname = resident(attr_types::FILE_NAME, None, 0, &[0u8; 66]);
        let data = resident(attr_types::DATA, None, 0, b"file contents");
        let rec = record_with(0x38, &[si, fname, data]);
        let attrs = parse_attributes(&rec, 0x38).unwrap();
        assert_eq!(attrs.len(), 3);
        assert_eq!(attrs[0].type_code, attr_types::STANDARD_INFORMATION);
        assert_eq!(attrs[1].type_code, attr_types::FILE_NAME);
        assert_eq!(attrs[2].type_code, attr_types::DATA);
    }

    #[test]
    fn detects_compressed_and_sparse_flags() {
        let attr = nonresident(
            attr_types::DATA,
            None,
            flag::COMPRESSED | flag::SPARSE,
            0,
            0,
            0x1000,
            0x800,
            0x800,
            &[0x00],
        );
        let rec = record_with(0x38, &[attr]);
        let a = &parse_attributes(&rec, 0x38).unwrap()[0];
        assert!(a.is_compressed());
        assert!(a.is_sparse());
        assert!(!a.is_encrypted());
    }

    #[test]
    fn end_marker_at_start_yields_no_attributes() {
        let rec = record_with(0x38, &[]);
        assert!(parse_attributes(&rec, 0x38).unwrap().is_empty());
    }

    // ── Hardening against crafted records ─────────────────────────────────────

    #[test]
    fn rejects_zero_length_attribute() {
        // length = 0 would never advance the cursor — must be rejected, not loop.
        let mut rec = vec![0u8; 0x40];
        rec[0x00..0x04].copy_from_slice(&attr_types::DATA.to_le_bytes());
        rec[0x04..0x08].copy_from_slice(&0u32.to_le_bytes()); // length 0
        assert!(matches!(
            parse_attributes(&rec, 0x00),
            Err(NtfsError::BadAttribute { .. })
        ));
    }

    #[test]
    fn rejects_length_below_header_min() {
        let mut rec = vec![0u8; 0x40];
        rec[0x00..0x04].copy_from_slice(&attr_types::DATA.to_le_bytes());
        rec[0x04..0x08].copy_from_slice(&8u32.to_le_bytes()); // < HEADER_MIN
        assert!(matches!(
            parse_attributes(&rec, 0x00),
            Err(NtfsError::BadAttribute { .. })
        ));
    }

    #[test]
    fn rejects_attribute_past_record_end() {
        let mut rec = vec![0u8; 0x20];
        rec[0x00..0x04].copy_from_slice(&attr_types::DATA.to_le_bytes());
        rec[0x04..0x08].copy_from_slice(&0x1000u32.to_le_bytes()); // way past the 0x20 record
        rec[0x08] = 0;
        assert!(matches!(
            parse_attributes(&rec, 0x00),
            Err(NtfsError::BadAttribute { .. })
        ));
    }

    #[test]
    fn rejects_name_out_of_bounds() {
        // A resident attr claiming a long name that runs past its own length.
        let mut attr = resident(attr_types::DATA, None, 0, b"x");
        attr[o::NAME_LENGTH] = 200; // 200 u16 chars = 400 bytes, far past the attr
        attr[o::NAME_OFFSET..o::NAME_OFFSET + 2]
            .copy_from_slice(&(RESIDENT_MIN as u16).to_le_bytes());
        let rec = record_with(0x00, &[attr]);
        assert!(matches!(
            parse_attributes(&rec, 0x00),
            Err(NtfsError::BadAttribute { .. })
        ));
    }

    #[test]
    fn missing_end_marker_does_not_overrun() {
        // A single attribute that fills the record with no end marker: the walk
        // must stop at the record boundary, not read past it.
        let attr = resident(attr_types::DATA, None, 0, b"data");
        let mut rec = vec![0u8; 0];
        rec.extend_from_slice(&attr);
        // no end marker appended
        let attrs = parse_attributes(&rec, 0).unwrap();
        assert_eq!(attrs.len(), 1);
    }
}
