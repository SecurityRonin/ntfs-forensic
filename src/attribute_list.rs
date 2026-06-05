//! `$ATTRIBUTE_LIST` (type `0x20`) — present when a file's attributes don't fit
//! in one MFT record. Each entry points at the extension record (a file
//! reference) holding one of the file's attributes, with its type, starting
//! VCN, id, and name. Following these references is how a heavily-fragmented
//! file's attributes are gathered.

use forensicnomicon::ntfs::attribute_type_name;

use crate::error::{NtfsError, Result};
use crate::file_name::FileReference;

/// Fixed size of an entry header (through the attribute id; name follows).
const ENTRY_MIN: usize = 0x1A;
/// Loop cap on entries.
const MAX_ENTRIES: usize = 1 << 20;

/// One `$ATTRIBUTE_LIST` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeListEntry {
    /// Attribute type code.
    pub type_code: u32,
    /// Starting VCN of this attribute's portion.
    pub start_vcn: u64,
    /// Reference to the MFT record that holds the attribute.
    pub base_reference: FileReference,
    /// Attribute id.
    pub attribute_id: u16,
    /// Attribute name, or `None` if unnamed.
    pub name: Option<String>,
}

impl AttributeListEntry {
    /// Canonical `$NAME` of this entry's attribute type, if known.
    #[must_use]
    pub fn type_name(&self) -> Option<&'static str> {
        attribute_type_name(self.type_code)
    }
}

/// Parse an `$ATTRIBUTE_LIST` value into its entries.
///
/// # Errors
///
/// [`NtfsError::BadAttributeList`] for an undersized entry, an entry past the
/// content, or a name out of bounds.
pub fn parse(content: &[u8]) -> Result<Vec<AttributeListEntry>> {
    let mut entries = Vec::new();
    let mut pos = 0;

    for _ in 0..MAX_ENTRIES {
        if pos + ENTRY_MIN > content.len() {
            break;
        }
        let entry_length =
            u16::from_le_bytes(content[pos + 0x04..pos + 0x06].try_into().unwrap()) as usize;
        if entry_length < ENTRY_MIN {
            return Err(NtfsError::BadAttributeList("entry length below minimum"));
        }
        let entry_end = pos
            .checked_add(entry_length)
            .ok_or(NtfsError::BadAttributeList("entry length overflow"))?;
        if entry_end > content.len() {
            return Err(NtfsError::BadAttributeList("entry extends past content"));
        }

        let type_code = u32::from_le_bytes(content[pos..pos + 4].try_into().unwrap());
        let name_length = content[pos + 0x06] as usize;
        let name_offset = content[pos + 0x07] as usize;
        let start_vcn = u64::from_le_bytes(content[pos + 0x08..pos + 0x10].try_into().unwrap());
        let base_reference = FileReference::from_u64(u64::from_le_bytes(
            content[pos + 0x10..pos + 0x18].try_into().unwrap(),
        ));
        let attribute_id = u16::from_le_bytes(content[pos + 0x18..pos + 0x1A].try_into().unwrap());

        let name = if name_length == 0 {
            None
        } else {
            let n_start = pos
                .checked_add(name_offset)
                .ok_or(NtfsError::BadAttributeList("name offset overflow"))?;
            let n_end = n_start
                .checked_add(name_length * 2)
                .ok_or(NtfsError::BadAttributeList("name length overflow"))?;
            if n_end > entry_end {
                return Err(NtfsError::BadAttributeList("name extends past entry"));
            }
            let units: Vec<u16> = content[n_start..n_end]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            Some(
                char::decode_utf16(units)
                    .map(|r| r.unwrap_or('\u{FFFD}'))
                    .collect(),
            )
        };

        entries.push(AttributeListEntry {
            type_code,
            start_vcn,
            base_reference,
            attribute_id,
            name,
        });
        pos = entry_end;
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensicnomicon::ntfs::attr_types;

    fn entry(type_code: u32, start_vcn: u64, base_record: u64, name: Option<&str>) -> Vec<u8> {
        let name_u: Vec<u16> = name.map(|n| n.encode_utf16().collect()).unwrap_or_default();
        let name_off = ENTRY_MIN;
        let len = (name_off + name_u.len() * 2 + 7) & !7;
        let mut e = vec![0u8; len];
        e[0x00..0x04].copy_from_slice(&type_code.to_le_bytes());
        e[0x04..0x06].copy_from_slice(&(len as u16).to_le_bytes());
        e[0x06] = name_u.len() as u8;
        e[0x07] = name_off as u8;
        e[0x08..0x10].copy_from_slice(&start_vcn.to_le_bytes());
        let base_ref = (1u64 << 48) | base_record;
        e[0x10..0x18].copy_from_slice(&base_ref.to_le_bytes());
        e[0x18..0x1A].copy_from_slice(&3u16.to_le_bytes());
        for (i, u) in name_u.iter().enumerate() {
            e[name_off + i * 2..name_off + i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
        e
    }

    #[test]
    fn parses_entries_pointing_to_extension_records() {
        let content = [
            entry(attr_types::STANDARD_INFORMATION, 0, 5, None),
            entry(attr_types::DATA, 0, 9, None),
        ]
        .concat();
        let es = parse(&content).unwrap();
        assert_eq!(es.len(), 2);
        assert_eq!(es[0].type_code, attr_types::STANDARD_INFORMATION);
        assert_eq!(es[0].base_reference.record_number, 5);
        assert_eq!(es[1].type_code, attr_types::DATA);
        assert_eq!(es[1].base_reference.record_number, 9);
        assert_eq!(es[1].type_name(), Some("$DATA"));
    }

    #[test]
    fn decodes_named_entry() {
        let content = entry(attr_types::DATA, 7, 12, Some("stream"));
        let es = parse(&content).unwrap();
        assert_eq!(es[0].name.as_deref(), Some("stream"));
        assert_eq!(es[0].start_vcn, 7);
    }

    #[test]
    fn rejects_undersized_entry() {
        let mut content = vec![0u8; 0x20];
        content[0x04..0x06].copy_from_slice(&4u16.to_le_bytes()); // < ENTRY_MIN
        assert!(matches!(
            parse(&content),
            Err(NtfsError::BadAttributeList(_))
        ));
    }

    #[test]
    fn rejects_entry_past_content() {
        let mut content = vec![0u8; 0x20];
        content[0x04..0x06].copy_from_slice(&0x100u16.to_le_bytes());
        assert!(matches!(
            parse(&content),
            Err(NtfsError::BadAttributeList(_))
        ));
    }
}
