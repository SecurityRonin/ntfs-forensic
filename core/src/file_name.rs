//! `$FILE_NAME` (type `0x30`) — a name link for a file: its parent directory
//! reference, a *second* set of MACE timestamps, the file sizes, flags, and the
//! name itself in one of four namespaces.
//!
//! A record may hold several `$FILE_NAME` attributes (one per hard link, plus a
//! short DOS 8.3 name). The parent reference is what path reconstruction walks
//! (increment 7); the `$FN` timestamps are the harder-to-forge counterpart used
//! for timestomping detection.

use forensicnomicon::ntfs::filename_namespace;

use crate::error::{NtfsError, Result};
use crate::time::Filetime;

/// Minimum `$FILE_NAME` content (through the namespace byte; name follows).
const FN_MIN: usize = 0x42;

/// A 64-bit NTFS file reference: a 48-bit MFT record number plus a 16-bit
/// sequence (reuse) number. A stale sequence flags a dangling reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileReference {
    /// MFT record number (low 48 bits).
    pub record_number: u64,
    /// Sequence number (high 16 bits).
    pub sequence: u16,
}

impl FileReference {
    /// Split a little-endian 64-bit reference into record number + sequence.
    #[must_use]
    pub fn from_u64(raw: u64) -> Self {
        FileReference {
            record_number: raw & 0x0000_FFFF_FFFF_FFFF,
            sequence: (raw >> 48) as u16,
        }
    }
}

/// Parsed `$FILE_NAME` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileName {
    /// Reference to the parent directory.
    pub parent: FileReference,
    /// Creation time.
    pub created: Filetime,
    /// File content modification time.
    pub modified: Filetime,
    /// MFT record modification time.
    pub mft_modified: Filetime,
    /// Last access time.
    pub accessed: Filetime,
    /// Allocated size of the file, in bytes.
    pub allocated_size: u64,
    /// Real (logical) size of the file, in bytes.
    pub real_size: u64,
    /// `FILE_ATTRIBUTE_*` flags.
    pub flags: u32,
    /// Namespace code (see [`forensicnomicon::ntfs::filename_namespace`]).
    pub namespace: u8,
    /// The decoded file name.
    pub name: String,
}

impl FileName {
    /// Human-readable namespace name, if recognised.
    #[must_use]
    pub fn namespace_name(&self) -> Option<&'static str> {
        filename_namespace::name(self.namespace)
    }

    /// `true` if this is the short DOS (8.3) name — the one tools often omit
    /// when listing, and which carries its own timestamps.
    #[must_use]
    pub fn is_dos_namespace(&self) -> bool {
        self.namespace == filename_namespace::DOS
    }

    /// Parse a `$FILE_NAME` value from its resident content bytes.
    ///
    /// # Errors
    ///
    /// [`NtfsError::TooShort`] when smaller than the fixed header, or
    /// [`NtfsError::BadAttribute`] when the name runs past the content.
    pub fn parse(content: &[u8]) -> Result<FileName> {
        if content.len() < FN_MIN {
            return Err(NtfsError::TooShort {
                what: "$FILE_NAME",
                need: FN_MIN,
                got: content.len(),
            });
        }

        let parent =
            FileReference::from_u64(u64::from_le_bytes(content[0x00..0x08].try_into().unwrap()));
        let ft = |o: usize| Filetime::from_le(content[o..o + 8].try_into().unwrap());
        let allocated_size = u64::from_le_bytes(content[0x28..0x30].try_into().unwrap());
        let real_size = u64::from_le_bytes(content[0x30..0x38].try_into().unwrap());
        let flags = u32::from_le_bytes(content[0x38..0x3C].try_into().unwrap());

        let name_length = content[0x40] as usize;
        let namespace = content[0x41];
        let name_bytes = name_length.checked_mul(2).ok_or(NtfsError::BadAttribute {
            offset: 0,
            detail: "$FILE_NAME name length overflow",
        })?;
        let name_end = FN_MIN
            .checked_add(name_bytes)
            .ok_or(NtfsError::BadAttribute {
                offset: 0,
                detail: "$FILE_NAME name overflow",
            })?;
        if name_end > content.len() {
            return Err(NtfsError::BadAttribute {
                offset: 0,
                detail: "$FILE_NAME name extends past content",
            });
        }

        let units: Vec<u16> = content[FN_MIN..name_end]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let name = char::decode_utf16(units)
            .map(|r| r.unwrap_or('\u{FFFD}'))
            .collect();

        Ok(FileName {
            parent,
            created: ft(0x08),
            modified: ft(0x10),
            mft_modified: ft(0x18),
            accessed: ft(0x20),
            allocated_size,
            real_size,
            flags,
            namespace,
            name,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    fn make_fn(
        parent: u64,
        created: u64,
        modified: u64,
        mft_modified: u64,
        accessed: u64,
        allocated: u64,
        real: u64,
        flags: u32,
        namespace: u8,
        name: &str,
    ) -> Vec<u8> {
        let name_units: Vec<u16> = name.encode_utf16().collect();
        let mut c = vec![0u8; FN_MIN + name_units.len() * 2];
        c[0x00..0x08].copy_from_slice(&parent.to_le_bytes());
        c[0x08..0x10].copy_from_slice(&created.to_le_bytes());
        c[0x10..0x18].copy_from_slice(&modified.to_le_bytes());
        c[0x18..0x20].copy_from_slice(&mft_modified.to_le_bytes());
        c[0x20..0x28].copy_from_slice(&accessed.to_le_bytes());
        c[0x28..0x30].copy_from_slice(&allocated.to_le_bytes());
        c[0x30..0x38].copy_from_slice(&real.to_le_bytes());
        c[0x38..0x3C].copy_from_slice(&flags.to_le_bytes());
        c[0x40] = name_units.len() as u8;
        c[0x41] = namespace;
        for (i, u) in name_units.iter().enumerate() {
            let p = 0x42 + i * 2;
            c[p..p + 2].copy_from_slice(&u.to_le_bytes());
        }
        c
    }

    #[test]
    fn file_reference_splits_record_and_sequence() {
        // sequence 5 in the high 16 bits, record number 0x1234 in the low 48.
        let raw = (5u64 << 48) | 0x1234;
        let r = FileReference::from_u64(raw);
        assert_eq!(r.record_number, 0x1234);
        assert_eq!(r.sequence, 5);
    }

    #[test]
    fn parses_file_name() {
        let c = make_fn(
            (3u64 << 48) | 5, // parent: record 5, sequence 3
            0x10,
            0x20,
            0x30,
            0x40,
            0x1000,
            0x0ABC,
            super::super::standard_information::file_attr::ARCHIVE,
            filename_namespace::WIN32,
            "report.docx",
        );
        let f = FileName::parse(&c).unwrap();
        assert_eq!(f.parent.record_number, 5);
        assert_eq!(f.parent.sequence, 3);
        assert_eq!(f.created, Filetime(0x10));
        assert_eq!(f.accessed, Filetime(0x40));
        assert_eq!(f.allocated_size, 0x1000);
        assert_eq!(f.real_size, 0x0ABC);
        assert_eq!(f.namespace, filename_namespace::WIN32);
        assert_eq!(f.namespace_name(), Some("Win32"));
        assert!(!f.is_dos_namespace());
        assert_eq!(f.name, "report.docx");
    }

    #[test]
    fn detects_dos_namespace() {
        let c = make_fn(
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            filename_namespace::DOS,
            "REPORT~1.DOC",
        );
        let f = FileName::parse(&c).unwrap();
        assert!(f.is_dos_namespace());
    }

    #[test]
    fn rejects_name_past_content() {
        let mut c = make_fn(0, 0, 0, 0, 0, 0, 0, 0, filename_namespace::WIN32, "ab");
        c[0x40] = 200; // claim a 200-char name that isn't there
        assert!(matches!(
            FileName::parse(&c),
            Err(NtfsError::BadAttribute { .. })
        ));
    }

    #[test]
    fn rejects_too_short() {
        let c = vec![0u8; 0x20];
        assert!(matches!(
            FileName::parse(&c),
            Err(NtfsError::TooShort { .. })
        ));
    }
}
