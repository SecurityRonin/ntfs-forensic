//! `$STANDARD_INFORMATION` (type `0x10`) — the core file metadata: the four
//! MACE timestamps, DOS attribute flags, and (NTFS 3.0+) the security id and
//! the `$UsnJrnl` update sequence number.
//!
//! These are the timestamps an attacker most easily forges. Comparing them
//! against the `$FILE_NAME` set (see [`crate::file_name`]) is the classic
//! timestomping check — wired in at the Tier-2 forensic layer.

use crate::error::{NtfsError, Result};
use crate::time::Filetime;

/// Minimum `$STANDARD_INFORMATION` content (NTFS 1.2: four timestamps + flags +
/// version fields).
const SI_MIN: usize = 0x30;
/// Content length at which NTFS 3.0+ fields (owner/security/quota/usn) appear.
const SI_V3: usize = 0x48;

/// Windows `FILE_ATTRIBUTE_*` flags (shared with `$FILE_NAME`).
// TODO(forensicnomicon): migrate to forensicnomicon::ntfs::file_attributes.
pub mod file_attr {
    pub const READONLY: u32 = 0x0001;
    pub const HIDDEN: u32 = 0x0002;
    pub const SYSTEM: u32 = 0x0004;
    pub const ARCHIVE: u32 = 0x0020;
    pub const TEMPORARY: u32 = 0x0100;
    pub const SPARSE_FILE: u32 = 0x0200;
    pub const REPARSE_POINT: u32 = 0x0400;
    pub const COMPRESSED: u32 = 0x0800;
    pub const ENCRYPTED: u32 = 0x4000;
}

/// Parsed `$STANDARD_INFORMATION` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandardInformation {
    /// Creation time.
    pub created: Filetime,
    /// File content modification time ("M").
    pub modified: Filetime,
    /// MFT record modification time ("C" / entry-changed).
    pub mft_modified: Filetime,
    /// Last access time ("A").
    pub accessed: Filetime,
    /// `FILE_ATTRIBUTE_*` flags.
    pub file_attributes: u32,
    /// Security id (NTFS 3.0+), else `None`.
    pub security_id: Option<u32>,
    /// `$UsnJrnl` update sequence number (NTFS 3.0+), else `None`.
    pub usn: Option<u64>,
}

impl StandardInformation {
    /// `true` if the hidden attribute is set.
    #[must_use]
    pub fn is_hidden(&self) -> bool {
        self.file_attributes & file_attr::HIDDEN != 0
    }

    /// `true` if the system attribute is set.
    #[must_use]
    pub fn is_system(&self) -> bool {
        self.file_attributes & file_attr::SYSTEM != 0
    }

    /// `true` if the read-only attribute is set.
    #[must_use]
    pub fn is_read_only(&self) -> bool {
        self.file_attributes & file_attr::READONLY != 0
    }

    /// Parse a `$STANDARD_INFORMATION` value from its resident content bytes.
    ///
    /// # Errors
    ///
    /// [`NtfsError::TooShort`] when `content` is smaller than the minimum.
    pub fn parse(content: &[u8]) -> Result<StandardInformation> {
        if content.len() < SI_MIN {
            return Err(NtfsError::TooShort {
                what: "$STANDARD_INFORMATION",
                need: SI_MIN,
                got: content.len(),
            });
        }
        let ft = |o: usize| Filetime::from_le(content[o..o + 8].try_into().unwrap());
        let file_attributes = u32::from_le_bytes(content[0x20..0x24].try_into().unwrap());

        let (security_id, usn) = if content.len() >= SI_V3 {
            (
                Some(u32::from_le_bytes(content[0x34..0x38].try_into().unwrap())),
                Some(u64::from_le_bytes(content[0x40..0x48].try_into().unwrap())),
            )
        } else {
            (None, None)
        };

        Ok(StandardInformation {
            created: ft(0x00),
            modified: ft(0x08),
            mft_modified: ft(0x10),
            accessed: ft(0x18),
            file_attributes,
            security_id,
            usn,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_si(
        created: u64,
        modified: u64,
        mft_modified: u64,
        accessed: u64,
        attrs: u32,
        v3: Option<(u32, u64)>, // (security_id, usn)
    ) -> Vec<u8> {
        let len = if v3.is_some() { SI_V3 } else { SI_MIN };
        let mut c = vec![0u8; len];
        c[0x00..0x08].copy_from_slice(&created.to_le_bytes());
        c[0x08..0x10].copy_from_slice(&modified.to_le_bytes());
        c[0x10..0x18].copy_from_slice(&mft_modified.to_le_bytes());
        c[0x18..0x20].copy_from_slice(&accessed.to_le_bytes());
        c[0x20..0x24].copy_from_slice(&attrs.to_le_bytes());
        if let Some((sid, usn)) = v3 {
            c[0x34..0x38].copy_from_slice(&sid.to_le_bytes());
            c[0x40..0x48].copy_from_slice(&usn.to_le_bytes());
        }
        c
    }

    #[test]
    fn parses_ntfs12_standard_information() {
        let c = make_si(0x10, 0x20, 0x30, 0x40, file_attr::ARCHIVE, None);
        let si = StandardInformation::parse(&c).unwrap();
        assert_eq!(si.created, Filetime(0x10));
        assert_eq!(si.modified, Filetime(0x20));
        assert_eq!(si.mft_modified, Filetime(0x30));
        assert_eq!(si.accessed, Filetime(0x40));
        assert_eq!(si.file_attributes, file_attr::ARCHIVE);
        assert_eq!(si.security_id, None);
        assert_eq!(si.usn, None);
    }

    #[test]
    fn parses_ntfs30_security_and_usn() {
        let c = make_si(1, 2, 3, 4, 0, Some((0x101, 0xDEAD_BEEF)));
        let si = StandardInformation::parse(&c).unwrap();
        assert_eq!(si.security_id, Some(0x101));
        assert_eq!(si.usn, Some(0xDEAD_BEEF));
    }

    #[test]
    fn flag_predicates() {
        let c = make_si(0, 0, 0, 0, file_attr::HIDDEN | file_attr::SYSTEM, None);
        let si = StandardInformation::parse(&c).unwrap();
        assert!(si.is_hidden());
        assert!(si.is_system());
        assert!(!si.is_read_only());
    }

    #[test]
    fn rejects_too_short() {
        let c = vec![0u8; 0x20];
        assert!(matches!(
            StandardInformation::parse(&c),
            Err(NtfsError::TooShort { .. })
        ));
    }
}
