//! MFT file-record-segment header parsing and update-sequence-array (fixup).
//!
//! Every `$MFT` entry is a fixed-size *file record segment* (typically 1024
//! bytes) beginning with a `FILE` signature. To protect against torn writes,
//! NTFS replaces the last two bytes of every sector with an incrementing
//! **Update Sequence Number (USN)**; the displaced originals are stored in the
//! **Update Sequence Array (USA)**. Reading a record means verifying each
//! sector still carries the expected USN (a mismatch is a torn write or
//! tampering) and restoring the originals before the bytes are interpreted.
//!
//! Layout facts (signatures, field offsets, flags) come from
//! [`forensicnomicon::ntfs`].

use forensicnomicon::ntfs::{mft_flags, mft_offsets as off, SIGNATURE_BAAD, SIGNATURE_FILE};

use crate::error::{NtfsError, Result};

/// Bytes required to read the full record header (through the record number at 0x2C).
const HEADER_LEN: usize = 0x30;

/// Parsed MFT file-record-segment header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MftRecordHeader {
    /// Record signature: `FILE` (normal) or `BAAD` (chkdsk marked it corrupt).
    pub signature: [u8; 4],
    /// Byte offset of the Update Sequence Array within the record.
    pub usa_offset: u16,
    /// Number of u16 entries in the USA (1 USN + one original per sector).
    pub usa_count: u16,
    /// `$LogFile` sequence number of the last change to this record.
    pub lsn: u64,
    /// Reuse counter — incremented each time this record number is reallocated.
    pub sequence_number: u16,
    /// Number of hard links (`$FILE_NAME` attributes) to this record.
    pub hard_link_count: u16,
    /// Byte offset of the first attribute.
    pub first_attribute_offset: u16,
    /// Record flags (see [`is_in_use`](Self::is_in_use) / [`is_directory`](Self::is_directory)).
    pub flags: u16,
    /// Bytes of the record actually used.
    pub used_size: u32,
    /// Bytes allocated to the record (the record size).
    pub allocated_size: u32,
    /// File reference to the base record (0 when this *is* the base record).
    pub base_record: u64,
    /// Id to assign to the next attribute added.
    pub next_attr_id: u16,
    /// This record's own number (Windows XP and later).
    pub record_number: u32,
}

impl MftRecordHeader {
    /// `true` if the record is currently allocated (in use).
    #[must_use]
    pub fn is_in_use(&self) -> bool {
        self.flags & mft_flags::IN_USE != 0
    }

    /// `true` if the record describes a directory.
    #[must_use]
    pub fn is_directory(&self) -> bool {
        self.flags & mft_flags::DIRECTORY != 0
    }

    /// `true` if this is a base record (not an extension/child record).
    #[must_use]
    pub fn is_base_record(&self) -> bool {
        self.base_record == 0
    }

    /// `true` if chkdsk marked this record corrupt (`BAAD` signature).
    #[must_use]
    pub fn is_corrupt(&self) -> bool {
        self.signature == SIGNATURE_BAAD
    }

    /// Parse a record header from the start of a record buffer.
    ///
    /// Does not apply the fixup (the header fields all precede the first
    /// sector boundary). Validates the `FILE`/`BAAD` signature.
    ///
    /// # Errors
    ///
    /// [`NtfsError::TooShort`] if `buf` is smaller than the header, or
    /// [`NtfsError::BadRecordSignature`] for an unrecognised signature.
    pub fn parse(buf: &[u8]) -> Result<MftRecordHeader> {
        if buf.len() < HEADER_LEN {
            return Err(NtfsError::TooShort {
                what: "MFT record header",
                need: HEADER_LEN,
                got: buf.len(),
            });
        }

        let signature: [u8; 4] = buf[off::SIGNATURE..off::SIGNATURE + 4].try_into().unwrap();
        if signature != SIGNATURE_FILE && signature != SIGNATURE_BAAD {
            return Err(NtfsError::BadRecordSignature(signature));
        }

        let u16at = |o: usize| u16::from_le_bytes(buf[o..o + 2].try_into().unwrap());
        let u32at = |o: usize| u32::from_le_bytes(buf[o..o + 4].try_into().unwrap());
        let u64at = |o: usize| u64::from_le_bytes(buf[o..o + 8].try_into().unwrap());

        Ok(MftRecordHeader {
            signature,
            usa_offset: u16at(off::USA_OFFSET),
            usa_count: u16at(off::USA_COUNT),
            lsn: u64at(off::LSN),
            sequence_number: u16at(off::SEQUENCE_NUMBER),
            hard_link_count: u16at(off::HARD_LINK_COUNT),
            first_attribute_offset: u16at(off::FIRST_ATTRIBUTE),
            flags: u16at(off::FLAGS),
            used_size: u32at(off::USED_SIZE),
            allocated_size: u32at(off::ALLOCATED_SIZE),
            base_record: u64at(off::BASE_RECORD),
            next_attr_id: u16at(off::NEXT_ATTR_ID),
            record_number: u32at(off::RECORD_NUMBER),
        })
    }
}

/// Apply the NTFS update-sequence-array fixup to a raw record buffer in place.
///
/// Verifies that each protected sector's last two bytes equal the USN, then
/// restores the displaced original bytes from the USA.
///
/// # Errors
///
/// [`NtfsError::FixupMismatch`] when a sector tail does not match the USN (torn
/// write / tampering), or [`NtfsError::BadUpdateSequence`] when the USA is
/// malformed.
pub fn apply_fixup(buf: &mut [u8], sector_size: usize) -> Result<()> {
    if buf.len() < HEADER_LEN {
        return Err(NtfsError::TooShort {
            what: "MFT record",
            need: HEADER_LEN,
            got: buf.len(),
        });
    }
    if sector_size < 2 {
        return Err(NtfsError::BadUpdateSequence(
            "sector size smaller than 2 bytes",
        ));
    }

    let usa_offset = u16::from_le_bytes(
        buf[off::USA_OFFSET..off::USA_OFFSET + 2]
            .try_into()
            .unwrap(),
    ) as usize;
    let usa_count =
        u16::from_le_bytes(buf[off::USA_COUNT..off::USA_COUNT + 2].try_into().unwrap()) as usize;
    if usa_count == 0 {
        return Err(NtfsError::BadUpdateSequence("usa_count is zero"));
    }

    // The USA holds `usa_count` u16 entries (1 USN + one original per sector).
    let usa_end = usa_offset
        .checked_add(usa_count * 2)
        .ok_or(NtfsError::BadUpdateSequence("usa offset/count overflow"))?;
    if usa_end > buf.len() {
        return Err(NtfsError::BadUpdateSequence("usa extends past record"));
    }

    let fixup_sectors = usa_count - 1;
    let span = fixup_sectors
        .checked_mul(sector_size)
        .ok_or(NtfsError::BadUpdateSequence("sector span overflow"))?;
    if span > buf.len() {
        return Err(NtfsError::BadUpdateSequence(
            "fixup sectors exceed record size",
        ));
    }

    let usn = u16::from_le_bytes(buf[usa_offset..usa_offset + 2].try_into().unwrap());

    for i in 0..fixup_sectors {
        let tail = (i + 1) * sector_size - 2;
        let found = u16::from_le_bytes([buf[tail], buf[tail + 1]]);
        if found != usn {
            return Err(NtfsError::FixupMismatch {
                sector: i,
                expected: usn,
                found,
            });
        }
        let original = usa_offset + 2 + i * 2;
        buf[tail] = buf[original];
        buf[tail + 1] = buf[original + 1];
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `FILE` record with a valid USA: `usn` written to each sector
    /// tail, the `originals` stored in the USA. One original per sector.
    fn make_record(size: usize, sector_size: usize, usn: u16, originals: &[u16]) -> Vec<u8> {
        assert_eq!(
            size / sector_size,
            originals.len(),
            "one original per sector"
        );
        let mut b = vec![0u8; size];
        b[0..4].copy_from_slice(b"FILE");
        let usa_offset: u16 = 0x30;
        let usa_count = (originals.len() + 1) as u16;
        b[0x04..0x06].copy_from_slice(&usa_offset.to_le_bytes());
        b[0x06..0x08].copy_from_slice(&usa_count.to_le_bytes());
        // first attribute offset: just past the USA.
        let first_attr = usa_offset + usa_count * 2;
        b[0x14..0x16].copy_from_slice(&first_attr.to_le_bytes());
        b[0x16..0x18].copy_from_slice(&mft_flags::IN_USE.to_le_bytes());

        let uo = usa_offset as usize;
        b[uo..uo + 2].copy_from_slice(&usn.to_le_bytes());
        for (i, orig) in originals.iter().enumerate() {
            let p = uo + 2 + i * 2;
            b[p..p + 2].copy_from_slice(&orig.to_le_bytes());
            // On disk, each sector tail holds the USN sentinel.
            let tail = (i + 1) * sector_size - 2;
            b[tail..tail + 2].copy_from_slice(&usn.to_le_bytes());
        }
        b
    }

    // ── MftRecordHeader::parse ────────────────────────────────────────────────

    #[test]
    fn parses_file_record_header() {
        let mut b = make_record(1024, 512, 0xABCD, &[0x1111, 0x2222]);
        // Set a few more header fields directly.
        b[0x08..0x10].copy_from_slice(&0x0000_0000_DEAD_BEEFu64.to_le_bytes()); // LSN
        b[0x10..0x12].copy_from_slice(&7u16.to_le_bytes()); // sequence number
        b[0x12..0x14].copy_from_slice(&1u16.to_le_bytes()); // hard link count
        b[0x18..0x1C].copy_from_slice(&0x0000_0188u32.to_le_bytes()); // used size
        b[0x1C..0x20].copy_from_slice(&1024u32.to_le_bytes()); // allocated size
        b[0x20..0x28].copy_from_slice(&0u64.to_le_bytes()); // base record (base)
        b[0x28..0x2A].copy_from_slice(&3u16.to_le_bytes()); // next attr id
        b[0x2C..0x30].copy_from_slice(&42u32.to_le_bytes()); // record number

        let h = MftRecordHeader::parse(&b).expect("valid FILE record");
        assert_eq!(&h.signature, b"FILE");
        assert_eq!(h.usa_offset, 0x30);
        assert_eq!(h.usa_count, 3);
        assert_eq!(h.lsn, 0xDEAD_BEEF);
        assert_eq!(h.sequence_number, 7);
        assert_eq!(h.hard_link_count, 1);
        assert_eq!(h.first_attribute_offset, 0x30 + 3 * 2);
        assert_eq!(h.used_size, 0x188);
        assert_eq!(h.allocated_size, 1024);
        assert_eq!(h.next_attr_id, 3);
        assert_eq!(h.record_number, 42);
        assert!(h.is_in_use());
        assert!(!h.is_directory());
        assert!(h.is_base_record());
        assert!(!h.is_corrupt());
    }

    #[test]
    fn directory_and_extension_flags_decode() {
        let mut b = make_record(1024, 512, 1, &[0, 0]);
        b[0x16..0x18].copy_from_slice(&(mft_flags::IN_USE | mft_flags::DIRECTORY).to_le_bytes());
        b[0x20..0x28].copy_from_slice(&0x0001_0000_0000_0005u64.to_le_bytes()); // base ref (extension)
        let h = MftRecordHeader::parse(&b).unwrap();
        assert!(h.is_in_use());
        assert!(h.is_directory());
        assert!(!h.is_base_record());
    }

    #[test]
    fn baad_signature_parses_as_corrupt() {
        let mut b = make_record(1024, 512, 1, &[0, 0]);
        b[0..4].copy_from_slice(b"BAAD");
        let h = MftRecordHeader::parse(&b).expect("BAAD is a valid (corrupt) record");
        assert!(h.is_corrupt());
    }

    #[test]
    fn rejects_unknown_signature() {
        let mut b = make_record(1024, 512, 1, &[0, 0]);
        b[0..4].copy_from_slice(b"XXXX");
        assert!(matches!(
            MftRecordHeader::parse(&b),
            Err(NtfsError::BadRecordSignature(s)) if &s == b"XXXX"
        ));
    }

    #[test]
    fn header_too_short_returns_error() {
        let b = vec![b'F', b'I', b'L', b'E', 0, 0];
        assert!(matches!(
            MftRecordHeader::parse(&b),
            Err(NtfsError::TooShort { .. })
        ));
    }

    // ── apply_fixup ───────────────────────────────────────────────────────────

    #[test]
    fn fixup_restores_sector_tails() {
        let mut b = make_record(1024, 512, 0xABCD, &[0x1111, 0x2222]);
        // Before fixup the tails hold the USN sentinel.
        assert_eq!(&b[510..512], &0xABCDu16.to_le_bytes());
        assert_eq!(&b[1022..1024], &0xABCDu16.to_le_bytes());

        apply_fixup(&mut b, 512).expect("valid fixup");

        // After fixup the tails hold the original values from the USA.
        assert_eq!(u16::from_le_bytes([b[510], b[511]]), 0x1111);
        assert_eq!(u16::from_le_bytes([b[1022], b[1023]]), 0x2222);
    }

    #[test]
    fn fixup_detects_torn_write() {
        let mut b = make_record(1024, 512, 0xABCD, &[0x1111, 0x2222]);
        // Corrupt the second sector's tail so it no longer matches the USN.
        b[1022..1024].copy_from_slice(&0xDEADu16.to_le_bytes());
        assert!(matches!(
            apply_fixup(&mut b, 512),
            Err(NtfsError::FixupMismatch {
                sector: 1,
                expected: 0xABCD,
                found: 0xDEAD
            })
        ));
    }

    #[test]
    fn fixup_rejects_zero_usa_count() {
        let mut b = make_record(1024, 512, 1, &[0, 0]);
        b[0x06..0x08].copy_from_slice(&0u16.to_le_bytes()); // usa_count = 0
        assert!(matches!(
            apply_fixup(&mut b, 512),
            Err(NtfsError::BadUpdateSequence(_))
        ));
    }

    #[test]
    fn fixup_rejects_usa_out_of_bounds() {
        let mut b = make_record(1024, 512, 1, &[0, 0]);
        b[0x04..0x06].copy_from_slice(&0x0FFEu16.to_le_bytes()); // usa_offset near end
        b[0x06..0x08].copy_from_slice(&8u16.to_le_bytes()); // count overruns buffer
        assert!(matches!(
            apply_fixup(&mut b, 512),
            Err(NtfsError::BadUpdateSequence(_))
        ));
    }
}
