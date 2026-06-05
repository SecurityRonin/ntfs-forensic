//! Forensic Tier-2: the artifacts a "clean" reader hides — timestomping
//! indicators, alternate data streams, MFT-record slack, and deleted records.
//!
//! These are pure analyses over already-parsed structures, so they are exact
//! and side-effect free.

use forensicnomicon::ntfs::{attr_types, SIGNATURE_BAAD, SIGNATURE_FILE};

use crate::attribute::Attribute;
use crate::file_name::FileName;
use crate::record::MftRecordHeader;
use crate::standard_information::StandardInformation;
use crate::time::Filetime;

/// `FILETIME` ticks per second (100-ns intervals).
const TICKS_PER_SECOND: u64 = 10_000_000;

/// Indicators that a file's `$STANDARD_INFORMATION` timestamps were forged.
///
/// `$FN` timestamps are harder to forge than `$SI`, so divergence between the
/// two — or `$SI` times landing on a whole second — is suspicious.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TimestompIndicators {
    /// `$SI` creation time predates `$FN` creation time.
    pub si_created_before_fn: bool,
    /// `$SI` creation time differs from `$FN` creation time.
    pub created_mismatch: bool,
    /// One or more `$SI` timestamps fall exactly on a whole second (no
    /// sub-second precision — a common timestomp artifact).
    pub si_whole_second: bool,
}

impl TimestompIndicators {
    /// `true` if any strong indicator fired.
    #[must_use]
    pub fn is_suspicious(&self) -> bool {
        self.si_created_before_fn || self.si_whole_second
    }
}

/// Compare a file's `$STANDARD_INFORMATION` against one of its `$FILE_NAME`
/// attributes for timestomping indicators.
#[must_use]
pub fn detect_timestomp(si: &StandardInformation, file_name: &FileName) -> TimestompIndicators {
    TimestompIndicators {
        si_created_before_fn: si.created.0 < file_name.created.0,
        created_mismatch: si.created.0 != file_name.created.0,
        si_whole_second: whole_second(si.created)
            || whole_second(si.modified)
            || whole_second(si.mft_modified)
            || whole_second(si.accessed),
    }
}

/// `true` when a timestamp is non-zero yet lands exactly on a whole second.
fn whole_second(ft: Filetime) -> bool {
    ft.0 != 0 && ft.0 % TICKS_PER_SECOND == 0
}

/// The named `$DATA` attributes of a file — its alternate data streams.
#[must_use]
pub fn alternate_data_streams(attributes: &[Attribute]) -> Vec<&Attribute> {
    attributes
        .iter()
        .filter(|a| a.type_code == attr_types::DATA && a.name.is_some())
        .collect()
}

/// The slack of an MFT record: the bytes from the record's used size to its end,
/// which may hold residue from a previously-resident attribute.
#[must_use]
pub fn record_slack<'a>(record: &'a [u8], header: &MftRecordHeader) -> &'a [u8] {
    let used = header.used_size as usize;
    record.get(used..).unwrap_or(&[])
}

/// `true` if the record is not currently allocated (a deleted file).
#[must_use]
pub fn is_deleted(header: &MftRecordHeader) -> bool {
    !header.is_in_use()
}

/// Scan a raw MFT byte region for `FILE`/`BAAD` records at record-size
/// boundaries, returning the offset of each.
#[must_use]
pub fn carve_file_records(mft: &[u8], record_size: usize) -> Vec<usize> {
    if record_size == 0 {
        return Vec::new();
    }
    let mut offsets = Vec::new();
    let mut pos = 0;
    while pos + 4 <= mft.len() {
        let sig = &mft[pos..pos + 4];
        if sig == SIGNATURE_FILE || sig == SIGNATURE_BAAD {
            offsets.push(pos);
        }
        pos += record_size;
    }
    offsets
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribute::AttributeBody;

    fn si(created: u64, modified: u64, mft_modified: u64, accessed: u64) -> StandardInformation {
        StandardInformation {
            created: Filetime(created),
            modified: Filetime(modified),
            mft_modified: Filetime(mft_modified),
            accessed: Filetime(accessed),
            file_attributes: 0,
            security_id: None,
            usn: None,
        }
    }

    fn fname(created: u64) -> FileName {
        use crate::file_name::FileReference;
        FileName {
            parent: FileReference::from_u64(5),
            created: Filetime(created),
            modified: Filetime(created),
            mft_modified: Filetime(created),
            accessed: Filetime(created),
            allocated_size: 0,
            real_size: 0,
            flags: 0,
            namespace: 1,
            name: "f".to_string(),
        }
    }

    fn data_attr(name: Option<&str>) -> Attribute {
        Attribute {
            type_code: attr_types::DATA,
            length: 0,
            non_resident: false,
            name: name.map(str::to_string),
            flags: 0,
            attribute_id: 0,
            offset: 0,
            body: AttributeBody::Resident {
                content_offset: 0,
                content_length: 0,
            },
        }
    }

    #[test]
    fn timestomp_si_before_fn_is_suspicious() {
        // $SI created well before $FN created → timestomp.
        let ind = detect_timestomp(&si(1_000, 1_000, 1_000, 1_000), &fname(2_000_000_000));
        assert!(ind.si_created_before_fn);
        assert!(ind.is_suspicious());
    }

    #[test]
    fn timestomp_whole_second_is_suspicious() {
        // $SI times all on whole seconds (multiples of 10^7) → timestomp tell.
        let t = 5 * TICKS_PER_SECOND;
        let ind = detect_timestomp(&si(t, t, t, t), &fname(t));
        assert!(ind.si_whole_second);
        assert!(ind.is_suspicious());
    }

    #[test]
    fn matching_subsecond_times_are_clean() {
        let t = 129_067_776_000_000_123; // has sub-second precision
        let ind = detect_timestomp(&si(t, t, t, t), &fname(t));
        assert!(!ind.is_suspicious());
        assert!(!ind.created_mismatch);
    }

    #[test]
    fn finds_alternate_data_streams() {
        let attrs = [
            data_attr(None),
            data_attr(Some("Zone.Identifier")),
            data_attr(Some("evil")),
        ];
        let ads = alternate_data_streams(&attrs);
        assert_eq!(ads.len(), 2);
        assert_eq!(ads[0].name.as_deref(), Some("Zone.Identifier"));
    }

    #[test]
    fn slack_is_the_tail_after_used_size() {
        let mut record = vec![0u8; 1024];
        record[600..610].copy_from_slice(b"RESIDUEXYZ");
        let header = MftRecordHeader {
            signature: *b"FILE",
            usa_offset: 0x30,
            usa_count: 3,
            lsn: 0,
            sequence_number: 1,
            hard_link_count: 1,
            first_attribute_offset: 0x38,
            flags: 0x01,
            used_size: 600,
            allocated_size: 1024,
            base_record: 0,
            next_attr_id: 1,
            record_number: 0,
        };
        let slack = record_slack(&record, &header);
        assert_eq!(slack.len(), 1024 - 600);
        assert_eq!(&slack[0..10], b"RESIDUEXYZ");
    }

    #[test]
    fn deleted_when_not_in_use() {
        let mut header = MftRecordHeader {
            signature: *b"FILE",
            usa_offset: 0x30,
            usa_count: 3,
            lsn: 0,
            sequence_number: 1,
            hard_link_count: 1,
            first_attribute_offset: 0x38,
            flags: 0x00, // not in use
            used_size: 0x100,
            allocated_size: 1024,
            base_record: 0,
            next_attr_id: 1,
            record_number: 0,
        };
        assert!(is_deleted(&header));
        header.flags = 0x01;
        assert!(!is_deleted(&header));
    }

    #[test]
    fn carve_with_zero_record_size_is_empty() {
        // A zero stride would loop forever; it is refused with an empty result.
        assert!(carve_file_records(b"FILE....", 0).is_empty());
    }

    #[test]
    fn carves_file_records_at_boundaries() {
        let rec = 1024usize;
        let mut mft = vec![0u8; rec * 4];
        mft[0..4].copy_from_slice(b"FILE"); // record 0
        mft[2 * rec..2 * rec + 4].copy_from_slice(b"BAAD"); // record 2 (corrupt)
                                                            // record 1 and 3 are zeroed (no signature)
        let offsets = carve_file_records(&mft, rec);
        assert_eq!(offsets, vec![0, 2 * rec]);
    }
}
