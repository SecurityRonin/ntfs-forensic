//! Forensic Tier-2: the artifacts a "clean" reader hides — timestomping
//! indicators, alternate data streams, MFT-record slack, and deleted records.
//!
//! These are pure analyses over already-parsed structures, so they are exact
//! and side-effect free.

use forensicnomicon::ntfs::{attr_types, SIGNATURE_BAAD, SIGNATURE_FILE};

use ntfs_core::attribute::Attribute;
use ntfs_core::file_name::FileName;
use ntfs_core::record::MftRecordHeader;
use ntfs_core::standard_information::StandardInformation;
use ntfs_core::time::Filetime;

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

// ── Tier-2 anomaly auditor (findings → forensicnomicon::report) ──────────────
//
// The primitives above answer "what does this record show?"; the auditor grades
// those observations into severity-ranked findings on the shared
// `forensicnomicon::report` model, so an NTFS volume's anomalies aggregate
// uniformly with the partition/container layers. Each anomaly is an
// *observation* ("consistent with …"); the examiner draws the conclusions.

/// The canonical 5-level severity scale, shared across every `SecurityRonin`
/// analyzer via [`forensicnomicon::report`].
pub use forensicnomicon::report::Severity;

/// Classification of an NTFS forensic anomaly. Each variant carries the MFT
/// record it was observed in plus the evidence to reproduce it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnomalyKind {
    /// `$STANDARD_INFORMATION` timestamps show forgery tells relative to the
    /// harder-to-forge `$FILE_NAME` times (or land on whole seconds).
    Timestomp {
        /// MFT record number.
        record: u64,
        /// The specific tell that fired.
        signal: &'static str,
    },
    /// A named `$DATA` attribute — an alternate data stream, a common place to
    /// carry hidden payloads (also used benignly, e.g. `Zone.Identifier`).
    AlternateDataStream {
        /// MFT record number.
        record: u64,
        /// The stream name.
        stream: String,
    },
    /// The MFT record is not in use — a recoverable deleted file.
    DeletedRecord {
        /// MFT record number.
        record: u64,
    },
    /// Non-zero residue in the record's slack (past `used_size`).
    RecordSlackResidue {
        /// MFT record number.
        record: u64,
        /// Count of non-zero bytes in the slack.
        residue_len: usize,
    },
}

impl AnomalyKind {
    /// The MFT record this anomaly was observed in.
    #[must_use]
    pub fn record(&self) -> u64 {
        match self {
            AnomalyKind::Timestomp { record, .. }
            | AnomalyKind::AlternateDataStream { record, .. }
            | AnomalyKind::DeletedRecord { record }
            | AnomalyKind::RecordSlackResidue { record, .. } => *record,
        }
    }

    /// Severity — the single source of truth for this kind.
    #[must_use]
    pub fn severity(&self) -> Severity {
        match self {
            AnomalyKind::Timestomp { .. } => Severity::High,
            AnomalyKind::AlternateDataStream { .. } | AnomalyKind::RecordSlackResidue { .. } => {
                Severity::Low
            }
            AnomalyKind::DeletedRecord { .. } => Severity::Info,
        }
    }

    /// Stable machine-readable code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            AnomalyKind::Timestomp { .. } => "NTFS-TIMESTOMP",
            AnomalyKind::AlternateDataStream { .. } => "NTFS-ADS",
            AnomalyKind::DeletedRecord { .. } => "NTFS-DELETED-RECORD",
            AnomalyKind::RecordSlackResidue { .. } => "NTFS-SLACK-RESIDUE",
        }
    }

    /// Human-readable, "consistent with" note.
    #[must_use]
    pub fn note(&self) -> String {
        match self {
            AnomalyKind::Timestomp { record, signal } => format!(
                "record {record}: $STANDARD_INFORMATION timestamps consistent with tampering ({signal})"
            ),
            AnomalyKind::AlternateDataStream { record, stream } => format!(
                "record {record}: named $DATA stream `{stream}` — consistent with data carried in an alternate data stream"
            ),
            AnomalyKind::DeletedRecord { record } => {
                format!("record {record}: MFT entry not in use — a recoverable deleted file")
            }
            AnomalyKind::RecordSlackResidue { record, residue_len } => format!(
                "record {record}: {residue_len} non-zero byte(s) in MFT-record slack — consistent with residue from an overwritten resident attribute"
            ),
        }
    }
}

/// An NTFS forensic anomaly: an observation graded by severity, with a stable
/// code and note derived from its [`AnomalyKind`] so they cannot drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anomaly {
    /// Severity, derived from `kind`.
    pub severity: Severity,
    /// Stable machine-readable code, derived from `kind`.
    pub code: &'static str,
    /// The classified anomaly with its evidence.
    pub kind: AnomalyKind,
    /// Human-readable note, derived from `kind`.
    pub note: String,
}

impl Anomaly {
    /// Build an [`Anomaly`], deriving severity/code/note from `kind`.
    #[must_use]
    pub fn new(kind: AnomalyKind) -> Self {
        Anomaly {
            severity: kind.severity(),
            code: kind.code(),
            note: kind.note(),
            kind,
        }
    }
}

impl forensicnomicon::report::Observation for Anomaly {
    fn severity(&self) -> Option<Severity> {
        Some(self.severity)
    }
    fn code(&self) -> &'static str {
        self.code
    }
    fn note(&self) -> String {
        self.note.clone()
    }
    fn evidence(&self) -> Vec<forensicnomicon::report::Evidence> {
        let record = self.kind.record();
        vec![forensicnomicon::report::Evidence {
            field: "mft record".to_string(),
            value: record.to_string(),
            location: Some(forensicnomicon::report::Location::RecordId(record)),
        }]
    }
}

/// Audit a parsed MFT record's components for anomalies. The caller supplies the
/// already-parsed pieces, so this is exact and side-effect free; see
/// [`audit_record`] for the convenience that parses raw bytes.
#[must_use]
pub fn audit_components(
    record_number: u64,
    header: &MftRecordHeader,
    record: &[u8],
    attributes: &[Attribute],
    standard_information: Option<&StandardInformation>,
    primary_file_name: Option<&FileName>,
) -> Vec<Anomaly> {
    let mut out = Vec::new();

    if is_deleted(header) {
        out.push(Anomaly::new(AnomalyKind::DeletedRecord {
            record: record_number,
        }));
    }

    let residue = record_slack(record, header)
        .iter()
        .filter(|&&b| b != 0)
        .count();
    if residue > 0 {
        out.push(Anomaly::new(AnomalyKind::RecordSlackResidue {
            record: record_number,
            residue_len: residue,
        }));
    }

    for ads in alternate_data_streams(attributes) {
        out.push(Anomaly::new(AnomalyKind::AlternateDataStream {
            record: record_number,
            stream: ads.name.clone().unwrap_or_default(),
        }));
    }

    if let (Some(si), Some(fname)) = (standard_information, primary_file_name) {
        let ind = detect_timestomp(si, fname);
        if ind.si_created_before_fn {
            out.push(Anomaly::new(AnomalyKind::Timestomp {
                record: record_number,
                signal: "$SI created before $FN",
            }));
        }
        if ind.si_whole_second {
            out.push(Anomaly::new(AnomalyKind::Timestomp {
                record: record_number,
                signal: "$SI timestamp on a whole second",
            }));
        }
    }

    out
}

/// Audit a single raw MFT record's bytes: parse the header and attributes,
/// extract `$STANDARD_INFORMATION`/`$FILE_NAME`, and delegate to
/// [`audit_components`]. A record whose header does not parse yields no
/// anomalies (structural corruption is surfaced by the reader/carver).
#[must_use]
pub fn audit_record(record: &[u8]) -> Vec<Anomaly> {
    let Ok(header) = MftRecordHeader::parse(record) else {
        return Vec::new();
    };
    let attributes =
        ntfs_core::attribute::parse_attributes(record, header.first_attribute_offset as usize)
            .unwrap_or_default();

    let resident = |type_code: u32| {
        attributes
            .iter()
            .find(|a| a.type_code == type_code)
            .and_then(|a| a.resident_content(record))
    };
    let si =
        resident(attr_types::STANDARD_INFORMATION).and_then(|c| StandardInformation::parse(c).ok());
    let fname = resident(attr_types::FILE_NAME).and_then(|c| FileName::parse(c).ok());

    audit_components(
        u64::from(header.record_number),
        &header,
        record,
        &attributes,
        si.as_ref(),
        fname.as_ref(),
    )
}

// ── Volume-level metadata-artifact auditor ($MFTMirr, $LogFile) ───────────────
//
// The record auditor above grades per-MFT-record anomalies; these grade
// volume-scoped artifacts whose parsers live in `ntfs_core` (`mftmirr`,
// `logfile`). Each is an observation — the examiner draws the conclusions.

/// Names of the four system records mirrored in `$MFTMirr`.
const MIRROR_NAMES: [&str; 4] = ["$MFT", "$MFTMirr", "$LogFile", "$Volume"];

/// Render mismatched mirror-entry indices as a human-readable system-file list.
fn mismatched_names(entries: &[usize]) -> String {
    entries
        .iter()
        .map(|&i| MIRROR_NAMES.get(i).copied().unwrap_or("?"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// A volume-level NTFS metadata-artifact anomaly — scoped to a metadata file
/// rather than a single MFT record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactAnomaly {
    /// One or more of the first four system records in `$MFTMirr` differ from
    /// the live `$MFT` — consistent with MFT tampering or corruption.
    MftMirrorMismatch {
        /// Indices (`0..4`) of the mirrored system records that differ.
        mismatched_entries: Vec<usize>,
    },
    /// `$LogFile` shows page gaps or restart-area anomalies — consistent with
    /// the NTFS transaction journal having been cleared.
    LogFileCleared,
}

impl ArtifactAnomaly {
    /// Severity — the single source of truth for this kind.
    #[must_use]
    pub fn severity(&self) -> Severity {
        match self {
            ArtifactAnomaly::MftMirrorMismatch { .. } => Severity::High,
            ArtifactAnomaly::LogFileCleared => Severity::Medium,
        }
    }

    /// Stable machine-readable code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            ArtifactAnomaly::MftMirrorMismatch { .. } => "NTFS-MFTMIRR-MISMATCH",
            ArtifactAnomaly::LogFileCleared => "NTFS-LOGFILE-CLEARED",
        }
    }

    /// Human-readable, "consistent with" note.
    #[must_use]
    pub fn note(&self) -> String {
        match self {
            ArtifactAnomaly::MftMirrorMismatch { mismatched_entries } => format!(
                "$MFTMirr differs from $MFT for {} — consistent with MFT tampering or corruption",
                mismatched_names(mismatched_entries)
            ),
            ArtifactAnomaly::LogFileCleared => "$LogFile shows gaps/restart-area anomalies — consistent with the transaction journal having been cleared".to_string(),
        }
    }
}

impl forensicnomicon::report::Observation for ArtifactAnomaly {
    fn severity(&self) -> Option<Severity> {
        Some(self.severity())
    }
    fn code(&self) -> &'static str {
        self.code()
    }
    fn note(&self) -> String {
        self.note()
    }
    fn evidence(&self) -> Vec<forensicnomicon::report::Evidence> {
        use forensicnomicon::report::{Evidence, Location};
        match self {
            ArtifactAnomaly::MftMirrorMismatch { mismatched_entries } => vec![Evidence {
                field: "mismatched system records".to_string(),
                value: mismatched_names(mismatched_entries),
                location: Some(Location::Field("$MFTMirr".to_string())),
            }],
            ArtifactAnomaly::LogFileCleared => vec![Evidence {
                field: "$LogFile".to_string(),
                value: "gaps/restart-area anomalies consistent with journal clearing".to_string(),
                location: Some(Location::Field("$LogFile".to_string())),
            }],
        }
    }
}

/// Audit the `$MFTMirr` against the live `$MFT`, flagging any of the first four
/// system records that differ. Malformed input yields no findings.
#[must_use]
pub fn audit_mft_mirror(mft_data: &[u8], mftmirr_data: &[u8]) -> Vec<ArtifactAnomaly> {
    match ntfs_core::mftmirr::compare_mft_mirror(mft_data, mftmirr_data) {
        Ok(cmp) if !cmp.is_consistent => {
            let mismatched_entries = cmp
                .matches
                .iter()
                .enumerate()
                .filter_map(|(i, &m)| (!m).then_some(i))
                .collect();
            vec![ArtifactAnomaly::MftMirrorMismatch { mismatched_entries }]
        }
        _ => Vec::new(),
    }
}

/// Audit a raw `$LogFile` for journal-clearing indicators. Malformed input
/// yields no findings.
#[must_use]
pub fn audit_logfile(logfile_data: &[u8]) -> Vec<ArtifactAnomaly> {
    match ntfs_core::logfile::parse_logfile(logfile_data) {
        Ok(summary) if ntfs_core::logfile::detect_journal_clearing(&summary) => {
            vec![ArtifactAnomaly::LogFileCleared]
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ntfs_core::attribute::AttributeBody;

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
        use ntfs_core::file_name::FileReference;
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

    // ── Anomaly auditor (Tier-2 findings → forensicnomicon::report) ──────────

    fn hdr(flags: u16, used_size: u32, record_number: u32) -> MftRecordHeader {
        MftRecordHeader {
            signature: *b"FILE",
            usa_offset: 0x30,
            usa_count: 3,
            lsn: 0,
            sequence_number: 1,
            hard_link_count: 1,
            first_attribute_offset: 0x38,
            flags,
            used_size,
            allocated_size: 1024,
            base_record: 0,
            next_attr_id: 1,
            record_number,
        }
    }

    #[test]
    fn audit_flags_deleted_record() {
        let header = hdr(0x00, 0x100, 42); // not in use
        let an = audit_components(42, &header, &vec![0u8; 1024], &[], None, None);
        assert!(an
            .iter()
            .any(|a| matches!(a.kind, AnomalyKind::DeletedRecord { record: 42 })));
    }

    #[test]
    fn audit_flags_timestomp() {
        let header = hdr(0x01, 0x100, 7);
        let si = si(1_000, 1_000, 1_000, 1_000);
        let fnm = fname(2_000_000_000);
        let an = audit_components(7, &header, &vec![0u8; 1024], &[], Some(&si), Some(&fnm));
        assert!(an
            .iter()
            .any(|a| matches!(a.kind, AnomalyKind::Timestomp { .. })));
    }

    #[test]
    fn audit_flags_alternate_data_stream() {
        let header = hdr(0x01, 0x100, 9);
        let attrs = [data_attr(None), data_attr(Some("evil"))];
        let an = audit_components(9, &header, &vec![0u8; 1024], &attrs, None, None);
        assert!(an.iter().any(
            |a| matches!(&a.kind, AnomalyKind::AlternateDataStream { stream, .. } if stream == "evil")
        ));
    }

    #[test]
    fn audit_flags_slack_residue() {
        let header = hdr(0x01, 600, 3);
        let mut record = vec![0u8; 1024];
        record[700] = 0xAA;
        let an = audit_components(3, &header, &record, &[], None, None);
        assert!(an
            .iter()
            .any(|a| matches!(a.kind, AnomalyKind::RecordSlackResidue { .. })));
    }

    #[test]
    fn audit_clean_record_has_no_anomalies() {
        let header = hdr(0x01, 1024, 1); // in use, no slack, no attrs
        let an = audit_components(1, &header, &vec![0u8; 1024], &[], None, None);
        assert!(an.is_empty(), "clean record: {an:?}");
    }

    #[test]
    fn audit_record_on_non_record_bytes_is_empty_not_panic() {
        // A header that does not parse yields no anomalies (no panic).
        assert!(audit_record(&[0u8; 16]).is_empty());
        assert!(audit_record(b"not even a FILE record").is_empty());
    }

    // ── Builders for an audit_record() end-to-end test (parse → extract → audit) ─

    /// A resident attribute with no name: 24-byte header, content at 0x18.
    fn resident_attr(type_code: u32, content: &[u8]) -> Vec<u8> {
        let content_offset = 0x18usize;
        let length = (content_offset + content.len() + 7) & !7;
        let mut a = vec![0u8; length];
        a[0..4].copy_from_slice(&type_code.to_le_bytes()); // TYPE
        a[4..8].copy_from_slice(&(length as u32).to_le_bytes()); // LENGTH
        a[8] = 0; // resident
        a[0x0A..0x0C].copy_from_slice(&(content_offset as u16).to_le_bytes()); // NAME_OFFSET
        a[0x0E..0x10].copy_from_slice(&1u16.to_le_bytes()); // ATTRIBUTE_ID
        a[0x10..0x14].copy_from_slice(&(content.len() as u32).to_le_bytes()); // content length
        a[0x14..0x16].copy_from_slice(&(content_offset as u16).to_le_bytes()); // content offset
        a[content_offset..content_offset + content.len()].copy_from_slice(content);
        a
    }

    fn si_content(created: u64) -> Vec<u8> {
        let mut c = vec![0u8; 0x30];
        c[0x00..0x08].copy_from_slice(&created.to_le_bytes()); // $SI created
        c
    }

    fn fn_content(created: u64) -> Vec<u8> {
        let mut c = vec![0u8; 0x44]; // FN_MIN (0x42) + one UTF-16 char
        c[0x00..0x08].copy_from_slice(&5u64.to_le_bytes()); // parent ref
        c[0x08..0x10].copy_from_slice(&created.to_le_bytes()); // $FN created
        c[0x40] = 1; // name length (chars)
        c[0x41] = 1; // namespace
        c[0x42..0x44].copy_from_slice(&u16::from(b'f').to_le_bytes());
        c
    }

    #[test]
    fn audit_record_parses_and_flags_timestomp_end_to_end() {
        // Exercises the full audit_record() path: header parse, attribute parse,
        // $SI/$FN resident-content extraction, then timestomp detection.
        // $SI created (1000) far predates $FN created (2e9) → NTFS-TIMESTOMP.
        let si = resident_attr(attr_types::STANDARD_INFORMATION, &si_content(1_000));
        let fnm = resident_attr(attr_types::FILE_NAME, &fn_content(2_000_000_000));
        let first_attr = 0x30usize;

        let mut rec = vec![0u8; 1024];
        rec[0..4].copy_from_slice(b"FILE");
        rec[0x04..0x06].copy_from_slice(&0x30u16.to_le_bytes()); // usa_offset
        rec[0x06..0x08].copy_from_slice(&3u16.to_le_bytes()); // usa_count
        rec[0x14..0x16].copy_from_slice(&(first_attr as u16).to_le_bytes()); // first attr
        rec[0x16..0x18].copy_from_slice(&0x01u16.to_le_bytes()); // flags = in use
        rec[0x1C..0x20].copy_from_slice(&1024u32.to_le_bytes()); // allocated_size
        rec[0x2C..0x30].copy_from_slice(&7u32.to_le_bytes()); // record_number

        let mut pos = first_attr;
        rec[pos..pos + si.len()].copy_from_slice(&si);
        pos += si.len();
        rec[pos..pos + fnm.len()].copy_from_slice(&fnm);
        pos += fnm.len();
        rec[pos..pos + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // end marker
        rec[0x18..0x1C].copy_from_slice(&((pos + 4) as u32).to_le_bytes()); // used_size

        let anomalies = audit_record(&rec);
        let timestomped =
            anomalies.iter().any(|a| matches!(a.kind, AnomalyKind::Timestomp { record: 7, .. }));
        assert!(timestomped, "{anomalies:?}");
    }

    #[test]
    fn audit_components_flags_whole_second_timestomp() {
        // $SI times on whole seconds (no sub-second precision) → timestomp tell,
        // exercising the si_whole_second branch of audit_components.
        let header = hdr(0x01, 1024, 4);
        let whole = 5 * 10_000_000; // 5s in FILETIME ticks
        let si = si(whole, whole, whole, whole);
        let fnm = fname(whole);
        let an = audit_components(4, &header, &vec![0u8; 1024], &[], Some(&si), Some(&fnm));
        assert!(an
            .iter()
            .any(|a| matches!(&a.kind, AnomalyKind::Timestomp { signal, .. } if signal.contains("whole second"))));
    }

    #[test]
    fn every_anomaly_kind_carries_its_record_as_evidence() {
        use forensicnomicon::report::{Location, Observation};
        // Drives AnomalyKind::record() for every variant via evidence().
        let kinds = [
            AnomalyKind::Timestomp { record: 1, signal: "x" },
            AnomalyKind::AlternateDataStream { record: 2, stream: "s".to_string() },
            AnomalyKind::DeletedRecord { record: 3 },
            AnomalyKind::RecordSlackResidue { record: 4, residue_len: 5 },
        ];
        for (i, k) in kinds.into_iter().enumerate() {
            let ev = Anomaly::new(k).evidence();
            let rec = (i + 1) as u64;
            assert!(ev.iter().any(|e| matches!(e.location, Some(Location::RecordId(r)) if r == rec)));
        }
    }

    #[test]
    fn anomaly_converts_to_canonical_finding() {
        use forensicnomicon::report::{Observation, Source};
        let a = Anomaly::new(AnomalyKind::Timestomp {
            record: 5,
            signal: "test",
        });
        let f = a.to_finding(Source {
            analyzer: "ntfs-forensic".to_string(),
            scope: "NTFS".to_string(),
            version: None,
        });
        assert!(f.code.starts_with("NTFS-"));
        assert!(f.severity.is_some());
    }

    // ── Volume-level artifact auditor ─────────────────────────────────────

    fn rstr_page() -> Vec<u8> {
        let mut p = vec![0u8; 0x1000];
        p[0..4].copy_from_slice(b"RSTR");
        p[0x10..0x12].copy_from_slice(&1u16.to_le_bytes());
        p[0x20..0x24].copy_from_slice(&4096u32.to_le_bytes());
        p[0x24..0x28].copy_from_slice(&4096u32.to_le_bytes());
        p
    }

    fn rcrd_page(lsn: u64) -> Vec<u8> {
        let mut p = vec![0u8; 0x1000];
        p[0..4].copy_from_slice(b"RCRD");
        p[0x18..0x20].copy_from_slice(&lsn.to_le_bytes());
        p
    }

    #[test]
    fn audit_mft_mirror_consistent_yields_no_findings() {
        let mft = vec![0xAAu8; 1024 * 4];
        assert!(audit_mft_mirror(&mft, &mft).is_empty());
    }

    #[test]
    fn audit_mft_mirror_flags_each_differing_system_record() {
        let mft = vec![0xAAu8; 1024 * 4];
        let mut mirr = mft.clone();
        mirr[0] = 0xBB; // record 0 ($MFT) differs
        mirr[1024 * 2] = 0xCC; // record 2 ($LogFile) differs
        let anomalies = audit_mft_mirror(&mft, &mirr);
        assert_eq!(anomalies.len(), 1);
        assert_eq!(
            anomalies[0],
            ArtifactAnomaly::MftMirrorMismatch {
                mismatched_entries: vec![0, 2]
            }
        );
        assert_eq!(anomalies[0].severity(), Severity::High);
        assert_eq!(anomalies[0].code(), "NTFS-MFTMIRR-MISMATCH");
        let note = anomalies[0].note();
        assert!(note.contains("$MFT") && note.contains("$LogFile"));
    }

    #[test]
    fn audit_logfile_flags_cleared_journal() {
        // Empty $LogFile → no restart areas → treated as cleared.
        let anomalies = audit_logfile(&[]);
        assert_eq!(anomalies.len(), 1);
        assert_eq!(anomalies[0], ArtifactAnomaly::LogFileCleared);
        assert_eq!(anomalies[0].severity(), Severity::Medium);
        assert_eq!(anomalies[0].code(), "NTFS-LOGFILE-CLEARED");
        assert!(anomalies[0].note().contains("$LogFile"));
    }

    #[test]
    fn audit_logfile_normal_journal_yields_no_findings() {
        // Two restart areas + a record page, no gaps → not cleared.
        let mut data = Vec::new();
        data.extend_from_slice(&rstr_page());
        data.extend_from_slice(&rstr_page());
        data.extend_from_slice(&rcrd_page(3000));
        assert!(audit_logfile(&data).is_empty());
    }

    #[test]
    fn artifact_anomalies_convert_to_canonical_findings() {
        use forensicnomicon::report::{Evidence, Observation, Source};
        let src = || Source {
            analyzer: "ntfs-forensic".to_string(),
            scope: "volume".to_string(),
            version: None,
        };

        let mirror = ArtifactAnomaly::MftMirrorMismatch {
            mismatched_entries: vec![1],
        };
        let f = mirror.to_finding(src());
        assert_eq!(f.code, "NTFS-MFTMIRR-MISMATCH");
        assert_eq!(f.severity, Some(Severity::High));
        let ev: &Evidence = &f.evidence[0];
        assert_eq!(ev.value, "$MFTMirr");

        let cleared = ArtifactAnomaly::LogFileCleared;
        let f = cleared.to_finding(src());
        assert_eq!(f.code, "NTFS-LOGFILE-CLEARED");
        assert!(!f.evidence.is_empty());
    }

    #[test]
    fn mismatched_names_handles_out_of_range_index() {
        // The field is public, so guard the name lookup defensively.
        assert_eq!(mismatched_names(&[99]), "?");
    }
}
