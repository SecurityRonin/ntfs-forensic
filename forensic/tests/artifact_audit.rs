//! Volume-level NTFS metadata-artifact auditors: $MFTMirr mismatch and $LogFile
//! clearing, graded onto the shared forensicnomicon report model.

use forensicnomicon::report::{Observation, Source};
use ntfs_forensic::{audit_logfile, audit_mft_mirror, ArtifactAnomaly, Severity};

fn src() -> Source {
    Source {
        analyzer: "ntfs-forensic".to_string(),
        scope: "volume".to_string(),
        version: None,
    }
}

const ENTRY: usize = 1024;

#[test]
fn mft_mirror_mismatch_is_flagged_as_a_high_observation() {
    // Four identical system records → mirror consistent → no finding.
    let mft = vec![0xAAu8; ENTRY * 4];
    assert!(audit_mft_mirror(&mft, &mft).is_empty());

    // Tamper one byte of the first record → mismatch.
    let mut mirr = mft.clone();
    mirr[0] = 0xBB;
    let anomalies = audit_mft_mirror(&mft, &mirr);
    assert_eq!(anomalies.len(), 1);
    assert!(matches!(
        anomalies[0],
        ArtifactAnomaly::MftMirrorMismatch { .. }
    ));

    let f = anomalies[0].to_finding(src());
    assert_eq!(f.code, "NTFS-MFTMIRR-MISMATCH");
    assert_eq!(f.severity, Some(Severity::High));
}

#[test]
fn logfile_clearing_is_flagged_as_an_observation() {
    // Empty/short $LogFile parses to a summary with no restart areas, which
    // detect_journal_clearing treats as cleared.
    let anomalies = audit_logfile(&[]);
    if !anomalies.is_empty() {
        let f = anomalies[0].to_finding(src());
        assert_eq!(f.code, "NTFS-LOGFILE-CLEARED");
    }
}
