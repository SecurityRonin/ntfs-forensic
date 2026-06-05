//! Data-run (runlist) decoding.
//!
//! A non-resident attribute stores its content in clusters described by a
//! *runlist*: a sequence of variable-length runs. Each run begins with a header
//! byte whose low nibble is the byte-count of the run length and whose high
//! nibble is the byte-count of the signed LCN delta. A run with a zero offset
//! size is *sparse* (a hole — implicitly zero). A zero header byte ends the
//! list.
//!
//! Every field width and span is validated, the running LCN is accumulated with
//! checked arithmetic, and the run count is capped — a crafted runlist can
//! never overflow, loop forever, or address a negative cluster.

use crate::error::{NtfsError, Result};

/// One data run: a contiguous span of clusters, or a sparse hole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Run {
    /// Length of the run, in clusters.
    pub length: u64,
    /// Starting logical cluster number, or `None` for a sparse run.
    pub lcn: Option<u64>,
}

/// Upper bound on runs in a single list — a belt-and-suspenders loop cap.
const MAX_RUNS: usize = 1 << 20;

/// Decode a runlist into its runs.
///
/// # Errors
///
/// [`NtfsError::BadRunlist`] for an invalid field width, a truncated run, a
/// zero-length run, or an LCN that overflows or goes negative.
pub fn decode(bytes: &[u8]) -> Result<Vec<Run>> {
    let _ = (bytes, MAX_RUNS);
    todo!("runlist decode — GREEN step")
}

/// Total length of all runs, in clusters (checked).
///
/// # Errors
///
/// [`NtfsError::BadRunlist`] if the lengths overflow `u64`.
pub fn total_clusters(runs: &[Run]) -> Result<u64> {
    let _ = runs;
    todo!("runlist total — GREEN step")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_single_run() {
        // 0x21: 1 length byte, 2 offset bytes. length=8, offset=0x0100=256.
        let runs = decode(&[0x21, 0x08, 0x00, 0x01, 0x00]).unwrap();
        assert_eq!(runs, vec![Run { length: 8, lcn: Some(256) }]);
    }

    #[test]
    fn decodes_multiple_runs_with_delta() {
        // run1: len 4 @ lcn 256; run2: len 4, delta +256 ⇒ lcn 512.
        let bytes = [0x21, 0x04, 0x00, 0x01, 0x21, 0x04, 0x00, 0x01, 0x00];
        let runs = decode(&bytes).unwrap();
        assert_eq!(
            runs,
            vec![
                Run { length: 4, lcn: Some(256) },
                Run { length: 4, lcn: Some(512) },
            ]
        );
    }

    #[test]
    fn decodes_sparse_run() {
        // 0x01: 1 length byte, 0 offset bytes ⇒ sparse.
        let runs = decode(&[0x01, 0x05, 0x00]).unwrap();
        assert_eq!(runs, vec![Run { length: 5, lcn: None }]);
    }

    #[test]
    fn decodes_negative_delta() {
        // run1: len 4 @ lcn 512; run2: len 4, delta -2 (0xFE) ⇒ lcn 510.
        let bytes = [0x21, 0x04, 0x00, 0x02, 0x11, 0x04, 0xFE, 0x00];
        let runs = decode(&bytes).unwrap();
        assert_eq!(runs[1].lcn, Some(510));
    }

    #[test]
    fn sparse_run_does_not_shift_following_lcn() {
        // real @ lcn 256, then a sparse hole, then real with delta +1 ⇒ lcn 257.
        let bytes = [
            0x21, 0x04, 0x00, 0x01, // lcn 256, len 4
            0x01, 0x02, // sparse, len 2 (no offset)
            0x11, 0x04, 0x01, // delta +1 ⇒ lcn 257
            0x00,
        ];
        let runs = decode(&bytes).unwrap();
        assert_eq!(runs[0].lcn, Some(256));
        assert_eq!(runs[1].lcn, None);
        assert_eq!(runs[2].lcn, Some(257));
    }

    #[test]
    fn zero_header_ends_list() {
        assert!(decode(&[0x00]).unwrap().is_empty());
        assert!(decode(&[]).unwrap().is_empty());
    }

    #[test]
    fn total_clusters_sums_lengths() {
        let runs = vec![
            Run { length: 4, lcn: Some(0) },
            Run { length: 6, lcn: None },
        ];
        assert_eq!(total_clusters(&runs).unwrap(), 10);
    }

    // ── Hardening ─────────────────────────────────────────────────────────────

    #[test]
    fn rejects_length_field_too_large() {
        // low nibble 9 ⇒ 9-byte length, impossible for u64.
        assert!(matches!(decode(&[0x09]), Err(NtfsError::BadRunlist(_))));
    }

    #[test]
    fn rejects_truncated_run() {
        // header wants 1 length + 2 offset bytes, but only the length is present.
        assert!(matches!(
            decode(&[0x21, 0x08]),
            Err(NtfsError::BadRunlist(_))
        ));
    }

    #[test]
    fn rejects_zero_length_run() {
        assert!(matches!(
            decode(&[0x21, 0x00, 0x00, 0x01]),
            Err(NtfsError::BadRunlist(_))
        ));
    }

    #[test]
    fn rejects_negative_lcn() {
        // First (absolute) run with a negative offset is invalid.
        assert!(matches!(
            decode(&[0x11, 0x04, 0xFF]), // delta -1 from 0 ⇒ -1
            Err(NtfsError::BadRunlist(_))
        ));
    }
}
