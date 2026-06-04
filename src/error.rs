//! Crate-wide error type.

/// Errors produced while parsing NTFS structures.
#[derive(Debug, thiserror::Error)]
pub enum NtfsError {
    /// The input slice was shorter than the structure requires.
    #[error("input too short for {what}: need {need} bytes, got {got}")]
    TooShort {
        what: &'static str,
        need: usize,
        got: usize,
    },

    /// The OEM ID at offset 3 was not `b"NTFS    "`.
    #[error("not an NTFS volume: OEM ID is {0:x?}, expected \"NTFS    \"")]
    BadOemId([u8; 8]),

    /// Bytes-per-sector is not a power of two in the range 256..=4096.
    #[error("invalid bytes-per-sector: {0} (must be a power of two in 256..=4096)")]
    BadBytesPerSector(u16),

    /// Sectors-per-cluster is zero or not a power of two.
    #[error("invalid sectors-per-cluster encoding: {0:#04x}")]
    BadSectorsPerCluster(u8),

    /// The clusters-per-file-record-segment byte encodes an out-of-range size.
    #[error("invalid MFT record size encoding: byte {0:#04x}")]
    BadRecordSize(u8),

    /// The clusters-per-index-buffer byte encodes an out-of-range size.
    #[error("invalid index record size encoding: byte {0:#04x}")]
    BadIndexRecordSize(u8),

    /// An underlying I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, NtfsError>;
