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

    /// An MFT record's signature was neither `FILE` nor `BAAD`.
    #[error("bad MFT record signature: {0:x?} (expected \"FILE\" or \"BAAD\")")]
    BadRecordSignature([u8; 4]),

    /// An update-sequence fixup did not match the Update Sequence Number — the
    /// record was torn across a sector boundary, or has been tampered with.
    #[error("fixup mismatch in sector {sector}: expected USN {expected:#06x}, found {found:#06x}")]
    FixupMismatch {
        sector: usize,
        expected: u16,
        found: u16,
    },

    /// The update sequence array is malformed (offset/count out of bounds).
    #[error("malformed update sequence array: {0}")]
    BadUpdateSequence(&'static str),

    /// An attribute is corrupt or would read out of bounds — rejected rather
    /// than trusted (defends against crafted records).
    #[error("corrupt attribute at offset {offset}: {detail}")]
    BadAttribute { offset: usize, detail: &'static str },

    /// A data runlist is malformed (bad field size, truncated, or overflowing).
    #[error("malformed runlist: {0}")]
    BadRunlist(&'static str),

    /// A directory index node or entry is malformed.
    #[error("malformed index: {0}")]
    BadIndex(&'static str),

    /// A path component was not found.
    #[error("path not found: {0}")]
    NotFound(String),

    /// A path component that should be a directory is not one.
    #[error("not a directory: {0}")]
    NotADirectory(String),

    /// A structure declared a size that would require an unreasonable
    /// allocation — refused rather than attempted (defends against crafted
    /// sizes / allocation bombs).
    #[error("refusing to allocate {bytes} bytes")]
    TooLarge { bytes: u64 },

    /// An underlying I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, NtfsError>;
