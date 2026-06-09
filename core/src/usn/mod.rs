//! USN Journal record parsing.
//!
//! Decodes `USN_RECORD_V2`/`V3`/`V4` structures from raw `$UsnJrnl:$J` data.
//! The `$UsnJrnl` change journal is an NTFS metadata file, so its record format
//! is part of the NTFS reader surface — higher-level extraction (reading the
//! journal off a live volume, carving records from unallocated space) lives in
//! the analyzer/application layers built on top of this.

mod attributes;
mod reason;
mod reader;
mod record;

pub use attributes::FileAttributes;
pub use reason::UsnReason;
pub use record::{parse_usn_journal, parse_usn_record_v2, parse_usn_record_v3, UsnRecord};
