//! # ntfs-forensic
//!
//! A forensic-grade, from-scratch NTFS reader. It parses NTFS structures
//! directly from any `Read + Seek` source (a raw image, an EWF/VMDK-backed
//! `DataSource`, or an in-memory buffer) and surfaces the artifacts a forensic
//! examiner needs — including deleted records, slack, and anti-forensic
//! indicators that a "clean" filesystem reader is designed to hide.
//!
//! This is a clean, spec-first implementation (no third-party NTFS parsing
//! dependency). Its output is cross-validated against The Sleuth Kit and the
//! `ntfs` / `mft` crates on real disk images.
//!
//! ## Status
//!
//! Built incrementally under strict TDD. Currently implemented:
//! - [`boot::BootSector`] — the Volume Boot Record (BPB / extended BPB).

#![forbid(unsafe_code)]

pub mod attribute;
pub mod attribute_list;
pub mod boot;
pub mod compress;
pub mod data;
pub mod error;
pub mod file_name;
pub mod fs;
pub mod index;
pub mod record;
pub mod runlist;
pub mod standard_information;
pub mod time;

pub use attribute::{parse_attributes, Attribute, AttributeBody};
pub use attribute_list::{parse as parse_attribute_list, AttributeListEntry};
pub use boot::BootSector;
pub use compress::decompress;
pub use data::{read_attribute_value, read_runs};
pub use error::{NtfsError, Result};
pub use file_name::{FileName, FileReference};
pub use fs::NtfsFs;
pub use index::{parse_entries, parse_index_buffer, IndexEntry, IndexRoot};
pub use record::{apply_fixup, MftRecordHeader};
pub use runlist::{decode as decode_runlist, Run};
pub use standard_information::StandardInformation;
pub use time::Filetime;
