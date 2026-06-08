//! # ntfs-core
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
//! Built incrementally under strict TDD. Implemented:
//! - [`boot::BootSector`] — the Volume Boot Record (BPB / extended BPB).
//! - [`record::MftRecordHeader`] + [`record::apply_fixup`] — FILE records and
//!   the update-sequence-array fixup.
//! - [`attribute::parse_attributes`] — resident and non-resident attributes.
//! - [`standard_information`] / [`file_name`] — the two timestamp sets.
//! - [`runlist::decode`] + [`data::read_attribute_value`] — data runs.
//! - [`index`] — directory `$INDEX_ROOT` / INDX buffers.
//! - [`attribute_list`] — fragmented-file extension records.
//! - [`compress::decompress`] — LZNT1.
//! - [`fs::NtfsFs`] — path resolution and file read over any `Read + Seek`.
//! - [`source::OffsetReader`] — open a partition inside a whole-disk image.
//! - [`forensic`] — Tier-2: timestomp, ADS, slack, deleted-record carving.
//!
//! Hardened against crafted input and exercised by `cargo-fuzz`
//! (see `fuzz/`); the boot parser is cross-validated against The Sleuth Kit on
//! a real disk image (see `tests/real_image.rs`).

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
pub mod source;
pub mod standard_information;
pub mod time;
pub mod usn;

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
pub use source::OffsetReader;
pub use standard_information::StandardInformation;
pub use time::Filetime;
pub use usn::{parse_usn_record_v2, FileAttributes, UsnReason, UsnRecord};
