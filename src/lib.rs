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
pub mod boot;
pub mod error;
pub mod record;

pub use attribute::{parse_attributes, Attribute, AttributeBody};
pub use boot::BootSector;
pub use error::{NtfsError, Result};
pub use record::{apply_fixup, MftRecordHeader};
