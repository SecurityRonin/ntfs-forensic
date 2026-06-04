//! NTFS Volume Boot Record ($Boot / VBR).
//!
//! The first sector of an NTFS volume holds the BIOS Parameter Block (BPB) and
//! NTFS's extended BPB. It tells us the geometry needed to locate everything
//! else: sector/cluster size, the total volume size, and the cluster numbers of
//! `$MFT` and `$MFTMirr`.
//!
//! ## Layout (little-endian; offsets in hex)
//!
//! ```text
//! 0x03  u8[8]  OEM ID                 = "NTFS    "
//! 0x0B  u16    bytes per sector
//! 0x0D  u8     sectors per cluster
//! 0x28  u64    total sectors
//! 0x30  u64    $MFT  cluster number (LCN)
//! 0x38  u64    $MFTMirr cluster number (LCN)
//! 0x40  i8     clusters per file-record segment   (signed: <0 ⇒ 2^|v| bytes)
//! 0x44  i8     clusters per index buffer          (signed: same encoding)
//! 0x48  u64    volume serial number
//! ```

use crate::error::{NtfsError, Result};

/// Expected OEM identifier at offset 3.
const OEM_ID: &[u8; 8] = b"NTFS    ";

/// Highest offset we read (volume serial ends at 0x50); we require this many bytes.
const MIN_LEN: usize = 0x50;

/// Lower/upper sanity bounds for record and index buffer sizes (bytes).
const MIN_RECORD_SIZE: u64 = 256;
const MAX_RECORD_SIZE: u64 = 1 << 20; // 1 MiB — far above any real NTFS value

/// Parsed NTFS boot sector geometry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootSector {
    /// Bytes per logical sector (power of two, 256..=4096; typically 512).
    pub bytes_per_sector: u16,
    /// Logical sectors per cluster (power of two; typically 8).
    pub sectors_per_cluster: u8,
    /// Total number of sectors in the volume.
    pub total_sectors: u64,
    /// Cluster number (LCN) of the `$MFT`.
    pub mft_lcn: u64,
    /// Cluster number (LCN) of the `$MFTMirr`.
    pub mftmirr_lcn: u64,
    /// Size of one MFT file-record segment, in bytes (typically 1024).
    pub mft_record_size: u64,
    /// Size of one index buffer, in bytes (typically 4096).
    pub index_record_size: u64,
    /// 64-bit volume serial number.
    pub volume_serial: u64,
}

impl BootSector {
    /// Cluster size in bytes (`bytes_per_sector × sectors_per_cluster`).
    #[must_use]
    pub fn cluster_size(&self) -> u64 {
        u64::from(self.bytes_per_sector) * u64::from(self.sectors_per_cluster)
    }

    /// Absolute byte offset of the `$MFT` within the volume.
    #[must_use]
    pub fn mft_byte_offset(&self) -> u64 {
        self.mft_lcn.saturating_mul(self.cluster_size())
    }

    /// Absolute byte offset of the `$MFTMirr` within the volume.
    #[must_use]
    pub fn mftmirr_byte_offset(&self) -> u64 {
        self.mftmirr_lcn.saturating_mul(self.cluster_size())
    }

    /// Parse an NTFS boot sector from the start of a volume.
    ///
    /// # Errors
    ///
    /// Returns [`NtfsError::TooShort`] if `sector` is smaller than the BPB,
    /// [`NtfsError::BadOemId`] if it is not an NTFS volume, and the various
    /// `Bad*` variants for out-of-range geometry fields.
    pub fn parse(sector: &[u8]) -> Result<BootSector> {
        let _ = sector;
        todo!("VBR/$Boot parse — implemented in the GREEN step")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic 512-byte NTFS boot sector from field values.
    #[allow(clippy::too_many_arguments)]
    fn make_boot(
        bytes_per_sector: u16,
        sectors_per_cluster: u8,
        total_sectors: u64,
        mft_lcn: u64,
        mftmirr_lcn: u64,
        clusters_per_record: u8,
        clusters_per_index: u8,
        volume_serial: u64,
    ) -> [u8; 512] {
        let mut b = [0u8; 512];
        b[0..3].copy_from_slice(&[0xEB, 0x52, 0x90]); // jump
        b[3..11].copy_from_slice(b"NTFS    ");
        b[0x0B..0x0D].copy_from_slice(&bytes_per_sector.to_le_bytes());
        b[0x0D] = sectors_per_cluster;
        b[0x15] = 0xF8; // media descriptor
        b[0x28..0x30].copy_from_slice(&total_sectors.to_le_bytes());
        b[0x30..0x38].copy_from_slice(&mft_lcn.to_le_bytes());
        b[0x38..0x40].copy_from_slice(&mftmirr_lcn.to_le_bytes());
        b[0x40] = clusters_per_record;
        b[0x44] = clusters_per_index;
        b[0x48..0x50].copy_from_slice(&volume_serial.to_le_bytes());
        b[510] = 0x55;
        b[511] = 0xAA;
        b
    }

    #[test]
    fn parses_standard_boot_sector() {
        // 512 B/sector, 8 sectors/cluster ⇒ 4096-byte clusters.
        // clusters_per_record = 0xF6 (-10) ⇒ 2^10 = 1024-byte MFT records.
        // clusters_per_index  = 0x01       ⇒ 1 cluster = 4096-byte index buffers.
        let b = make_boot(512, 8, 0x0010_0000, 0x0004_0000, 0x02, 0xF6, 0x01, 0xDEAD_BEEF_CAFE_F00D);
        let bs = BootSector::parse(&b).expect("valid NTFS boot sector");
        assert_eq!(bs.bytes_per_sector, 512);
        assert_eq!(bs.sectors_per_cluster, 8);
        assert_eq!(bs.cluster_size(), 4096);
        assert_eq!(bs.total_sectors, 0x0010_0000);
        assert_eq!(bs.mft_lcn, 0x0004_0000);
        assert_eq!(bs.mftmirr_lcn, 0x02);
        assert_eq!(bs.mft_record_size, 1024);
        assert_eq!(bs.index_record_size, 4096);
        assert_eq!(bs.volume_serial, 0xDEAD_BEEF_CAFE_F00D);
        assert_eq!(bs.mft_byte_offset(), 0x0004_0000 * 4096);
        assert_eq!(bs.mftmirr_byte_offset(), 0x02 * 4096);
    }

    #[test]
    fn positive_clusters_per_record_multiplies_cluster_size() {
        // clusters_per_record = 1 (positive) ⇒ 1 × 4096 = 4096-byte records.
        let b = make_boot(512, 8, 1000, 100, 2, 0x01, 0x01, 0);
        let bs = BootSector::parse(&b).unwrap();
        assert_eq!(bs.mft_record_size, 4096);
    }

    #[test]
    fn rejects_non_ntfs_oem_id() {
        let mut b = make_boot(512, 8, 1000, 100, 2, 0xF6, 0x01, 0);
        b[3..11].copy_from_slice(b"MSDOS5.0");
        assert!(matches!(BootSector::parse(&b), Err(NtfsError::BadOemId(_))));
    }

    #[test]
    fn too_short_returns_error() {
        let short = [0u8; 16];
        assert!(matches!(
            BootSector::parse(&short),
            Err(NtfsError::TooShort { .. })
        ));
    }

    #[test]
    fn rejects_bad_bytes_per_sector() {
        // 513 is neither a power of two nor in range.
        let b = make_boot(513, 8, 1000, 100, 2, 0xF6, 0x01, 0);
        assert!(matches!(
            BootSector::parse(&b),
            Err(NtfsError::BadBytesPerSector(513))
        ));
    }

    #[test]
    fn rejects_zero_sectors_per_cluster() {
        let b = make_boot(512, 0, 1000, 100, 2, 0xF6, 0x01, 0);
        assert!(matches!(
            BootSector::parse(&b),
            Err(NtfsError::BadSectorsPerCluster(0))
        ));
    }

    #[test]
    fn record_size_encoding_min_i8_does_not_panic() {
        // clusters_per_record = 0x80 (-128) ⇒ 2^128, which overflows — must be
        // rejected cleanly, never panic. (This is the isomage/NTFS cpfrs bug.)
        let b = make_boot(512, 8, 1000, 100, 2, 0x80, 0x01, 0);
        assert!(matches!(
            BootSector::parse(&b),
            Err(NtfsError::BadRecordSize(0x80))
        ));
    }

    #[test]
    fn rejects_bad_index_record_size() {
        let b = make_boot(512, 8, 1000, 100, 2, 0xF6, 0x80, 0);
        assert!(matches!(
            BootSector::parse(&b),
            Err(NtfsError::BadIndexRecordSize(0x80))
        ));
    }
}
