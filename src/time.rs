//! Windows `FILETIME` — the timestamp format used throughout NTFS.
//!
//! A `FILETIME` is a 64-bit count of 100-nanosecond intervals since
//! 1601-01-01 00:00:00 UTC. Timestamps are trivially forgeable (timestomping),
//! so this type stays a thin, lossless wrapper over the raw value and offers
//! conversions for display — it never normalises or discards the original.

/// 100-ns intervals between the FILETIME epoch (1601) and the Unix epoch (1970).
const FILETIME_TO_UNIX_100NS: i128 = 116_444_736_000_000_000;

/// A raw Windows `FILETIME` (100-ns ticks since 1601-01-01 UTC).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Filetime(pub u64);

impl Filetime {
    /// Read a little-endian `FILETIME` from the start of `bytes` (needs 8 bytes).
    #[must_use]
    pub fn from_le(bytes: &[u8; 8]) -> Self {
        Filetime(u64::from_le_bytes(*bytes))
    }

    /// `true` for the all-zero value (an unset timestamp).
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }

    /// Whole seconds since the Unix epoch (may be negative for pre-1970 times).
    #[must_use]
    pub fn to_unix_seconds(&self) -> i64 {
        let _ = FILETIME_TO_UNIX_100NS;
        todo!("FILETIME → unix seconds — GREEN step")
    }

    /// Nanoseconds since the Unix epoch (`i128` to span the full FILETIME range).
    #[must_use]
    pub fn to_unix_nanos(&self) -> i128 {
        todo!("FILETIME → unix nanos — GREEN step")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_is_unset() {
        assert!(Filetime(0).is_zero());
        assert!(!Filetime(1).is_zero());
    }

    #[test]
    fn filetime_epoch_maps_to_unix_zero() {
        // 116444736000000000 ticks = exactly the Unix epoch.
        assert_eq!(Filetime(116_444_736_000_000_000).to_unix_seconds(), 0);
    }

    #[test]
    fn known_date_converts() {
        // 2010-01-01 00:00:00 UTC → unix 1262304000.
        let ft = Filetime(129_067_776_000_000_000);
        assert_eq!(ft.to_unix_seconds(), 1_262_304_000);
    }

    #[test]
    fn pre_unix_epoch_is_negative() {
        // One second before the Unix epoch.
        let ft = Filetime(116_444_736_000_000_000 - 10_000_000);
        assert_eq!(ft.to_unix_seconds(), -1);
    }

    #[test]
    fn nanos_granularity() {
        // One 100-ns tick past the epoch = 100 ns.
        let ft = Filetime(116_444_736_000_000_000 + 1);
        assert_eq!(ft.to_unix_nanos(), 100);
    }

    #[test]
    fn from_le_reads_little_endian() {
        let ft = Filetime::from_le(&1u64.to_le_bytes());
        assert_eq!(ft.0, 1);
    }
}
