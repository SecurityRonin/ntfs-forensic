//! A bounded sub-reader that re-bases a partition to offset zero.
//!
//! A whole-disk image (raw, EWF- or VMDK-backed) holds several partitions. The
//! NTFS reader expects offset 0 to be the volume boot record, so opening a
//! partition means presenting just that partition's byte window as if it began
//! at zero. [`OffsetReader`] does exactly that — and refuses every read or seek
//! that would escape the window, so the filesystem layer cannot wander into an
//! adjacent partition no matter how corrupt the structures it follows.

use std::io::{Read, Seek, SeekFrom};

use crate::error::Result;

/// A `Read + Seek` view of `[base, base + len)` within an underlying source,
/// addressed as if it began at offset 0.
#[derive(Debug)]
pub struct OffsetReader<R> {
    inner: R,
    base: u64,
    len: u64,
    pos: u64,
}

impl<R: Read + Seek> OffsetReader<R> {
    /// Create a window of `len` bytes starting at absolute byte `base`.
    ///
    /// # Errors
    ///
    /// [`NtfsError::Io`] if the underlying source cannot seek to `base`.
    pub fn new(mut inner: R, base: u64, len: u64) -> Result<Self> {
        inner.seek(SeekFrom::Start(base))?;
        Ok(Self {
            inner,
            base,
            len,
            pos: 0,
        })
    }

    /// The partition length in bytes.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the partition window is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl<R: Read + Seek> Read for OffsetReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.len.saturating_sub(self.pos);
        if remaining == 0 {
            return Ok(0);
        }
        // Never hand the inner reader more than the window has left.
        let cap = remaining.min(buf.len() as u64) as usize;
        // Re-anchor the inner reader: callers may have moved it elsewhere.
        let abs = self.base.checked_add(self.pos).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "offset overflow")
        })?;
        self.inner.seek(SeekFrom::Start(abs))?;
        let n = self.inner.read(&mut buf[..cap])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl<R: Read + Seek> Seek for OffsetReader<R> {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        // Resolve the requested position relative to the window, as a signed
        // value so we can reject seeks before the start.
        let target: i128 = match from {
            SeekFrom::Start(n) => n as i128,
            SeekFrom::Current(d) => self.pos as i128 + d as i128,
            SeekFrom::End(d) => self.len as i128 + d as i128,
        };
        if target < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek before partition start",
            ));
        }
        // Position past the end is allowed (mirrors std semantics); reads there
        // simply return EOF. Cap the stored value at u64.
        self.pos = u64::try_from(target).unwrap_or(u64::MAX);
        Ok(self.pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// 64 bytes of disk: partition at offset 16, length 32.
    fn disk() -> Cursor<Vec<u8>> {
        Cursor::new((0u8..64).collect())
    }

    #[test]
    fn reads_are_relative_to_base() {
        let mut r = OffsetReader::new(disk(), 16, 32).unwrap();
        let mut buf = [0u8; 4];
        r.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [16, 17, 18, 19]); // partition byte 0 == disk byte 16
    }

    #[test]
    fn seek_is_relative_to_base() {
        let mut r = OffsetReader::new(disk(), 16, 32).unwrap();
        r.seek(SeekFrom::Start(8)).unwrap();
        let mut buf = [0u8; 2];
        r.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [24, 25]); // disk byte 16 + 8
    }

    #[test]
    fn seek_end_is_partition_length() {
        let mut r = OffsetReader::new(disk(), 16, 32).unwrap();
        let end = r.seek(SeekFrom::End(0)).unwrap();
        assert_eq!(end, 32); // not 64 — the window ends at the partition
    }

    #[test]
    fn read_is_clamped_at_partition_end() {
        let mut r = OffsetReader::new(disk(), 16, 32).unwrap();
        r.seek(SeekFrom::Start(30)).unwrap();
        let mut buf = [0u8; 8];
        let n = r.read(&mut buf).unwrap();
        assert_eq!(n, 2); // only 2 bytes remain in the window
        assert_eq!(&buf[..2], &[46, 47]); // disk bytes 46, 47
                                          // A further read sees EOF, never disk bytes 48+.
        assert_eq!(r.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn rejects_seek_before_start() {
        let mut r = OffsetReader::new(disk(), 16, 32).unwrap();
        assert!(r.seek(SeekFrom::Current(-1)).is_err());
    }

    #[test]
    fn len_reports_window_size() {
        let r = OffsetReader::new(disk(), 16, 32).unwrap();
        assert_eq!(r.len(), 32);
        assert!(!r.is_empty());
    }
}
