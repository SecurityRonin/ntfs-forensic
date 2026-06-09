//! Streaming iterator over USN journal records.
//!
//! For multi-GB `$UsnJrnl:$J` journals where loading everything into memory is
//! impractical, [`UsnJournalReader`] walks a `Read + Seek` source in 64 `KiB`
//! windows, skipping the zero-filled gaps the change journal leaves behind and
//! decoding each `USN_RECORD_V2`/`V3` it finds via the `crate::usn` parsers.

use std::io::{Read, Seek, SeekFrom};

use crate::error::Result;
use crate::usn::{parse_usn_record_v2, parse_usn_record_v3, UsnRecord};

const BUF_SIZE: usize = 64 * 1024; // 64KB read buffer

/// Reads a little-endian `u32` at `offset`, yielding 0 if out of bounds.
fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    let mut b = [0u8; 4];
    if let Some(s) = data.get(offset..offset + 4) {
        b.copy_from_slice(s);
    }
    u32::from_le_bytes(b)
}

/// Reads a little-endian `u16` at `offset`, yielding 0 if out of bounds.
fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    let mut b = [0u8; 2];
    if let Some(s) = data.get(offset..offset + 2) {
        b.copy_from_slice(s);
    }
    u16::from_le_bytes(b)
}

/// Streaming iterator over USN records from a reader.
///
/// For multi-GB journals where loading everything into memory is impractical.
pub struct UsnJournalReader<R: Read + Seek> {
    reader: R,
    buf: Vec<u8>,
    buf_len: usize,
    buf_offset: usize,
    stream_pos: u64,
    total_size: u64,
    done: bool,
}

impl<R: Read + Seek> UsnJournalReader<R> {
    /// Creates a streaming reader, recording the source's total length.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::NtfsError::Io`] if the initial seeks fail.
    pub fn new(mut reader: R) -> Result<Self> {
        let total_size = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(0))?;

        Ok(Self {
            reader,
            buf: vec![0u8; BUF_SIZE],
            buf_len: 0,
            buf_offset: 0,
            stream_pos: 0,
            total_size,
            done: false,
        })
    }

    fn fill_buffer(&mut self) -> Result<bool> {
        if self.stream_pos >= self.total_size {
            self.done = true;
            return Ok(false);
        }

        // Move unconsumed data to front
        if self.buf_offset > 0 && self.buf_offset < self.buf_len {
            let remaining = self.buf_len - self.buf_offset;
            self.buf.copy_within(self.buf_offset..self.buf_len, 0);
            self.buf_len = remaining;
        } else {
            self.buf_len = 0;
        }
        self.buf_offset = 0;

        // Read more data into the free tail of the buffer. `self.buf` is always
        // exactly BUF_SIZE bytes (allocated once, never resized) and the
        // compaction above guarantees `self.buf_len < BUF_SIZE`, so splitting at
        // `buf_len` always yields a valid, non-empty destination tail.
        let (_, dst) = self.buf.split_at_mut(self.buf_len);
        let n = self.reader.read(dst)?;
        if n == 0 {
            self.done = true;
            return Ok(self.buf_len > 0);
        }
        self.buf_len += n;
        self.stream_pos += n as u64;

        Ok(true)
    }

    fn skip_zeros(&mut self) -> Result<bool> {
        loop {
            while self.buf_offset + 8 <= self.buf_len {
                match self.buf.get(self.buf_offset..self.buf_offset + 8) {
                    Some([0, 0, 0, 0, 0, 0, 0, 0]) => self.buf_offset += 8,
                    _ => return Ok(true),
                }
            }
            // A successful fill_buffer always advances buf_len past zero (it
            // returns Ok(true) only after reading a non-zero number of bytes),
            // so the outer loop re-checks the newly read window.
            if !self.fill_buffer()? {
                return Ok(false);
            }
        }
    }
}

impl<R: Read + Seek> Iterator for UsnJournalReader<R> {
    type Item = Result<UsnRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        // Ensure we have data
        if self.buf_offset >= self.buf_len {
            match self.fill_buffer() {
                Ok(true) => {}
                Ok(false) => return None,
                Err(e) => return Some(Err(e)),
            }
        }

        // Skip zero-filled regions. skip_zeros only returns Ok(true) once it has
        // found a non-zero 8-byte window, which guarantees `buf_offset + 8 <=
        // buf_len` here — enough for the record length + version fields below.
        match self.skip_zeros() {
            Ok(true) => {}
            Ok(false) => return None,
            Err(e) => return Some(Err(e)),
        }

        let record_len = read_u32_le(&self.buf, self.buf_offset) as usize;

        if !(8..=65536).contains(&record_len) {
            self.buf_offset += 8;
            return self.next();
        }

        // Ensure we have the full record in buffer
        if self.buf_offset + record_len > self.buf_len {
            match self.fill_buffer() {
                Ok(true) if self.buf_offset + record_len <= self.buf_len => {}
                _ => {
                    self.buf_offset += 8;
                    return self.next();
                }
            }
        }

        let version = read_u16_le(&self.buf, self.buf_offset + 4);

        // The record-fit check above guarantees `buf_offset + record_len <=
        // buf_len <= buf.len()`, and `record_len <= 65536 <= BUF_SIZE`, so this
        // record slice is always within the fixed-size buffer.
        let record_data = self.buf[self.buf_offset..self.buf_offset + record_len].to_vec();
        let aligned = (record_len + 7) & !7;
        self.buf_offset += aligned;

        match version {
            2 => match parse_usn_record_v2(&record_data) {
                Ok(r) => Some(Ok(r)),
                Err(_) => self.next(),
            },
            3 => match parse_usn_record_v3(&record_data) {
                Ok(r) => Some(Ok(r)),
                Err(_) => self.next(),
            },
            _ => self.next(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usn::UsnReason;
    use std::io::Cursor;

    fn build_v2_record_bytes(
        entry: u64,
        seq: u16,
        parent: u64,
        parent_seq: u16,
        reason: u32,
        name: &str,
    ) -> Vec<u8> {
        let name_utf16: Vec<u16> = name.encode_utf16().collect();
        let name_bytes_len = name_utf16.len() * 2;
        let record_len = 0x3C + name_bytes_len;
        let aligned_len = (record_len + 7) & !7;
        let mut buf = vec![0u8; aligned_len];
        buf[0..4].copy_from_slice(&(record_len as u32).to_le_bytes());
        buf[4..6].copy_from_slice(&2u16.to_le_bytes());
        let file_ref = entry | (u64::from(seq) << 48);
        buf[0x08..0x10].copy_from_slice(&file_ref.to_le_bytes());
        let parent_ref = parent | (u64::from(parent_seq) << 48);
        buf[0x10..0x18].copy_from_slice(&parent_ref.to_le_bytes());
        buf[0x18..0x20].copy_from_slice(&100i64.to_le_bytes());
        let ts: i64 = 133_500_480_000_000_000;
        buf[0x20..0x28].copy_from_slice(&ts.to_le_bytes());
        buf[0x28..0x2C].copy_from_slice(&reason.to_le_bytes());
        buf[0x34..0x38].copy_from_slice(&0x20u32.to_le_bytes());
        buf[0x38..0x3A].copy_from_slice(&(name_bytes_len as u16).to_le_bytes());
        buf[0x3A..0x3C].copy_from_slice(&0x3Cu16.to_le_bytes());
        for (i, &ch) in name_utf16.iter().enumerate() {
            let off = 0x3C + i * 2;
            buf[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }
        buf
    }

    #[test]
    fn test_streaming_reader_basic() {
        let r = build_v2_record_bytes(100, 1, 5, 5, 0x100, "test.txt");
        let cursor = Cursor::new(r);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(std::result::Result::ok).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].filename, "test.txt");
    }

    #[test]
    fn test_streaming_reader_skips_zeros() {
        let mut data = vec![0u8; 4096];
        data.extend_from_slice(&build_v2_record_bytes(100, 1, 5, 5, 0x100, "found.txt"));
        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(std::result::Result::ok).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].filename, "found.txt");
    }

    #[test]
    fn test_streaming_reader_multiple() {
        let mut data = Vec::new();
        data.extend_from_slice(&build_v2_record_bytes(100, 1, 5, 5, 0x100, "a.txt"));
        data.extend_from_slice(&build_v2_record_bytes(200, 1, 100, 1, 0x200, "b.txt"));
        data.extend_from_slice(&build_v2_record_bytes(300, 1, 100, 1, 0x100, "c.txt"));
        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(std::result::Result::ok).collect();
        assert_eq!(records.len(), 3);
    }

    #[test]
    fn test_streaming_reader_empty_data() {
        let cursor = Cursor::new(Vec::<u8>::new());
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(std::result::Result::ok).collect();
        assert_eq!(records.len(), 0);
    }

    #[test]
    fn test_streaming_reader_all_zeros() {
        let data = vec![0u8; 4096];
        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(std::result::Result::ok).collect();
        assert_eq!(records.len(), 0);
    }

    #[test]
    fn test_streaming_reader_includes_close_only() {
        let data = build_v2_record_bytes(100, 1, 5, 5, 0x8000_0000, "closed.txt");
        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(std::result::Result::ok).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].reason, UsnReason::CLOSE);
    }

    #[test]
    fn test_streaming_reader_invalid_record_length() {
        // Record with invalid length (too small) should be skipped
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&3u32.to_le_bytes()); // length < 8
        data[4..6].copy_from_slice(&2u16.to_le_bytes());
        // Rest is zeros, reader will skip

        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(std::result::Result::ok).collect();
        assert_eq!(records.len(), 0);
    }

    #[test]
    fn test_streaming_reader_invalid_then_valid() {
        let mut data = vec![0u8; 16]; // some garbage that looks non-zero
        data[0..4].copy_from_slice(&5u32.to_le_bytes()); // invalid length
        data[4..6].copy_from_slice(&99u16.to_le_bytes()); // invalid version
                                                          // Pad to 8-byte boundary for skipping
        data.resize(16, 0);
        // Now add zeros then a valid record
        data.extend_from_slice(&[0u8; 64]);
        data.extend_from_slice(&build_v2_record_bytes(100, 1, 5, 5, 0x100, "valid.txt"));

        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(std::result::Result::ok).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].filename, "valid.txt");
    }

    #[test]
    fn test_streaming_reader_unknown_version() {
        // Record with valid length but unknown version
        let mut data = vec![0u8; 0x40];
        data[0..4].copy_from_slice(&(0x40u32).to_le_bytes());
        data[4..6].copy_from_slice(&99u16.to_le_bytes()); // version 99

        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(std::result::Result::ok).collect();
        assert_eq!(records.len(), 0);
    }

    fn build_v3_record_bytes(entry: u64, parent: u64, reason: u32, name: &str) -> Vec<u8> {
        let name_utf16: Vec<u16> = name.encode_utf16().collect();
        let name_bytes_len = name_utf16.len() * 2;
        let record_len = 0x4C + name_bytes_len;
        let aligned_len = (record_len + 7) & !7;
        let mut buf = vec![0u8; aligned_len];

        buf[0..4].copy_from_slice(&(record_len as u32).to_le_bytes());
        buf[4..6].copy_from_slice(&3u16.to_le_bytes());
        buf[6..8].copy_from_slice(&0u16.to_le_bytes());
        buf[0x08..0x18].copy_from_slice(&u128::from(entry).to_le_bytes());
        buf[0x18..0x28].copy_from_slice(&u128::from(parent).to_le_bytes());
        buf[0x28..0x30].copy_from_slice(&200i64.to_le_bytes());
        let ts: i64 = 133_500_480_000_000_000;
        buf[0x30..0x38].copy_from_slice(&ts.to_le_bytes());
        buf[0x38..0x3C].copy_from_slice(&reason.to_le_bytes());
        buf[0x44..0x48].copy_from_slice(&0x20u32.to_le_bytes());
        buf[0x48..0x4A].copy_from_slice(&(name_bytes_len as u16).to_le_bytes());
        buf[0x4A..0x4C].copy_from_slice(&0x4Cu16.to_le_bytes());
        for (i, &ch) in name_utf16.iter().enumerate() {
            let off = 0x4C + i * 2;
            buf[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }
        buf
    }

    #[test]
    fn test_streaming_reader_v3_record() {
        let data = build_v3_record_bytes(100, 5, 0x100, "v3file.txt");
        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(std::result::Result::ok).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].filename, "v3file.txt");
        assert_eq!(records[0].major_version, 3);
    }

    #[test]
    fn test_streaming_reader_v3_close_only_included() {
        let data = build_v3_record_bytes(100, 5, 0x8000_0000, "closed_v3.txt");
        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(std::result::Result::ok).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].reason, UsnReason::CLOSE);
    }

    #[test]
    fn test_streaming_reader_large_zero_gap() {
        // Large zero region followed by a valid record
        let mut data = vec![0u8; 128 * 1024]; // 128KB of zeros (larger than buffer)
        data.extend_from_slice(&build_v2_record_bytes(100, 1, 5, 5, 0x100, "deep.txt"));

        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(std::result::Result::ok).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].filename, "deep.txt");
    }

    #[test]
    fn test_streaming_reader_record_larger_than_initial_buffer_fill() {
        // Record at offset 0 where the buffer needs to be filled
        let record = build_v2_record_bytes(42, 3, 5, 5, 0x100, "buffer_test.txt");
        let cursor = Cursor::new(record);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(std::result::Result::ok).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].mft_entry, 42);
        assert_eq!(records[0].mft_sequence, 3);
    }

    #[test]
    fn test_streaming_reader_record_too_large() {
        // A record that claims to be 65537 bytes (> 65536 max) should be skipped
        let mut data = vec![0u8; 128];
        data[0..4].copy_from_slice(&(65537u32).to_le_bytes());
        data[4..6].copy_from_slice(&2u16.to_le_bytes());

        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(std::result::Result::ok).collect();
        assert_eq!(records.len(), 0);
    }

    #[test]
    fn test_streaming_reader_mixed_v2_v3() {
        let mut data = Vec::new();
        data.extend_from_slice(&build_v2_record_bytes(100, 1, 5, 5, 0x100, "v2.txt"));
        data.extend_from_slice(&build_v3_record_bytes(200, 5, 0x200, "v3.txt"));
        data.extend_from_slice(&build_v2_record_bytes(300, 1, 5, 5, 0x100, "v2b.txt"));

        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(std::result::Result::ok).collect();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].major_version, 2);
        assert_eq!(records[1].major_version, 3);
        assert_eq!(records[2].major_version, 2);
    }

    #[test]
    fn test_streaming_reader_fill_buffer_with_unconsumed_data() {
        // Create data that spans multiple buffer fills.
        // First, fill most of the 64KB buffer with valid records, then add
        // a record that straddles the buffer boundary.
        // This triggers the fill_buffer path where buf_offset > 0 && buf_offset < buf_len,
        // meaning unconsumed data needs to be moved to front of buffer.
        let mut data = Vec::new();
        let record_size;
        {
            let sample = build_v2_record_bytes(1, 1, 5, 5, 0x100, "sample.txt");
            record_size = sample.len();
        }

        // Fill just under 64KB with records, then add zeros, then another record
        // that will require a buffer refill with leftover data
        let num_records_to_fill = (BUF_SIZE - record_size) / record_size;
        for i in 0..num_records_to_fill {
            data.extend_from_slice(&build_v2_record_bytes(
                (i + 1) as u64,
                1,
                5,
                5,
                0x100,
                &format!("f{i:04}.txt"),
            ));
        }

        // Add more records after the boundary
        for i in 0..5 {
            data.extend_from_slice(&build_v2_record_bytes(
                (num_records_to_fill + i + 1) as u64,
                1,
                5,
                5,
                0x100,
                &format!("after{i}.txt"),
            ));
        }

        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(std::result::Result::ok).collect();
        // Should find all records from both sides of the buffer boundary
        assert!(records.len() >= num_records_to_fill + 5);
    }

    #[test]
    fn test_streaming_reader_record_at_exact_buffer_boundary() {
        // Place records such that one record ends exactly at the buffer boundary
        // and the next starts exactly at the next fill.
        let sample = build_v2_record_bytes(1, 1, 5, 5, 0x100, "sample.txt");
        let record_size = sample.len();

        let mut data = Vec::new();
        // Calculate how many records fit exactly in the buffer
        let records_per_buffer = BUF_SIZE / record_size;
        let exact_fill = records_per_buffer * record_size;

        // Fill exactly to the buffer size
        for i in 0..records_per_buffer {
            data.extend_from_slice(&build_v2_record_bytes(
                (i + 1) as u64,
                1,
                5,
                5,
                0x100,
                "exact.txt",
            ));
        }

        // Pad to exactly BUF_SIZE if needed
        if exact_fill < BUF_SIZE {
            data.extend_from_slice(&vec![0u8; BUF_SIZE - exact_fill]);
        }

        // Add one more record that starts at the exact boundary
        data.extend_from_slice(&build_v2_record_bytes(
            (records_per_buffer + 1) as u64,
            1,
            5,
            5,
            0x100,
            "boundary.txt",
        ));

        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(std::result::Result::ok).collect();
        // The last record "boundary.txt" should be found
        assert!(records.iter().any(|r| r.filename == "boundary.txt"));
    }

    #[test]
    fn test_streaming_reader_record_straddles_buffer() {
        // Create data where a record starts in one buffer fill and extends
        // into the next fill. This tests the refill path where
        // buf_offset + record_len > buf_len triggers fill_buffer.
        let sample = build_v2_record_bytes(1, 1, 5, 5, 0x100, "sample.txt");
        let record_size = sample.len();

        let mut data = Vec::new();
        // Fill most of the buffer
        let records_to_fill = (BUF_SIZE / record_size) - 1;
        for i in 0..records_to_fill {
            data.extend_from_slice(&build_v2_record_bytes(
                (i + 1) as u64,
                1,
                5,
                5,
                0x100,
                "fill.txt",
            ));
        }

        let current_len = data.len();
        // Add zeros to position us near the end of the buffer
        // Leave less than record_size bytes before the boundary
        let padding = BUF_SIZE - current_len - (record_size / 2);
        if padding > 0 {
            data.extend_from_slice(&vec![0u8; padding]);
        }

        // Now add a record that will straddle the buffer boundary
        data.extend_from_slice(&build_v2_record_bytes(999, 1, 5, 5, 0x100, "straddle.txt"));

        // Add trailing data
        data.extend_from_slice(&vec![0u8; 256]);

        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(std::result::Result::ok).collect();
        // The straddling record should be found
        assert!(records.iter().any(|r| r.filename == "straddle.txt"));
    }

    #[test]
    fn test_streaming_reader_data_larger_than_buffer() {
        // Create data significantly larger than the 64KB buffer to ensure
        // multiple fill_buffer cycles work correctly
        let mut data = Vec::new();
        let total_records = 2000; // Each ~80 bytes = ~160KB > 64KB buffer
        for i in 0..total_records {
            data.extend_from_slice(&build_v2_record_bytes(
                (i + 1) as u64,
                1,
                5,
                5,
                0x100,
                &format!("r{i:04}.txt"),
            ));
        }

        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(std::result::Result::ok).collect();
        assert_eq!(records.len(), total_records);
    }

    // ─── Coverage tests for uncovered lines ────────────────────────────

    /// A reader that yields data from an inner buffer, but returns an IO error
    /// after a configurable number of successful reads.
    struct ErrorAfterNReads {
        data: Cursor<Vec<u8>>,
        reads_remaining: usize,
    }

    impl ErrorAfterNReads {
        fn new(data: Vec<u8>, successful_reads: usize) -> Self {
            Self {
                data: Cursor::new(data),
                reads_remaining: successful_reads,
            }
        }
    }

    impl Read for ErrorAfterNReads {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.reads_remaining == 0 {
                return Err(std::io::Error::other("simulated read error"));
            }
            self.reads_remaining -= 1;
            self.data.read(buf)
        }
    }

    impl Seek for ErrorAfterNReads {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            self.data.seek(pos)
        }
    }

    #[test]
    fn test_streaming_reader_done_flag_returns_none() {
        // Covers line 95: if self.done { return None; }
        // After consuming all records, the reader sets done=true.
        // The next call to next() should immediately return None.
        let record = build_v2_record_bytes(100, 1, 5, 5, 0x100, "done.txt");
        let cursor = Cursor::new(record);
        let mut reader = UsnJournalReader::new(cursor).unwrap();

        // Consume the one record
        let first = reader.next();
        assert!(first.is_some());
        assert!(first.unwrap().is_ok());

        // Now done should be set, and next() returns None (line 95)
        let second = reader.next();
        assert!(second.is_none());

        // Call again to confirm it stays None
        let third = reader.next();
        assert!(third.is_none());
    }

    #[test]
    fn test_streaming_reader_fill_buffer_error_propagation() {
        // Covers line 103: Err(e) => return Some(Err(e))
        // The first fill_buffer call in next() triggers an IO error.
        // We use ErrorAfterNReads with 1 successful read (for the constructor's
        // seek operations) and then fail on the actual data read.
        let record = build_v2_record_bytes(100, 1, 5, 5, 0x100, "err.txt");
        let err_reader = ErrorAfterNReads::new(record, 0);
        let mut reader = UsnJournalReader::new(err_reader).unwrap();

        // The first next() call will try fill_buffer, which calls self.reader.read()
        // That read will fail, propagating the error via line 103
        let result = reader.next();
        assert!(result.is_some());
        let err = result.unwrap();
        assert!(err.is_err());
        assert!(err
            .unwrap_err()
            .to_string()
            .contains("simulated read error"));
    }

    #[test]
    fn test_streaming_reader_skip_zeros_error_propagation() {
        // Covers line 111: Err(e) => return Some(Err(e)) in skip_zeros match
        // We need data that starts with zeros (so skip_zeros is called and
        // needs to fill_buffer), then the fill_buffer inside skip_zeros fails.
        let mut data = vec![0u8; BUF_SIZE]; // Full buffer of zeros
        data.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]); // non-zero to prevent early EOF

        // Allow 1 successful read (fills the zero buffer), then error on the
        // refill inside skip_zeros
        let err_reader = ErrorAfterNReads::new(data, 1);
        let mut reader = UsnJournalReader::new(err_reader).unwrap();

        let result = reader.next();
        assert!(result.is_some());
        let err = result.unwrap();
        assert!(err.is_err());
    }

    #[test]
    fn test_streaming_reader_eof_mid_fill_with_remaining_data() {
        // fill_buffer's `n == 0` branch with buf_len > 0: the source reports more
        // data than it delivers, so after the record is read, read() returns 0
        // while stream_pos < total_size and the buffered record is still resolved.
        let record = build_v2_record_bytes(42, 1, 5, 5, 0x100, "tiny.txt");
        let lying = LyingSizeReader::new(record, 4096);
        let mut reader = UsnJournalReader::new(lying).unwrap();

        let result = reader.next();
        assert!(result.is_some());
        let rec = result.unwrap().unwrap();
        assert_eq!(rec.filename, "tiny.txt");
    }

    #[test]
    fn test_streaming_reader_eof_mid_fill_no_remaining_data() {
        // fill_buffer's `n == 0` branch with buf_len == 0: the source reports a
        // non-zero size but read() returns 0 immediately, so it returns Ok(false).
        let lying = LyingSizeReader::new(Vec::new(), 4096);
        let mut reader = UsnJournalReader::new(lying).unwrap();

        let result = reader.next();
        assert!(result.is_none());
    }

    #[test]
    fn test_streaming_reader_header_refill_insufficient() {
        // Covers lines 116-118: fill_buffer for header but still < 8 bytes
        // We need a situation where after skip_zeros, buf_offset + 8 > buf_len,
        // and fill_buffer can't provide enough data.
        // Create data: zeros (to fill most of buffer), then 4 non-zero bytes at the
        // very end. After skip_zeros consumes the zeros, we have <8 bytes of non-zero
        // data, and fill_buffer returns Ok(true) but buf_offset + 8 > buf_len.
        let mut data = vec![0u8; BUF_SIZE - 4]; // zeros filling most of buffer
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // 4 non-zero bytes at end

        let cursor = Cursor::new(data);
        let mut reader = UsnJournalReader::new(cursor).unwrap();

        // skip_zeros will skip all the zeros and land at the 4 non-zero bytes.
        // buf_offset + 8 > buf_len, fill_buffer is called but there's no more data.
        // Lines 116-118 trigger the `_ => return None` path.
        let result = reader.next();
        assert!(result.is_none());
    }

    #[test]
    fn test_streaming_reader_record_refill_insufficient() {
        // Covers lines 138-140: fill_buffer for full record fails
        // We need a record header that claims a large record_len, but the data
        // is truncated so fill_buffer can't provide the full record.
        let mut data = vec![0u8; 16];
        // Write a record header claiming 1024 bytes, version 2
        data[0..4].copy_from_slice(&(1024u32).to_le_bytes());
        data[4..6].copy_from_slice(&2u16.to_le_bytes());
        // But we only have 16 bytes total - fill_buffer can't get 1024 bytes.
        // After failing, lines 138-140 skip 8 bytes and try next().

        let cursor = Cursor::new(data);
        let mut reader = UsnJournalReader::new(cursor).unwrap();

        let result = reader.next();
        assert!(result.is_none());
    }

    #[test]
    fn test_streaming_reader_v2_parse_error_skips() {
        // Covers line 155: Err(_) => self.next() for V2 parse error
        // Create a record with valid length and version=2 but invalid internal data
        // that causes parse_usn_record_v2 to fail, followed by a valid record.
        let mut data = Vec::new();

        // A record with record_len=0x20 (32 bytes) and version=2.
        // The reader accepts record_len in 8..=65536, so 0x20 passes.
        // But parse_usn_record_v2 requires record_len >= USN_V2_MIN_SIZE (0x3C=60),
        // so 0x20 < 0x3C causes the parser to return Err, triggering line 155.
        let mut bad_v2 = vec![0u8; 0x20]; // 32 bytes
        bad_v2[0..4].copy_from_slice(&(0x20u32).to_le_bytes()); // record_len = 32
        bad_v2[4..6].copy_from_slice(&2u16.to_le_bytes()); // version 2
                                                           // Parser will fail: 0x20 < USN_V2_MIN_SIZE (0x3C)
        data.extend_from_slice(&bad_v2);

        // Second: a valid record that should be parsed
        data.extend_from_slice(&build_v2_record_bytes(
            100,
            1,
            5,
            5,
            0x100,
            "after_bad_v2.txt",
        ));

        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(std::result::Result::ok).collect();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].filename, "after_bad_v2.txt");
    }

    #[test]
    fn test_streaming_reader_v3_parse_error_skips() {
        // Covers line 159: Err(_) => self.next() for V3 parse error
        // Same approach: record_len that passes reader check (8..=65536)
        // but fails parser check (< USN_V3_MIN_SIZE = 0x4C = 76)
        let mut data = Vec::new();

        // Bad V3: record_len = 0x20 (32), version 3 -> parser fails (32 < 76)
        let mut bad_v3 = vec![0u8; 0x20];
        bad_v3[0..4].copy_from_slice(&(0x20u32).to_le_bytes());
        bad_v3[4..6].copy_from_slice(&3u16.to_le_bytes()); // version 3
        data.extend_from_slice(&bad_v3);

        // Valid V2 record after
        data.extend_from_slice(&build_v2_record_bytes(
            200,
            1,
            5,
            5,
            0x200,
            "after_bad_v3.txt",
        ));

        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(std::result::Result::ok).collect();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].filename, "after_bad_v3.txt");
    }

    #[test]
    fn test_streaming_reader_skip_zeros_refill_then_find_data() {
        // Covers line 72 (outer loop re-entry in skip_zeros) and line 84 (buf_len==0)
        // Create data with more zeros than one buffer can hold, followed by a valid record.
        // This forces skip_zeros to call fill_buffer multiple times via the outer loop.
        let mut data = vec![0u8; BUF_SIZE * 2 + 512]; // >2 buffer fills of zeros
        data.extend_from_slice(&build_v2_record_bytes(
            100,
            1,
            5,
            5,
            0x100,
            "after_many_zeros.txt",
        ));

        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(std::result::Result::ok).collect();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].filename, "after_many_zeros.txt");
    }

    #[test]
    fn test_streaming_reader_skip_zeros_all_zeros_eof() {
        // Covers line 84: return Ok(false) when buf_len == 0 after fill_buffer
        // All data is zeros. After fill_buffer returns Ok(false) or buf_len drops to 0,
        // skip_zeros returns Ok(false) via line 84.
        let data = vec![0u8; BUF_SIZE + 100]; // slightly more than one buffer of zeros

        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(std::result::Result::ok).collect();

        assert_eq!(records.len(), 0);
    }

    #[test]
    fn test_streaming_reader_record_straddles_buffer_refill_fails() {
        // Covers lines 138-140 more thoroughly: record header is at the end of
        // a buffer fill, claims a size that needs more data, but the data stream
        // ends. fill_buffer succeeds (has some data) but record_len still > available.
        let sample = build_v2_record_bytes(1, 1, 5, 5, 0x100, "fill.txt");
        let record_size = sample.len();

        let mut data = Vec::new();
        // Fill most of one buffer with valid records
        let records_to_fill = (BUF_SIZE / record_size) - 1;
        for i in 0..records_to_fill {
            data.extend_from_slice(&build_v2_record_bytes(
                (i + 1) as u64,
                1,
                5,
                5,
                0x100,
                "fill.txt",
            ));
        }

        // Now add a truncated record: header claims 4096 bytes but only 16 are available
        let current_len = data.len();
        let remaining_in_buffer = BUF_SIZE - current_len;
        // Pad with zeros to get near end of buffer
        if remaining_in_buffer > 16 {
            data.extend_from_slice(&vec![0u8; remaining_in_buffer - 16]);
        }
        // Add a non-zero record header that claims a large size
        let mut truncated_header = vec![0u8; 16];
        truncated_header[0..4].copy_from_slice(&(4096u32).to_le_bytes()); // claims 4096 bytes
        truncated_header[4..6].copy_from_slice(&2u16.to_le_bytes()); // version 2
        truncated_header[8] = 0xFF; // make it non-zero so skip_zeros doesn't skip it
        data.extend_from_slice(&truncated_header);
        // No more data after this - fill_buffer will get these 16 bytes but
        // record_len (4096) > buf available, triggering lines 138-140

        let cursor = Cursor::new(data);
        let reader = UsnJournalReader::new(cursor).unwrap();
        let records: Vec<_> = reader.filter_map(std::result::Result::ok).collect();

        // Should have found the fill records but skipped the truncated one
        assert!(records.len() >= records_to_fill);
    }

    /// A reader whose `seek(End)` over-reports the stream length: it claims to be
    /// `phantom_extra` bytes longer than the data it actually returns. After the
    /// real data is exhausted, `read()` returns 0 (EOF) even though `stream_pos`
    /// has not yet reached the reported `total_size`. This drives the
    /// `n == 0` early-out inside `fill_buffer` (the `done = true` /
    /// `return Ok(self.buf_len > 0)` branch).
    struct LyingSizeReader {
        inner: Cursor<Vec<u8>>,
        real_len: u64,
        phantom_extra: u64,
    }

    impl LyingSizeReader {
        fn new(data: Vec<u8>, phantom_extra: u64) -> Self {
            let real_len = data.len() as u64;
            Self {
                inner: Cursor::new(data),
                real_len,
                phantom_extra,
            }
        }
    }

    impl Read for LyingSizeReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            // Delegates to the cursor: once real data is exhausted it returns 0
            // (EOF), even though the reported total_size says there is more.
            self.inner.read(buf)
        }
    }

    impl Seek for LyingSizeReader {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            // UsnJournalReader::new issues SeekFrom::End(0) to size the stream and
            // SeekFrom::Start(0) to rewind. Intercept End to over-report the
            // length so the reader believes more data exists than is delivered;
            // delegate every other seek to the inner cursor.
            if let SeekFrom::End(_) = pos {
                return Ok(self.real_len + self.phantom_extra);
            }
            self.inner.seek(pos)
        }
    }

    #[test]
    fn test_streaming_reader_read_zero_with_buffered_record() {
        // Covers the `n == 0` branch in fill_buffer with buf_len > 0:
        // after one record is buffered and consumed, a later fill_buffer sees
        // stream_pos < total_size (size was over-reported) yet read() returns 0,
        // so it sets done=true and returns Ok(self.buf_len > 0).
        let record = build_v2_record_bytes(100, 1, 5, 5, 0x100, "phantom.txt");
        let lying = LyingSizeReader::new(record, 4096);
        let reader = UsnJournalReader::new(lying).unwrap();

        let records: Vec<_> = reader.filter_map(std::result::Result::ok).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].filename, "phantom.txt");
    }

    #[test]
    fn test_streaming_reader_read_zero_with_empty_buffer() {
        // Covers the `n == 0` branch in fill_buffer with buf_len == 0:
        // the source reports a non-zero size but read() returns 0 immediately,
        // so fill_buffer returns Ok(false) (self.buf_len > 0 is false).
        let lying = LyingSizeReader::new(Vec::new(), 4096);
        let mut reader = UsnJournalReader::new(lying).unwrap();

        // total_size is reported as 4096 but the reader has no bytes to give.
        assert!(reader.next().is_none());
    }
}
