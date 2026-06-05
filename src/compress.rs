//! LZNT1 decompression — the algorithm NTFS uses for compressed attributes.
//!
//! Compressed data is a series of chunks, each preceded by a 2-byte header:
//! bit 15 marks the chunk compressed, the low 12 bits are `size - 1` of the
//! bytes that follow, and a zero header ends the stream. A compressed chunk is
//! groups of "1 flag byte + up to 8 tokens"; each flag bit selects a literal
//! byte or a back-reference whose length/offset bit-split widens as the 4 KiB
//! chunk fills.
//!
//! Every length and offset is validated against what has actually been
//! produced, so crafted compressed data cannot read out of bounds or expand
//! without bound.

use crate::error::{NtfsError, Result};

/// Maximum bytes a single decompression may produce — an allocation-bomb guard.
const MAX_OUTPUT: usize = 1 << 30; // 1 GiB

/// Decompress an LZNT1 byte stream.
///
/// # Errors
///
/// [`NtfsError::BadCompression`] for a truncated chunk, a back-reference before
/// the chunk start, or output exceeding the safety ceiling.
pub fn decompress(input: &[u8]) -> Result<Vec<u8>> {
    let _ = (input, MAX_OUTPUT);
    todo!("LZNT1 decompress — GREEN step")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a compressed-chunk byte stream from a chunk body and a terminator.
    fn compressed_chunk(body: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        let header = 0x8000u16 | (3 << 12) | ((body.len() - 1) as u16);
        v.extend_from_slice(&header.to_le_bytes());
        v.extend_from_slice(body);
        v.extend_from_slice(&0u16.to_le_bytes()); // end
        v
    }

    fn uncompressed_chunk(body: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        let header = (3u16 << 12) | ((body.len() - 1) as u16); // bit 15 clear
        v.extend_from_slice(&header.to_le_bytes());
        v.extend_from_slice(body);
        v.extend_from_slice(&0u16.to_le_bytes());
        v
    }

    #[test]
    fn decompresses_uncompressed_chunk() {
        let stream = uncompressed_chunk(b"verbatim bytes");
        assert_eq!(decompress(&stream).unwrap(), b"verbatim bytes");
    }

    #[test]
    fn decompresses_all_literals() {
        // flag byte 0x00 → next 8 tokens are literals.
        let body = [0x00, b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h'];
        let out = decompress(&compressed_chunk(&body)).unwrap();
        assert_eq!(out, b"abcdefgh");
    }

    #[test]
    fn decompresses_back_reference() {
        // Literals "abc", then a back-reference (offset 3, length 3) ⇒ "abcabc".
        // After 3 bytes, length_bits = 4 ⇒ token = ((offset-1) << 4) | (length-3).
        let token: u16 = ((3 - 1) << 4) | (3 - 3); // offset 3, length 3
        let tb = token.to_le_bytes();
        // flags: bits 0..2 literals (0), bit 3 back-ref (1) ⇒ 0b0000_1000 = 0x08.
        let body = [0x08, b'a', b'b', b'c', tb[0], tb[1]];
        let out = decompress(&compressed_chunk(&body)).unwrap();
        assert_eq!(out, b"abcabc");
    }

    #[test]
    fn decompresses_run_length() {
        // Literal 'x', then back-ref offset 1 length 10 ⇒ "xxxxxxxxxxx".
        let token: u16 = ((1 - 1) << 4) | (10 - 3); // offset 1, length 10
        let tb = token.to_le_bytes();
        let body = [0x02, b'x', tb[0], tb[1]]; // bit0 literal, bit1 back-ref
        let out = decompress(&compressed_chunk(&body)).unwrap();
        assert_eq!(out, b"xxxxxxxxxxx"); // 1 + 10
    }

    #[test]
    fn empty_input_yields_empty() {
        assert!(decompress(&[]).unwrap().is_empty());
        assert!(decompress(&0u16.to_le_bytes()).unwrap().is_empty());
    }

    // ── Hardening ─────────────────────────────────────────────────────────────

    #[test]
    fn rejects_back_reference_at_chunk_start() {
        // First token is a back-reference with nothing decompressed yet.
        let body = [0x01u8, 0x00, 0x00]; // bit0 set, token 0
        assert!(matches!(
            decompress(&compressed_chunk(&body)),
            Err(NtfsError::BadCompression(_))
        ));
    }

    #[test]
    fn rejects_truncated_chunk() {
        // Header claims 10 bytes follow, but the input is shorter.
        let header = 0x8000u16 | (3 << 12) | 9;
        let mut stream = header.to_le_bytes().to_vec();
        stream.extend_from_slice(&[0x00, b'a']); // only 2 bytes, not 10
        assert!(matches!(
            decompress(&stream),
            Err(NtfsError::BadCompression(_))
        ));
    }
}
