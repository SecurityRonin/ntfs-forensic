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

/// LZNT1 decodes each chunk into at most a 4 KiB window. This bound is what
/// keeps the back-reference bit-split (`length_bits`) at most 12, so the
/// `1u16 << length_bits` shift can never overflow.
const CHUNK_MAX: usize = 4096;

/// Decompress an LZNT1 byte stream.
///
/// # Errors
///
/// [`NtfsError::BadCompression`] for a truncated chunk, a back-reference before
/// the chunk start, or output exceeding the safety ceiling.
pub fn decompress(input: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut pos = 0;

    while pos + 2 <= input.len() {
        let header = u16::from_le_bytes([input[pos], input[pos + 1]]);
        pos += 2;
        if header == 0 {
            break; // end of the compressed stream
        }
        let chunk_size = (header & 0x0FFF) as usize + 1;
        let is_compressed = header & 0x8000 != 0;
        let chunk = input
            .get(pos..pos + chunk_size)
            .ok_or(NtfsError::BadCompression("chunk extends past input"))?;
        pos += chunk_size;

        if is_compressed {
            decompress_chunk(chunk, &mut out)?;
        } else {
            grow(&mut out, chunk.len())?;
            let end = out.len();
            out[end - chunk.len()..].copy_from_slice(chunk);
        }
    }

    Ok(out)
}

/// Decompress one LZNT1 chunk, appending to `out`.
fn decompress_chunk(chunk: &[u8], out: &mut Vec<u8>) -> Result<()> {
    let chunk_start = out.len();
    let mut i = 0;

    while i < chunk.len() {
        let flags = chunk[i];
        i += 1;
        for bit in 0..8 {
            if i >= chunk.len() {
                break;
            }
            if flags & (1 << bit) == 0 {
                // Literal byte.
                grow(out, 1)?;
                let end = out.len();
                out[end - 1] = chunk[i];
                i += 1;
            } else {
                // Back-reference token (2 bytes).
                let token_bytes = chunk
                    .get(i..i + 2)
                    .ok_or(NtfsError::BadCompression("truncated back-reference"))?;
                let token = u16::from_le_bytes([token_bytes[0], token_bytes[1]]);
                i += 2;

                let produced = out.len() - chunk_start;
                if produced == 0 {
                    return Err(NtfsError::BadCompression("back-reference at chunk start"));
                }
                if produced > CHUNK_MAX {
                    return Err(NtfsError::BadCompression("chunk decodes past 4 KiB window"));
                }

                // The length/offset bit-split widens as the chunk fills.
                let mut length_bits = 4u32;
                let mut threshold = 0x10usize;
                while produced >= threshold {
                    length_bits += 1;
                    threshold <<= 1;
                }
                let length_mask = (1u16 << length_bits) - 1;
                let length = (token & length_mask) as usize + 3;
                let offset = (token >> length_bits) as usize + 1;
                if offset > produced {
                    return Err(NtfsError::BadCompression(
                        "back-reference before chunk start",
                    ));
                }

                let src = out.len() - offset;
                grow(out, length)?;
                for k in 0..length {
                    let b = out[src + k]; // overlapping copy is well-defined
                    let idx = out.len() - length + k;
                    out[idx] = b;
                }
            }
        }
    }
    Ok(())
}

/// Grow `out` by `n` zero bytes, refusing implausible totals.
fn grow(out: &mut Vec<u8>, n: usize) -> Result<()> {
    let new_len = out
        .len()
        .checked_add(n)
        .filter(|&l| l <= MAX_OUTPUT)
        .ok_or(NtfsError::BadCompression("output exceeds ceiling"))?;
    out.resize(new_len, 0);
    Ok(())
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
    #[allow(clippy::identity_op)] // keep the ((offset-1)<<4)|(length-3) formula explicit
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
    #[allow(clippy::identity_op)] // keep the ((offset-1)<<4)|(length-3) formula explicit
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
    fn fuzzer_crash_no_chunk_overflow() {
        // Regression: a crafted stream whose chunk decodes past 32 KiB drove
        // `length_bits` over 16 and overflowed `1u16 << length_bits`. A chunk
        // must decode to at most 4096 bytes; this input must error, not panic.
        let crash = [
            0x4a, 0xc0, 0x36, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x1a, 0x00, 0x4a,
            0xc0, 0x36, 0x36, 0x09, 0x00, 0x00, 0x00, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18,
            0x18, 0x18, 0x18, 0x00, 0x00, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18,
            0x18, 0x18, 0x18, 0x18, 0x00, 0x00, 0x0a, 0x00, 0x1a, 0x00, 0x4a, 0xc0, 0x36, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x01, 0x00, 0x41, 0xff, 0x00, 0x40, 0x00, 0x00, 0x40, 0x00, 0x00,
            0x40, 0x01, 0xff, 0x51, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
        ];
        // Must not panic; whatever it returns is fine.
        let _ = decompress(&crash);
    }

    #[test]
    fn rejects_chunk_decoding_past_4096() {
        // A single compressed chunk that tries to expand beyond the 4 KiB
        // window via run-length must be rejected, not allowed to run away.
        let mut body = vec![0x01u8, b'x']; // flag: 1 back-ref-or-literal; seed
                                           // Pad with run-length tokens that each repeat the window; the decoder
                                           // must stop at 4096 and report BadCompression rather than looping out.
        body[0] = 0x02; // bit0 literal 'x', bit1 back-ref
        let token: u16 = 0x07; // offset 1, length 10 at length_bits=4
        body.extend_from_slice(&token.to_le_bytes());
        let mut group = vec![0xFFu8]; // all-back-ref flag byte + 8 tokens
        for _ in 0..8 {
            group.extend_from_slice(&token.to_le_bytes());
        }
        for _ in 0..600 {
            body.extend_from_slice(&group);
        }
        let mut stream = (0x8000u16 | (3 << 12) | ((body.len() - 1) as u16))
            .to_le_bytes()
            .to_vec();
        stream.extend_from_slice(&body);
        stream.extend_from_slice(&0u16.to_le_bytes());
        assert!(matches!(
            decompress(&stream),
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
