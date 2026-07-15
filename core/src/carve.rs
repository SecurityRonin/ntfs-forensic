//! MFT entry carving from unallocated space or raw disk data.
//!
//! Scans arbitrary binary data looking for valid MFT entries ("FILE" signature
//! at 1024-byte boundaries), validates each candidate, and extracts identity
//! fields needed for path resolution via the Rewind engine.

use safe_read::{le_u16, le_u32, le_u64};

// ─── Constants ───────────────────────────────────────────────────────────────

/// MFT entry signature: "FILE"
const FILE_SIGNATURE: [u8; 4] = [0x46, 0x49, 0x4C, 0x45];

/// Standard MFT entry size in bytes.
const MFT_ENTRY_SIZE: usize = 1024;

/// FILE_NAME attribute type identifier.
const ATTR_FILE_NAME: u32 = 0x30;

/// End-of-attributes marker.
const ATTR_END_MARKER: u32 = 0xFFFF_FFFF;

/// Maximum number of attributes to walk before giving up.
const MAX_ATTR_WALK: usize = 20;

/// Filename namespace: Win32 (preferred for display).
const NS_WIN32: u8 = 1;

/// Filename namespace: Win32+DOS (also preferred).
const NS_WIN32_AND_DOS: u8 = 3;

/// Filename namespace: DOS (8.3 short name, least preferred).
const NS_DOS: u8 = 2;

// ─── Result types ────────────────────────────────────────────────────────────

/// A carved MFT entry with its offset in the source data.
#[derive(Debug, Clone)]
pub struct CarvedMftEntry {
    /// Byte offset in the source data where this entry was found.
    pub offset: usize,
    /// MFT record number (from NTFS 3.1+ header field at offset 44).
    pub entry_number: u64,
    /// Sequence number from the MFT entry header.
    pub sequence_number: u16,
    /// Best filename extracted from FILE_NAME attribute (Win32 preferred over DOS).
    pub filename: String,
    /// Parent directory MFT entry number.
    pub parent_entry: u64,
    /// Parent directory sequence number.
    pub parent_sequence: u16,
    /// Whether this entry has the directory flag set.
    pub is_directory: bool,
    /// Whether this entry has the in-use flag set.
    pub is_in_use: bool,
}

/// Statistics from an MFT carving operation.
#[derive(Debug, Clone, Default)]
pub struct MftCarvingStats {
    /// Total bytes scanned.
    pub bytes_scanned: usize,
    /// Number of "FILE" signature candidates found.
    pub candidates_examined: u64,
    /// Number of entries successfully carved.
    pub entries_carved: usize,
    /// Number of candidates rejected (invalid header, no filename, etc.).
    pub rejected: u64,
}

// ─── Carver ──────────────────────────────────────────────────────────────────

/// Carve MFT entries from raw binary data.
///
/// Scans on 1024-byte boundaries looking for the "FILE" signature, validates
/// the entry header, and extracts identity fields from the FILE_NAME attribute.
///
/// # Arguments
/// * `data` - Raw binary data to scan
///
/// # Returns
/// A tuple of (carved entries, carving statistics).
pub fn carve_mft_entries(data: &[u8]) -> (Vec<CarvedMftEntry>, MftCarvingStats) {
    let mut results = Vec::new();
    let mut stats = MftCarvingStats {
        bytes_scanned: data.len(),
        ..Default::default()
    };

    let len = data.len();
    let mut offset = 0;

    while offset + MFT_ENTRY_SIZE <= len {
        // Check for FILE signature at 1024-byte boundary
        if data[offset..offset + 4] == FILE_SIGNATURE {
            stats.candidates_examined += 1;

            if let Some(entry) = try_carve_entry(data, offset, &mut stats) {
                results.push(entry);
            }
        }

        offset += MFT_ENTRY_SIZE;
    }

    stats.entries_carved = results.len();
    (results, stats)
}

/// Attempt to carve a single MFT entry at the given offset.
fn try_carve_entry(
    data: &[u8],
    offset: usize,
    stats: &mut MftCarvingStats,
) -> Option<CarvedMftEntry> {
    let entry = &data[offset..offset + MFT_ENTRY_SIZE];

    // Validate sequence number (0 = never used)
    let sequence_number = le_u16(entry, 16);
    if sequence_number == 0 {
        stats.rejected += 1;
        return None;
    }

    // Validate first attribute offset
    let first_attr_offset = le_u16(entry, 20) as usize;
    if !(48..MFT_ENTRY_SIZE - 8).contains(&first_attr_offset) {
        stats.rejected += 1;
        return None;
    }

    let flags = le_u16(entry, 22);
    let entry_number = u64::from(le_u32(entry, 44));

    // Walk attributes looking for FILE_NAME (0x30)
    let mut best_filename: Option<(String, u64, u16, u8)> = None; // (name, parent_entry, parent_seq, namespace)
    let mut attr_offset = first_attr_offset;
    let mut attrs_walked = 0;

    while attr_offset + 8 <= MFT_ENTRY_SIZE && attrs_walked < MAX_ATTR_WALK {
        let attr_type = le_u32(entry, attr_offset);

        if attr_type == ATTR_END_MARKER {
            break;
        }

        let attr_len = le_u32(entry, attr_offset + 4) as usize;
        if attr_len < 8 || attr_offset + attr_len > MFT_ENTRY_SIZE {
            break; // corrupt attribute chain
        }

        // Only resident $FILE_NAME attributes carry an extractable name. The loop
        // guard permits `attr_offset` up to `MFT_ENTRY_SIZE - 8`, so the
        // non-resident-flag byte at `attr_offset + 8` can be one past the end —
        // read it bounds-checked (a truncated attribute is never a resident name).
        let is_resident_filename =
            attr_type == ATTR_FILE_NAME && entry.get(attr_offset + 8) == Some(&0);
        if let Some((name, parent_e, parent_s, ns)) = is_resident_filename
            .then(|| parse_filename_attr(entry, attr_offset))
            .flatten()
        {
            // Prefer Win32 or Win32+DOS over DOS.
            let dominated = match &best_filename {
                None => true,
                Some((_, _, _, prev_ns)) => {
                    // Replace if current is Win32/Win32+DOS and prev is DOS,
                    // or if we have no Win32 name yet.
                    *prev_ns == NS_DOS && (ns == NS_WIN32 || ns == NS_WIN32_AND_DOS)
                        || *prev_ns != NS_WIN32 && *prev_ns != NS_WIN32_AND_DOS && ns != NS_DOS
                }
            };
            if dominated {
                best_filename = Some((name, parent_e, parent_s, ns));
            }
        }

        attr_offset += attr_len;
        attrs_walked += 1;
    }

    if let Some((filename, parent_entry, parent_sequence, _)) = best_filename {
        Some(CarvedMftEntry {
            offset,
            entry_number,
            sequence_number,
            filename,
            parent_entry,
            parent_sequence,
            is_directory: flags & 0x02 != 0,
            is_in_use: flags & 0x01 != 0,
        })
    } else {
        stats.rejected += 1;
        None
    }
}

/// Parse a FILE_NAME attribute and extract identity fields.
/// Returns (filename, `parent_entry`, `parent_sequence`, namespace).
fn parse_filename_attr(entry: &[u8], attr_offset: usize) -> Option<(String, u64, u16, u8)> {
    let content_offset = le_u16(entry, attr_offset + 20) as usize;
    let content_size = le_u32(entry, attr_offset + 16) as usize;

    let fn_start = attr_offset + content_offset;
    if fn_start + 66 > entry.len() || content_size < 66 {
        return None;
    }

    // Parent file reference
    let parent_ref = le_u64(entry, fn_start);
    let parent_entry = parent_ref & 0x0000_FFFF_FFFF_FFFF;
    let parent_sequence = (parent_ref >> 48) as u16;

    // Filename
    let name_len_chars = entry[fn_start + 64] as usize;
    let namespace = entry[fn_start + 65];

    if name_len_chars == 0 {
        return None;
    }

    let name_bytes_start = fn_start + 66;
    let name_bytes_end = name_bytes_start + name_len_chars * 2;
    if name_bytes_end > entry.len()
        || name_bytes_end > attr_offset + le_u32(entry, attr_offset + 4) as usize
    {
        return None;
    }

    let name_u16: Vec<u16> = (0..name_len_chars)
        .map(|i| le_u16(entry, name_bytes_start + i * 2))
        .collect();
    let filename = String::from_utf16_lossy(&name_u16);

    Some((filename, parent_entry, parent_sequence, namespace))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::cast_lossless)]
mod tests {
    use super::*;

    /// Build a synthetic MFT entry with a FILE_NAME attribute.
    fn build_mft_entry(
        entry_number: u32,
        sequence: u16,
        parent_entry: u64,
        parent_sequence: u16,
        filename: &str,
        flags: u16, // 0x01 = in-use, 0x02 = directory, 0x03 = both
    ) -> Vec<u8> {
        let mut buf = vec![0u8; MFT_ENTRY_SIZE];

        // FILE signature
        buf[0..4].copy_from_slice(&FILE_SIGNATURE);
        // Fixup array offset = 48
        buf[4..6].copy_from_slice(&48u16.to_le_bytes());
        // Fixup array count = 3 (signature + 2 sector fixups)
        buf[6..8].copy_from_slice(&3u16.to_le_bytes());
        // $LogFile sequence number
        buf[8..16].copy_from_slice(&1u64.to_le_bytes());
        // Sequence number
        buf[16..18].copy_from_slice(&sequence.to_le_bytes());
        // Hard link count
        buf[18..20].copy_from_slice(&1u16.to_le_bytes());
        // First attribute offset = 56
        let first_attr_offset: u16 = 56;
        buf[20..22].copy_from_slice(&first_attr_offset.to_le_bytes());
        // Flags
        buf[22..24].copy_from_slice(&flags.to_le_bytes());
        // Used size
        buf[24..28].copy_from_slice(&512u32.to_le_bytes());
        // Allocated size
        buf[28..32].copy_from_slice(&1024u32.to_le_bytes());
        // Base MFT record = 0
        // Next attribute ID
        buf[40..42].copy_from_slice(&2u16.to_le_bytes());
        // MFT record number (NTFS 3.1+, offset 44)
        buf[44..48].copy_from_slice(&entry_number.to_le_bytes());

        // Fixup array at offset 48
        buf[48..50].copy_from_slice(&0x0001u16.to_le_bytes());
        buf[50..52].copy_from_slice(&0x0000u16.to_le_bytes());
        buf[52..54].copy_from_slice(&0x0000u16.to_le_bytes());

        // Build FILE_NAME attribute at first_attr_offset
        write_filename_attr(
            &mut buf,
            first_attr_offset as usize,
            parent_entry,
            parent_sequence,
            filename,
            NS_WIN32_AND_DOS,
        );

        buf
    }

    /// Write a FILE_NAME attribute into a buffer at the given offset.
    /// Returns the attribute size (8-byte aligned).
    fn write_filename_attr(
        buf: &mut [u8],
        attr_start: usize,
        parent_entry: u64,
        parent_sequence: u16,
        filename: &str,
        namespace: u8,
    ) -> usize {
        let name_utf16: Vec<u16> = filename.encode_utf16().collect();
        let name_bytes_len = name_utf16.len() * 2;
        let fn_content_size = 66 + name_bytes_len;
        let content_offset: u16 = 24;
        let attr_size = (content_offset as usize + fn_content_size + 7) & !7;

        // Attribute header
        buf[attr_start..attr_start + 4].copy_from_slice(&ATTR_FILE_NAME.to_le_bytes());
        buf[attr_start + 4..attr_start + 8].copy_from_slice(&(attr_size as u32).to_le_bytes());
        buf[attr_start + 8] = 0; // resident
        buf[attr_start + 9] = 0; // name length
        buf[attr_start + 10..attr_start + 12].copy_from_slice(&0x18u16.to_le_bytes());
        // Content size
        buf[attr_start + 16..attr_start + 20]
            .copy_from_slice(&(fn_content_size as u32).to_le_bytes());
        // Content offset
        buf[attr_start + 20..attr_start + 22].copy_from_slice(&content_offset.to_le_bytes());

        // FILE_NAME content
        let fn_start = attr_start + content_offset as usize;
        let parent_ref = parent_entry | ((parent_sequence as u64) << 48);
        buf[fn_start..fn_start + 8].copy_from_slice(&parent_ref.to_le_bytes());

        // Timestamps (4 × 8 bytes)
        let ts: i64 = 133_500_480_000_000_000;
        for i in 0..4 {
            let off = fn_start + 8 + i * 8;
            buf[off..off + 8].copy_from_slice(&ts.to_le_bytes());
        }

        // Allocated size, real size, flags, reparse
        // (already zeroed)

        // Filename length (chars) and namespace
        buf[fn_start + 64] = name_utf16.len() as u8;
        buf[fn_start + 65] = namespace;

        // Filename UTF-16LE
        for (i, &ch) in name_utf16.iter().enumerate() {
            let off = fn_start + 66 + i * 2;
            buf[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }

        // End-of-attributes marker after this attribute
        let end_offset = attr_start + attr_size;
        if end_offset + 4 <= buf.len() {
            buf[end_offset..end_offset + 4].copy_from_slice(&ATTR_END_MARKER.to_le_bytes());
        }

        attr_size
    }

    // ─── Test: crafted FILE_NAME attr near the entry end must not panic ──────

    #[test]
    fn crafted_filename_attr_near_end_does_not_panic() {
        // A FILE_NAME attribute placed so parse_filename_attr's read at
        // `attr_offset + 20` lands past the 1024-byte entry. Direct-index readers
        // panic on this OOB (a DoS on a crafted MFT); the record must instead be
        // rejected without panicking.
        let mut e = vec![0u8; MFT_ENTRY_SIZE];
        e[0..4].copy_from_slice(&FILE_SIGNATURE);
        e[16..18].copy_from_slice(&1u16.to_le_bytes()); // sequence != 0
        let fao: u16 = 1005; // in [48, MFT_ENTRY_SIZE - 8)
        e[20..22].copy_from_slice(&fao.to_le_bytes());
        let ao = fao as usize;
        e[ao..ao + 4].copy_from_slice(&ATTR_FILE_NAME.to_le_bytes());
        e[ao + 4..ao + 8].copy_from_slice(&16u32.to_le_bytes()); // attr_len (>=8, ao+len<=1024)
        e[ao + 8] = 0; // resident flag → reaches parse_filename_attr
                       // parse_filename_attr reads at ao+20 = 1025, one past the entry.
        let (entries, _stats) = carve_mft_entries(&e);
        assert!(
            entries.is_empty(),
            "the malformed record must be rejected, not carved"
        );
    }

    // ─── Test: empty/garbage data ────────────────────────────────────────────

    #[test]
    fn test_carve_empty_data() {
        let (entries, stats) = carve_mft_entries(&[]);
        assert_eq!(entries.len(), 0);
        assert_eq!(stats.bytes_scanned, 0);
    }

    #[test]
    fn test_carve_filename_dos_then_posix_domination() {
        // Two $FILE_NAMEs: first DOS (8.3), then POSIX. The domination check has
        // to evaluate its second disjunct (prev_ns is neither Win32 nor Win32+DOS,
        // and the current name is not DOS), so the POSIX long name wins.
        let mut buf = build_mft_entry(500, 1, 5, 5, "placeholder", 0x01);
        let s0 = write_filename_attr(&mut buf, 56, 5, 5, "DOS~1.TXT", NS_DOS);
        let s1 = write_filename_attr(&mut buf, 56 + s0, 5, 5, "longposix.txt", 0); // POSIX
        let end = 56 + s0 + s1;
        buf[end..end + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

        let (entries, _) = carve_mft_entries(&buf);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].filename, "longposix.txt");
    }

    #[test]
    fn test_carve_all_zeros() {
        let data = vec![0u8; 8192];
        let (entries, stats) = carve_mft_entries(&data);
        assert_eq!(entries.len(), 0);
        assert_eq!(stats.bytes_scanned, 8192);
    }

    #[test]
    fn test_carve_random_garbage() {
        let mut data = vec![0xDE; 4096];
        for i in (0..data.len()).step_by(7) {
            data[i] = (i % 256) as u8;
        }
        let (entries, _) = carve_mft_entries(&data);
        assert_eq!(entries.len(), 0);
    }

    // ─── Test: single valid entry ────────────────────────────────────────────

    #[test]
    fn test_carve_single_entry() {
        let entry = build_mft_entry(42, 3, 5, 1, "malware.exe", 0x01);
        let (entries, stats) = carve_mft_entries(&entry);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].entry_number, 42);
        assert_eq!(entries[0].sequence_number, 3);
        assert_eq!(entries[0].filename, "malware.exe");
        assert_eq!(entries[0].parent_entry, 5);
        assert_eq!(entries[0].parent_sequence, 1);
        assert!(entries[0].is_in_use);
        assert!(!entries[0].is_directory);
        assert_eq!(entries[0].offset, 0);
        assert_eq!(stats.entries_carved, 1);
        assert_eq!(stats.candidates_examined, 1);
    }

    #[test]
    fn test_carve_directory_entry() {
        let entry = build_mft_entry(100, 1, 5, 1, "Documents", 0x03); // in-use + directory
        let (entries, _) = carve_mft_entries(&entry);

        assert_eq!(entries.len(), 1);
        assert!(entries[0].is_directory);
        assert!(entries[0].is_in_use);
        assert_eq!(entries[0].filename, "Documents");
    }

    #[test]
    fn test_carve_deleted_entry() {
        // Flags = 0 means not in use (deleted)
        let entry = build_mft_entry(200, 5, 100, 2, "deleted.tmp", 0x00);
        let (entries, _) = carve_mft_entries(&entry);

        assert_eq!(entries.len(), 1);
        assert!(!entries[0].is_in_use);
        assert_eq!(entries[0].filename, "deleted.tmp");
    }

    // ─── Test: entry embedded in garbage ─────────────────────────────────────

    #[test]
    fn test_carve_entry_embedded_in_garbage() {
        // 2KB garbage prefix (must be 1024-byte aligned)
        let mut data = vec![0xAA; 2048];
        let entry = build_mft_entry(77, 2, 5, 1, "evidence.docx", 0x01);
        let entry_offset = data.len();
        data.extend_from_slice(&entry);
        data.extend_from_slice(&vec![0xBB; 2048]); // garbage suffix

        let (entries, stats) = carve_mft_entries(&data);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].offset, entry_offset);
        assert_eq!(entries[0].entry_number, 77);
        assert_eq!(entries[0].filename, "evidence.docx");
        assert!(stats.candidates_examined >= 1);
    }

    // ─── Test: multiple entries with gaps ────────────────────────────────────

    #[test]
    fn test_carve_multiple_entries_with_gaps() {
        let mut data = Vec::new();

        // First entry at offset 0
        let e1 = build_mft_entry(10, 1, 5, 1, "first.txt", 0x01);
        data.extend_from_slice(&e1);

        // 2KB gap (2 × 1024, no "FILE" signature)
        data.extend_from_slice(&vec![0x00; 2048]);

        // Second entry at offset 3072
        let e2 = build_mft_entry(20, 2, 10, 1, "second.doc", 0x01);
        let e2_offset = data.len();
        data.extend_from_slice(&e2);

        // Third entry immediately after
        let e3 = build_mft_entry(30, 1, 5, 1, "third.pdf", 0x03);
        let e3_offset = data.len();
        data.extend_from_slice(&e3);

        let (entries, stats) = carve_mft_entries(&data);

        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].offset, 0);
        assert_eq!(entries[0].filename, "first.txt");
        assert_eq!(entries[1].offset, e2_offset);
        assert_eq!(entries[1].filename, "second.doc");
        assert_eq!(entries[2].offset, e3_offset);
        assert_eq!(entries[2].filename, "third.pdf");
        assert_eq!(stats.entries_carved, 3);
    }

    // ─── Test: invalid entries rejected ──────────────────────────────────────

    #[test]
    fn test_carve_rejects_zero_sequence() {
        // Sequence number 0 is technically invalid for a carved entry
        // (means the entry was never used)
        let mut entry = build_mft_entry(42, 0, 5, 1, "test.txt", 0x01);
        // sequence = 0 at offset 16
        entry[16..18].copy_from_slice(&0u16.to_le_bytes());

        let (entries, stats) = carve_mft_entries(&entry);
        assert_eq!(entries.len(), 0);
        assert!(stats.rejected > 0);
    }

    #[test]
    fn test_carve_rejects_bad_first_attr_offset() {
        let mut entry = build_mft_entry(42, 1, 5, 1, "test.txt", 0x01);
        // Set first attribute offset to something past the entry
        entry[20..22].copy_from_slice(&2000u16.to_le_bytes());

        let (entries, stats) = carve_mft_entries(&entry);
        assert_eq!(entries.len(), 0);
        assert!(stats.rejected > 0);
    }

    #[test]
    fn test_carve_rejects_no_filename_attr() {
        let mut entry = vec![0u8; MFT_ENTRY_SIZE];
        entry[0..4].copy_from_slice(&FILE_SIGNATURE);
        entry[4..6].copy_from_slice(&48u16.to_le_bytes());
        entry[6..8].copy_from_slice(&3u16.to_le_bytes());
        entry[16..18].copy_from_slice(&1u16.to_le_bytes()); // sequence = 1
        entry[20..22].copy_from_slice(&56u16.to_le_bytes()); // first attr offset
        entry[22..24].copy_from_slice(&0x01u16.to_le_bytes()); // in-use
        entry[24..28].copy_from_slice(&512u32.to_le_bytes());
        entry[28..32].copy_from_slice(&1024u32.to_le_bytes());
        entry[44..48].copy_from_slice(&42u32.to_le_bytes());
        // Put end-of-attributes immediately (no FILE_NAME attribute)
        entry[56..60].copy_from_slice(&ATTR_END_MARKER.to_le_bytes());

        let (entries, stats) = carve_mft_entries(&entry);
        assert_eq!(entries.len(), 0);
        assert!(stats.rejected > 0);
    }

    #[test]
    fn test_carve_rejects_truncated_data() {
        // Less than 1024 bytes with FILE signature
        let mut data = vec![0u8; 512];
        data[0..4].copy_from_slice(&FILE_SIGNATURE);
        data[16..18].copy_from_slice(&1u16.to_le_bytes());

        let (entries, _) = carve_mft_entries(&data);
        assert_eq!(entries.len(), 0);
    }

    // ─── Test: non-aligned FILE signature ignored ────────────────────────────

    #[test]
    fn test_carve_ignores_non_aligned_file_signature() {
        let mut data = vec![0u8; 2048];
        // Put "FILE" at offset 500 (not 1024-byte aligned)
        data[500..504].copy_from_slice(&FILE_SIGNATURE);
        data[516..518].copy_from_slice(&1u16.to_le_bytes()); // fake sequence

        let (entries, _) = carve_mft_entries(&data);
        assert_eq!(entries.len(), 0);
    }

    // ─── Test: Win32 name preferred over DOS name ────────────────────────────

    #[test]
    fn test_carve_prefers_win32_over_dos_name() {
        let mut buf = vec![0u8; MFT_ENTRY_SIZE];

        // FILE header
        buf[0..4].copy_from_slice(&FILE_SIGNATURE);
        buf[4..6].copy_from_slice(&48u16.to_le_bytes());
        buf[6..8].copy_from_slice(&3u16.to_le_bytes());
        buf[8..16].copy_from_slice(&1u64.to_le_bytes());
        buf[16..18].copy_from_slice(&1u16.to_le_bytes());
        buf[18..20].copy_from_slice(&1u16.to_le_bytes());
        let first_attr: u16 = 56;
        buf[20..22].copy_from_slice(&first_attr.to_le_bytes());
        buf[22..24].copy_from_slice(&0x01u16.to_le_bytes());
        buf[24..28].copy_from_slice(&800u32.to_le_bytes());
        buf[28..32].copy_from_slice(&1024u32.to_le_bytes());
        buf[44..48].copy_from_slice(&99u32.to_le_bytes());
        buf[48..50].copy_from_slice(&0x0001u16.to_le_bytes());

        // First FILE_NAME: DOS name (namespace=2)
        let attr1_size =
            write_filename_attr(&mut buf, first_attr as usize, 5, 1, "IMPORT~1.XLS", NS_DOS);

        // Remove end marker from first attr so we can chain another
        let attr2_start = first_attr as usize + attr1_size;
        // Second FILE_NAME: Win32 name (namespace=1)
        write_filename_attr(
            &mut buf,
            attr2_start,
            5,
            1,
            "Important Spreadsheet.xlsx",
            NS_WIN32,
        );

        let (entries, _) = carve_mft_entries(&buf);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].filename, "Important Spreadsheet.xlsx");
    }

    // ─── Test: stats tracking ────────────────────────────────────────────────

    #[test]
    fn test_carving_stats() {
        let mut data = Vec::new();

        // Valid entry
        data.extend_from_slice(&build_mft_entry(10, 1, 5, 1, "valid.txt", 0x01));

        // Entry with zero sequence (will be rejected)
        let mut bad = build_mft_entry(20, 0, 5, 1, "bad.txt", 0x01);
        bad[16..18].copy_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&bad);

        let (_, stats) = carve_mft_entries(&data);

        assert_eq!(stats.bytes_scanned, data.len());
        assert_eq!(stats.candidates_examined, 2); // both have FILE signature
        assert_eq!(stats.entries_carved, 1);
        assert_eq!(stats.rejected, 1);
    }

    #[test]
    fn test_stats_default() {
        let stats = MftCarvingStats::default();
        assert_eq!(stats.bytes_scanned, 0);
        assert_eq!(stats.candidates_examined, 0);
        assert_eq!(stats.entries_carved, 0);
        assert_eq!(stats.rejected, 0);
    }

    // ─── Coverage tests for uncovered lines ─────────────────────────────

    #[test]
    fn test_carve_corrupt_attr_chain_short_attr_len() {
        // Covers line 149: break on attr_len < 8 (corrupt attribute chain)
        let mut buf = vec![0u8; MFT_ENTRY_SIZE];

        // FILE header
        buf[0..4].copy_from_slice(&FILE_SIGNATURE);
        buf[4..6].copy_from_slice(&48u16.to_le_bytes());
        buf[6..8].copy_from_slice(&3u16.to_le_bytes());
        buf[8..16].copy_from_slice(&1u64.to_le_bytes());
        buf[16..18].copy_from_slice(&1u16.to_le_bytes()); // sequence
        buf[18..20].copy_from_slice(&1u16.to_le_bytes());
        let first_attr: u16 = 56;
        buf[20..22].copy_from_slice(&first_attr.to_le_bytes());
        buf[22..24].copy_from_slice(&0x01u16.to_le_bytes()); // in-use
        buf[24..28].copy_from_slice(&512u32.to_le_bytes());
        buf[28..32].copy_from_slice(&1024u32.to_le_bytes());
        buf[44..48].copy_from_slice(&42u32.to_le_bytes());
        buf[48..50].copy_from_slice(&0x0001u16.to_le_bytes());

        // Write an attribute with attr_len = 4 (< 8, triggers line 149 break)
        buf[56..60].copy_from_slice(&0x10u32.to_le_bytes()); // some attr_type != END
        buf[60..64].copy_from_slice(&4u32.to_le_bytes()); // attr_len = 4 < 8

        let (entries, stats) = carve_mft_entries(&buf);
        assert_eq!(entries.len(), 0);
        assert!(stats.rejected > 0);
    }

    #[test]
    fn test_carve_attr_exceeds_entry_boundary() {
        // Covers line 149 variant: attr_offset + attr_len > MFT_ENTRY_SIZE
        let mut buf = vec![0u8; MFT_ENTRY_SIZE];

        buf[0..4].copy_from_slice(&FILE_SIGNATURE);
        buf[4..6].copy_from_slice(&48u16.to_le_bytes());
        buf[6..8].copy_from_slice(&3u16.to_le_bytes());
        buf[8..16].copy_from_slice(&1u64.to_le_bytes());
        buf[16..18].copy_from_slice(&1u16.to_le_bytes());
        buf[18..20].copy_from_slice(&1u16.to_le_bytes());
        let first_attr: u16 = 56;
        buf[20..22].copy_from_slice(&first_attr.to_le_bytes());
        buf[22..24].copy_from_slice(&0x01u16.to_le_bytes());
        buf[24..28].copy_from_slice(&512u32.to_le_bytes());
        buf[28..32].copy_from_slice(&1024u32.to_le_bytes());
        buf[44..48].copy_from_slice(&42u32.to_le_bytes());
        buf[48..50].copy_from_slice(&0x0001u16.to_le_bytes());

        // Attribute at offset 56 with length that extends past entry
        buf[56..60].copy_from_slice(&0x10u32.to_le_bytes()); // attr_type
        buf[60..64].copy_from_slice(&2000u32.to_le_bytes()); // attr_len > remaining space

        let (entries, stats) = carve_mft_entries(&buf);
        assert_eq!(entries.len(), 0);
        assert!(stats.rejected > 0);
    }

    #[test]
    fn test_carve_non_resident_filename_attr_skipped() {
        // Covers line 154-155: non_resident != 0 skips the FILE_NAME attribute.
        // The entry has a FILE_NAME attribute with non_resident flag set,
        // so it's skipped. No filename is found, entry is rejected.
        let mut buf = vec![0u8; MFT_ENTRY_SIZE];

        buf[0..4].copy_from_slice(&FILE_SIGNATURE);
        buf[4..6].copy_from_slice(&48u16.to_le_bytes());
        buf[6..8].copy_from_slice(&3u16.to_le_bytes());
        buf[8..16].copy_from_slice(&1u64.to_le_bytes());
        buf[16..18].copy_from_slice(&1u16.to_le_bytes());
        buf[18..20].copy_from_slice(&1u16.to_le_bytes());
        let first_attr: u16 = 56;
        buf[20..22].copy_from_slice(&first_attr.to_le_bytes());
        buf[22..24].copy_from_slice(&0x01u16.to_le_bytes());
        buf[24..28].copy_from_slice(&512u32.to_le_bytes());
        buf[28..32].copy_from_slice(&1024u32.to_le_bytes());
        buf[44..48].copy_from_slice(&42u32.to_le_bytes());
        buf[48..50].copy_from_slice(&0x0001u16.to_le_bytes());

        // FILE_NAME attribute with non_resident = 1
        let attr_size = 96u32;
        buf[56..60].copy_from_slice(&ATTR_FILE_NAME.to_le_bytes()); // FILE_NAME type
        buf[60..64].copy_from_slice(&attr_size.to_le_bytes());
        buf[64] = 1; // non_resident = 1 (should be skipped)

        // End marker after this attribute
        let end_off = 56 + attr_size as usize;
        buf[end_off..end_off + 4].copy_from_slice(&ATTR_END_MARKER.to_le_bytes());

        let (entries, stats) = carve_mft_entries(&buf);
        assert_eq!(entries.len(), 0);
        assert!(stats.rejected > 0);
    }

    #[test]
    fn test_carve_filename_attr_content_too_short() {
        // Covers line 211 in parse_filename_attr: fn_start + 66 > entry.len() || content_size < 66
        let mut buf = vec![0u8; MFT_ENTRY_SIZE];

        buf[0..4].copy_from_slice(&FILE_SIGNATURE);
        buf[4..6].copy_from_slice(&48u16.to_le_bytes());
        buf[6..8].copy_from_slice(&3u16.to_le_bytes());
        buf[8..16].copy_from_slice(&1u64.to_le_bytes());
        buf[16..18].copy_from_slice(&1u16.to_le_bytes());
        buf[18..20].copy_from_slice(&1u16.to_le_bytes());
        let first_attr: u16 = 56;
        buf[20..22].copy_from_slice(&first_attr.to_le_bytes());
        buf[22..24].copy_from_slice(&0x01u16.to_le_bytes());
        buf[24..28].copy_from_slice(&512u32.to_le_bytes());
        buf[28..32].copy_from_slice(&1024u32.to_le_bytes());
        buf[44..48].copy_from_slice(&42u32.to_le_bytes());
        buf[48..50].copy_from_slice(&0x0001u16.to_le_bytes());

        // FILE_NAME attribute with content_size < 66
        let attr_size = 48u32; // small attribute
        buf[56..60].copy_from_slice(&ATTR_FILE_NAME.to_le_bytes());
        buf[60..64].copy_from_slice(&attr_size.to_le_bytes());
        buf[64] = 0; // resident
                     // content_size at attr_offset + 16
        buf[72..76].copy_from_slice(&30u32.to_le_bytes()); // content_size = 30 < 66
                                                           // content_offset at attr_offset + 20
        buf[76..78].copy_from_slice(&24u16.to_le_bytes());

        // End marker
        let end_off = 56 + attr_size as usize;
        buf[end_off..end_off + 4].copy_from_slice(&ATTR_END_MARKER.to_le_bytes());

        let (entries, stats) = carve_mft_entries(&buf);
        assert_eq!(entries.len(), 0);
        assert!(stats.rejected > 0);
    }

    #[test]
    fn test_carve_filename_attr_zero_name_len() {
        // Covers line 224 in parse_filename_attr: name_len_chars == 0
        let mut buf = vec![0u8; MFT_ENTRY_SIZE];

        buf[0..4].copy_from_slice(&FILE_SIGNATURE);
        buf[4..6].copy_from_slice(&48u16.to_le_bytes());
        buf[6..8].copy_from_slice(&3u16.to_le_bytes());
        buf[8..16].copy_from_slice(&1u64.to_le_bytes());
        buf[16..18].copy_from_slice(&1u16.to_le_bytes());
        buf[18..20].copy_from_slice(&1u16.to_le_bytes());
        let first_attr: u16 = 56;
        buf[20..22].copy_from_slice(&first_attr.to_le_bytes());
        buf[22..24].copy_from_slice(&0x01u16.to_le_bytes());
        buf[24..28].copy_from_slice(&512u32.to_le_bytes());
        buf[28..32].copy_from_slice(&1024u32.to_le_bytes());
        buf[44..48].copy_from_slice(&42u32.to_le_bytes());
        buf[48..50].copy_from_slice(&0x0001u16.to_le_bytes());

        // FILE_NAME attribute with content_size >= 66 but name_len_chars = 0
        let content_offset: u16 = 24;
        let content_size = 66u32; // exactly minimum
        let attr_size = (content_offset as u32 + content_size + 7) & !7;
        buf[56..60].copy_from_slice(&ATTR_FILE_NAME.to_le_bytes());
        buf[60..64].copy_from_slice(&attr_size.to_le_bytes());
        buf[64] = 0; // resident
        buf[72..76].copy_from_slice(&content_size.to_le_bytes());
        buf[76..78].copy_from_slice(&content_offset.to_le_bytes());

        // FILE_NAME content at attr_offset + content_offset = 56 + 24 = 80
        let fn_start = 56 + content_offset as usize;
        // Parent reference
        let parent_ref = 5u64 | (1u64 << 48);
        buf[fn_start..fn_start + 8].copy_from_slice(&parent_ref.to_le_bytes());
        // name_len_chars at fn_start + 64
        buf[fn_start + 64] = 0; // zero-length filename
        buf[fn_start + 65] = NS_WIN32_AND_DOS;

        // End marker
        let end_off = 56 + attr_size as usize;
        if end_off + 4 <= buf.len() {
            buf[end_off..end_off + 4].copy_from_slice(&ATTR_END_MARKER.to_le_bytes());
        }

        let (entries, stats) = carve_mft_entries(&buf);
        assert_eq!(entries.len(), 0);
        assert!(stats.rejected > 0);
    }

    #[test]
    fn test_carve_filename_attr_name_exceeds_attr() {
        // Covers line 232 in parse_filename_attr: name_bytes_end > attr boundary
        let mut buf = vec![0u8; MFT_ENTRY_SIZE];

        buf[0..4].copy_from_slice(&FILE_SIGNATURE);
        buf[4..6].copy_from_slice(&48u16.to_le_bytes());
        buf[6..8].copy_from_slice(&3u16.to_le_bytes());
        buf[8..16].copy_from_slice(&1u64.to_le_bytes());
        buf[16..18].copy_from_slice(&1u16.to_le_bytes());
        buf[18..20].copy_from_slice(&1u16.to_le_bytes());
        let first_attr: u16 = 56;
        buf[20..22].copy_from_slice(&first_attr.to_le_bytes());
        buf[22..24].copy_from_slice(&0x01u16.to_le_bytes());
        buf[24..28].copy_from_slice(&512u32.to_le_bytes());
        buf[28..32].copy_from_slice(&1024u32.to_le_bytes());
        buf[44..48].copy_from_slice(&42u32.to_le_bytes());
        buf[48..50].copy_from_slice(&0x0001u16.to_le_bytes());

        // FILE_NAME attribute where filename extends past attr boundary
        let content_offset: u16 = 24;
        let content_size = 70u32; // enough for header but filename will exceed
        let attr_size = (content_offset as u32 + content_size + 7) & !7;
        buf[56..60].copy_from_slice(&ATTR_FILE_NAME.to_le_bytes());
        buf[60..64].copy_from_slice(&attr_size.to_le_bytes());
        buf[64] = 0; // resident
        buf[72..76].copy_from_slice(&content_size.to_le_bytes());
        buf[76..78].copy_from_slice(&content_offset.to_le_bytes());

        let fn_start = 56 + content_offset as usize;
        let parent_ref = 5u64 | (1u64 << 48);
        buf[fn_start..fn_start + 8].copy_from_slice(&parent_ref.to_le_bytes());
        // name_len_chars = 100 chars = 200 bytes, way more than attr_size allows
        buf[fn_start + 64] = 100;
        buf[fn_start + 65] = NS_WIN32_AND_DOS;

        let end_off = 56 + attr_size as usize;
        if end_off + 4 <= buf.len() {
            buf[end_off..end_off + 4].copy_from_slice(&ATTR_END_MARKER.to_le_bytes());
        }

        let (entries, stats) = carve_mft_entries(&buf);
        assert_eq!(entries.len(), 0);
        assert!(stats.rejected > 0);
    }

    #[test]
    fn test_carve_dos_name_not_replaced_by_posix() {
        // Covers lines 166-168: the dominated logic for namespace preference.
        // First attr has Win32 name, second has DOS name - Win32 should be kept.
        let mut buf = vec![0u8; MFT_ENTRY_SIZE];

        buf[0..4].copy_from_slice(&FILE_SIGNATURE);
        buf[4..6].copy_from_slice(&48u16.to_le_bytes());
        buf[6..8].copy_from_slice(&3u16.to_le_bytes());
        buf[8..16].copy_from_slice(&1u64.to_le_bytes());
        buf[16..18].copy_from_slice(&1u16.to_le_bytes());
        buf[18..20].copy_from_slice(&1u16.to_le_bytes());
        let first_attr: u16 = 56;
        buf[20..22].copy_from_slice(&first_attr.to_le_bytes());
        buf[22..24].copy_from_slice(&0x01u16.to_le_bytes());
        buf[24..28].copy_from_slice(&800u32.to_le_bytes());
        buf[28..32].copy_from_slice(&1024u32.to_le_bytes());
        buf[44..48].copy_from_slice(&99u32.to_le_bytes());
        buf[48..50].copy_from_slice(&0x0001u16.to_le_bytes());

        // First FILE_NAME: Win32 (namespace=1) - should be the preferred one
        let attr1_size = write_filename_attr(
            &mut buf,
            first_attr as usize,
            5,
            1,
            "LongFileName.xlsx",
            NS_WIN32,
        );

        // Second FILE_NAME: DOS (namespace=2) - should NOT replace Win32
        let attr2_start = first_attr as usize + attr1_size;
        write_filename_attr(&mut buf, attr2_start, 5, 1, "LONGFI~1.XLS", NS_DOS);

        let (entries, _) = carve_mft_entries(&buf);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].filename, "LongFileName.xlsx");
    }

    #[test]
    fn test_carve_resident_filename_parse_none_then_valid() {
        // Covers the fall-through after a resident ($FILE_NAME, non_resident==0)
        // attribute whose parse_filename_attr returns None: the attribute walk
        // must continue and pick up a subsequent valid $FILE_NAME.
        let mut buf = vec![0u8; MFT_ENTRY_SIZE];

        buf[0..4].copy_from_slice(&FILE_SIGNATURE);
        buf[4..6].copy_from_slice(&48u16.to_le_bytes());
        buf[6..8].copy_from_slice(&3u16.to_le_bytes());
        buf[8..16].copy_from_slice(&1u64.to_le_bytes());
        buf[16..18].copy_from_slice(&1u16.to_le_bytes());
        buf[18..20].copy_from_slice(&1u16.to_le_bytes());
        let first_attr: u16 = 56;
        buf[20..22].copy_from_slice(&first_attr.to_le_bytes());
        buf[22..24].copy_from_slice(&0x01u16.to_le_bytes());
        buf[24..28].copy_from_slice(&800u32.to_le_bytes());
        buf[28..32].copy_from_slice(&1024u32.to_le_bytes());
        buf[44..48].copy_from_slice(&99u32.to_le_bytes());
        buf[48..50].copy_from_slice(&0x0001u16.to_le_bytes());

        // First $FILE_NAME: resident (non_resident == 0) but content_size < 66,
        // so parse_filename_attr returns None. attr_len is valid so the walk
        // continues to the next attribute.
        let bad_attr_size = 48usize;
        buf[56..60].copy_from_slice(&ATTR_FILE_NAME.to_le_bytes());
        buf[60..64].copy_from_slice(&(bad_attr_size as u32).to_le_bytes());
        buf[64] = 0; // resident
        buf[72..76].copy_from_slice(&30u32.to_le_bytes()); // content_size = 30 < 66
        buf[76..78].copy_from_slice(&24u16.to_le_bytes()); // content_offset

        // Second $FILE_NAME: valid resident attribute that parses successfully.
        let good_start = 56 + bad_attr_size;
        write_filename_attr(&mut buf, good_start, 5, 1, "recovered.txt", NS_WIN32);

        let (entries, _) = carve_mft_entries(&buf);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].filename, "recovered.txt");
    }

    // ─── Test: preserves all fields ──────────────────────────────────────────

    #[test]
    fn test_carve_preserves_all_fields() {
        let entry = build_mft_entry(12345, 7, 999, 3, "evidence.xlsx", 0x03);
        let (entries, _) = carve_mft_entries(&entry);

        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.entry_number, 12345);
        assert_eq!(e.sequence_number, 7);
        assert_eq!(e.parent_entry, 999);
        assert_eq!(e.parent_sequence, 3);
        assert_eq!(e.filename, "evidence.xlsx");
        assert!(e.is_directory);
        assert!(e.is_in_use);
        assert_eq!(e.offset, 0);
    }

    #[test]
    fn carve_filename_attr_at_entry_boundary_does_not_panic() {
        // Regression: a crafted MFT entry whose attribute walk lands a
        // `$FILE_NAME` attribute at offset `MFT_ENTRY_SIZE - 8` (1016) made the
        // loop guard `attr_offset + 8 <= MFT_ENTRY_SIZE` true while the
        // non-resident-flag read `entry[attr_offset + 8]` indexed `entry[1024]`,
        // one past the end — an out-of-bounds panic on attacker-controlled input.
        let mut entry = vec![0u8; MFT_ENTRY_SIZE];
        entry[0..4].copy_from_slice(&FILE_SIGNATURE);
        entry[16..18].copy_from_slice(&1u16.to_le_bytes()); // sequence_number != 0
        entry[20..22].copy_from_slice(&48u16.to_le_bytes()); // first_attr_offset
                                                             // First attribute at 48: a non-`$FILE_NAME` type, length 968 → next
                                                             // attribute lands at 48 + 968 = 1016.
        entry[48..52].copy_from_slice(&0x10u32.to_le_bytes()); // $STANDARD_INFORMATION
        entry[52..56].copy_from_slice(&968u32.to_le_bytes());
        // Second attribute at 1016: `$FILE_NAME`, length 8 — passes the
        // `attr_offset + attr_len <= MFT_ENTRY_SIZE` guard (1016 + 8 == 1024),
        // then the non-resident-flag read at 1016 + 8 == 1024 must NOT panic.
        entry[1016..1020].copy_from_slice(&ATTR_FILE_NAME.to_le_bytes());
        entry[1020..1024].copy_from_slice(&8u32.to_le_bytes());

        // Must return without panicking; no valid filename is extractable.
        let (entries, _) = carve_mft_entries(&entry);
        assert!(entries.is_empty());
    }
}
