//! Directory index B-tree: `$INDEX_ROOT` (resident) and the `INDX` buffers of
//! `$INDEX_ALLOCATION` (non-resident).
//!
//! A directory's children are kept in a B-tree of *index entries*, each holding
//! a file reference and an embedded `$FILE_NAME`. Small directories fit entirely
//! in the resident `$INDEX_ROOT`; larger ones spill into fixed-size `INDX`
//! buffers (each `INDX`-signed and protected by the same update-sequence fixup
//! as an MFT record).
//!
//! Entry, node, and stream bounds are all validated against the buffer; a
//! crafted index cannot drive an out-of-bounds read or a non-terminating walk.

use crate::error::{NtfsError, Result};
use crate::file_name::{FileName, FileReference};
use crate::record::apply_fixup;

/// `INDX` index-buffer signature.
// TODO(forensicnomicon): migrate to forensicnomicon::ntfs::SIGNATURE_INDX.
const INDX_SIGNATURE: [u8; 4] = *b"INDX";

/// Index-header field offsets (relative to the index header start).
mod ih {
    pub const FIRST_ENTRY: usize = 0x00;
    pub const TOTAL_SIZE: usize = 0x04;
    pub const FLAGS: usize = 0x0C;
}
/// Index-header flag: this index has an `$INDEX_ALLOCATION` (it is "large").
const IH_FLAG_LARGE: u32 = 0x01;
/// Bytes of the fixed index header.
const INDEX_HEADER_LEN: usize = 0x10;

/// Index-entry field offsets.
mod ie {
    pub const FILE_REFERENCE: usize = 0x00;
    pub const ENTRY_LENGTH: usize = 0x08;
    pub const STREAM_LENGTH: usize = 0x0A;
    pub const FLAGS: usize = 0x0C;
    pub const STREAM: usize = 0x10;
}
/// Entry flag: the entry points to a child node (its last 8 bytes are a VCN).
const IE_FLAG_SUBNODE: u8 = 0x01;
/// Entry flag: this is the final entry in the node.
const IE_FLAG_LAST: u8 = 0x02;
/// Minimum entry size (the fixed entry header).
const ENTRY_MIN: usize = 0x10;
/// `$INDEX_ROOT` fixed header before its index header.
const ROOT_HEADER_LEN: usize = 0x10;
/// `INDX` buffer fixed header before its index header.
const INDX_HEADER_LEN: usize = 0x18;
/// Loop cap on entries per node.
const MAX_ENTRIES: usize = 1 << 20;

/// One directory index entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    /// File reference of the entry's target (0 for the terminal entry).
    pub file_reference: FileReference,
    /// The embedded `$FILE_NAME`, or `None` for the terminal entry.
    pub file_name: Option<FileName>,
    /// VCN of the child index buffer, if this entry has a sub-node.
    pub child_vcn: Option<u64>,
}

/// A parsed `$INDEX_ROOT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexRoot {
    /// The attribute type this index is keyed on (usually `$FILE_NAME` = 0x30).
    pub indexed_type: u32,
    /// `true` if the directory also has an `$INDEX_ALLOCATION`.
    pub is_large: bool,
    /// The entries held directly in the root node.
    pub entries: Vec<IndexEntry>,
}

impl IndexRoot {
    /// Parse an `$INDEX_ROOT` attribute value.
    ///
    /// # Errors
    ///
    /// [`NtfsError::TooShort`] / [`NtfsError::BadIndex`] on malformed input.
    pub fn parse(content: &[u8]) -> Result<IndexRoot> {
        if content.len() < ROOT_HEADER_LEN + INDEX_HEADER_LEN {
            return Err(NtfsError::TooShort {
                what: "$INDEX_ROOT",
                need: ROOT_HEADER_LEN + INDEX_HEADER_LEN,
                got: content.len(),
            });
        }
        let indexed_type = u32::from_le_bytes(content[0x00..0x04].try_into().unwrap());
        let (entries, is_large) = parse_index_header(content, ROOT_HEADER_LEN)?;
        Ok(IndexRoot {
            indexed_type,
            is_large,
            entries,
        })
    }
}

/// Parse the index header at `base` and the entries it points to.
/// Returns the entries and the "large index" flag.
fn parse_index_header(node: &[u8], base: usize) -> Result<(Vec<IndexEntry>, bool)> {
    let header_end = base
        .checked_add(INDEX_HEADER_LEN)
        .ok_or(NtfsError::BadIndex("index header overflow"))?;
    if header_end > node.len() {
        return Err(NtfsError::BadIndex("index header past buffer"));
    }
    let u32at = |o: usize| u32::from_le_bytes(node[base + o..base + o + 4].try_into().unwrap());
    let first_entry = u32at(ih::FIRST_ENTRY) as usize;
    let total_size = u32at(ih::TOTAL_SIZE) as usize;
    let is_large = u32at(ih::FLAGS) & IH_FLAG_LARGE != 0;

    let start = base
        .checked_add(first_entry)
        .ok_or(NtfsError::BadIndex("first-entry offset overflow"))?;
    let end = base
        .checked_add(total_size)
        .ok_or(NtfsError::BadIndex("total-size overflow"))?;
    if start < header_end || end > node.len() || start > end {
        return Err(NtfsError::BadIndex("index entry region out of bounds"));
    }
    let entries = parse_entries(node, start, end)?;
    Ok((entries, is_large))
}

/// Parse the entries in the byte range `[start, end)` of `node`.
///
/// # Errors
///
/// [`NtfsError::BadIndex`] for an undersized / non-advancing entry, or a stream
/// or sub-node VCN that would read outside the entry.
pub fn parse_entries(node: &[u8], start: usize, end: usize) -> Result<Vec<IndexEntry>> {
    if end > node.len() || start > end {
        return Err(NtfsError::BadIndex("entry region out of bounds"));
    }
    let mut entries = Vec::new();
    let mut pos = start;

    for _ in 0..MAX_ENTRIES {
        if pos + ENTRY_MIN > end {
            break; // no room for another entry header
        }
        let entry_length = u16::from_le_bytes(
            node[pos + ie::ENTRY_LENGTH..pos + ie::ENTRY_LENGTH + 2]
                .try_into()
                .unwrap(),
        ) as usize;
        if entry_length < ENTRY_MIN {
            return Err(NtfsError::BadIndex("entry length below minimum"));
        }
        let entry_end = pos
            .checked_add(entry_length)
            .ok_or(NtfsError::BadIndex("entry length overflow"))?;
        if entry_end > end {
            return Err(NtfsError::BadIndex("entry extends past node"));
        }

        let flags = node[pos + ie::FLAGS];
        let is_last = flags & IE_FLAG_LAST != 0;
        let file_reference = FileReference::from_u64(u64::from_le_bytes(
            node[pos + ie::FILE_REFERENCE..pos + ie::FILE_REFERENCE + 8]
                .try_into()
                .unwrap(),
        ));

        let child_vcn = if flags & IE_FLAG_SUBNODE != 0 {
            if entry_end < pos + ENTRY_MIN + 8 {
                return Err(NtfsError::BadIndex("sub-node VCN does not fit in entry"));
            }
            let vcn_pos = entry_end - 8;
            Some(u64::from_le_bytes(
                node[vcn_pos..vcn_pos + 8].try_into().unwrap(),
            ))
        } else {
            None
        };

        let file_name = if is_last {
            None
        } else {
            let stream_length = u16::from_le_bytes(
                node[pos + ie::STREAM_LENGTH..pos + ie::STREAM_LENGTH + 2]
                    .try_into()
                    .unwrap(),
            ) as usize;
            let s_start = pos + ie::STREAM;
            let s_end = s_start
                .checked_add(stream_length)
                .ok_or(NtfsError::BadIndex("stream length overflow"))?;
            if s_end > entry_end {
                return Err(NtfsError::BadIndex("stream extends past entry"));
            }
            Some(FileName::parse(&node[s_start..s_end])?)
        };

        entries.push(IndexEntry {
            file_reference,
            file_name,
            child_vcn,
        });

        if is_last {
            break;
        }
        pos = entry_end;
    }

    Ok(entries)
}

/// Parse one `INDX` index buffer: validate the signature, apply the
/// update-sequence fixup in place, and return its entries.
///
/// # Errors
///
/// [`NtfsError::TooShort`], [`NtfsError::BadIndex`] (bad signature), or a fixup
/// / entry error.
pub fn parse_index_buffer(
    buffer: &mut [u8],
    index_record_size: usize,
    sector_size: usize,
) -> Result<Vec<IndexEntry>> {
    if buffer.len() < index_record_size || index_record_size < INDX_HEADER_LEN + INDEX_HEADER_LEN {
        return Err(NtfsError::TooShort {
            what: "INDX buffer",
            need: index_record_size.max(INDX_HEADER_LEN + INDEX_HEADER_LEN),
            got: buffer.len(),
        });
    }
    let buf = &mut buffer[..index_record_size];
    if buf[0..4] != INDX_SIGNATURE {
        return Err(NtfsError::BadIndex("INDX signature missing"));
    }
    apply_fixup(buf, sector_size)?;
    let (entries, _is_large) = parse_index_header(buf, INDX_HEADER_LEN)?;
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensicnomicon::ntfs::filename_namespace;

    fn fname(parent: u64, name: &str) -> Vec<u8> {
        let units: Vec<u16> = name.encode_utf16().collect();
        let mut c = vec![0u8; 0x42 + units.len() * 2];
        c[0..8].copy_from_slice(&parent.to_le_bytes());
        c[0x40] = units.len() as u8;
        c[0x41] = filename_namespace::WIN32;
        for (i, u) in units.iter().enumerate() {
            c[0x42 + i * 2..0x42 + i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
        c
    }

    fn entry(file_ref: u64, name: &str) -> Vec<u8> {
        let fnc = fname(5, name);
        let len = (ie::STREAM + fnc.len() + 7) & !7;
        let mut e = vec![0u8; len];
        e[ie::FILE_REFERENCE..ie::FILE_REFERENCE + 8].copy_from_slice(&file_ref.to_le_bytes());
        e[ie::ENTRY_LENGTH..ie::ENTRY_LENGTH + 2].copy_from_slice(&(len as u16).to_le_bytes());
        e[ie::STREAM_LENGTH..ie::STREAM_LENGTH + 2]
            .copy_from_slice(&(fnc.len() as u16).to_le_bytes());
        e[ie::FLAGS] = 0;
        e[ie::STREAM..ie::STREAM + fnc.len()].copy_from_slice(&fnc);
        e
    }

    fn end_entry() -> Vec<u8> {
        let mut e = vec![0u8; ENTRY_MIN];
        e[ie::ENTRY_LENGTH..ie::ENTRY_LENGTH + 2]
            .copy_from_slice(&(ENTRY_MIN as u16).to_le_bytes());
        e[ie::FLAGS] = IE_FLAG_LAST;
        e
    }

    fn make_root(is_large: bool, entries: &[Vec<u8>]) -> Vec<u8> {
        let blob: Vec<u8> = entries.concat();
        let total = (INDEX_HEADER_LEN + blob.len()) as u32;
        let mut c = vec![0u8; ROOT_HEADER_LEN + INDEX_HEADER_LEN + blob.len()];
        c[0x00..0x04].copy_from_slice(&0x30u32.to_le_bytes()); // indexed type = $FILE_NAME
        let base = ROOT_HEADER_LEN;
        c[base + ih::FIRST_ENTRY..base + ih::FIRST_ENTRY + 4]
            .copy_from_slice(&(INDEX_HEADER_LEN as u32).to_le_bytes());
        c[base + ih::TOTAL_SIZE..base + ih::TOTAL_SIZE + 4].copy_from_slice(&total.to_le_bytes());
        c[base + ih::FLAGS..base + ih::FLAGS + 4]
            .copy_from_slice(&(if is_large { IH_FLAG_LARGE } else { 0 }).to_le_bytes());
        c[base + INDEX_HEADER_LEN..].copy_from_slice(&blob);
        c
    }

    #[test]
    fn parses_entries_until_last() {
        let node = [entry(11, "alpha.txt"), entry(12, "beta.txt"), end_entry()].concat();
        let es = parse_entries(&node, 0, node.len()).unwrap();
        assert_eq!(es.len(), 3);
        assert_eq!(es[0].file_reference.record_number, 11);
        assert_eq!(es[0].file_name.as_ref().unwrap().name, "alpha.txt");
        assert_eq!(es[1].file_name.as_ref().unwrap().name, "beta.txt");
        assert!(es[2].file_name.is_none()); // terminal entry
    }

    #[test]
    fn parses_small_index_root() {
        let root = make_root(false, &[entry(20, "report.docx"), end_entry()]);
        let ir = IndexRoot::parse(&root).unwrap();
        assert_eq!(ir.indexed_type, 0x30);
        assert!(!ir.is_large);
        assert_eq!(ir.entries.len(), 2);
        assert_eq!(
            ir.entries[0].file_name.as_ref().unwrap().name,
            "report.docx"
        );
    }

    #[test]
    fn large_index_root_flag_detected() {
        let root = make_root(true, &[end_entry()]);
        assert!(IndexRoot::parse(&root).unwrap().is_large);
    }

    #[test]
    fn subnode_vcn_is_read() {
        // A sub-node entry reserves 8 extra bytes after the $FILE_NAME stream
        // for the child VCN (the stream length is unchanged).
        let mut e = entry(30, "dir");
        let new_len = e.len() + 8;
        e.resize(new_len, 0);
        e[ie::ENTRY_LENGTH..ie::ENTRY_LENGTH + 2].copy_from_slice(&(new_len as u16).to_le_bytes());
        e[ie::FLAGS] = IE_FLAG_SUBNODE;
        e[new_len - 8..new_len].copy_from_slice(&7u64.to_le_bytes());
        let node = [e, end_entry()].concat();
        let es = parse_entries(&node, 0, node.len()).unwrap();
        assert_eq!(es[0].child_vcn, Some(7));
        assert_eq!(es[0].file_name.as_ref().unwrap().name, "dir");
    }

    #[test]
    fn parses_indx_buffer_with_fixup() {
        // 512-byte INDX buffer (one sector), entries after the USA.
        let record_size = 512usize;
        let mut b = vec![0u8; record_size];
        b[0..4].copy_from_slice(b"INDX");
        let usa_offset = 0x28u16;
        let usa_count = 2u16; // 1 USN + 1 sector
        b[0x04..0x06].copy_from_slice(&usa_offset.to_le_bytes());
        b[0x06..0x08].copy_from_slice(&usa_count.to_le_bytes());
        // index header at 0x18; entries start at 0x40 (past the USA).
        let base = INDX_HEADER_LEN;
        let first_entry = 0x40 - base; // 0x28
        let blob = [entry(40, "child.bin"), end_entry()].concat();
        let total = (first_entry + blob.len()) as u32;
        b[base + ih::FIRST_ENTRY..base + ih::FIRST_ENTRY + 4]
            .copy_from_slice(&(first_entry as u32).to_le_bytes());
        b[base + ih::TOTAL_SIZE..base + ih::TOTAL_SIZE + 4].copy_from_slice(&total.to_le_bytes());
        b[0x40..0x40 + blob.len()].copy_from_slice(&blob);
        // USA: USN sentinel at the sector tail (510), original 0 in the USA.
        let usn = 0x0001u16;
        b[usa_offset as usize..usa_offset as usize + 2].copy_from_slice(&usn.to_le_bytes());
        b[510..512].copy_from_slice(&usn.to_le_bytes());

        let es = parse_index_buffer(&mut b, record_size, 512).unwrap();
        assert_eq!(es[0].file_name.as_ref().unwrap().name, "child.bin");
    }

    // ── Hardening ─────────────────────────────────────────────────────────────

    #[test]
    fn rejects_undersized_entry() {
        let mut node = vec![0u8; 0x20];
        node[ie::ENTRY_LENGTH..ie::ENTRY_LENGTH + 2].copy_from_slice(&4u16.to_le_bytes()); // < ENTRY_MIN
        assert!(matches!(
            parse_entries(&node, 0, node.len()),
            Err(NtfsError::BadIndex(_))
        ));
    }

    #[test]
    fn rejects_entry_past_node_end() {
        let mut node = vec![0u8; 0x20];
        node[ie::ENTRY_LENGTH..ie::ENTRY_LENGTH + 2].copy_from_slice(&0x100u16.to_le_bytes());
        assert!(matches!(
            parse_entries(&node, 0, node.len()),
            Err(NtfsError::BadIndex(_))
        ));
    }

    #[test]
    fn rejects_indx_bad_signature() {
        let mut b = vec![0u8; 512];
        b[0..4].copy_from_slice(b"BADX");
        assert!(matches!(
            parse_index_buffer(&mut b, 512, 512),
            Err(NtfsError::BadIndex(_))
        ));
    }
}
