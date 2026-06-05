//! [`NtfsFs`] — the top-level reader that ties every layer together over a
//! `Read + Seek` volume.
//!
//! On open it parses the boot sector and bootstraps the `$MFT`'s own data runs
//! (the MFT may be fragmented), so [`NtfsFs::read_record`] can fetch any MFT
//! record by number — fixup applied — wherever it physically lives. From there
//! [`NtfsFs::read_file`] resolves a path by walking the directory B-tree from
//! the root (record 5) and reads the file's unnamed `$DATA`.

use std::io::{Read, Seek, SeekFrom};

use forensicnomicon::ntfs::{attr_types, mft_records};

use crate::attribute::{parse_attributes, Attribute, AttributeBody};
use crate::boot::BootSector;
use crate::data::read_attribute_value;
use crate::error::{NtfsError, Result};
use crate::index::{parse_index_buffer, IndexEntry, IndexRoot};
use crate::record::{apply_fixup, MftRecordHeader};
use crate::runlist::{self, Run};

/// A read-only NTFS filesystem over a seekable volume.
pub struct NtfsFs<R: Read + Seek> {
    reader: R,
    boot: BootSector,
    mft_runs: Vec<Run>,
}

impl<R: Read + Seek> NtfsFs<R> {
    /// Open an NTFS volume: parse the boot sector and the `$MFT`'s data runs.
    ///
    /// # Errors
    ///
    /// Propagates boot-sector, record, and runlist errors.
    pub fn open(reader: R) -> Result<Self> {
        let _ = (reader, SeekFrom::Start(0));
        todo!("NtfsFs::open — GREEN step")
    }

    /// The parsed boot sector.
    #[must_use]
    pub fn boot(&self) -> &BootSector {
        &self.boot
    }

    /// Read MFT record `n` (raw bytes, update-sequence fixup applied).
    ///
    /// # Errors
    ///
    /// [`NtfsError::BadRunlist`] if the record lies outside the MFT, plus
    /// record / fixup errors.
    pub fn read_record(&mut self, n: u64) -> Result<Vec<u8>> {
        let _ = n;
        todo!("NtfsFs::read_record — GREEN step")
    }

    /// List a directory's child entries (those carrying a `$FILE_NAME`).
    ///
    /// # Errors
    ///
    /// [`NtfsError::NotADirectory`] if the record has no `$INDEX_ROOT`, plus
    /// index errors.
    pub fn directory_entries(&mut self, record: &[u8]) -> Result<Vec<IndexEntry>> {
        let _ = (record, IndexRoot::parse as fn(&[u8]) -> _);
        todo!("NtfsFs::directory_entries — GREEN step")
    }

    /// Resolve a `\`- or `/`-separated path to an MFT record number.
    ///
    /// # Errors
    ///
    /// [`NtfsError::NotFound`] for a missing component.
    pub fn resolve_path(&mut self, path: &str) -> Result<u64> {
        let _ = (path, mft_records::ROOT);
        todo!("NtfsFs::resolve_path — GREEN step")
    }

    /// Read a file's unnamed `$DATA` by path.
    ///
    /// # Errors
    ///
    /// [`NtfsError::NotFound`] if the path or its `$DATA` is missing.
    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>> {
        let _ = (path, read_attribute_value::<R> as fn(&mut R, &[u8], &Attribute, u64) -> _);
        todo!("NtfsFs::read_file — GREEN step")
    }
}

/// Extract the unnamed non-resident `$DATA` runlist from a fixed-up record.
fn mft_data_runs(record: &[u8]) -> Result<Vec<Run>> {
    let header = MftRecordHeader::parse(record)?;
    let attrs = parse_attributes(record, header.first_attribute_offset as usize)?;
    for a in &attrs {
        if a.type_code == attr_types::DATA && a.name.is_none() {
            if let AttributeBody::NonResident { runs_offset, .. } = a.body {
                let start = a.offset + runs_offset as usize;
                let end = a.offset + a.length as usize;
                let rl = record
                    .get(start..end)
                    .ok_or(NtfsError::BadAttribute {
                        offset: a.offset,
                        detail: "$MFT runlist out of bounds",
                    })?;
                return runlist::decode(rl);
            }
        }
    }
    Err(NtfsError::BadAttribute {
        offset: 0,
        detail: "$MFT has no non-resident $DATA",
    })
}

/// Read `len` bytes from virtual offset `offset`, mapped through `runs`.
/// Sparse runs read as zeroes.
fn read_virtual<R: Read + Seek>(
    reader: &mut R,
    runs: &[Run],
    cluster_size: u64,
    offset: u64,
    len: u64,
) -> Result<Vec<u8>> {
    let len_usize = usize::try_from(len).map_err(|_| NtfsError::TooLarge { bytes: len })?;
    let mut out: Vec<u8> = Vec::new();
    out.try_reserve_exact(len_usize)
        .map_err(|_| NtfsError::TooLarge { bytes: len })?;

    let mut want = len;
    let mut pos = offset;
    let mut run_base = 0u64;

    for run in runs {
        if want == 0 {
            break;
        }
        let run_bytes = run
            .length
            .checked_mul(cluster_size)
            .ok_or(NtfsError::BadRunlist("run byte length overflow"))?;
        let run_end = run_base
            .checked_add(run_bytes)
            .ok_or(NtfsError::BadRunlist("run end overflow"))?;

        if pos < run_end {
            let within = pos - run_base;
            let take = (run_bytes - within).min(want);
            let take_usize = take as usize;
            match run.lcn {
                None => out.resize(out.len() + take_usize, 0),
                Some(lcn) => {
                    let phys = lcn
                        .checked_mul(cluster_size)
                        .and_then(|b| b.checked_add(within))
                        .ok_or(NtfsError::BadRunlist("physical offset overflow"))?;
                    reader.seek(SeekFrom::Start(phys))?;
                    let s = out.len();
                    out.resize(s + take_usize, 0);
                    reader.read_exact(&mut out[s..])?;
                }
            }
            want -= take;
            pos += take;
        }
        run_base = run_end;
    }

    if want > 0 {
        return Err(NtfsError::BadRunlist("read past end of runs"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const SECTOR: usize = 512;
    const CLUSTER: usize = 512;
    const REC: usize = 1024;
    const MFT_LCN: u64 = 4;

    fn build_boot() -> [u8; 512] {
        let mut b = [0u8; 512];
        b[3..11].copy_from_slice(b"NTFS    ");
        b[0x0B..0x0D].copy_from_slice(&(SECTOR as u16).to_le_bytes());
        b[0x0D] = (CLUSTER / SECTOR) as u8;
        b[0x30..0x38].copy_from_slice(&MFT_LCN.to_le_bytes());
        b[0x38..0x40].copy_from_slice(&(MFT_LCN + 100).to_le_bytes());
        b[0x40] = 0xF6; // -10 ⇒ 2^10 = 1024-byte records
        b[0x44] = 0x01;
        b[510] = 0x55;
        b[511] = 0xAA;
        b
    }

    /// Wrap attribute bytes into a fixup-encoded FILE record.
    fn build_record(flags: u16, attrs: &[u8]) -> Vec<u8> {
        let mut r = vec![0u8; REC];
        r[0..4].copy_from_slice(b"FILE");
        let usa_offset = 0x30u16;
        let usa_count = (REC / SECTOR + 1) as u16;
        r[0x04..0x06].copy_from_slice(&usa_offset.to_le_bytes());
        r[0x06..0x08].copy_from_slice(&usa_count.to_le_bytes());
        let first_attr = 0x38usize;
        r[0x14..0x16].copy_from_slice(&(first_attr as u16).to_le_bytes());
        r[0x16..0x18].copy_from_slice(&flags.to_le_bytes());
        r[0x18..0x1C].copy_from_slice(&((first_attr + attrs.len() + 4) as u32).to_le_bytes());
        r[0x1C..0x20].copy_from_slice(&(REC as u32).to_le_bytes());
        r[first_attr..first_attr + attrs.len()].copy_from_slice(attrs);
        r[first_attr + attrs.len()..first_attr + attrs.len() + 4]
            .copy_from_slice(&attr_types::END.to_le_bytes());
        // Encode the fixup: save each sector tail into the USA, write the USN.
        let usn = 0x0001u16;
        let uo = usa_offset as usize;
        r[uo..uo + 2].copy_from_slice(&usn.to_le_bytes());
        for i in 0..(usa_count as usize - 1) {
            let tail = (i + 1) * SECTOR - 2;
            let orig = [r[tail], r[tail + 1]];
            let usa_pos = uo + 2 + i * 2;
            r[usa_pos..usa_pos + 2].copy_from_slice(&orig);
            r[tail..tail + 2].copy_from_slice(&usn.to_le_bytes());
        }
        r
    }

    fn resident_data(content: &[u8]) -> Vec<u8> {
        attr_resident(attr_types::DATA, None, content)
    }

    fn attr_resident(type_code: u32, name: Option<&str>, content: &[u8]) -> Vec<u8> {
        let name_u: Vec<u16> = name.map(|n| n.encode_utf16().collect()).unwrap_or_default();
        let name_off = 0x18usize;
        let content_off = (name_off + name_u.len() * 2 + 7) & !7;
        let len = (content_off + content.len() + 7) & !7;
        let mut a = vec![0u8; len];
        a[0..4].copy_from_slice(&type_code.to_le_bytes());
        a[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        a[0x09] = name_u.len() as u8;
        a[0x0A..0x0C].copy_from_slice(&(name_off as u16).to_le_bytes());
        a[0x10..0x14].copy_from_slice(&(content.len() as u32).to_le_bytes());
        a[0x14..0x16].copy_from_slice(&(content_off as u16).to_le_bytes());
        for (i, u) in name_u.iter().enumerate() {
            a[name_off + i * 2..name_off + i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
        a[content_off..content_off + content.len()].copy_from_slice(content);
        a
    }

    fn nonresident_data(runs: &[u8], real_size: u64) -> Vec<u8> {
        let runs_off = 0x40usize;
        let len = (runs_off + runs.len() + 7) & !7;
        let mut a = vec![0u8; len];
        a[0..4].copy_from_slice(&attr_types::DATA.to_le_bytes());
        a[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        a[0x08] = 1;
        a[0x0A..0x0C].copy_from_slice(&(runs_off as u16).to_le_bytes());
        a[0x20..0x22].copy_from_slice(&(runs_off as u16).to_le_bytes());
        a[0x28..0x30].copy_from_slice(&real_size.to_le_bytes());
        a[0x30..0x38].copy_from_slice(&real_size.to_le_bytes());
        a[runs_off..runs_off + runs.len()].copy_from_slice(runs);
        a
    }

    fn fname_content(parent_record: u64, name: &str) -> Vec<u8> {
        use forensicnomicon::ntfs::filename_namespace;
        let units: Vec<u16> = name.encode_utf16().collect();
        let mut c = vec![0u8; 0x42 + units.len() * 2];
        let parent_ref = (1u64 << 48) | parent_record;
        c[0..8].copy_from_slice(&parent_ref.to_le_bytes());
        c[0x40] = units.len() as u8;
        c[0x41] = filename_namespace::WIN32;
        for (i, u) in units.iter().enumerate() {
            c[0x42 + i * 2..0x42 + i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
        c
    }

    fn index_entry(target_record: u64, name: &str) -> Vec<u8> {
        let fnc = fname_content(5, name);
        let len = (0x10 + fnc.len() + 7) & !7;
        let mut e = vec![0u8; len];
        let target_ref = (1u64 << 48) | target_record;
        e[0..8].copy_from_slice(&target_ref.to_le_bytes());
        e[0x08..0x0A].copy_from_slice(&(len as u16).to_le_bytes());
        e[0x0A..0x0C].copy_from_slice(&(fnc.len() as u16).to_le_bytes());
        e[0x10..0x10 + fnc.len()].copy_from_slice(&fnc);
        e
    }

    fn index_end() -> Vec<u8> {
        let mut e = vec![0u8; 0x10];
        e[0x08..0x0A].copy_from_slice(&0x10u16.to_le_bytes());
        e[0x0C] = 0x02;
        e
    }

    fn index_root(entries: &[Vec<u8>]) -> Vec<u8> {
        let blob: Vec<u8> = entries.concat();
        let mut content = vec![0u8; 0x10 + 0x10 + blob.len()];
        content[0x00..0x04].copy_from_slice(&attr_types::FILE_NAME.to_le_bytes());
        content[0x10..0x14].copy_from_slice(&0x10u32.to_le_bytes()); // first entry
        content[0x14..0x18].copy_from_slice(&((0x10 + blob.len()) as u32).to_le_bytes()); // total
        content[0x20..0x20 + blob.len()].copy_from_slice(&blob);
        attr_resident(attr_types::INDEX_ROOT, Some("$I30"), &content)
    }

    /// Build a volume: boot + a 7-record MFT (record 0 = $MFT, 5 = root, 6 = file).
    fn build_volume() -> Cursor<Vec<u8>> {
        let num_records = 7usize;
        let mft_clusters = (num_records * REC / CLUSTER) as u64; // 14
        let total_clusters = MFT_LCN + mft_clusters + 2;
        let mut vol = vec![0u8; total_clusters as usize * CLUSTER];
        vol[0..512].copy_from_slice(&build_boot());

        // record 0: $MFT with a non-resident $DATA covering the whole MFT.
        let runs = [0x11u8, mft_clusters as u8, MFT_LCN as u8, 0x00]; // len 1B, off 1B
        let rec0 = build_record(0x0001, &nonresident_data(&runs, mft_clusters * CLUSTER as u64));

        // record 5: root directory with one child "test.txt" → record 6.
        let root_index = index_root(&[index_entry(6, "test.txt"), index_end()]);
        let rec5 = build_record(0x0003, &root_index); // IN_USE | DIRECTORY

        // record 6: the file, resident $DATA "hello world".
        let mut file_attrs = Vec::new();
        file_attrs.extend_from_slice(&attr_resident(
            attr_types::STANDARD_INFORMATION,
            None,
            &[0u8; 0x30],
        ));
        file_attrs.extend_from_slice(&attr_resident(
            attr_types::FILE_NAME,
            None,
            &fname_content(5, "test.txt"),
        ));
        file_attrs.extend_from_slice(&resident_data(b"hello world"));
        let rec6 = build_record(0x0001, &file_attrs);

        let mft_off = MFT_LCN as usize * CLUSTER;
        let place = |vol: &mut [u8], idx: usize, rec: &[u8]| {
            let o = mft_off + idx * REC;
            vol[o..o + rec.len()].copy_from_slice(rec);
        };
        place(&mut vol, 0, &rec0);
        place(&mut vol, 5, &rec5);
        place(&mut vol, 6, &rec6);

        Cursor::new(vol)
    }

    #[test]
    fn open_parses_boot_and_mft_runs() {
        let fs = NtfsFs::open(build_volume()).unwrap();
        assert_eq!(fs.boot().mft_record_size, 1024);
        assert_eq!(fs.boot().cluster_size(), 512);
    }

    #[test]
    fn reads_mft_record_by_number() {
        let mut fs = NtfsFs::open(build_volume()).unwrap();
        let rec6 = fs.read_record(6).unwrap();
        assert_eq!(&rec6[0..4], b"FILE");
        let header = MftRecordHeader::parse(&rec6).unwrap();
        let attrs = parse_attributes(&rec6, header.first_attribute_offset as usize).unwrap();
        let data = attrs
            .iter()
            .find(|a| a.type_code == attr_types::DATA)
            .unwrap();
        assert_eq!(data.resident_content(&rec6), Some(&b"hello world"[..]));
    }

    #[test]
    fn lists_directory_entries() {
        let mut fs = NtfsFs::open(build_volume()).unwrap();
        let root = fs.read_record(mft_records::ROOT).unwrap();
        let entries = fs.directory_entries(&root).unwrap();
        assert!(entries
            .iter()
            .any(|e| e.file_name.as_ref().map(|f| f.name.as_str()) == Some("test.txt")));
    }

    #[test]
    fn resolves_path_to_record() {
        let mut fs = NtfsFs::open(build_volume()).unwrap();
        assert_eq!(fs.resolve_path("\\test.txt").unwrap(), 6);
        assert_eq!(fs.resolve_path("/test.txt").unwrap(), 6);
    }

    #[test]
    fn read_file_returns_contents() {
        let mut fs = NtfsFs::open(build_volume()).unwrap();
        assert_eq!(fs.read_file("\\test.txt").unwrap(), b"hello world");
    }

    #[test]
    fn missing_path_is_not_found() {
        let mut fs = NtfsFs::open(build_volume()).unwrap();
        assert!(matches!(
            fs.read_file("\\nope.txt"),
            Err(NtfsError::NotFound(_))
        ));
    }
}
