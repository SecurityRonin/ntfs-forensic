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
    pub fn open(mut reader: R) -> Result<Self> {
        reader.seek(SeekFrom::Start(0))?;
        let mut boot_buf = [0u8; 512];
        reader.read_exact(&mut boot_buf)?;
        let boot = BootSector::parse(&boot_buf)?;

        // Bootstrap: record 0 ($MFT) sits at its byte offset; read it directly
        // and pull its own $DATA runlist so we can find every other record.
        reader.seek(SeekFrom::Start(boot.mft_byte_offset()))?;
        let mut rec0 = vec![0u8; boot.mft_record_size as usize];
        reader.read_exact(&mut rec0)?;
        apply_fixup(&mut rec0, boot.bytes_per_sector as usize)?;
        let mft_runs = mft_data_runs(&rec0)?;

        Ok(NtfsFs {
            reader,
            boot,
            mft_runs,
        })
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
        let rec_size = self.boot.mft_record_size;
        let virt = n
            .checked_mul(rec_size)
            .ok_or(NtfsError::BadRunlist("record offset overflow"))?;
        let mut buf = read_virtual(
            &mut self.reader,
            &self.mft_runs,
            self.boot.cluster_size(),
            virt,
            rec_size,
        )?;
        apply_fixup(&mut buf, self.boot.bytes_per_sector as usize)?;
        Ok(buf)
    }

    /// List a directory's child entries (those carrying a `$FILE_NAME`).
    ///
    /// # Errors
    ///
    /// [`NtfsError::NotADirectory`] if the record has no `$INDEX_ROOT`, plus
    /// index errors.
    pub fn directory_entries(&mut self, record: &[u8]) -> Result<Vec<IndexEntry>> {
        let attrs = record_attributes(record)?;

        let root_attr = attrs
            .iter()
            .find(|a| a.type_code == attr_types::INDEX_ROOT)
            .ok_or_else(|| NtfsError::NotADirectory("record has no $INDEX_ROOT".to_string()))?;
        let root_content = root_attr
            .resident_content(record)
            .ok_or(NtfsError::BadIndex("$INDEX_ROOT content out of bounds"))?;
        let root = IndexRoot::parse(root_content)?;

        let mut out: Vec<IndexEntry> = root
            .entries
            .into_iter()
            .filter(|e| e.file_name.is_some())
            .collect();

        if root.is_large {
            if let Some(alloc) = attrs
                .iter()
                .find(|a| a.type_code == attr_types::INDEX_ALLOCATION)
            {
                let data = read_attribute_value(
                    &mut self.reader,
                    record,
                    alloc,
                    self.boot.cluster_size(),
                )?;
                let irs = self.boot.index_record_size as usize;
                let mut off = 0;
                while off + irs <= data.len() {
                    if &data[off..off + 4] == b"INDX" {
                        let mut buf = data[off..off + irs].to_vec();
                        let entries =
                            parse_index_buffer(&mut buf, irs, self.boot.bytes_per_sector as usize)?;
                        out.extend(entries.into_iter().filter(|e| e.file_name.is_some()));
                    }
                    off += irs;
                }
            }
        }

        Ok(out)
    }

    /// Resolve a `\`- or `/`-separated path to an MFT record number.
    ///
    /// # Errors
    ///
    /// [`NtfsError::NotFound`] for a missing component.
    pub fn resolve_path(&mut self, path: &str) -> Result<u64> {
        let mut current = mft_records::ROOT;
        for component in path.split(['\\', '/']).filter(|c| !c.is_empty()) {
            let record = self.read_record(current)?;
            let entries = self.directory_entries(&record)?;
            current = entries
                .iter()
                .find_map(|e| {
                    e.file_name
                        .as_ref()
                        .filter(|f| f.name.eq_ignore_ascii_case(component))
                        .map(|_| e.file_reference.record_number)
                })
                .ok_or_else(|| NtfsError::NotFound(component.to_string()))?;
        }
        Ok(current)
    }

    /// Read a file's unnamed (default) `$DATA` by path.
    ///
    /// # Errors
    ///
    /// [`NtfsError::NotFound`] if the path or its `$DATA` is missing.
    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>> {
        self.read_data_stream(path, None)
    }

    /// Read a named `$DATA` stream — an alternate data stream (ADS) — by path
    /// and stream name (e.g. `$UsnJrnl`'s `$J`, or a file's `Zone.Identifier`).
    ///
    /// # Errors
    ///
    /// [`NtfsError::NotFound`] if the path or the named stream is missing.
    pub fn read_named_stream(&mut self, path: &str, stream: &str) -> Result<Vec<u8>> {
        self.read_data_stream(path, Some(stream))
    }

    /// Read the `$DATA` attribute named `stream` (or the unnamed/default stream
    /// when `None`) of the file at `path`.
    fn read_data_stream(&mut self, path: &str, stream: Option<&str>) -> Result<Vec<u8>> {
        let rec_num = self.resolve_path(path)?;
        let record = self.read_record(rec_num)?;
        // Gather the base record and any extension records the file's attributes
        // are spread across (via $ATTRIBUTE_LIST), then find the $DATA wherever
        // it lives.
        let records = self.gather_records(rec_num, &record)?;
        let cluster_size = self.boot.cluster_size();

        // Collect every matching $DATA attribute, paired with its source record.
        // A resident stream is a single attribute; a non-resident stream may be
        // split into several fragments (different start VCNs) across records.
        let mut resident: Option<(usize, Attribute)> = None;
        // (start_vcn, real_size, record index, attribute) per non-resident fragment.
        let mut fragments: Vec<(u64, u64, usize, Attribute)> = Vec::new();
        for (idx, rec_bytes) in records.iter().enumerate() {
            for attr in record_attributes(rec_bytes)? {
                if attr.type_code != attr_types::DATA || attr.name.as_deref() != stream {
                    continue;
                }
                match &attr.body {
                    AttributeBody::Resident { .. } => resident = Some((idx, attr)),
                    AttributeBody::NonResident {
                        start_vcn,
                        real_size,
                        ..
                    } => fragments.push((*start_vcn, *real_size, idx, attr)),
                }
            }
        }

        if let Some((idx, attr)) = resident {
            return read_attribute_value(&mut self.reader, &records[idx], &attr, cluster_size);
        }
        if fragments.is_empty() {
            return Err(match stream {
                Some(s) => NtfsError::NotFound(format!("{path}:{s}")),
                None => NtfsError::NotFound(format!("{path}::$DATA")),
            });
        }

        // Concatenate the fragments' runlists in VCN order; the total size is
        // carried by the first fragment (start VCN 0).
        fragments.sort_by_key(|(start_vcn, _, _, _)| *start_vcn);
        let real_size = fragments[0].1;
        let mut runs = Vec::new();
        for (_, _, idx, attr) in &fragments {
            runs.extend(crate::data::attribute_runlist(&records[*idx], attr)?);
        }
        crate::data::read_runs(&mut self.reader, &runs, cluster_size, real_size)
    }

    /// The base record plus every distinct extension record referenced by its
    /// `$ATTRIBUTE_LIST` (if any) — so a fragmented file's attributes can be
    /// found wherever the MFT spread them. Cycles are broken by tracking seen
    /// record numbers.
    fn gather_records(&mut self, base_num: u64, base_record: &[u8]) -> Result<Vec<Vec<u8>>> {
        let base_attrs = record_attributes(base_record)?;
        let mut records = vec![base_record.to_vec()];

        if let Some(al) = base_attrs
            .iter()
            .find(|a| a.type_code == attr_types::ATTRIBUTE_LIST)
        {
            let content =
                read_attribute_value(&mut self.reader, base_record, al, self.boot.cluster_size())?;
            let entries = crate::attribute_list::parse(&content)?;
            let mut seen = std::collections::BTreeSet::new();
            seen.insert(base_num);
            for entry in entries {
                let rn = entry.base_reference.record_number;
                if seen.insert(rn) {
                    records.push(self.read_record(rn)?);
                }
            }
        }
        Ok(records)
    }
}

/// Parse a record's header and return its attributes.
fn record_attributes(record: &[u8]) -> Result<Vec<Attribute>> {
    let header = MftRecordHeader::parse(record)?;
    parse_attributes(record, header.first_attribute_offset as usize)
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
                let rl = record.get(start..end).ok_or(NtfsError::BadAttribute {
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
    use crate::source::OffsetReader;
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
        nonresident_data_vcn(runs, real_size, 0)
    }

    /// A non-resident `$DATA` whose mapping begins at `start_vcn` — a fragment of
    /// a runlist split across several `$DATA` attributes.
    fn nonresident_data_vcn(runs: &[u8], real_size: u64, start_vcn: u64) -> Vec<u8> {
        let runs_off = 0x40usize;
        let len = (runs_off + runs.len() + 7) & !7;
        let mut a = vec![0u8; len];
        a[0..4].copy_from_slice(&attr_types::DATA.to_le_bytes());
        a[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        a[0x08] = 1;
        a[0x0A..0x0C].copy_from_slice(&(runs_off as u16).to_le_bytes());
        a[0x10..0x18].copy_from_slice(&start_vcn.to_le_bytes());
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

    /// One `$ATTRIBUTE_LIST` entry: attribute `type_code` (id `attr_id`) lives in
    /// MFT `record`.
    fn attrlist_entry(type_code: u32, record: u64, attr_id: u16) -> Vec<u8> {
        attrlist_entry_vcn(type_code, record, attr_id, 0)
    }

    /// Like [`attrlist_entry`] but with an explicit starting VCN — used to point
    /// a later `$DATA` fragment (VCN > 0) at its extension record.
    fn attrlist_entry_vcn(type_code: u32, record: u64, attr_id: u16, start_vcn: u64) -> Vec<u8> {
        let len = 0x20usize; // ENTRY_MIN (0x1A) padded to 8
        let mut e = vec![0u8; len];
        e[0x00..0x04].copy_from_slice(&type_code.to_le_bytes());
        e[0x04..0x06].copy_from_slice(&(len as u16).to_le_bytes());
        e[0x07] = 0x1A; // name_offset (no name)
        e[0x08..0x10].copy_from_slice(&start_vcn.to_le_bytes());
        e[0x10..0x18].copy_from_slice(&((1u64 << 48) | record).to_le_bytes()); // base ref
        e[0x18..0x1A].copy_from_slice(&attr_id.to_le_bytes());
        e
    }

    /// Build a volume: boot + an MFT with $MFT, root, an inline file, and a
    /// fragmented file whose `$DATA` lives in an extension record.
    fn build_volume() -> Cursor<Vec<u8>> {
        let num_records = 11usize;
        let mft_clusters = (num_records * REC / CLUSTER) as u64; // 14
        let total_clusters = MFT_LCN + mft_clusters + 2;
        let mut vol = vec![0u8; total_clusters as usize * CLUSTER];
        vol[0..512].copy_from_slice(&build_boot());

        // record 0: $MFT with a non-resident $DATA covering the whole MFT.
        let runs = [0x11u8, mft_clusters as u8, MFT_LCN as u8, 0x00]; // len 1B, off 1B
        let rec0 = build_record(
            0x0001,
            &nonresident_data(&runs, mft_clusters * CLUSTER as u64),
        );

        // record 5: root directory — test.txt → 6, frag.txt → 9, split.bin → 7.
        let root_index = index_root(&[
            index_entry(6, "test.txt"),
            index_entry(7, "split.bin"),
            index_entry(9, "frag.txt"),
            index_end(),
        ]);
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
        // A named $DATA stream (alternate data stream).
        file_attrs.extend_from_slice(&attr_resident(
            attr_types::DATA,
            Some("Zone.Identifier"),
            b"[ZoneTransfer]",
        ));
        let rec6 = build_record(0x0001, &file_attrs);

        // record 9: "frag.txt" base — $SI, $FN, and an $ATTRIBUTE_LIST whose
        // $DATA entry points at extension record 10.
        let attrlist = [
            attrlist_entry(attr_types::STANDARD_INFORMATION, 9, 0),
            attrlist_entry(attr_types::FILE_NAME, 9, 0),
            attrlist_entry(attr_types::DATA, 10, 0),
        ]
        .concat();
        let mut a9 = Vec::new();
        a9.extend_from_slice(&attr_resident(
            attr_types::STANDARD_INFORMATION,
            None,
            &[0u8; 0x30],
        ));
        a9.extend_from_slice(&attr_resident(
            attr_types::FILE_NAME,
            None,
            &fname_content(5, "frag.txt"),
        ));
        a9.extend_from_slice(&attr_resident(attr_types::ATTRIBUTE_LIST, None, &attrlist));
        let rec9 = build_record(0x0001, &a9);

        // record 10: the extension record holding frag.txt's $DATA.
        let rec10 = build_record(0x0001, &resident_data(b"fragmented!"));

        // split.bin: a non-resident $DATA whose runlist is split into two
        // fragments — VCN 0 in base record 7 (LCN 26), VCN 1 in extension
        // record 8 (LCN 27). Total real size 1024 (two clusters).
        let data_lcn0 = (MFT_LCN + mft_clusters) as u8; // 26
        let data_lcn1 = data_lcn0 + 1; // 27
        let attrlist_split = [
            attrlist_entry(attr_types::STANDARD_INFORMATION, 7, 0),
            attrlist_entry(attr_types::FILE_NAME, 7, 0),
            attrlist_entry(attr_types::DATA, 7, 0),
            attrlist_entry(attr_types::DATA, 8, 1),
        ]
        .concat();
        let mut a7 = Vec::new();
        a7.extend_from_slice(&attr_resident(
            attr_types::STANDARD_INFORMATION,
            None,
            &[0u8; 0x30],
        ));
        a7.extend_from_slice(&attr_resident(
            attr_types::FILE_NAME,
            None,
            &fname_content(5, "split.bin"),
        ));
        a7.extend_from_slice(&attr_resident(
            attr_types::ATTRIBUTE_LIST,
            None,
            &attrlist_split,
        ));
        a7.extend_from_slice(&nonresident_data_vcn(
            &[0x11, 0x01, data_lcn0, 0x00],
            2 * CLUSTER as u64,
            0,
        ));
        let rec7 = build_record(0x0001, &a7);
        let rec8 = build_record(
            0x0001,
            &nonresident_data_vcn(&[0x11, 0x01, data_lcn1, 0x00], 0, 1),
        );

        let mft_off = MFT_LCN as usize * CLUSTER;
        let place = |vol: &mut [u8], idx: usize, rec: &[u8]| {
            let o = mft_off + idx * REC;
            vol[o..o + rec.len()].copy_from_slice(rec);
        };
        place(&mut vol, 0, &rec0);
        place(&mut vol, 5, &rec5);
        place(&mut vol, 6, &rec6);
        place(&mut vol, 7, &rec7);
        place(&mut vol, 8, &rec8);
        place(&mut vol, 9, &rec9);
        place(&mut vol, 10, &rec10);

        // split.bin's two data clusters.
        let c0 = data_lcn0 as usize * CLUSTER;
        let c1 = data_lcn1 as usize * CLUSTER;
        vol[c0..c0 + CLUSTER].fill(b'A');
        vol[c1..c1 + CLUSTER].fill(b'B');

        Cursor::new(vol)
    }

    /// Build a volume whose `$MFT` `$DATA` runlist is split across record 0 and
    /// an extension record (record 4) via an `$ATTRIBUTE_LIST` — the real-world
    /// case where the MFT outgrows a single FILE record. The first `$DATA`
    /// fragment (VCN 0) maps the first half of the MFT (records 0–7); the second
    /// fragment (VCN 16) — described in extension record 4 — maps the second
    /// half (records 8–15). A reader that ignores the `$ATTRIBUTE_LIST` sees only
    /// the first fragment and truncates the MFT.
    fn build_volume_split_mft() -> Cursor<Vec<u8>> {
        const NUM_RECORDS: usize = 16;
        let mft_clusters = (NUM_RECORDS * REC / CLUSTER) as u64; // 32
        let half = mft_clusters / 2; // 16
        let total_clusters = MFT_LCN + mft_clusters;
        let mut vol = vec![0u8; total_clusters as usize * CLUSTER];
        vol[0..512].copy_from_slice(&build_boot());

        // The MFT is laid out contiguously starting at MFT_LCN, but its $DATA is
        // *described* as two fragments so it must be reassembled from both.
        let lcn0 = MFT_LCN as u8; // first fragment LCN (4)
        let lcn1 = (MFT_LCN + half) as u8; // second fragment LCN (20)

        // record 0: $MFT base. First $DATA fragment (VCN 0, `half` clusters) plus
        // an $ATTRIBUTE_LIST whose second $DATA entry (VCN `half`) is in record 4.
        let attrlist = [
            attrlist_entry(attr_types::DATA, 0, 0),
            attrlist_entry_vcn(attr_types::DATA, 4, 1, half),
        ]
        .concat();
        let mut a0 = Vec::new();
        a0.extend_from_slice(&attr_resident(attr_types::ATTRIBUTE_LIST, None, &attrlist));
        a0.extend_from_slice(&nonresident_data_vcn(
            &[0x11, half as u8, lcn0, 0x00],
            mft_clusters * CLUSTER as u64,
            0,
        ));
        let rec0 = build_record(0x0001, &a0);

        // record 4: extension record holding the $MFT's second $DATA fragment
        // (VCN `half`, the remaining `half` clusters at lcn1).
        let rec4 = build_record(
            0x0001,
            &nonresident_data_vcn(&[0x11, half as u8, lcn1, 0x00], 0, half),
        );

        let mft_off = MFT_LCN as usize * CLUSTER;
        let place = |vol: &mut [u8], idx: usize, rec: &[u8]| {
            let o = mft_off + idx * REC;
            vol[o..o + rec.len()].copy_from_slice(rec);
        };
        place(&mut vol, 0, &rec0);
        place(&mut vol, 4, &rec4);
        // Mark every record with its own number so reads can be verified; record
        // 12 lives in the SECOND $DATA fragment (records 8–15).
        for n in 0..NUM_RECORDS {
            if n == 0 || n == 4 {
                continue;
            }
            place(&mut vol, n, &build_record(0x0001, &resident_data(&[n as u8])));
        }

        Cursor::new(vol)
    }

    #[test]
    fn open_assembles_split_mft_data_via_attribute_list() {
        // record 12 physically lives in the $MFT's SECOND $DATA fragment, only
        // reachable once record 0's $ATTRIBUTE_LIST is followed. Before the fix
        // this fails with "read past end of runs".
        let mut fs = NtfsFs::open(build_volume_split_mft()).unwrap();
        let rec12 = fs.read_record(12).unwrap();
        assert_eq!(&rec12[0..4], b"FILE");
        let header = MftRecordHeader::parse(&rec12).unwrap();
        let attrs = parse_attributes(&rec12, header.first_attribute_offset as usize).unwrap();
        let data = attrs
            .iter()
            .find(|a| a.type_code == attr_types::DATA)
            .unwrap();
        assert_eq!(data.resident_content(&rec12), Some(&[12u8][..]));
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
        // read_file reads only the unnamed stream, not the ADS.
        assert_eq!(fs.read_file("\\test.txt").unwrap(), b"hello world");
    }

    #[test]
    fn read_named_stream_returns_ads_contents() {
        let mut fs = NtfsFs::open(build_volume()).unwrap();
        assert_eq!(
            fs.read_named_stream("\\test.txt", "Zone.Identifier")
                .unwrap(),
            b"[ZoneTransfer]"
        );
    }

    #[test]
    fn read_named_stream_missing_is_not_found() {
        let mut fs = NtfsFs::open(build_volume()).unwrap();
        assert!(matches!(
            fs.read_named_stream("\\test.txt", "NoSuchStream"),
            Err(NtfsError::NotFound(_))
        ));
    }

    #[test]
    fn read_file_on_directory_has_no_data_stream() {
        // The root directory has no unnamed $DATA.
        let mut fs = NtfsFs::open(build_volume()).unwrap();
        assert!(matches!(fs.read_file("\\"), Err(NtfsError::NotFound(_))));
    }

    #[test]
    fn read_file_follows_attribute_list_to_extension_record() {
        // frag.txt's $DATA is not in its base record — it lives in extension
        // record 10, reachable only via $ATTRIBUTE_LIST.
        let mut fs = NtfsFs::open(build_volume()).unwrap();
        assert_eq!(fs.read_file("\\frag.txt").unwrap(), b"fragmented!");
    }

    #[test]
    fn read_file_assembles_split_nonresident_data() {
        // split.bin's runlist is split across two $DATA attributes (VCN 0 and 1)
        // in different records — they must be concatenated in VCN order.
        let mut fs = NtfsFs::open(build_volume()).unwrap();
        let data = fs.read_file("\\split.bin").unwrap();
        assert_eq!(data.len(), 1024);
        assert!(data[..512].iter().all(|&b| b == b'A'));
        assert!(data[512..].iter().all(|&b| b == b'B'));
    }

    #[test]
    fn missing_path_is_not_found() {
        let mut fs = NtfsFs::open(build_volume()).unwrap();
        assert!(matches!(
            fs.read_file("\\nope.txt"),
            Err(NtfsError::NotFound(_))
        ));
    }

    /// Materialise the synthetic volume to a unique temp file.
    fn write_temp(bytes: &[u8], tag: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("ntfsf_{tag}_{}.img", std::process::id()));
        std::fs::write(&path, bytes).unwrap();
        path
    }

    /// End-to-end over a real `std::fs::File` (not an in-memory cursor) — this
    /// is the path a CLI takes against a raw NTFS partition image.
    #[test]
    fn read_file_over_file_backing() {
        use std::fs::File;
        let bytes = build_volume().into_inner();
        let path = write_temp(&bytes, "file");
        let mut fs = NtfsFs::open(File::open(&path).unwrap()).unwrap();
        assert_eq!(fs.read_file("\\test.txt").unwrap(), b"hello world");
        std::fs::remove_file(&path).ok();
    }

    /// End-to-end through an [`OffsetReader`] over a `File` — the partition sits
    /// at a non-zero offset inside the disk image, exactly as in a real image.
    #[test]
    fn read_file_over_offset_reader_partition() {
        use std::fs::File;
        let bytes = build_volume().into_inner();
        let pad = 8192usize; // partition begins 8 KiB into the "disk"
        let mut disk = vec![0u8; pad];
        disk.extend_from_slice(&bytes);
        let path = write_temp(&disk, "offset");
        let part =
            OffsetReader::new(File::open(&path).unwrap(), pad as u64, bytes.len() as u64).unwrap();
        let mut fs = NtfsFs::open(part).unwrap();
        assert_eq!(fs.read_file("\\test.txt").unwrap(), b"hello world");
        std::fs::remove_file(&path).ok();
    }

    // ── read_virtual branches ─────────────────────────────────────────────────

    #[test]
    fn read_virtual_sparse_run_reads_zeroes() {
        let runs = [Run {
            length: 2,
            lcn: None,
        }];
        let mut cur = Cursor::new(Vec::<u8>::new()); // empty — proves no read happens
        let out = read_virtual(&mut cur, &runs, CLUSTER as u64, 0, 1024).unwrap();
        assert_eq!(out, vec![0u8; 1024]);
    }

    #[test]
    fn read_virtual_rejects_physical_overflow() {
        let runs = [Run {
            length: 1,
            lcn: Some(u64::MAX),
        }];
        let mut cur = Cursor::new(vec![0u8; CLUSTER]);
        assert!(matches!(
            read_virtual(&mut cur, &runs, CLUSTER as u64, 0, 16),
            Err(NtfsError::BadRunlist(_))
        ));
    }

    #[test]
    fn read_virtual_rejects_read_past_runs() {
        // One cluster mapped, but more is requested than the runs cover.
        let runs = [Run {
            length: 1,
            lcn: Some(0),
        }];
        let mut cur = Cursor::new(vec![0u8; CLUSTER]);
        assert!(matches!(
            read_virtual(&mut cur, &runs, CLUSTER as u64, 0, 1024),
            Err(NtfsError::BadRunlist(_))
        ));
    }

    #[test]
    fn read_virtual_skips_leading_runs_and_stops_when_satisfied() {
        // Three runs; read just the middle cluster: run 0 is skipped (offset is
        // past it) and run 2 is never reached (the request is already satisfied).
        let runs = [
            Run {
                length: 1,
                lcn: Some(0),
            },
            Run {
                length: 1,
                lcn: Some(1),
            },
            Run {
                length: 1,
                lcn: Some(2),
            },
        ];
        let mut cur = Cursor::new(vec![7u8; 3 * CLUSTER]);
        let out = read_virtual(
            &mut cur,
            &runs,
            CLUSTER as u64,
            CLUSTER as u64,
            CLUSTER as u64,
        )
        .unwrap();
        assert_eq!(out.len(), CLUSTER);
    }

    // ── mft_data_runs errors ──────────────────────────────────────────────────

    #[test]
    fn mft_data_runs_rejects_record_without_nonresident_data() {
        // A non-$DATA attribute (skipped) followed by a resident $DATA (matched
        // by type but not non-resident) — neither yields a runlist.
        let mut attrs = attr_resident(attr_types::STANDARD_INFORMATION, None, &[0u8; 0x30]);
        attrs.extend_from_slice(&resident_data(b"x"));
        let rec = build_record(0x0001, &attrs);
        assert!(matches!(
            mft_data_runs(&rec),
            Err(NtfsError::BadAttribute { detail, .. })
                if detail == "$MFT has no non-resident $DATA"
        ));
    }

    #[test]
    fn read_record_rejects_number_past_mft() {
        // Record 11 lies just past the 11-record synthetic MFT.
        let mut fs = NtfsFs::open(build_volume()).unwrap();
        assert!(matches!(fs.read_record(11), Err(NtfsError::BadRunlist(_))));
    }

    #[test]
    fn large_directory_without_index_allocation_yields_root_entries() {
        // is_large is set but there is no $INDEX_ALLOCATION; the scan is skipped.
        let attrs = index_root_large(&[index_entry(9, "only.txt"), index_end()]);
        let rec = build_record(0x0003, &attrs);
        let mut fs = NtfsFs::open(build_volume()).unwrap();
        let entries = fs.directory_entries(&rec).unwrap();
        assert!(entries
            .iter()
            .any(|e| e.file_name.as_ref().map(|f| f.name.as_str()) == Some("only.txt")));
    }

    #[test]
    fn mft_data_runs_rejects_runlist_out_of_bounds() {
        // Non-resident $DATA whose runs_offset points past the attribute.
        let mut a = vec![0u8; 0x40];
        a[0..4].copy_from_slice(&attr_types::DATA.to_le_bytes());
        a[4..8].copy_from_slice(&0x40u32.to_le_bytes());
        a[0x08] = 1; // non-resident
        a[0x20..0x22].copy_from_slice(&0xFFFFu16.to_le_bytes()); // runs offset past attr
        let rec = build_record(0x0001, &a);
        assert!(matches!(
            mft_data_runs(&rec),
            Err(NtfsError::BadAttribute { detail, .. }) if detail == "$MFT runlist out of bounds"
        ));
    }

    // ── Large directory ($INDEX_ALLOCATION / INDX) ────────────────────────────

    /// `$INDEX_ROOT` with the large-index flag set, so `directory_entries`
    /// follows the `$INDEX_ALLOCATION`.
    fn index_root_large(entries: &[Vec<u8>]) -> Vec<u8> {
        let blob: Vec<u8> = entries.concat();
        let mut content = vec![0u8; 0x10 + 0x10 + blob.len()];
        content[0x00..0x04].copy_from_slice(&attr_types::FILE_NAME.to_le_bytes());
        content[0x10..0x14].copy_from_slice(&0x10u32.to_le_bytes());
        content[0x14..0x18].copy_from_slice(&((0x10 + blob.len()) as u32).to_le_bytes());
        content[0x1C..0x20].copy_from_slice(&1u32.to_le_bytes()); // IH large flag
        content[0x20..0x20 + blob.len()].copy_from_slice(&blob);
        attr_resident(attr_types::INDEX_ROOT, Some("$I30"), &content)
    }

    /// A non-resident `$INDEX_ALLOCATION` whose runlist maps one cluster.
    fn index_allocation(runs: &[u8], real_size: u64) -> Vec<u8> {
        let mut a = nonresident_data(runs, real_size);
        a[0..4].copy_from_slice(&attr_types::INDEX_ALLOCATION.to_le_bytes());
        a
    }

    /// A 512-byte INDX buffer holding one entry → `target` named `name`.
    fn build_indx(target: u64, name: &str) -> Vec<u8> {
        let mut b = vec![0u8; CLUSTER];
        b[0..4].copy_from_slice(b"INDX");
        b[0x04..0x06].copy_from_slice(&0x28u16.to_le_bytes()); // usa_offset
        b[0x06..0x08].copy_from_slice(&2u16.to_le_bytes()); // usa_count
        let base = 0x18usize; // INDX index-header base
        let first_entry = 0x40 - base;
        let blob = [index_entry(target, name), index_end()].concat();
        let total = (first_entry + blob.len()) as u32;
        b[base..base + 4].copy_from_slice(&(first_entry as u32).to_le_bytes());
        b[base + 4..base + 8].copy_from_slice(&total.to_le_bytes());
        b[0x40..0x40 + blob.len()].copy_from_slice(&blob);
        let usn = 0x0001u16;
        b[0x28..0x2A].copy_from_slice(&usn.to_le_bytes());
        b[510..512].copy_from_slice(&usn.to_le_bytes());
        b
    }

    #[test]
    fn lists_large_directory_via_index_allocation() {
        // Volume: MFT (records 0,5) at LCN 4, INDX buffer at LCN 18.
        let mft_clusters = 14u64; // 7 records × 1024 / 512
        let indx_lcn = MFT_LCN + mft_clusters; // 18
        let total_clusters = indx_lcn + 3;
        let mut vol = vec![0u8; total_clusters as usize * CLUSTER];
        vol[0..512].copy_from_slice(&build_boot());

        let runs = [0x11u8, mft_clusters as u8, MFT_LCN as u8, 0x00];
        let rec0 = build_record(
            0x0001,
            &nonresident_data(&runs, mft_clusters * CLUSTER as u64),
        );

        // record 5: large root → $INDEX_ALLOCATION spanning two clusters at
        // LCN 18; the second cluster is not an INDX buffer, exercising the
        // "boundary without an INDX signature" path of the scan.
        let alloc_runs = [0x11u8, 0x02, indx_lcn as u8, 0x00];
        let mut root_attrs = index_root_large(&[index_end()]);
        root_attrs.extend_from_slice(&index_allocation(&alloc_runs, 2 * CLUSTER as u64));
        let rec5 = build_record(0x0003, &root_attrs);

        let mft_off = MFT_LCN as usize * CLUSTER;
        vol[mft_off..mft_off + rec0.len()].copy_from_slice(&rec0);
        let r5 = mft_off + 5 * REC;
        vol[r5..r5 + rec5.len()].copy_from_slice(&rec5);

        // The INDX buffer cluster, holding child "deep.bin" → record 9.
        let indx = build_indx(9, "deep.bin");
        let io = indx_lcn as usize * CLUSTER;
        vol[io..io + indx.len()].copy_from_slice(&indx);

        let mut fs = NtfsFs::open(Cursor::new(vol)).unwrap();
        let root = fs.read_record(mft_records::ROOT).unwrap();
        let entries = fs.directory_entries(&root).unwrap();
        assert!(entries
            .iter()
            .any(|e| e.file_name.as_ref().map(|f| f.name.as_str()) == Some("deep.bin")));
    }

    #[test]
    fn directory_without_index_root_is_not_a_directory() {
        let rec = build_record(0x0001, &resident_data(b"x"));
        let mut fs = NtfsFs::open(build_volume()).unwrap();
        assert!(matches!(
            fs.directory_entries(&rec),
            Err(NtfsError::NotADirectory(_))
        ));
    }

    #[test]
    fn read_record_propagates_fixup_error() {
        // Corrupt record 6's second-sector tail so the fixup detects a torn write.
        let mut vol = build_volume().into_inner();
        let rec6_tail = MFT_LCN as usize * CLUSTER + 6 * REC + 1022;
        vol[rec6_tail] ^= 0xFF;
        let mut fs = NtfsFs::open(Cursor::new(vol)).unwrap();
        assert!(matches!(
            fs.read_record(6),
            Err(NtfsError::FixupMismatch { .. })
        ));
    }

    #[test]
    fn directory_entries_propagates_index_allocation_error() {
        // Large directory whose $INDEX_ALLOCATION runlist points past the volume.
        let alloc_runs = [0x11u8, 0x01, 0x7F, 0x00]; // LCN 127, beyond the volume
        let mut attrs = index_root_large(&[index_end()]);
        attrs.extend_from_slice(&index_allocation(&alloc_runs, CLUSTER as u64));
        let rec = build_record(0x0003, &attrs);
        let mut fs = NtfsFs::open(build_volume()).unwrap();
        assert!(fs.directory_entries(&rec).is_err());
    }
}
