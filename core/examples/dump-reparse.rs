#![allow(clippy::unwrap_used)]
use std::fs::File;
use ntfs_core::fs::NtfsFs;
use ntfs_core::parse_attributes;
use ntfs_core::record::MftRecordHeader;

fn main() {
    let f = File::open("/tmp/ntfs-link/ntfs.img").unwrap();
    let fs = NtfsFs::open(f).unwrap();
    let root = fs.resolve_path("\\").unwrap();
    // walk: root -> src? no — cp -a copied src/. into the root: README.txt, nested/
    let root_rec = fs.read_record(root).unwrap();
    for e in fs.directory_entries(&root_rec).unwrap() {
        if let Some(name) = &e.file_name {
            println!("root: {:?} flags={:#x} ref={}", name.name, name.flags, e.file_reference.record_number);
        }
    }
    // find nested/readme-link.txt: read nested dir
    let nested_rec = fs.read_record(root).unwrap();
    for e in fs.directory_entries(&nested_rec).unwrap() {
        if let Some(name) = &e.file_name {
            if name.name == "nested" {
                let rec = fs.read_record(e.file_reference.record_number).unwrap();
                for c in fs.directory_entries(&rec).unwrap() {
                    if let Some(cn) = &c.file_name {
                        println!("nested: {:?} ref={}", cn.name, c.file_reference.record_number);
                        if cn.name == "readme-link.txt" {
                            let r = fs.read_record(c.file_reference.record_number).unwrap();
                            let hdr = MftRecordHeader::parse(&r).unwrap();
                            let attrs = parse_attributes(&r, hdr.first_attribute_offset as usize).unwrap();
                            for a in &attrs {
                                println!("    attr type={:#x} name={:?} nonres={}", a.type_code, a.name, a.non_resident);
                                if a.type_code == 0x80 {
                                    let content = a.resident_content(&r).unwrap();
                                    println!("    $DATA content ({} bytes): {:02x?} utf16le={:?}", content.len(), content, String::from_utf16_lossy(&content.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<_>>()));
                                }
                                if a.type_code == 0x30 {
                                    let content = a.resident_content(&r).unwrap();
                                    // $FILE_NAME: parent(8) times(24) alloc(8) size(8) flags(4) reuse(4) name_len(1) ns(1) name...
                                    let flags = u32::from_le_bytes([content[56], content[57], content[58], content[59]]);
                                    println!("    $FILE_NAME flags={:#x} name={:?}", flags, String::from_utf8_lossy(&content[66..]));
                                }
                                if a.type_code == 0xC0 {
                                    let content = a.resident_content(&r).unwrap();
                                    println!("REPARSE content ({} bytes): {:02x?}", content.len(), content);
                                    println!("utf16le: {:?}", String::from_utf16_lossy(&content.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<_>>()));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
