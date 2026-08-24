//! Every non-regular node type NTFS can express, in both encodings a Linux
//! driver writes.
//!
//! `ntfs_all_node_types.zip` holds one volume mounted twice by ntfs-3g 2022.10.3:
//! once in its default **Interix** mode, once with `-o special_files=wsl`. The
//! two subtrees carry the same five nodes in different on-disk forms:
//!
//! | | Interix | WSL |
//! |---|---|---|
//! | symlink | `IntxLNK\1` + UTF-16 target | `LX_SYMLINK` reparse `0xA000001D` |
//! | char device | `IntxCHR\0` + major/minor | `LX_CHR` reparse `0x80000025` |
//! | block device | `IntxBLK\0` + major/minor | `LX_BLK` reparse `0x80000026` |
//! | FIFO | **zero-length `$DATA`** | `LX_FIFO` reparse `0x80000024` |
//! | socket | **one-byte `$DATA`** | `AF_UNIX` reparse `0x80000023` |
//!
//! The two bold cells are a real format limitation, not a gap in this reader:
//! ntfs-3g's Interix encoding records nothing that distinguishes a FIFO from an
//! empty file, or a socket from a one-byte file (`libntfs-3g/dir.c`, whose own
//! comment reads *"FIFO or regular file"*). They are asserted as `File` because
//! that is all the bytes say.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use forensic_vfs::{FileId, FileSystem, NodeKind};
use ntfs_core::NtfsFs;
use std::io::{Cursor, Read};

const NODE_TYPES_ZIP: &[u8] = include_bytes!("../../tests/data/ntfs_all_node_types.zip");

fn open_zipped(zip_bytes: &[u8], member: &str) -> NtfsFs<Cursor<Vec<u8>>> {
    let mut archive = zip::ZipArchive::new(Cursor::new(zip_bytes)).expect("open zip");
    let mut img = Vec::new();
    archive
        .by_name(member)
        .expect("member present")
        .read_to_end(&mut img)
        .expect("read member");
    NtfsFs::open(Cursor::new(img)).expect("open NTFS volume")
}

fn child(fs: &NtfsFs<Cursor<Vec<u8>>>, dir: FileId, name: &[u8]) -> Option<FileId> {
    fs.read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .find(|e| e.name == name)
        .map(|e| e.id)
}

fn dir_kinds(fs: &NtfsFs<Cursor<Vec<u8>>>, dir: &str) -> Vec<(String, NodeKind)> {
    let id = child(fs, fs.root(), dir.as_bytes()).expect("subtree present");
    fs.read_dir(id)
        .expect("read_dir")
        .filter_map(Result::ok)
        .map(|e| (String::from_utf8_lossy(&e.name).into_owned(), e.kind))
        .collect()
}

fn kind_of(entries: &[(String, NodeKind)], name: &str) -> NodeKind {
    entries
        .iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("{name} present"))
        .1
}

#[test]
fn interix_special_files_are_classified() {
    let fs = open_zipped(NODE_TYPES_ZIP, "ntfs_all_node_types.img");
    let e = dir_kinds(&fs, "interix");

    assert_eq!(kind_of(&e, "symlink"), NodeKind::Symlink, "IntxLNK");
    assert_eq!(kind_of(&e, "chardev"), NodeKind::CharDevice, "IntxCHR");
    assert_eq!(kind_of(&e, "blockdev"), NodeKind::BlockDevice, "IntxBLK");

    // Not a defect: the Interix encoding stores a FIFO as a zero-length $DATA
    // and a socket as a one-byte $DATA, with no magic. Nothing on disk
    // distinguishes them from ordinary files, so File is the honest reading.
    assert_eq!(kind_of(&e, "fifo"), NodeKind::File, "Interix FIFO is bare");
    assert_eq!(
        kind_of(&e, "socket"),
        NodeKind::File,
        "Interix socket is bare"
    );
}

#[test]
fn wsl_special_files_are_classified() {
    let fs = open_zipped(NODE_TYPES_ZIP, "ntfs_all_node_types.img");
    let e = dir_kinds(&fs, "wsl");

    assert_eq!(kind_of(&e, "symlink"), NodeKind::Symlink, "LX_SYMLINK");
    assert_eq!(kind_of(&e, "chardev"), NodeKind::CharDevice, "LX_CHR");
    assert_eq!(kind_of(&e, "blockdev"), NodeKind::BlockDevice, "LX_BLK");
    assert_eq!(kind_of(&e, "fifo"), NodeKind::Fifo, "LX_FIFO");
    assert_eq!(kind_of(&e, "socket"), NodeKind::Socket, "AF_UNIX");
}

#[test]
fn a_device_node_is_not_a_link_and_reads_an_empty_target() {
    // read_link is for link targets. A device, FIFO or socket has none, and
    // must read as empty rather than as an error or a fabricated path.
    let fs = open_zipped(NODE_TYPES_ZIP, "ntfs_all_node_types.img");
    let wsl = child(&fs, fs.root(), b"wsl").expect("wsl subtree");
    for name in [&b"chardev"[..], b"blockdev", b"fifo", b"socket"] {
        let id = child(&fs, wsl, name).expect("node present");
        assert!(
            fs.read_link(id, 4096).expect("read_link").is_empty(),
            "{} carries no link target",
            String::from_utf8_lossy(name)
        );
    }
}
