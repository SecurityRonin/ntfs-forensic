//! Tier-2 cross-check of the classic Windows reparse decoder, against
//! Windows' own `fsutil reparsepoint query` output as the answer key.
//!
//! Neither the bytes nor the expected values were authored here — `mklink` and
//! the NTFS driver wrote the one, `fsutil` reported the other, on Windows 11
//! (10.0.26200.8875). It is **not** Tier 1, because the scenario is ours: which
//! links exist, their names and their targets were chosen by the generator
//! script recorded in `tests/data/README.md`. Tier 1 would need a real-world
//! installation image, where the reparse points exist because Windows Setup
//! made them on a real machine.
//!
//! This is a **regression test, not TDD** — the defect it covers was fixed
//! before this fixture existed (the fix was driven by a synthetic RED built
//! from the MS-FSCC layout). What the real artifact adds is a control the
//! synthetic one could not give: Windows stores the *print* name first, so
//! reverting the fix yields `"xttarget.t"` — a plausible-looking filename
//! rather than the obvious `"\0\0…"` a zero-offset fixture produces.
//!
//! `fsutil` reports, verbatim:
//!
//! ```text
//!   rel_link.txt  0xa000000c  Flags=1  len 0x34 = 12+20+20  -> target.txt
//!   abs_link.txt  0xa000000c  Flags=0  len 0x48 = 12+26+34  -> \??\W:\target.txt
//!   rel_dirlink   0xa000000c  Flags=1  len 0x28 = 12+14+14  -> realdir
//!   abs_dirlink   0xa000000c  Flags=0                       -> \??\W:\realdir
//!   junction      0xa0000003  no Flags len 0x3c =  8+…      -> \??\W:\realdir
//! ```
#![allow(clippy::unwrap_used, clippy::expect_used)]

use forensic_vfs::{FileId, FileSystem, NodeKind};
use ntfs_core::NtfsFs;
use std::io::{Cursor, Read};

const WINDOWS_ZIP: &[u8] = include_bytes!("../../tests/data/ntfs_windows_reparse.zip");

fn open() -> NtfsFs<Cursor<Vec<u8>>> {
    let mut archive = zip::ZipArchive::new(Cursor::new(WINDOWS_ZIP)).expect("open zip");
    let mut img = Vec::new();
    archive
        .by_name("ntfs_windows_reparse.img")
        .expect("member present")
        .read_to_end(&mut img)
        .expect("read member");
    NtfsFs::open(Cursor::new(img)).expect("open Windows-authored NTFS volume")
}

fn find(fs: &NtfsFs<Cursor<Vec<u8>>>, want: &[u8]) -> Option<FileId> {
    fs.read_dir(fs.root())
        .ok()?
        .filter_map(Result::ok)
        .find(|e| e.name == want)
        .map(|e| e.id)
}

#[test]
fn windows_authored_reparse_points_match_fsutil() {
    let fs = open();

    // Substitute names exactly as `fsutil reparsepoint query` reports them.
    for (name, want) in [
        (&b"rel_link.txt"[..], "target.txt"),
        (&b"abs_link.txt"[..], r"\??\W:\target.txt"),
        (&b"rel_dirlink"[..], "realdir"),
        (&b"abs_dirlink"[..], r"\??\W:\realdir"),
        (&b"junction"[..], r"\??\W:\realdir"),
    ] {
        let id =
            find(&fs, name).unwrap_or_else(|| panic!("{} present", String::from_utf8_lossy(name)));
        assert_eq!(
            String::from_utf8_lossy(&fs.read_link(id, 4096).expect("read_link")),
            want,
            "substitute name for {}",
            String::from_utf8_lossy(name)
        );
    }
}

#[test]
fn windows_reparse_points_classify_as_symlinks() {
    let fs = open();
    for name in [
        &b"rel_link.txt"[..],
        b"abs_link.txt",
        b"rel_dirlink",
        b"abs_dirlink",
        b"junction",
    ] {
        let id = find(&fs, name).expect("present");
        assert_eq!(
            fs.meta(id).expect("meta").kind,
            NodeKind::Symlink,
            "{} is a reparse point",
            String::from_utf8_lossy(name)
        );
    }
}

#[test]
fn a_hard_link_is_not_a_reparse_point() {
    // `mklink /H` creates a second $FILE_NAME on the same record, not a
    // reparse point. It must read as an ordinary file with an empty target,
    // never as a link to a fabricated path.
    let fs = open();
    let id = find(&fs, b"hardlink.txt").expect("hardlink.txt present");
    assert_eq!(fs.meta(id).expect("meta").kind, NodeKind::File);
    assert!(fs.read_link(id, 4096).expect("read_link").is_empty());
}
