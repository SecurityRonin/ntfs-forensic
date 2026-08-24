# `ntfs-forensic` test fixtures

Per-file provenance for the committed test data. The fleet-wide machine index is
[`issen/docs/corpus-catalog.md`](https://github.com/SecurityRonin/issen) (§A3c for the
LZNT1 fixtures, §A1 for the boot sector) — this README is the co-located human detail;
cross-reference, never duplicate.

`tests/data/` here is **not** gitignored (`.gitignore` is just `/target`), so these small
fixtures are committed.

#### defcon2018_cdrive_boot.bin

- **Source / Identity:** first 4 KiB (NTFS boot sector) of the C: partition from the publicly
  distributed DEF CON DFIR CTF 2018 `MaxPowers` disk image.
- **Used by:** `core/tests/real_image.rs` — boot-parser values checked against TSK `fsstat`.
- **Catalog:** `issen/docs/corpus-catalog.md` §A1 (DEF CON DFIR CTF 2018 `MaxPowersCDrive.E01`).

#### lznt1_real.bin / lznt1_real.expected

Real on-disk **LZNT1** stream + its TSK-decompressed plaintext, used by
`core/tests/lznt1_real.rs` to validate the `lznt1` codec against real bytes (doer-checker)
rather than a self-consistent synthetic round-trip — with **The Sleuth Kit as the independent
oracle** for the plaintext.

- **Source image:** DFIR Madness "Stolen Szechuan Sauce" Case 001 — **CITADEL-DC01** C: drive
  (Windows Server 2012 R2), `20200918_0347_CDrive.E01`. By James Smith, dfirmadness.com.
  Case page: <https://dfirmadness.com/the-stolen-szechuan-sauce/> · image:
  <https://dfirmadness.com/case001/DC01-E01.zip>. Educational/research use.
- **In-image file:** `C:\ProgramData\Microsoft\Windows\WER\...\Report.wer` — **MFT inode 437**.
  Its `$DATA` is `Non-Resident, Compressed`, actual size **1832 bytes**, occupying a single
  allocated cluster at **LCN 291553** (one 16-cluster LZNT1 compression unit → the cluster holds
  the entire compressed stream, so `icat` returns the full plaintext). **Single-unit**, no fallback.
- **NTFS geometry:** partition at sector **offset 718848**; cluster size **4096** (8 sectors/cluster).
- **Verbatim TSK commands** (TSK decompresses independently — the oracle):

  ```sh
  E01=".../extracted/E01-DC01/20200918_0347_CDrive.E01"
  istat  -o 718848 "$E01" 437                                   # $DATA Non-Resident, Compressed  size 1832 → LCN 291553
  icat   -o 718848 "$E01" 437      > lznt1_real.expected         # TSK plaintext (oracle), 1832 bytes
  blkcat -o 718848 "$E01" 291553 1 > lznt1_real.bin             # raw on-disk LZNT1 stream, one 4096-byte cluster
  ```

- **Oracle agreement (verified before committing):** `ntfs_core::decompress(lznt1_real.bin)`
  truncated to 1832 bytes equals `lznt1_real.expected` byte-for-byte.

| File | Bytes | MD5 |
|---|---|---|
| `lznt1_real.bin` | 4096 | `8c791f1d34a7f4a9aaeaddce71210a26` |
| `lznt1_real.expected` | 1832 | `f4cc46d7e07ab76540a46471622e10af` |

#### SampleTinyNtfsVolume.zip

A small synthetic NTFS volume (`$MFT`, `$LogFile`, `$MFTMirr`, …) that ships inside Joakim
Schicht's **LogFileParser** release as its self-contained `$LogFile`/NTFS validation sample.
Used as the small-input case for the `$LogFile` transaction decoder + its oracle harness
(LogFileParser via Wine — see `issen/docs/plans/2026-06-21-four-depth-builds-design.md` §B);
the primary `$LogFile` test data is the real DC01 stream (§A1/§A3c image), TSK-cross-validated.

- **Author / source:** [jschicht/LogFileParser](https://github.com/jschicht/LogFileParser),
  bundled in `LogFileParser_v2.0.0.53.zip`
  (<https://github.com/jschicht/LogFileParser/releases/download/v2.0.0.53/LogFileParser_v2.0.0.53.zip>).
- **Also used by** `core/tests/vfs_ntfs.rs` (`deleted_nodes` test): the extracted `partition.dd`
  is loaded into memory and MFT record 32 (`file8.txt`) is marked deleted **exactly as NTFS
  does it** — the record-header IN_USE flag (bit `0x0001` at record offset `0x16`) is cleared,
  leaving `$STANDARD_INFORMATION`/`$FILE_NAME` intact. That yields a genuine deleted MFT record
  (a real on-disk delete, not a mock) whose recovered name/parent/times the test asserts. No
  new committed bytes; the mutation is in-test only.
- **Redistribution / license:** LogFileParser is **MIT** (`LICENSE.md`, SPDX `MIT`, verified via
  `gh api repos/jschicht/LogFileParser`), which permits redistribution with attribution — so this
  bundled sample is committed. Attribution: © Joakim Schicht, MIT.

| File | Bytes | MD5 |
|---|---|---|
| `SampleTinyNtfsVolume.zip` | 2169791 | `5e3a65e60920fe6bb089ebf6cecc5595` |

#### real_logfile_rcrd_page.bin

A single **real RCRD record page** (one 4096-byte LFS page) carved from the **CITADEL-DC01**
`$LogFile`, used by `core/tests/logfile_rcrd.rs` to validate the RCRD reader + multi-sector USA
fixup against genuine on-disk bytes (doer-checker) rather than a self-encoded synthetic page.

- **Source image:** DFIR Madness "Stolen Szechuan Sauce" Case 001 — **CITADEL-DC01** C: drive
  (Windows Server 2012 R2), `20200918_0347_CDrive.E01`. Same corpus as `lznt1_real.bin` above.
  Case page: <https://dfirmadness.com/the-stolen-szechuan-sauce/>. Educational/research use.
- **Extraction (TSK as the independent input oracle):** `$LogFile` is MFT inode 2; the partition
  is at sector offset **718848**. The full stream was extracted with `icat -o 718848 "$E01" 2`
  (byte-identical to issen's own extraction, MD5 `a8e8582498464b4fbc15f83db8782516` — two
  independent extractors agree), then the second 4096-byte page (file offset `0x2000`, the first
  RCRD after the RSTR restart pages) was sliced out.
- **Page facts:** signature `RCRD`, `usa_offset` `0x28`, `usa_count` `9` (→ 8 × 512-byte sectors),
  `last_lsn` `0x0d54fa40` at offset `0x08`. The USA fixup must restore each sector's last two
  bytes from `usa[1..9]`; a page whose on-disk sector tail no longer matches `usa[0]` (the USN) is
  rejected by the integrity self-check.

| File | Bytes | MD5 |
|---|---|---|
| `real_logfile_rcrd_page.bin` | 4096 | `b5ef734e91222a606b675ced9db2ea92` |
### tiny.zip — NTFS volume with an ntfs-3g `IntxLNK` symlink

- **Source:** an 8 MiB NTFS volume authored with `mkntfs` (ntfs-3g 2022.10.3) inside a
  privileged `ubuntu:24.04` container (loop mount, no FUSE), populated via `cp -a` from a
  small tree: `README.txt`, `nested/file.txt`, and a symlink `nested/readme-link.txt ->
  ../README.txt` created by the Linux UDF/ntfs-3g driver. ntfs-3g stores symlinks as a
  resident unnamed `$DATA` whose content is the 8-byte `IntxLNK\x01` magic followed by the
  UTF-16LE target — no `$REPARSE_POINT` attribute is written.
- **Ground truth:** ntfs-3g's own mount resolves the symlink to `../README.txt`; the same
  record is listed by 7-Zip as a symlink (34 bytes).
- **Consumed by:** `core/tests/vfs_ntfs.rs` `symlink_surfaces_as_symlink_with_target`.

### ntfs_all_node_types.zip — every non-regular node type, in both Linux encodings

- **Source:** a 16 MiB NTFS volume authored with `mkntfs` (ntfs-3g 2022.10.3), then mounted
  **twice** by ntfs-3g and populated once per mode, so the same five nodes exist in both
  on-disk forms. A superset of `tiny.zip`'s tree (`README.txt`, `nested/file.txt`,
  `nested/readme-link.txt -> ../README.txt`), so those assertions keep their ground truth.
- **What each mode records** (`libntfs-3g/dir.c`, `include/ntfs-3g/layout.h:2450`):

  | node | `interix/` (default) | `wsl/` (`-o special_files=wsl`) |
  |---|---|---|
  | `symlink` | `IntxLNK\x01` + UTF-16 target | `LX_SYMLINK` `0xA000001D` |
  | `chardev` | `IntxCHR\x00` + major/minor | `LX_CHR` `0x80000025` |
  | `blockdev` | `IntxBLK\x00` + major/minor | `LX_BLK` `0x80000026` |
  | `fifo` | **zero-length `$DATA`, no magic** | `LX_FIFO` `0x80000024` |
  | `socket` | **one-byte `$DATA`, no magic** | `AF_UNIX` `0x80000023` |

  The two bold cells are a genuine format limitation: nothing on disk distinguishes an Interix
  FIFO from an empty file, or a socket from a one-byte file. `dir.c`'s own comment reads
  *"FIFO or regular file."* The tests assert `File` for those two rather than inferring a type
  the volume never recorded.
- **Generator command (verbatim), rootful container inside the podman VM:**
  ```sh
  dd if=/dev/zero of=ntfs_all_node_types.img bs=1M count=16
  mkntfs -F -Q -L NODETYPES ntfs_all_node_types.img
  ntfs-3g -o special_files=interix ntfs_all_node_types.img /mnt/ntfs
  #   seed README.txt / nested/ / nested/readme-link.txt, then in interix/:
  #   ln -s ../README.txt symlink; mknod chardev c 1 3; mknod blockdev b 7 0
  #   mkfifo fifo; python3 -c "import socket;s=socket.socket(socket.AF_UNIX);s.bind('socket')"
  umount /mnt/ntfs
  ntfs-3g -o special_files=wsl ntfs_all_node_types.img /mnt/ntfs   # repeat in wsl/
  ```
  **`mknod` needs real `CAP_MKNOD`.** Rootless podman cannot create device nodes even with
  `--privileged` — the capability is namespaced, and it fails on tmpfs too, which is the tell.
  On macOS: `podman machine ssh 'sudo podman run --privileged --device /dev/fuse …'`.
- **Size / MD5 (uncompressed image):** 16 777 216 bytes - `e6fe500d36b911e12f5bf7d705581a26`
- **Ground truth:** ntfs-3g's own readback in each mode lists `b`, `c`, `p`, `s` and `l` for
  the five nodes. Byte-level confirmation: `IntxLNK ×2, IntxCHR ×1, IntxBLK ×1`, and each WSL
  tag ×3; **zero** occurrences of the classic `0xA000000C` / `0xA0000003` — no Linux tool
  writes those, which is why `ntfs_windows_reparse.zip` exists.
- **Classification:** Tier 2 — real tool output, ground truth from the driver's own readback,
  scenario chosen here.
- **Consumed by:** `core/tests/node_types.rs`.

### ntfs_windows_reparse.zip — classic reparse points authored by Windows

- **Source:** a 64 MiB VHD created and formatted by `diskpart` on **Windows 11
  10.0.26200.8875**, populated with `mklink`, then detached; the NTFS partition (MBR type
  `0x07`, LBA 128) extracted to a raw volume image. No Linux tool can create these tags —
  ntfs-3g writes Interix or WSL forms, and the in-kernel `ntfs3` driver defines only
  `MOUNT_POINT` and `SYMLINK` with no LX tags at all.
- **Contents and Windows' own decode** (`fsutil reparsepoint query`, captured verbatim into
  `win_reparse_truth.txt` at generation time):

  | path | tag | `Flags` | `PathBuffer` at | substitute name |
  |---|---|---|---|---|
  | `rel_link.txt` | `0xa000000c` | `1` (RELATIVE) | `data + 12` | `target.txt` |
  | `abs_link.txt` | `0xa000000c` | `0` | `data + 12` | `\??\W:\target.txt` |
  | `rel_dirlink` | `0xa000000c` | `1` | `data + 12` | `realdir` |
  | `abs_dirlink` | `0xa000000c` | `0` | `data + 12` | `\??\W:\realdir` |
  | `junction` | `0xa0000003` | *(none)* | `data + 8` | `\??\W:\realdir` |
  | `hardlink.txt` | — | — | — | not a reparse point (control) |

  `rel_link.txt`'s reparse data length is `0x34` = 12 + 20 + 20, and `junction`'s is `0x3c`
  = 8 + names: Microsoft's own tool confirming that a symlink carries a 4-byte `Flags` field
  a junction does not.
- **Generator script:** `make-ntfs-reparse-fixture.cmd`, run from an elevated `cmd.exe`
  (symbolic links need `SeCreateSymbolicLinkPrivilege`; junctions do not).
- **Size / MD5 (extracted volume):** 65 994 752 bytes - `4f2672e79358e15f9e2dfeced4e393d0`
- **Classification:** Tier 2, at the strong end — neither the bytes nor the expected values
  were authored here, but the scenario (which links exist) was chosen. Tier 1 would need a
  real-world installation image, where the reparse points exist because Windows Setup made
  them.
- **Negative control:** reverting the `data + 12` symlink base makes
  `windows_authored_reparse_points_match_fsutil` fail with `"xttarget.t"` — Windows stores the
  *print* name first, so the bug yields a plausible-looking filename rather than the obvious
  NUL-prefixed garbage a zero-offset synthetic fixture produces. That is the specific reason
  this fixture earns its place alongside the synthetic ones.
- **Consumed by:** `core/tests/windows_reparse_oracle.rs`.
