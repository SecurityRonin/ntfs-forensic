# Security Policy

`ntfs-forensic` is designed to parse **untrusted NTFS images** — including disk
images acquired from compromised or actively hostile systems. Hostile input is
the expected case, not an edge case. Robustness against crafted structures is a
core design goal, and we take reports of crashes, hangs, or memory-safety issues
seriously.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x   | ✅ — current release line, receives security fixes |
| < 0.1   | ❌ — pre-release, unsupported |

Security fixes are released against the latest published `0.1.x` line.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Report privately, by either:

- **GitHub Security Advisories** — open a private advisory on the
  [`ntfs-forensic` repository](https://github.com/SecurityRonin/ntfs-forensic/security/advisories/new), or
- **Email** — [albert@securityronin.com](mailto:albert@securityronin.com).

Please include:

- the affected version and target triple,
- a minimal reproducing NTFS image or byte buffer (a fuzz corpus entry is ideal),
- the observed behaviour (panic, hang, excessive allocation, mis-parse) and the
  expected behaviour.

We aim to acknowledge a report within a few business days and to coordinate
disclosure once a fix is available.

## Security posture

`ntfs-forensic` is hardened against adversarial input by construction:

- **`#![forbid(unsafe_code)]`** across the whole crate — no `unsafe`, anywhere.
- **No panics on malicious input** — every length and offset is validated
  against both the structure's declared size and the actual buffer; arithmetic
  is checked or saturating.
- **Bounded allocations** — `try_reserve_exact` and explicit ceilings refuse
  allocation bombs (e.g. a crafted runlist or LZNT1 stream).
- **Loop caps** — attribute chains, runlists, and index entries are bounded
  against non-terminating walks.
- **Fixup verification** — torn writes and update-sequence-array tampering
  surface as a typed `FixupMismatch` error rather than silently-wrong output.
- **Partition isolation** — `OffsetReader` makes reading past the volume
  boundary structurally impossible.

### Fuzzing

Continuous fuzzing with [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz)
backs the hardening above. Seven targets cover the parsers that consume
attacker-controlled bytes:

| Target | Surface |
|---|---|
| `boot`          | boot sector / BPB |
| `record`        | FILE record header + fixup |
| `attributes`    | attribute chain walking |
| `attribute_list`| `$ATTRIBUTE_LIST` extension records |
| `runlist`       | data-run (VCN→LCN) decoding |
| `compress`      | LZNT1 decompression |
| `index_buffer`  | `$INDEX_ROOT` / INDX directory buffers |

The crates' panics found by fuzzing (e.g. an LZNT1 chunk-size overflow) are
fixed and pinned as regression tests.

For how to run the targets yourself, see
[CONTRIBUTING.md](CONTRIBUTING.md#quality-gates).
