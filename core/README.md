# ntfs-core

[![Crates.io](https://img.shields.io/crates/v/ntfs-core.svg)](https://crates.io/crates/ntfs-core)
[![Docs.rs](https://img.shields.io/docsrs/ntfs-core)](https://docs.rs/ntfs-core)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Pure-Rust, from-scratch NTFS filesystem reader** — `$MFT`, attributes, indexes, data runs, `$DATA`/named streams, LZNT1 decompression, and `NtfsFs` navigation over any `Read + Seek` source. No `unsafe`, no C bindings.

```toml
[dependencies]
ntfs-core = "0.4"
```

Forensic analysis (timestomp / ADS / deleted-record / slack findings) lives in the sibling **[`ntfs-forensic`](https://crates.io/crates/ntfs-forensic)** crate, built on this one — the reader/analyzer split mirrors `vmdk-core`/`vmdk-forensic`.

---

[Privacy Policy](https://securityronin.github.io/ntfs-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/ntfs-forensic/terms/) · © 2026 Security Ronin Ltd
