# ntfs-forensic

[![Crates.io](https://img.shields.io/crates/v/ntfs-forensic.svg)](https://crates.io/crates/ntfs-forensic)
[![Docs.rs](https://img.shields.io/docsrs/ntfs-forensic)](https://docs.rs/ntfs-forensic)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Forensic anomaly auditor for NTFS** — turns the artifacts a clean reader hides (timestomping, alternate data streams, deleted MFT records, record slack) into graded `forensicnomicon::report::Finding`s via the `Observation` trait, built on **[`ntfs-core`](https://crates.io/crates/ntfs-core)**.

```rust
use ntfs_forensic::audit_record; // -> Vec<Anomaly>; an.to_finding(source) for a canonical Finding
```

Codes: `NTFS-TIMESTOMP` (High), `NTFS-ADS` / `NTFS-SLACK-RESIDUE` (Low), `NTFS-DELETED-RECORD` (Info).

---

[Privacy Policy](https://securityronin.github.io/ntfs-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/ntfs-forensic/terms/) · © 2026 Security Ronin Ltd
