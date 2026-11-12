# Changelog

All notable changes to `ntfs-forensic` (the analyzer) are documented here. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.0](https://github.com/SecurityRonin/ntfs-forensic/compare/ntfs-forensic-v0.8.5...ntfs-forensic-v0.9.0) - 2026-11-11

### Documentation

- *(forensic)* [**breaking**] record that ntfs-core types in our API make this breaking

## [0.8.0]

- Current published analyzer: anomaly auditing over raw NTFS bytes
  (`audit_record`, `audit_mft_mirror`, `audit_logfile`) emitting
  `forensicnomicon::report::Finding`s.

<!-- release-plz appends new versions above this line, newest first. -->
