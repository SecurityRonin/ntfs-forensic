# 4. `forensicnomicon` as the KNOWLEDGE leaf — format constants and the shared report model

Date: 2026-07-24

Status: Accepted

## Context

Two kinds of shared knowledge cut across the fleet: (1) the *format facts* an
NTFS parser needs — magic bytes (`SIGNATURE_FILE`, `SIGNATURE_BAAD`), attribute
type codes, field offsets — and (2) the *normalized reporting vocabulary* every
analyzer emits so ORCHESTRATION (issen, disk4n6) renders findings uniformly
instead of N bespoke `XxxAnalysis` types.

The fleet layer architecture (`~/src/ronin-issen/CLAUDE.md` → "Multi-Repo
Architecture" and "The Reporting Model — `forensicnomicon::report`") places both
in the zero-dependency `forensicnomicon` KNOWLEDGE leaf, and mandates that every
analyzer depend *down* onto it. `ntfs-forensic/src/lib.rs` imports
`forensicnomicon::ntfs::{attr_types, SIGNATURE_BAAD, SIGNATURE_FILE}` and
`forensicnomicon::report::{Severity, Source, ...}`; `ntfs-core/Cargo.toml`
documents the dependency as "NTFS on-disk structure knowledge ... lives in the
KNOWLEDGE layer — the published forensicnomicon crate."

## Decision

- Take all NTFS on-disk structure constants from `forensicnomicon::ntfs` rather
  than re-declaring magic bytes and offsets in this workspace (`ntfs-core` and
  `ntfs-forensic` both depend on `forensicnomicon = "1"`).
- Emit every anomaly as a `forensicnomicon::report::Finding`, constructing it
  through the `Observation` trait / builder, so NTFS findings aggregate with the
  container and partition layers into a single `Report`.

## Consequences

- Dependency direction is strictly downward onto the leaf; `forensicnomicon`
  depends on nothing, so there is no cycle risk and a constant is defined once
  for the whole fleet.
- Anomaly `code`s are a published contract (scheme-prefixed SCREAMING-KEBAB);
  the analyzer keeps its own typed `AnomalyKind` and maps to canonical findings,
  rather than `forensicnomicon` enumerating every NTFS anomaly.
- A `forensicnomicon` major bump is a coordinated fleet event: the workspace
  moved `0.5 → 0.11` (commit `5773bde`) and then to `1.0` (commit `6175dfe`) in
  step with the leaf's releases.
