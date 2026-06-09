# usnjrnl-forensic → ntfs-core / ntfs-forensic absorption

Status: in progress (started 2026-06-09). Strict TDD (RED/GREEN separate commits).

## Goal

Move all reader-level intelligence from `usnjrnl-forensic` into **`ntfs-core`**, and all
findings-level intelligence into **`ntfs-forensic`**, leaving `usnjrnl-forensic` a thin CLI
shell (arg-parsing + output formats + monitor + the rayon parallel driver).

## Destination map

| usnjrnl module | → | Notes |
|---|---|---|
| `refs/` | **ntfs-core** | std-only, cleanest; Phase 1a |
| `usn/reader.rs` (`UsnJournalReader`) | **ntfs-core** | `anyhow`→`NtfsError` |
| `usn/carver.rs` (`carve_usn_records`) | **ntfs-core** | drop `log` |
| `rewind/` (`RewindEngine`) + `mft/mod.rs` (`MftData`) | **ntfs-core** | move together (cluster: `seed_rewind` returns `RewindEngine`) |
| `rules/`, `analysis/`, `correlation/`, `triage/` | **ntfs-forensic** | add `impl Observation`/`to_finding` |
| `output/`, `monitor/`, `main.rs`, `image/`, `usn/parallel.rs` | **stay in usnjrnl** | thin shell |

## Architectural decisions (resolved)

- **`usn/parallel.rs` (rayon) stays in usnjrnl.** No `-core` reader in the fleet pulls rayon;
  parallelism is execution strategy, owned by the caller. ntfs-core instead exposes the pure
  decode-aware boundary primitive (`is_valid_record_start` / `find_record_boundary`).
- **`image/` stays in usnjrnl for this migration.** It is CONTAINER/orchestration, not a
  filesystem reader. Its eventual home is `disk-forensic::triage` — a **separate follow-on
  workstream** (promote `issen-disk`'s extraction into `disk-forensic`, de-dup `image/`). Not
  part of this migration.

## Phases

- **Phase 1** — pure readers → ntfs-core: `refs/` (1a), `usn/reader.rs` (1b), `usn/carver.rs` (1c).
- **Phase 2** — `rewind/` + `MftData` cluster → ntfs-core (move together).
- **Phase 3** — `rules`/`analysis`/`correlation`/`triage` → ntfs-forensic; add `Observation`
  conversions; reconcile `MftData::detect_timestomping` (raw) vs ntfs-forensic `detect_timestomp` (graded).
- **Phase 4** — gut usnjrnl to thin shell: delete moved modules, add `[patch.crates-io]` →
  local ntfs-core/ntfs-forensic during migration, rewire `main.rs`/`output/`.
- **Phase 5** — bump + publish `ntfs-core 0.7` / `ntfs-forensic 0.6`; repoint issen pins;
  rewrite ntfs-forensic + usnjrnl READMEs (folds into the fleet doc-sweep).

## Conventions

- Each moved module: tests move with code. RED commit = tests in new crate (fail to compile,
  types absent). GREEN commit = move impl, tests pass. ntfs-core keeps 100% line coverage,
  panic-free production code (no unwrap/expect outside `#[cfg(test)]`).
- During migration, usnjrnl temporarily duplicates moved modules; the duplicates are deleted
  in Phase 4 once usnjrnl is rewired onto local ntfs-core via `[patch.crates-io]`.
