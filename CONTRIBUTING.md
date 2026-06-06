# Contributing to ntfs-forensic

Thanks for your interest in improving `ntfs-forensic`. This crate parses
untrusted NTFS images from potentially compromised systems, so correctness and
robustness are not negotiable. The bar is high and the workflow is strict —
please read this before opening a pull request.

## Test-Driven Development is mandatory

Every code change follows strict Red-Green-Refactor, and the RED and GREEN steps
land as **two separate commits**:

1. **RED** — write the failing test(s) first. They must define the expected
   behaviour and actually fail. Commit them alone. This commit is the verifiable
   proof that the test was written first.
2. **GREEN** — write the minimal implementation that makes the tests pass.
   Commit it separately.
3. **REFACTOR** — clean up while keeping every test green.

A single combined commit is not accepted. There is no "hard to test" exemption:
if something is awkward to unit test, use the closest testable abstraction,
fixtures, or an integration test — but write the test first.

Because you are validating code you wrote with tests you wrote, also validate
against **real external data** where it matters: cross-check parsing against real
NTFS images and an independent oracle (The Sleuth Kit, the `mft` crate), not only
synthetic fixtures.

## Quality gates

All of the following must pass locally and in CI before a PR can merge:

```bash
cargo fmt --all -- --check          # formatting
cargo clippy --all-targets -- -D warnings   # lints, warnings denied
cargo deny check                    # license / advisory / source policy
cargo test                          # unit + integration + parity
cargo llvm-cov --lib --show-missing-lines   # 100% line coverage
```

- **Formatting** — `cargo fmt`; do not hand-format.
- **Lints** — `cargo clippy` with warnings denied.
- **Dependencies** — `cargo deny` must pass (no GPL, no flagged advisories).
- **Coverage** — 100% line coverage is enforced; no source line may be left
  uncovered. New code needs tests that exercise its error paths, not just the
  happy path.
- **Fuzzing** — changes to a parser must keep its fuzz target green. Run the
  relevant target before submitting:

  ```bash
  rustup install nightly
  cargo install cargo-fuzz
  cargo +nightly fuzz run record       # or: attributes, attribute_list,
                                       # boot, compress, index_buffer, runlist
  ```

  If a parser gains new structure handling, extend or add the matching fuzz
  target.

## Robustness expectations

- No panics on malicious input — validate every length and offset against both
  the declared size and the actual buffer; use checked or saturating arithmetic.
- Fail loud — surface malformed input as a typed `NtfsError` with enough context
  to diagnose it. Never swallow an error or substitute a silent default.
- Keep `#![forbid(unsafe_code)]` intact.

## Commits and signing

- Keep diffs minimal — change only the lines the task requires; no drive-by
  reformatting of unrelated code.
- Commits are signed with [gitsign](https://github.com/sigstore/gitsign)
  (keyless Sigstore signing). Ensure your commits are signed before pushing.

## Reporting security issues

Do not open a public issue for a security vulnerability. See
[SECURITY.md](SECURITY.md) for the private reporting process.
