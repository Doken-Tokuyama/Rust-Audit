# Joint audit — tokio@cdd9dae3 · Rust Audit × veyra-proof (2026-10-16)

First run of the mandatory pairing (installed `rust-audit` skill): both halves
on the same target, one verdict, both evidence paths.

## Merged verdict: REJECTED

Both halves independently fail their gates: veyra-proof **REJECTED** (blocker
findings) and Rust Audit **exit 1** (findings at/above `--fail-on high`).

| Half | Tool | Command | Exit | Verdict |
|---|---|---|---|---|
| Static | Rust Audit 0.1.0 | `scan … --format terminal,md,json,sarif --fail-on high` | 1 | 2436 findings (13 critical / 1245 high / 259 medium / 739 low / 180 info) |
| Toolchain | veyra 0.7.0 | `audit … --profile standard` (14 tools) | 1 | REJECTED — blockers `VT001`/`VT002` |

## Evidence paths

- **Rust Audit**: `/tmp/ra-proofs/joint/rust-audit/` —
  `rust-audit-20261016-231921.{json,md,sarif}`, terminal capture and the
  dated `not-executed-2026-10-16.md`.
- **veyra-proof**: `/tmp/ra-proofs/tokio/.veyra/evidence/20261016T212029Z/` —
  `report.json`, `manifest.json` and `tools/<tool>/` per tool. Plan at
  `/tmp/ra-proofs/joint/veyra-plan.json` (0 pending installs — nothing was
  installed during the run).

## Cross-signal analysis (why the pairing pays)

- **7/7 production placeholders corroborated by two independent methods.**
  veyra's anti-theater blockers (reachable `todo!()`/`unimplemented!()` in
  production paths) are at the exact file:line of Rust Audit R01 findings:
  `tokio/src/process/mod.rs:1697,1703,1709` (`todo!()`),
  `tokio/src/macros/join.rs:111`, `tokio/src/macros/select.rs:571`,
  `tokio/src/macros/try_join.rs:161`, `tokio/src/io/bsd/poll_aio.rs:32`
  (`unimplemented!()`). Human review still required — the `io/bsd` and
  `macros` locations suggest cfg-gated platform/macro paths.
- **Rust Audit adds 9 test-side placeholders** the anti-theater scan does not
  claim (loom tests in `tokio/src/sync/tests/`, `async_send_sync.rs`,
  `framed_write.rs`) — complementary, not conflicting.
- **Determinism**: the static half reproduces the E2E golden for this pinned
  commit exactly (2436 findings), so the two evidence sets describe the same
  code state.

## Problems (veyra, real output only)

- **clippy [error]** `tokio/tests/time_sleep.rs:424` — manual no-op waker
  implementation; the test build fails under rustc 1.97.1. The pinned commit
  is historical and clippy is current, so this may be lint drift rather than
  a defect of this commit — verify at a current tokio revision before
  treating it as one.
- **cargo-semver-checks [error]** — API breakage reported against its
  baseline.
- **cargo test** — 77 informational findings, none blocking.
- **cargo-geiger ERROR** (exit 1) — could not match registry package
  `hashbrown@0.15.5`; unsafe-count evidence is MISSING, not OK.

## Not executed (both halves, honest gaps)

- veyra **dylint** (no Dylint configuration found) and **veyra-e2e** (no
  `[[e2e.scenarios]]` declared) — SKIPPED, not passes.
- Rust Audit `setup`/`cargo --deep --supply-chain` evidence pipeline — the
  toolchain half (llvm-cov, deny, audit, machete, geiger, mutants-class) is
  covered by veyra; optional installs were deliberately not performed.
- Side effect: `Cargo.lock` created in the clone (tokio does not commit one);
  informational, no manifest changes (veyra policy).

## Follow-ups

1. Human review of the 7 corroborated placeholders (cfg context decides:
   real stub vs platform-gated idiom).
2. `cargo-geiger` hashbrown matching failure — report upstream or pin the
   tool version.
3. Cosmetic: Rust Audit R01 messages render `todo!!()` (double `!`).
