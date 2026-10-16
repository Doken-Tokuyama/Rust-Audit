# Rust Audit

Auditor and auto-fixer for **AI-generated Rust code**: stubs, demo code, fake
tests, fakes/mocks leaking into production, panic/unsafe misuse, swallowed
errors, async pitfalls, and **fake / hallucinated / typosquatted dependencies**
(slopsquatting). Python 3.11+ stdlib only — no dependencies. English output.

## Triggers

Use this skill when the user says: "audit this Rust code", "review AI-generated
Rust", "find stubs / fakes / fake tests", "check my dependencies for
hallucinated crates", "fix these findings", or invokes `Rust Audit`.

## Quick start

```bash
# 0) best-effort install of the optional evidence tools
#    (cargo-mutants, cargo-llvm-cov, cargo-udeps, guarddog, osv-scanner, miri, typomania)
python3 scripts/rust_audit.py setup

python3 scripts/rust_audit.py scan <rust-project> \
    --format terminal,md,json,sarif --fail-on high
python3 scripts/rust_audit.py fix  <rust-project> --dry-run
python3 scripts/rust_audit.py cargo <rust-project> --deep --supply-chain
python3 scripts/rust_audit.py selftest
```

Exit codes: `0` clean · `1` findings at/above `--fail-on` · `2` execution error
(invalid target, no sources).
CI-ready: use `--fail-on high` (or `--strict` = fail on medium) and upload the
SARIF file with `github/codeql-action/upload-sarif`.

**Not-executed report:** every run writes `report/not-executed-<date>.md` listing
ALL checks that could not be executed (tool missing, network unused, feature not
requested) with the reason and how to enable each one. Read it before claiming
an audit is complete; attach it to the PR. Disable with `--no-gap-report`.

## Workflow (agent checklist)

0. **`setup`** — attempt to install the optional evidence tools (cargo-mutants,
   cargo-llvm-cov, cargo-udeps, guarddog, osv-scanner, miri, typomania). Each
   install is best-effort with strategies + timeout; outcomes land in the
   not-executed report (`report/not-executed-<date>.md`). `--dry-run` previews.
1. **`scan`** on the target and read the JSON report (`report/rust-audit-*.json`)
   plus the not-executed report.
2. **`fix` (safe)** — apply machine-safe fixes; the tool validates each edit with
   `cargo fmt --check`, `cargo check`, `cargo test` and **rolls back** on failure.
   Verify idempotency (second run applies nothing).
3. **`fix --assisted`** — review the unified diffs for behaviour-changing fixes
   (unwrap→`?`, `let _ =` handling, `thread::sleep`→`tokio::time::sleep`). Never
   auto-apply these; the human decides the error-handling policy.
4. **`cargo`** evidence pipeline (`--deep` for coverage+mutation+unused deps,
   `--supply-chain` for audit/deny/vet/guarddog/OSV). Missing tools report
   *skipped*, never *pass*.
5. **`scan --online`** for new dependencies: verifies crates.io existence,
   yanked versions, feature names (sparse index), docs.rs builds and OSV
   advisories. A crate that *exists* is not proven safe: recently registered +
   few downloads + generic name = slopsquatting window (R19).
6. Run the checklist below, then remediate findings rule by rule.
7. **Report honestly:** the dated not-executed report must be part of the audit
   verdict — "verified" only covers the checks that actually ran.

**Golden rule: never accept a new dependency without a human verifying
crates.io + docs.rs themselves.** Self-refinement by the LLM does not reduce
crate hallucination (arxiv 2606.08444); post-generation verification does.

## Merge checklist (from the source research)

1. `cargo fmt` 2. `cargo clippy -- -D warnings` 3. `cargo test` 4.
`cargo build --release` if perf/unsafe is involved 5. verify every new
dependency on crates.io and docs.rs 6. search for `unwrap`, `unsafe`, `todo!`,
`unimplemented!`, secrets 7. ask: empty input? invalid input? network down?
disk full? concurrency? 8. prove stubs/fakes exist only in tests.

## Rule catalog

### Tier 1 — stubs, fakes, demo code, fake tests (the core ask)

| ID | Detects | Severity | Fix |
|---|---|---|---|
| R01 | `todo!()`, `unimplemented!()`, `panic!("not implemented")`, empty fn body | critical (prod) / info (tests) | none |
| R02 | fake tests (Test Smells Catalog 2.0), judged only on real test functions (helpers excluded): no oracle (high only when the body cannot fail; helper-delegating tests get low "no direct oracle"), tautologies (`assert!(true)`, `assert_eq!(2,2)`; not `assert!(false)`, the `#[should_panic]` guard), generic names (`test_ok`), assertion roulette (bare `assert!` only — Rust's `assert_eq!`/`assert_ne!` print values + line), magic numbers, duplicate asserts (same macro+args back-to-back within one scenario; same expectation across scenarios is intentional; read-only args claim plain redundancy, state-capable args carry a "redundant only if the interleaved asserts do not advance state" hedge — ADR 0002), 3+ `#[ignore]` | high/low | none |
| R03 | stubbed logic outside trait contracts (`impl X for Y` and `trait` default methods return constants by design): truly empty body `{}`, constant return, all params ignored (`_`-prefixed params are intentional), `if false` placeholder branch | high | none |
| R04 | placeholder data as real (`"lorem ipsum"`, `example.com`, `dummy`) in production | high | none |
| R05 | demo code (`demo*`/`sample*`/`placeholder*` names, trivial `fn main`) | medium/info | none |
| R06 | `Fake*`/`Mock*`/`InMemory*` types outside test code | medium | none |
| R07 | over-mocking / mock-only assertions | low | none |
| R08 | flaky tests: sleep/wall-clock/randomness/env mutation/unordered iteration | medium | none |

### Tier 2 — panics, unsafe, errors, security

| ID | Detects | Severity | Fix |
|---|---|---|---|
| R09 | `.unwrap()`/`.expect()`/`panic!` in production code | high | assisted (→`?`) |
| R10 | swallowed errors (`let _ =`, `if let Ok(_)`, `.ok();`, `unwrap_or_default()`) | medium | assisted |
| R11 | `unsafe`/`transmute`/raw pointers/`extern "C"` without `// SAFETY:` comment | high | none |
| R12 | hardcoded secrets (AWS/GitHub/Slack keys, private keys, high-entropy literals) | critical | **safe** (→ env var + `.env.example`) |
| R13 | missing input validation (`env::args`, unchecked `parse`/`from_str`) | medium | none |

### Tier 3 — idiom and quality

| ID | Detects | Severity | Fix |
|---|---|---|---|
| R14 | `.clone()` abuse (>3 per fn, configurable) | medium | none |
| R15 | invented lifetimes (≥3 per signature, configurable) | low | none |
| R16 | async misuse: blocking sleep/fs in async, `std::sync::Mutex` held across `.await`, `block_on` in async, unbounded `tokio::spawn` in loops, undeclared tokio features | high/medium | assisted (sleep) |
| R17 | `Arc<Mutex<..>>` wrapping everything | low | none |

### Tier 4 — fake/hallucinated dependencies and supply chain

Method from arxiv 2606.08444 (crate-hallucination study, 22% hallucination
rate): inventory = crates.io + std crates + compiler crates + mined aliases;
classification matters because **45% of hallucinations are std/internal modules
used as crates** and **86% of the rest are near-miss names** (omitted hyphens).

| ID | Detects | Severity | Fix |
|---|---|---|---|
| R18a | unresolved external crate reference (not declared; compile error) | high | none |
| R18b | std module used as crate (`use fs::File`) | high | **safe** (→ `use std::fs::File`) |
| R18c | near-miss name (`serdee` vs `serde`, ≤2 edits) with real-crate suggestion | high | none (never auto-rename) |
| R18d | suspicious generic name (`rust-*`, `*-utils`, `*-helpers`, corpus hit) or impossible version (`tokio = "25"`); online: nonexistent crate, yanked version, invented features, missing docs.rs build | critical/high | none |
| R18e | declared dependency never used (corroborated by cargo-machete/udeps) | low | none |
| R19 | slopsquatting window: first publish <90 days + low downloads + generic name; OSV advisories | high | none |
| R20 | potential typosquat of a popular crate (edit distance ≤2 vs bundled corpus) | high | none |
| R21 | risky `build.rs`/proc-macro: `Command::new`, network, file writes at compile time | high | none |

## Auto-fix policy

- **`fix` (default, `--safe`)**: machine-safe only — `use fs::` → `use std::fs::`
  (skipped when a real `mod fs` exists), secret literal → `std::env::var()` +
  `.env.example` entry, generate `deny.toml`, `cargo fmt`, `cargo clippy --fix`
  (rustc `MachineApplicable` suggestions only). Every run is **transactional**:
  files are backed up, edits validated with fmt+check+tests, and **reverted** if
  validation fails. A second run must apply nothing (idempotent — the tool
  self-checks).
- **`fix --assisted`**: unified diffs only, never written. Used for
  behaviour-changing rewrites (error handling, async) where the correct policy
  is a human decision.
- **Never auto-fixed**: unsafe, concurrency, security-sensitive code,
  architecture.
- Compilation passing is necessary but not proof of semantic correctness —
  re-run the test suite and review the diffs.

## Interpreting evidence

Each finding carries `source`, `confidence`, `fix`. Corroborating signals:
**mutants** (`cargo mutants`: survived mutants = tests that cannot fail, the
real test for "tests that prove nothing"); **coverage** (cargo-llvm-cov: stub
function never exercised); **machete/udeps/dead_code** (stub never called);
**clippy JSON** (compiler-level confirmation). Static heuristics alone are
triage; combine signals before declaring a defect.

## CI and templates

`templates/` contains: `github-workflow.yml` (scan + SARIF upload +
`cargo test --locked` + audit/deny/vet + zizmor self-check + Scorecard +
artifact attestations), `deny.toml` (only crates.io, deny yanked/banned), 
`rust-audit.toml` (thresholds, disabled rules, corpus), `dependabot.yml`,
`pre-commit-config.yaml`, `ast-grep/` (structural rewrite rules for the optional
ast-grep backend). Pin third-party Actions to full commit SHAs before enabling.

## Resources

`resources/popular_crates.txt` (typosquat baseline) and
`resources/suspicious_names.txt` (slopsquatting corpus seed). Both are
pluggable: point `corpus = "..."` in `rust-audit.toml` at your organization's
private list of known-hallucinated names. No public list of hallucinated names
exists (the USENIX Security 2025 study withheld its 205k names), so registry
verification + similarity + reputation signals are the reliable core.

## Limitations (be honest about these)

Before refining any heuristic, read
[docs/adr/0001-false-positive-vs-true-positive-criterion.md](docs/adr/0001-false-positive-vs-true-positive-criterion.md):
remove provably wrong claims, never rules that work as documented.

- Heuristic lexer + structural analysis, not a full `syn` parser: macro-heavy or
  unusual formatting can evade fn-level rules (file-level rules still run).
- R19/online checks need network; offline runs say so explicitly.
- The optional ast-grep backend needs `ast-grep` installed; Coccinelle-for-Rust
  is still a prototype and is not used.
- AI-authorship classification is deliberately absent: current detectors drop to
  ~0.20 Macro-F1 out of domain (AICD Bench) and would only add noise. Detect the
  *traps*, not the author.
- Fix validation requires a compilable project; on intentionally broken targets
  edits are applied without compile validation — the tool reports that
  explicitly.
- R02 "no oracle" cannot see through helper calls: tests whose assertions live
  in helpers are reported at low severity as "no direct oracle" — verify those
  by hand. R03 exempts trait contracts (`impl X for Y`, `trait` defaults) and
  the compile-time type-assertion idiom (`fn check<T: Send>() {}`), so a stubbed
  default method is reported only via its other signals. cfg/macro-gated no-op
  alternates (feature-off metric hooks, mock doubles) still read as empty
  bodies or constant returns — review those in context.

## License

Apache License 2.0 (see `LICENSE`) — © 2026 Doken-Tokuyama.
- `setup` cannot install everything everywhere (Go absent for osv-scanner,
  typomania is library-only, cargo-udeps needs nightly): failures are recorded,
  never hidden — see `report/not-executed-<date>.md`.
