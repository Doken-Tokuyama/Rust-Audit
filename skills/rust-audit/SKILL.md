---
name: rust-audit
description: >-
  Static auditor and auto-fixer for AI-generated Rust traps — stubs, fake
  tests, stubbed logic, panic/unsafe misuse, swallowed errors, hallucinated
  or typosquatted crates. Use when the user asks to audit, scan, review or
  fix Rust code, find stubs/fakes/fake tests, verify dependencies against
  crates.io, or invokes Rust Audit. Every audit runs jointly with the
  veyra-proof skill (static triage + real-toolchain evidence).
---

# Rust Audit

Static half of a Rust audit: stubs, fake tests, stubbed logic, panic/unsafe
misuse, swallowed errors, async pitfalls, hallucinated or typosquatted
dependencies. The tool is a Python 3.11+ stdlib CLI, English output.

## Pairing with veyra-proof — mandatory

Rust Audit is static triage; `veyra-proof` is real-toolchain evidence
(fmt, clippy, test, coverage, mutants). Every audit runs **both** skills on
the same target and delivers **one verdict with both evidence paths**: the
Rust Audit JSON + not-executed report, and the veyra-proof evidence dir.
Each half reports what actually ran — "verified" covers only that.

## Resolve the tool (`RUST_AUDIT`) and the interpreter (`PY`)

Tool — pick the first that works:

1. Env `RUST_AUDIT_HOME` — the script is `$RUST_AUDIT_HOME/scripts/rust_audit.py`
2. The home clone on this machine — `/Volumes/Lexar/Cursor/rust-ai-audit`
3. Otherwise ask the user once for the clone path and export `RUST_AUDIT_HOME`

Interpreter — the tool needs Python 3.11+ (`tomllib`) and a system `python3`
can be 3.9. Pick the first whose `$PY -c 'import tomllib'` succeeds:
`python3`, `python3.13`, `python3.12`, `python3.11`,
`$RUST_AUDIT_HOME/.venv/bin/python`. Every command runs as
`"$PY" "$RUST_AUDIT_HOME/scripts/rust_audit.py" …`.

Never hardcode the path into project files.

**Done when:** `$PY … scripts/rust_audit.py selftest` prints
`selftest PASS`, or the exact blocker is reported.

## Workflow

1. **`setup`** — best-effort install of the optional evidence tools; every
   outcome lands in the not-executed report.
2. **`scan <target> --format terminal,md,json,sarif --fail-on high`** — read
   the JSON report **and** `report/not-executed-<date>.md`: that report is
   part of the verdict, never an appendix to drop.
3. **`fix <target>`** — safe fixes only, transactional (validated with
   fmt+check+tests, rolled back on failure); a second run must apply nothing.
   Then show `fix --assisted` diffs for behaviour-changing rewrites — the
   human decides, they are never auto-applied.
4. **`cargo <target> --deep --supply-chain`** — the evidence pipeline;
   missing tools report *skipped*, never *pass*.
5. **`scan --online`** for new dependencies (crates.io existence, yanked,
   invented features, docs.rs, OSV). Golden rule: never accept a new
   dependency without the human verifying crates.io + docs.rs themselves —
   self-refinement does not reduce crate hallucination (arxiv 2606.08444).

## Hardened targets — `--no-exec`

Every subcommand accepts **`--no-exec`**: zero subprocesses (enforced at one
guarded spawn point), checks that would execute are recorded as *skipped*.
Use it when the target or the environment forbids running a toolchain —
the static rules still run in full.

## Release installs — verify first

When the tool is fetched as a release artifact, verify the exact file
before its first execution:
`"$RUST_AUDIT_HOME/scripts/verify_release.sh" [TAG] ./rust_audit.py` —
key pin → SSH signature → checksum → tag identity, plus your local copy
against the signed manifest; execute only on `VERIFIED` (exit 0), see
`$RUST_AUDIT_HOME/SECURITY.md`.

Exit codes: `0` clean · `1` findings at/above `--fail-on` · `2` execution
error. Cite real exit codes and report paths.

## Catalog and policy

The rule catalog (R01–R21), auto-fix policy, evidence interpretation and the
honest limitations live in the canonical copy — read
`$RUST_AUDIT_HOME/SKILL.md` for them. Before refining any heuristic, read
`$RUST_AUDIT_HOME/docs/adr/0001-false-positive-vs-true-positive-criterion.md`:
remove provably wrong claims, never rules that work as documented.
