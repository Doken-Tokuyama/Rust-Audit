# Security and trust model

Rust Audit is an auditor that **runs the Rust toolchain on the target it
audits**. This document states exactly what executes, what leaves the
machine and what writes to disk — so install-time auditors (SkillSpector
and friends) and humans can classify it without guessing. Everything below
was verified against the source (2026-10-16).

## What this tool executes, and why

`scripts/rust_audit.py` runs external commands in exactly these cases, always
as a **literal argument list** (never a shell string):

| When | Commands | Working dir |
|---|---|---|
| `fix` validation | `cargo fmt -- --check`, `cargo check --all-targets`, `cargo test` | the audit target |
| `fix` safe rewrites | `cargo clippy --fix …`, `cargo fmt` | the audit target |
| `cargo` evidence pipeline | `cargo fmt/check/test/build`, `cargo llvm-cov`, `cargo mutants`, `cargo machete`, `cargo +nightly miri test`, and — only when installed — `guarddog crates verify`, `osv-scanner` | the audit target |
| the test suite | the CLI itself, `git fetch` of pinned commits | test tmp dirs |

Verified guarantees:

- **No `shell=True`, `os.system`, `os.popen`, `eval` or `exec`** anywhere in
  the codebase.
- Every command is a fixed literal list; the only external input is the
  working directory — the target path **you** pass to `scan` / `fix` / `cargo`.
- Missing tools are reported as *skipped*, never silently ignored, and the
  check lands in `report/not-executed-<date>.md`.
- The tool carries no prompt strings; `RULES` is the static rule catalog
  (R01–R21 metadata) used for reporting. `SKILL.md` is agent-facing
  documentation, not executable logic.

## What leaves the machine (opt-in only)

Only `scan --online` makes network calls — off by default; offline runs say
so in the not-executed report:

- `https://index.crates.io/…` and `https://crates.io/api/v1/crates/{name}` —
  dependency existence, yanked-version and feature checks.
- `https://api.osv.dev/v1/query` with body
  `{"package": {"name": <dep>, "ecosystem": "crates.io"}, "version": <ver>}`
  — public OSV advisory lookup.

Dependency names and versions are the audit subject; **no source code,
environment values or tokens are ever sent**. User-Agent identifies the tool.

## What writes to disk

- `scan` never modifies the target.
- `fix` edits the target **transactionally**: backups under
  `report/backup-<timestamp>/`, every edit validated with `cargo fmt --check`,
  `cargo check` and `cargo test`, **rolled back** if validation fails, and a
  second run must apply nothing (idempotent). It creates at most
  `deny.toml` and `.env.example`.
- Every run writes its reports under `report/`.

## Inherent risk (any toolchain auditor)

`fix` and the cargo evidence pipeline **compile the target and run its
tests** — which executes the target's `build.rs` and test code. That is the
same trust model as running `cargo test` yourself: audit targets you trust,
or sandbox them. Static `scan` runs no target code.

## Static-auditor notes (SkillSpector, 2026-10-16)

A static skill auditor scored the source archive `DO_NOT_INSTALL`
(risk 100). Reviewed finding by finding against the source, every hit is an
expected property of an auditor, not malice:

| Finding | Verdict | Why |
|---|---|---|
| OH1 ×4 — `subprocess.run` | expected | literal argv lists, no shell/eval (see above) |
| P6 — "prompt leak" at `Finding.tier` | false positive | `RULES.get(rule_id)["tier"]` is rule metadata, not a prompt |
| network call to api.osv.dev | expected | opt-in `--online`, fixed public API, name+version payload only |
| filler / LICENSE patterns | false positive | boilerplate |

If your scanner still blocks on the *category* ("a skill that executes
commands"), use `scan` (static, zero subprocess calls) and skip `fix`/`cargo`.
