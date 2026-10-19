# Rust Audit

Auditor and auto-fixer for **AI-generated Rust code**: stubs, demo code, fake
tests, fakes/mocks leaking into production, panic/unsafe misuse, swallowed
errors, async pitfalls, and fake / hallucinated / typosquatted dependencies
(slopsquatting).

Python 3.11+ stdlib only — no dependencies. English output.

## Quick start

```bash
python3 scripts/rust_audit.py selftest
python3 scripts/rust_audit.py scan  <rust-project> --format terminal,md,json,sarif --fail-on high
python3 scripts/rust_audit.py fix   <rust-project> --dry-run
python3 scripts/rust_audit.py cargo <rust-project> --deep --supply-chain
```

Exit codes: `0` clean · `1` findings at/above `--fail-on` · `2` execution error.
Every run writes a **not-executed report** (`report/not-executed-<date>.md`)
listing the checks that could not run and how to enable them — read it before
calling an audit complete.

## Tests

Production E2E suite: the real CLI audited against real Rust workspaces
(`BurntSushi/ripgrep` and `tokio-rs/tokio`, each pinned by commit — no demo
fixtures), with per-project goldens. Needs network to fetch the pinned
workspaces, Python 3.11+ and pytest in a venv:

```bash
python3 -m venv .venv && .venv/bin/pip install pytest
.venv/bin/python -m pytest tests/
```

See [SKILL.md](SKILL.md) for the rule catalog (R01–R21), the auto-fix policy,
the CI templates and the honest limitations.

## Security

The trust model is explicit: what executes (literal `cargo` argv, no shell),
what leaves the machine (opt-in `--online` registry/OSV lookups only) and
what writes to disk (transactional `fix`). See [SECURITY.md](SECURITY.md) —
including the notes for static skill auditors.

Release assets are **SSH-signed**: an install can verify it has the exact
audited `rust_audit.py` with preinstalled `ssh-keygen` alone — commands and
the pinned signing key live in [SECURITY.md](SECURITY.md#release-attestation-v020--verify-the-exact-audited-bytes).

Hardened scanners can enforce the static-only contract in code: every
subcommand accepts **`--no-exec`**, under which process creation is
impossible (one guarded entry point refuses every spawn) and each check that
would have executed is recorded as *skipped* in the not-executed report.

## License

Apache License 2.0 — see [LICENSE](LICENSE). © 2026 Doken-Tokuyama.
