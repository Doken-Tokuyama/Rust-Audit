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

Production E2E suite: the real CLI audited against a real Rust workspace
(`BurntSushi/ripgrep` pinned by commit — no demo fixtures). Needs network to
fetch the pinned workspace, Python 3.11+ and pytest in a venv:

```bash
python3 -m venv .venv && .venv/bin/pip install pytest
.venv/bin/python -m pytest tests/
```

See [SKILL.md](SKILL.md) for the rule catalog (R01–R21), the auto-fix policy,
the CI templates and the honest limitations.

## License

Apache License 2.0 — see [LICENSE](LICENSE). © 2026 Doken-Tokuyama.
