# Rust Audit

Auditor and auto-fixer for **AI-generated Rust code**: stubs, demo code, fake
tests, fakes/mocks leaking into production, panic/unsafe misuse, swallowed
errors, async pitfalls, and fake / hallucinated / typosquatted dependencies
(slopsquatting).

Python 3.11+ stdlib only — no dependencies. English output.

## Install

```bash
pipx install rust-audit      # or: pip install rust-audit
rust-audit selftest          # prints `selftest PASS`
```

From PyPI as **`rust-audit`**, whose wheel installs both commands: `rust-audit`
and `rustaudit` run the same module. There is no separate one-word project on
PyPI — it answers "This project name is too similar to an existing project" —
so the spelling is served by this package's own entry point.
Nothing is fetched or executed at install time, and
the wheel carries the same `rust_audit.py` as the signed release asset — so the
verify-before-use chain below still applies to the script you download.

The wheel's digest is attested by the workflow that built it, so you can check
where it came from before running it:

```bash
gh attestation verify rust_audit-*-py3-none-any.whl -R Doken-Tokuyama/Rust-Audit
```

## Quick start

```bash
# 0) verify before use — check the exact audited bytes before executing them
#    (key pin -> SSH signature -> checksum -> tag identity) and proceed only
#    on VERIFIED (exit 0); see SECURITY.md for the pinned key and the chain
scripts/verify_release.sh v0.2.5 ./rust_audit.py

python3 scripts/rust_audit.py selftest
python3 scripts/rust_audit.py scan  <rust-project> --format terminal,md,json,sarif --fail-on high
python3 scripts/rust_audit.py fix   <rust-project> --dry-run
python3 scripts/rust_audit.py cargo <rust-project> --deep --supply-chain
```

Exit codes: `0` clean · `1` findings at/above `--fail-on` · `2` execution error.
Every run writes a **not-executed report** (`report/not-executed-<date>.md`)
listing the checks that could not run and how to enable them — read it before
calling an audit complete.

As a Freebuff agent skill: install `rust-audit` into Freebuff on any machine
by following [docs/freebuff-skill-install.md](docs/freebuff-skill-install.md).

## Tests

Production E2E suite: the real CLI audited against real Rust workspaces
(`BurntSushi/ripgrep` and `tokio-rs/tokio`, each pinned by commit — no demo
fixtures), with per-project goldens. Needs network to fetch the pinned
workspaces, Python 3.11+ and pytest in a venv:

```bash
python3 -m venv .venv && .venv/bin/pip install pytest
.venv/bin/python -m pytest tests/
```

CI runs exactly that on every push to `main`, every `v*` release tag and every
pull request (`.github/workflows/tests.yml`: Python 3.11 and 3.13, pytest as
the only install), so a commit is verified without anyone remembering to type
it. `tests/test_ci_workflows.py` keeps the job honest: it must exist, it must
run this suite, it may not swallow a failure, and every action is pinned to
one commit SHA across all workflows. A second job audits the **published
artifact**: `python -m build`, install with `--no-index` into a clean venv,
`rust-audit selftest`, then the golden scan from both the wheel and the
checkout, which `scripts/check_wheel_parity.py` requires to agree. What the
jobs prove — and what they do not, including why they cannot block a direct
push to `main` — is in [docs/ci.md](docs/ci.md).

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

Apache License 2.0 — see [LICENSE](LICENSE).
Copyright (c) 2026 Antonio Cantallops Alba · contact@exyonq.org
