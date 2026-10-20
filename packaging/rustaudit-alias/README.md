# rustaudit — alias for `rust-audit`

This distribution exists so the one-word spelling resolves:
`pip install rustaudit` installs the real package, [`rust-audit`](https://pypi.org/project/rust-audit/),
and nothing else. It ships no modules and no commands of its own — `rust-audit`
and `rustaudit` are both installed by the package it depends on.

Rust Audit is a static auditor and auto-fixer for AI-generated Rust code:
stubs, fake tests, swallowed errors, panic/unsafe misuse, and hallucinated or
typosquatted crates. Python 3.11+, no dependencies.

```bash
pipx install rustaudit     # or: pipx install rust-audit
rust-audit selftest
```

Source, docs and the signed release asset: https://github.com/Doken-Tokuyama/Rust-Audit
