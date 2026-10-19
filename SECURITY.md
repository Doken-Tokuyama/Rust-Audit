# Security and trust model

Rust Audit is an auditor that **runs the Rust toolchain on the target it
audits**. This document states exactly what executes, what leaves the
machine and what writes to disk — so install-time auditors (SkillSpector
and friends) and humans can classify it without guessing. Everything below
was verified against the source (2026-10-16; `--no-exec` choke point added
and re-verified 2026-10-18).

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
- Missing tools are reported as *skipped*, never silently ignored, andthe check lands in `report/not-executed-<date>.md`.
- **Single execution choke point.** Every external command goes through one
  `_spawn()` function — the only `subprocess.run` call site in the codebase —
  and with **`--no-exec`** (static-only mode, accepted by every subcommand)
  that entry point refuses to spawn: zero subprocesses is enforced in code,
  not by convention. Blocked runs are recorded as *skipped* in the evidence
  and the not-executed report; `shutil.which` (pure PATH lookup) is the only
  external-world check that remains.
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

## Release attestation (v0.2.0+) — verify the exact audited bytes

Every release ships `rust_audit.py` plus a **SHA256SUMS** manifest that is
**SSH-signed** (`ssh-keygen -Y sign`) with the maintainer's key. The
signature binds the checksums to the exact file audited (SkillSpector
re-audit 2026-10-18, the E2E suite and the proof runs — evidence under
`report/`), so an install can prove it runs the audited bytes and not a
substituted file.

Signing key — pinned **here** on purpose; never trust a key that arrives
with the download (fingerprint `SHA256:v/9tBKvWLy+NKzzqtvfH9vYwqLglF2gYYJ6K79LNmjU`):

```
release@rust-audit namespaces="file" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDAhVju61wmyPVI9EQiBN5nr8AyTTDSJ2YpxENURDUxAlGHWmBsFocMLHacjl2upKgP2R4jBwQ9gvhByQt0NllM87kFJstufjWv01vukk4G9IP/wtV5Xypqp6ZvvcDGNf6mJR1h1T2YZi6EtaQobGgxjteZvJBvRESltv03chfxti1bP3SWvlTcFEIKpKiSKoRzdDItWH5VMMxSZHoKtsESBY9WlbPg++IVReYhukmGarMoyX3nHAuXk8RHoHK+9YfHz5kG/s2p9xLsxHramoiWfhbrqAqBNxVYwiNcwsQlMQEU3L5Xx/eXFHpFwBneSNc7k+ZUDjaCDZAyiN5Nj7Ol
```

This line is also shipped as the `allowed_signers` release asset. Verify —
downloads need `gh` (private repository) or an authenticated `curl`; the
verification itself needs only `ssh-keygen` and a checksum tool, both
preinstalled on macOS/Linux:

```bash
gh release download v0.2.0 -R Doken-Tokuyama/Rust-Audit   # all four assets
sed 's/.*ssh-rsa/ssh-rsa/' allowed_signers | ssh-keygen -lf -
#   must show SHA256:v/9tBKvWLy+NKzzqtvfH9vYwqLglF2gYYJ6K79LNmjU
ssh-keygen -Y verify -f allowed_signers -I release@rust-audit -n file -s SHA256SUMS.sig < SHA256SUMS
shasum -a 256 -c SHA256SUMS      # Linux: sha256sum -c SHA256SUMS
```

The verify step must print `Good "file" signature`; the checksum step must
show `rust_audit.py: OK`.

**Scope (honest):** the signature proves *integrity and key identity* —
the bytes are exactly what the holder of this key published. It is **not
CI provenance**: GitHub's native artifact attestations
(`actions/attest`) are unavailable here (private repository on a non-Enterprise
plan — GitHub gates them to public repos, or private repos on Enterprise
Cloud), which was an explicit decision to keep the repository private. If
the repository ever goes public, GitHub attestations can layer on top
without changing the asset format.

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

### Re-audit — SkillSpector v2.3.7, 2026-10-18 (source archive rebuilt)

Re-run of the same auditor on a freshly built source archive (21 files,
`git ls-files` content including the `--no-exec` choke point), static mode
(`--no-llm`; no LLM key configured — same static scope as the 2026-10-16
review). **Score unchanged: 100/100, `DO NOT INSTALL`** — the scanner weighs
the *category* (a skill whose code runs a toolchain), which code hygiene
cannot flip. The findings, however, reclassified:

| 2026-10-16 finding | 2026-10-18 re-scan | Reclassification |
|---|---|---|
| OH1 ×4 — `subprocess.run` | OH1 ×2 + AST4 ×3 (5 hits) | the shipped tool now contributes **one** hit on one line — `_spawn()`, the only `subprocess.run` call site; the other 3 are the test suite's own CLI runner (`tests/test_production_e2e.py` invokes the tool as a subprocess on purpose) |
| P6 — "prompt leak" at `Finding.tier` | P6 ×1 (same location) | unchanged false positive: rule metadata lookup, not a prompt |
| network call to api.osv.dev | E1 ×2 ("External Transmission") | same behavior, split in two: the opt-in OSV request code + the *documentation* of that URL in this file (line 47) |
| filler / LICENSE patterns | EA3 ×2 (`LICENSE:56`, `LICENSE:161`) | unchanged false positive on Apache-2.0 text |
| — | MP2 ×3 ("Context Window Stuffing", new) | lands on `EvidenceRun` report construction in fix validation (`scripts/rust_audit.py` around lines 2076/2113/2116); the tool builds no prompts and no context payloads (see above) |

Evidence of this run: `report/skillspector-2026-10-18.txt` /
`report/skillspector-2026-10-18.json` (exit code 1 = findings present).

If your scanner still blocks on the *category* ("a skill that executes
commands"), run any subcommand with **`--no-exec`**: the guarantee that no
process is spawned is enforced at the single `_spawn()` call site (verified
by a test that poisons `subprocess.run`/`Popen` and runs every subcommand),
so `scan`/`fix`/`cargo`/`full`/`setup` are all safe in static-only mode.
