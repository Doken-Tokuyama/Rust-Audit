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

This line is also shipped as the `allowed_signers` release asset.

One command — downloads the assets and runs the whole chain (key pin →
signature → checksum → tag identity → receipt cross-check), exit 0 only on
`VERIFIED`:

```bash
scripts/verify_release.sh v0.2.0        # one release (default: latest)
scripts/verify_release.sh --all         # every release from v0.2.0 onward
scripts/verify_release.sh v0.2.0 ./rust_audit.py   # + the local copy to execute
scripts/verify_release.sh --dir dist v0.2.0        # staged assets, before upload
```

Every verification writes a **machine-readable receipt per release** —
`report/verify-release-<tag>-<utc>.json` (override the directory with
`RA_RECEIPT_DIR`) — carrying the mode, the per-check status, the result and
the exit code. The receipts stay under `report/` as the evidence trail of
what was verified, when, and with which outcome.

**Receipt cross-check** (download mode): when the release carries an
attached receipt, the verifier compares it against its own fresh
calculation — tag, repository, key fingerprint, result, and the manifest
checksum that binds the receipt to the exact bytes. A mismatch fails the
chain (exit 1): a receipt that contradicts the bytes *is* the tamper
signal. A missing receipt is reported as `absent` and is not a failure —
releases predating receipts stay verifiable. See
[ADR 0003](docs/adr/0003-evidence-model-receipts-gate-attestation.md).

CI runs the same chain automatically after every published release
(`.github/workflows/verify-release.yml`) and fails the job on any mismatch;
the same job can be dispatched by hand for any tag. A second workflow
(`.github/workflows/attest-release.yml`) attests the uploaded digests, so
the SSH chain and the build-provenance attestation are checked separately
and neither is inferred from the other.

### Cutting a release — the pre-publish gate

The release process verifies the **staged assets before anything is
uploaded**. One command cuts the whole release:

```bash
scripts/release.sh --cut v0.2.2 <signing-key>
```

It bumps `VERSION`, moves the verify-before-use pins in README.md and
SKILL.md to the new tag, commits, tags and pushes (refusing any commit that
carries a co-author trailer), stages the four attestation assets (manifest
+ SSH signature with `<signing-key>` — its `.pub` must sit next to it), and
then runs the **pre-publish gate**: `verify_release.sh --dir` must end on
`VERIFIED` (exit 0) — key pin -> signature -> checksum -> tag identity
against the git tag (the release is not published yet) — before anything is
uploaded (`gh release create --verify-tag`, or `gh release upload` when the
release already exists). The gate's JSON receipt is attached to the release
as evidence (and stays under `report/`); then `release.sh` itself re-runs
the chain on the uploaded bytes — including the cross-check of the
just-attached receipt — and prints `RELEASED` only on `VERIFIED` (an upload
that fails it is reported as uploaded-but-not-trusted). The post-release CI
workflow re-runs the same chain once more and keeps its receipt with the
run. `release.sh TAG STAGEDIR` serves pre-staged assets: same gate,
same upload rule.

The same chain by hand — the repository is public, so the downloads need no
authentication (`curl -LO` from the release URL, or `gh release download`
for a logged-in `gh`); the verification itself needs only `ssh-keygen` and a
checksum tool, both preinstalled on macOS/Linux:

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
the bytes are exactly what the holder of this key published. It says nothing
about *how* they were built. GitHub's native artifact attestations
(`actions/attest-build-provenance`, Sigstore) close part of that gap and are
wired in since v0.2.5 — possible because the repository is public since
2026-10-20:

- **wheel and sdist** are attested in the publishing workflow, in the same job
  that builds them:
  `gh attestation verify rust_audit-<version>-py3-none-any.whl -R Doken-Tokuyama/Rust-Audit`
- **release assets** are attested by `attest-release.yml` on
  `release: published`, which downloads what was uploaded and attests each
  file's digest:
  `gh attestation verify rust_audit.py -R Doken-Tokuyama/Rust-Audit`

What an attestation proves: that digest was signed by a run of a workflow in
this repository, with the repository, workflow file, ref and commit recorded
in the signed statement, and no signing secret involved. What it does **not**
prove: that the run's inputs were clean. For the release assets it is weaker
still — `release.sh` uploads them from a maintainer's machine, so the
attestation covers *the bytes that ended up in the release*, not their
production. There the SSH signature stays the only evidence of authorship;
the attestation adds a timestamped CI record that the digest has not changed
since the release was published.

## PyPI channel (v0.2.2+) — what a wheel does and does not prove

The tool is also published as `rust-audit` with **trusted publishing** —
GitHub's OIDC identity replaces an API token, so no upload secret exists in
this repository. One distribution serves both commands (`rust-audit` and
`rustaudit`): PyPI refuses a separate one-word project as too similar to this
name, so there is no alias package to reason about. The wheel ships
`scripts/rust_audit.py`
byte for byte (the same file the signed GitHub asset carries) plus the curated
data under `share/rustaudit/`; `rust-audit selftest` runs the same rules.

What each channel proves — they are **not** interchangeable:

| Channel | Proves | Does not prove |
|---|---|---|
| GitHub release asset | *those exact bytes* were published by the holder of the pinned key (SSH signature, checksum, tag identity, receipt), and `attest-release.yml` attested their digests from CI | how the maintainer produced them, or that their machine was clean |
| PyPI wheel/sdist | *built from this repository at this tag* by its own workflow (OIDC identity, recorded hashes), with the digest attested by that same run (`gh attestation verify`) | that the build inputs or the dependencies were clean |

So: verify a downloaded `rust_audit.py` with the chain above; install from PyPI
when you want the command on your `PATH`. `pip install --require-hashes` with
the published hashes is the closest equivalent for the wheel. The evaluator
the wheel runs is the same code, and `tests/test_packaging.py` fails if the
packaged module and the repo module ever drift apart.

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
