# Freebuff skill installation — `rust-audit`

How to install the `rust-audit` skill into Freebuff so it works in **every**
project on the machine. Reproducible from a clone of this repository alone.

## What gets installed

| Source (this repo) | Destination | Role |
|---|---|---|
| `skills/rust-audit/SKILL.md` | `~/.agents/skills/rust-audit/SKILL.md` | the agent-facing entry: workflow, interpreter resolution, verify-before-use |
| `skills/rust-audit-family/SKILL.md` | `~/.agents/skills/rust-audit-family/SKILL.md` | optional router for the skill family |

`~/.agents/skills` is Freebuff's machine-global install directory (read
together with `~/.claude/skills` and each project's own `.freebuff/skills` /
`.agents/skills`), so **no per-project step exists** — current and future
projects alike resolve the same package.

The wrapper is only half of it: the auditor itself can come from a checkout
(`RUST_AUDIT_HOME`) **or** from PyPI (`pipx install rust-audit`, which puts
`rust-audit` and `rustaudit` on the PATH). Pick one; mixing a stale checkout
with a fresh wheel is how two different versions end up auditing the same
workspace.

## Install

From the repo root:

```bash
mkdir -p ~/.agents/skills
cp -R skills/rust-audit skills/rust-audit-family ~/.agents/skills/
```

Then **restart Freebuff** — its orchestrator caches the skill registry at
startup, and a running instance does not see new packages.

The wrapper resolves the auditor from `$RUST_AUDIT_HOME` (export it if your
clone lives somewhere other than the default the wrapper knows) and picks a
Python **3.11+** interpreter itself; a system `python3` of 3.9 is normal on
macOS and is handled.

## Verify

With a Python 3.11+ interpreter — the probe picks the first that works
(a system `python3` of 3.9 is normal on macOS):

```bash
for PY in python3 python3.13 python3.12 python3.11; do
  "$PY" -c 'import tomllib' 2>/dev/null && break
done
"$PY" "$RUST_AUDIT_HOME/scripts/rust_audit.py" selftest
```

**Done when:** `selftest PASS` prints *and* a fresh Freebuff thread's `skill`
tool lists `rust-audit` (loading it by name returns its instructions). Both —
the command proves the tool runs on this machine; the skill tool proves
Freebuff sees the package.

## If the skill does not appear

Freebuff hides a local skill whose name is listed in its account-registry
cache as "migrated to the account" — a stale entry there silently suppresses
the local copy:

```bash
grep -o 'rust-audit[a-z-]*' ~/.config/freebuff-desktop/account-skills/*/imported.json
```

If that prints names, remove those names from the JSON list (the account
snapshot does not actually contain the skills), restart Freebuff, and verify
again.

For the whole sync state at once — registry revision, live snapshot, embed
against served copies, the `imported.json` trail — run
`python3 scripts/check_skill_sync.py` and read its verdict
([docs/freebuff-account-skills-sync.md](freebuff-account-skills-sync.md)).

## Uninstall

```bash
rm -rf ~/.agents/skills/rust-audit ~/.agents/skills/rust-audit-family
```
