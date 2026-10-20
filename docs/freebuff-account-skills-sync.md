# What the Freebuff account-skills sync rewrites — and how it is guarded

Diagnosis of the `~/.config/freebuff-desktop/account-skills/` machinery
behind the Cloud-synced skills, from the evidence left on this machine
(2026-10-19, re-observed 2026-10-20). Motivation: a sync once stripped the
trailing newline of the skill copies and nobody noticed, and a stale
snapshot silently served pre-fix instructions. Both are guarded by tests and
by one diagnostic command; this file records what the sync actually does so
the next drift is diagnosed in minutes.

## Run it — one command instead of this document

```bash
python3 scripts/check_skill_sync.py            # this machine
python3 scripts/check_skill_sync.py --all-disk # + ~/.agents/skills and Spotlight
python3 scripts/check_skill_sync.py ROOT --json  # a copy/tarball, machine-readable
```

It prints the model below for every account: registry revision and its
sha256, which directory that revision names (the live snapshot), which
directories are rollback archives, the embedded instructions against the
served files and against this repository's `skills/`, the extra files each
skill declares, the `imported.json` backup trail with what each step added
and removed, and the machine-global install copies.

**Skills and engines in one verdict.** A skill tree runs its *own*
`scripts/rust_audit.py`, so up-to-date instructions next to an engine from an
older release is still a machine that audits with the wrong rules. The
command therefore calls the copy detector (`sync_installed_copies.py`) in
process — its `discover`/`snapshot`, not a second implementation — and reports
every copy it finds under the scanned directories (`current`, `stale`,
`drift`, `newer`, `unreadable`, plus the instructions a copy still carries
from an older release). Scope: `ROOT` plus `--engine-root DIR` (repeatable);
`--all-disk` adds `~/.agents/skills` and every copy Spotlight knows about;
`--no-engines` leaves the engine half out. Default discovery is bounded to
the directories given, so a fixture tree (or a tarball) is judged on its own
contents and never on the machine's.

Exit codes follow the auditor's contract: `0` consistent · `1` findings
(instruction drift, a registry the sync never materialized, an orphan tree, a
missing declared file, a stale or drifted engine copy, stale engine
instructions) · `2` execution error (no such root, no account registry,
unreadable JSON, no detector beside the checker). `tests/test_check_skill_sync.py`
pins that contract; the live guard in `tests/test_skill_wrapper_cli.py` is
this command's verdict.

## The moving parts

Under `account-skills/<account-hash>/<…>/`:

| File / dir | Role | Rewritten by |
|---|---|---|
| `current.json` | the **live registry**: `revision`, and every skill's `name`, `description`, `instructions` (embedded inline) and `files` | every sync (observed rewrites at 13:52, 17:11, 21:41 and 00:55 on 2026-10-19/20) |
| `<sha256>.json`-named **snapshot dirs** | the full skill trees materialized per registry revision | each registry change |
| `imported.json` | the record of which skills were imported into the account (names only) | sync / import steps, with backup rotation |
| `imported.json.pre-sync-<date>.bak` | backup taken **before a Cloud sync** rewrote `imported.json` | the sync itself |
| `imported.json.pre-verify-<date>.bak` | backup taken **before a verify/import step** | the verify step |

## The decoded scheme (evidence)

- **The snapshot dir name IS the SHA-256 of `current.json`'s bytes.** On
  this machine `sha256(current.json)` = `d9d959621ac0…`, exactly the name
  of the live snapshot dir; `3648e0de0f78…` is the previous revision, kept
  as a rollback target. The hash is the identity, **not the mtime**: at
  2026-10-20 00:55 the sync rewrote `current.json` (same revision 2, same
  bytes, same hash) and re-materialized the snapshot dir it names, leaving
  the dir's own mtime older than the registry's. Older snapshots are
  archives, **not served** — nothing compares against them.
- **The sync normalizes exactly one byte class: the trailing newline of
  `SKILL.md`.** Two shapes have been observed: the *embed* lacking it while
  the file copy keeps it (2026-10-19 17:11), and **both the embed and the
  materialized file copy lacking it** (2026-10-20 00:55 —
  `rust-audit/SKILL.md` 4150 B on disk against 4151 B in this repo, embed
  identical to the file). That is harmless *as long as it stays the only
  difference*, so the guard classifies: `identical`, `newline-only` (zero
  drift) or `drift` (with byte counts and the first differing line). A
  strict "byte-identical including the newline" rule was in place until it
  produced a false positive on that re-materialization; per ADR 0001 a claim
  the sync provably does not honor is removed, not kept as a red check.
- **`imported.json` history (the `.bak` trail):** the pre-sync backup
  (13:52) held 20 names with `veyra-proof` but without `rust-audit` /
  `rust-audit-family`; the current file holds 21 with the two new imports
  and without `veyra-proof`; the pre-verify backup (17:11) is identical to
  the current file (the verify step changed nothing). The list is a
  migration record — the **served** set is `current.json` + the live
  snapshot (22 skills, `veyra-proof` included).
- **Extra files ride the registry too:** a skill may declare `files`
  (`{"path": …, "contents": …}`), as `research` does with
  `agents/openai.yaml`; they must exist under the live skill dir with the
  declared contents, and the diagnostic checks that.

## What is guarded, by which test

`tests/test_check_skill_sync.py` — the rule's own contract, against built
fixtures: consistent tree, both newline-only shapes, stale copy (exit 1,
skill named), registry with no materialized snapshot, orphan tree, missing
`SKILL.md`, declared file missing/diverging, the import trail, repo
cross-check with a stale canonical, terminal rendering, invalid JSON, a
missing root and an empty root. Engine side: a current copy under the root
(exit 0, `current` in the render), a stale engine (exit 1, version named), a
current engine beside stale instructions (`engine-docs`), `--no-engines`, and
`--engine-root` adding a directory (a missing one is exit 2). The fixtures
plant their own copies, so the machine's copies can never decide the result.

`tests/test_skill_wrapper_cli.py::test_live_copies_serve_the_repo_instructions`
— the live guard: the command's verdict on this machine must be consistent,
and the wrappers must actually have been compared (repo vs live snapshot vs
`~/.agents/skills` install), so a vacuous pass is impossible.

## Runbook when the guard fires

1. Run `python3 scripts/check_skill_sync.py` — it names the skill, the
   surface (embed, live copy, repo) and the first differing line.
2. **Stale content:** restore the copy from `skills/<name>/` and restart
   Freebuff (the registry is cached at startup).
3. **`live-snapshot-missing`:** the registry revision was never
   materialized — restart Freebuff to force a sync; do not hand-create the
   directory (its name is the hash of bytes you must not rewrite).
4. **`newline-only`:** not a failure. It is the sync's normalization; no
   action.
5. **`engine-stale` / `engine-drift` / `engine-docs`:** a copy of the auditor
   is behind, patched, or served with old instructions. Run
   `python3 scripts/sync_installed_copies.py` for the full list and `--fix`
   to refresh engine, runtime data and docs; a `drift` (same version,
   different bytes) needs `--force` and a human, because it may be a local
   patch worth keeping. `--all-disk` on `check_skill_sync.py` is what widens
   the search beyond the account tree.
6. Never edit `current.json` or the snapshot dirs by hand — they are
   rewritten wholesale by the sync; edit the repo and re-sync.
