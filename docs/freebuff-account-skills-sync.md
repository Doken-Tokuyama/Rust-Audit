# What the Freebuff account-skills sync rewrites — and how it is guarded

Diagnosis of the `~/.config/freebuff-desktop/account-skills/` machinery
behind the Cloud-synced skills, from the evidence left on this machine
(2026-10-19). Motivation: a sync once stripped the trailing newline of the
skill copies and nobody noticed, and a stale snapshot silently served
pre-fix instructions. Both are now guarded by tests; this file records
what the sync actually does so the next drift is diagnosed in minutes.

## The moving parts

Under `account-skills/<account-hash>/<…>/`:

| File / dir | Role | Rewritten by |
|---|---|---|
| `current.json` | the **live registry**: `revision`, and every skill's `name`, `description` and full `instructions` embedded inline | every sync (observed rewrites at 13:52, 17:11, 21:41 on 2026-10-19) |
| `<sha256>.json`-named **snapshot dirs** | the full skill trees materialized per registry revision | each registry change |
| `imported.json` | the record of which skills were imported into the account (names only) | sync / import steps, with backup rotation |
| `imported.json.pre-sync-<date>.bak` | backup taken **before a Cloud sync** rewrote `imported.json` | the sync itself |
| `imported.json.pre-verify-<date>.bak` | backup taken **before a verify/import step** | the verify step |

## The decoded scheme (evidence)

- **The snapshot dir name IS the SHA-256 of `current.json`'s bytes.** On
  this machine `sha256(current.json)` = `d9d959621ac0…`, exactly the name
  of the live snapshot dir; `3648e0de0f78…` is the previous revision, kept
  as a rollback target. Older snapshots are archives, **not served** — the
  drift test compares only the newest one per account.
- **The sync normalizes exactly one byte class: it strips the trailing
  newline** when embedding `SKILL.md` into `current.json`
  (`instructions == SKILL.md[:-1]` for both rust-audit skills — verified
  byte for byte). File-level copies keep the newline; the registry embed
  does not. That is harmless *as long as it stays the only difference* —
  which is what the test below pins.
- **`imported.json` history (the `.bak` trail):** the pre-sync backup
  (13:52) held 20 names with `veyra-proof` but without `rust-audit` /
  `rust-audit-family`; the current file holds 21 with the two new imports
  and without `veyra-proof`; the pre-verify backup (17:11) is identical to
  the current file (the verify step changed nothing). The list is a
  migration record — the **served** set is `current.json` + the live
  snapshot (which holds all 22 skills including `veyra-proof`).

## What is guarded, by which test

`tests/test_skill_wrapper_cli.py`:

1. `test_skill_copies_are_byte_identical` — the repo `skills/` copies, the
   machine-global `~/.agents/skills` install and the **newest account
   snapshot per account** must be byte-identical (trailing newline
   included). Older snapshots are rollback archives and are excluded.
2. `test_registry_instructions_match_the_skill_files` — the registry
   embed in `current.json` must equal `SKILL.md` minus the one trailing
   newline the sync strips. Any other difference (the stale pre-fix
   content that once rode an old snapshot) fails here.

## Runbook when either test fires

1. Diff the offending copy against `skills/<name>/SKILL.md` — the test
   message names the exact path.
2. If the copy is stale content: restore from `skills/<name>/` and restart
   Freebuff (the registry is cached at startup).
3. If the difference is a newline: the sync re-normalized; restoring the
   file copy is enough, the registry embed is allowed to lack the newline.
4. Never edit `current.json` or the snapshot dirs by hand — they are
   rewritten wholesale by the sync; edit the repo and re-sync.
