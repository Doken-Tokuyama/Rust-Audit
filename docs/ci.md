# CI — what runs, what it proves, and what it does not

`.github/workflows/tests.yml` runs the suite on every push to `main`, on every
pull request, on every `v*` release tag and on demand. Two Python versions
(`3.11`, the floor `requires-python` declares, and `3.13`, the newest the
classifiers claim), `pytest` as the only install, then `pytest -q tests/` and a
`selftest` step. Nothing else: the auditor is one stdlib-only module, so a
green job means *this commit's code* works, not that a dependency resolved.

A second job, `wheel`, runs after the suite and audits the published artifact
instead of the checkout (see below).

The same command runs locally — there is no CI-only path:

```bash
python3 -m venv .venv && .venv/bin/pip install pytest
.venv/bin/python -m pytest tests/
```

## What a green run proves

- The production E2E passed: the real CLI against `BurntSushi/ripgrep` and
  `tokio-rs/tokio` at their pinned commits, matching the goldens in
  `tests/test_production_e2e.py` (counts per severity and per rule).
- The packaging contract holds (`tests/test_packaging.py`): entry points,
  `dynamic` version from `VERSION`, data files, and the attestation wiring.
- The release machinery still agrees with its own tests
  (`tests/test_verify_release.py`, keys and signatures generated per run).
- The skill-sync guards hold (`tests/test_check_skill_sync.py`,
  `tests/test_sync_installed_copies.py`), except the two tests that inspect a
  *machine's* Freebuff registry and the Cursor store: they skip when absent.
- Every report format still carries the engine identity
  (`tests/test_report_identity.py`).
- The `wheel` job proved the **published artifact** audits like the checkout
  (next section), not just that the sources work.

## The `wheel` job — the published artifact is a path of its own

`AGENTS.md` §6b: a checkout that passes proves nothing about the wheel. The
sdist/wheel are found through `<sys.prefix>/share/rustaudit/`, not through the
sibling `resources/` directory the checkout reads, so `data-files` can go
missing without a single test noticing. The job walks the user's path:

```bash
python -m build --outdir dist
python -m venv /tmp/installed
/tmp/installed/bin/pip install --no-index --find-links dist rust-audit
test -s /tmp/installed/share/rustaudit/resources/suspicious_names.txt
/tmp/installed/bin/rust-audit selftest
python scripts/check_wheel_parity.py report/installed report/checkout
```

`--no-index` is the load-bearing flag: without it a broken wheel silently
falls back to PyPI or to the checkout and the job passes. The three `test -s`
lines are the packaging contract itself (curated lists and `deny.toml` under
the prefix).

Then the same pinned workspace (`BurntSushi/ripgrep` @ `3fce3b5b`, the pin
`tests/test_production_e2e.py` audits) is scanned twice — once with the
installed `rust-audit`, once with `python scripts/rust_audit.py` — and
`scripts/check_wheel_parity.py` requires the two JSON reports to agree (its own
refusals are unit-tested in `tests/test_check_wheel_parity.py`). It refuses,
with a reason for each:

| Refusal | What went wrong |
|---|---|
| `findings differ in …` | the artifact does not audit like the tested code |
| `version … installed vs …` | the wheel was built from other bytes |
| `does not ship the audited bytes` | packaging started transforming the module |
| `both reports name the same engine path` | nothing was installed: the comparison was vacuous |
| `an empty audit cannot show agreement` | the workspace did not parse |

Scan exits of `0` (clean) and `1` (findings at/above `--fail-on`) are both
normal on this workspace — the goldens are 321 findings — so the step fails
only on `2`, and the parity check carries the verdict. The goldens are not
repeated in this job: the `pytest` job validated this engine against them on
the same commit, and `needs: pytest` is what keeps that inference true.

Still not proven by it: the **sdist** (the install resolves the wheel), and
Windows/macOS.

## What it does not prove

- **Not Windows or macOS.** `ubuntu-latest` only. The suite has no
  platform-specific branches, but "no macOS-only test failed on Linux" is not
  the same as "verified on macOS" — that is the maintainer's manual run.
- **Not the release.** `publish.yml` and the signed assets are outside this
  job; a release can still be cut from a commit nobody reviewed if the job was
  red and ignored.
- **Not blocking, by construction.** See below.

## Why the job cannot block the maintainer's own pushes

Branch protection with *required status checks* applies to pull requests.
Blocking direct pushes as well needs "require a pull request before merging",
and this repository's release flow is a direct `git push origin HEAD`
(`scripts/release.sh --cut`). Turning that on would break cutting a release;
leaving `enforce_admins` off means the maintainer can push past a red check.
The job therefore reports, and the honest statement is: *the check is
advisory for the maintainer's direct pushes, mandatory for contributions*.

If a hard gate is ever wanted, the change is architectural, not cosmetic:
move the release to a PR (cut a branch, let CI run, merge, tag on the merge
commit). Then required checks mean something for every path. Not done here.

## Action pins

Every `uses:` is a 40-hex commit, one per action across all workflows, with
the version it resolved from in the comment. Resolve a pin from the API rather
than trusting a blog post:

```bash
curl -sL https://api.github.com/repos/actions/checkout/git/ref/tags/v7.0.1 \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['object']['sha'])"
```

`tests/test_ci_workflows.py` enforces the shape: pinned to a commit, a
readable version comment, one commit per action, the job present and running
the suite, the tag trigger present, no `|| true` / `continue-on-error`, and a
matrix that covers the `requires-python` floor. Bumping an action means
changing every occurrence and the comment together — the test fails otherwise.

## Cost and triage

Roughly three minutes per matrix leg on the hosted runners, dominated by
cloning the two pinned workspaces (the scan itself takes seconds). The `wheel`
job adds one more clone, a build and two scans, and is skipped entirely when
the suite is red. Caching `~/.cargo`, `uv` or a tarball of the cloned trees
would cut most of it; not done because the clone is also what proves the
pinned commits are reachable.

When a job fails, read in this order: the pytest summary line (which test),
the full assertion (the tool prints the finding, the path and the first
differing line), then `report/not-executed-*.md` inside the E2E temp dirs if
the failure is about a check that never ran. A golden mismatch is a decision,
not a bug: either a rule changed on purpose (update the golden with the reason
in the comment above `PROJECTS`) or a heuristics change misfired.
