# Verification evidence travels with the release: receipt, gate, attestation

The release chain (added v0.2.0, extended through v0.2.1) answers one
question: **how does an install know it runs the exact audited bytes?** The
answer is not prose in a README — it is a machine-checkable evidence model
with three moving parts, and this decision records the model so later
changes argue against it instead of quietly dropping pieces of it.

## The decision

1. **Every verification writes a receipt** —
   `report/verify-release-<tag>-<utc>.json` (`RA_RECEIPT_DIR` overrides the
   directory): tool, repo, tag, mode, key fingerprint, per-check status,
   result and exit code. It is written on *every* outcome — `VERIFIED`,
   `NOT VERIFIED` and `ERROR` — and an unwritable receipt is itself an
   exit-2 error. Evidence that only exists on success is not evidence.

2. **The pre-publish gate is the only path to upload.**
   `release.sh` (or `release.sh --cut`) refuses to upload anything unless
   `verify_release.sh --dir` ends on `VERIFIED` (exit 0) against the
   *staged* assets and the *local* git tag. The gate's receipt is attached
   to the release; the same chain is re-run post-publish by CI, whose run
   keeps its receipt as an artifact.

3. **The chain is: key pin -> SSH signature -> checksum -> tag identity ->
   receipt cross-check.** The receipt cross-check (download mode) binds the
   receipt attached to a release to the fresh calculation: tag, repo, key
   fingerprint, result, and the manifest checksum that ties the receipt to
   the exact bytes. A mismatch is a verification failure (exit 1) — a
   receipt that contradicts the bytes *is* the tamper signal. A missing
   receipt is reported as `absent` and is not a failure: releases predating
   receipts (v0.2.0, v0.2.1) must stay verifiable.

4. **The trust anchor lives in the repository, never in the download.** The
   pinned signing-key fingerprint sits in `scripts/verify_release.sh` and
   `SECURITY.md`; `RA_EXPECT_FINGERPRINT` overrides it for test fixtures
   only. A key that arrives with the artifact is never trusted.

5. **Honest scope: integrity + key identity, not CI provenance.** The SSH
   signature proves the bytes are what the holder of the pinned key
   published. GitHub artifact attestations are unavailable here (private
   repository, non-Enterprise plan). If the repository goes public they can
   layer on top without changing the asset format.

## Consequences

- A release without a matching attached receipt is *verifiable but weaker*:
  the chain still runs, and the fresh receipt is the evidence trail.
- A release whose attached receipt contradicts the bytes fails the chain —
  that asymmetry (absent neutral, contradictory fatal) is deliberate.
- The receipt JSON format is pinned by tests
  (`tests/test_verify_release.py`); format changes are deliberate,
  explained updates there, never silent drift.

Evidence of the model in action: `report/verify-release-*.json` (local
trail), the receipt assets on the releases, and the `verify-release` CI
runs. See [SECURITY.md](../../SECURITY.md) for the chain by hand and
[CONTEXT.md](../../CONTEXT.md) for the terms.
