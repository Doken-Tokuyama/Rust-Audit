#!/usr/bin/env bash
# release.sh — cut a Rust Audit release: verify the staged assets BEFORE
# they are uploaded, then upload them with the gate receipt attached.
#
# Usage: scripts/release.sh TAG STAGEDIR
#        scripts/release.sh --cut TAG SIGNING_KEY
#   TAG       the release tag (v1.2.3); must exist as a git tag (--cut
#             creates it) and on the remote (gh release create --verify-tag)
#   STAGEDIR  directory holding the four attestation assets prepared per
#             SECURITY.md: rust_audit.py SHA256SUMS SHA256SUMS.sig allowed_signers
#   --cut     the whole cut in one command: bump VERSION to the tag, move
#             the verify-before-use pins in README.md/SKILL.md to it,
#             commit, tag and push, stage + sign the assets with
#             SIGNING_KEY (its .pub must sit next to it), then run the same
#             pre-publish gate and upload.
#
# 0. CI gate — scripts/release_checks.py ci: the suite must have ended green
#    on the exact commit the tag points at (gh run list --commit <sha>). In
#    --cut mode this runs before the tag is created, so a red suite leaves no
#    tag and nothing signed. The workflow itself no longer runs on `v*` tags:
#    a cut pushed one commit and tagged it, which ran the identical suite
#    twice for one SHA (v0.2.6). This gate is the replacement, and it blocks
#    instead of reporting.
# 1. pre-publish gate — scripts/verify_release.sh --dir STAGEDIR TAG:
#    key pin -> SSH signature -> checksum -> tag identity against the git
#    tag, with the JSON receipt written under report/. Nothing is uploaded
#    unless this ends on VERIFIED (exit 0).
# 2. upload — only after the gate: gh release create (or gh release upload
#    when the release already exists) of the four staged assets, followed by
#    the gate's JSON receipt as evidence.
# 3. post-publish chain — the full verification (incl. the receipt
#    cross-check of the just-attached receipt) re-runs on the uploaded
#    bytes.
# 4. PyPI gate — scripts/release_checks.py pypi: the simple index must serve
#    rust_audit-<version>-py3-none-any.whl, with the digest the index records
#    and a rust_audit.py identical to the signed one. The JSON API listing a
#    version is not the same fact: pip resolves from the simple index and
#    answered "No matching distribution found" for a minute after 0.2.6 was
#    already listed there (2026-10-20).
# RELEASED is printed only when 1, 3 and 4 all pass.
#
# Exit: 0 released · 1 the CI gate found no green suite on that commit, the
#       pre-publish gate refused the staged assets, the uploaded bytes failed
#       the post-publish chain, or PyPI does not serve the version ·
#       2 environment/usage error
# Needs: gh authenticated as an account with release access to the
#        repository, python3 (both gates), plus what verify_release.sh needs
#        for --dir (ssh-keygen, git, shasum/sha256sum).

set -u

REPO="Doken-Tokuyama/Rust-Audit"
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT="${RA_REPO_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"
ASSETS="rust_audit.py SHA256SUMS SHA256SUMS.sig allowed_signers"
SIGN_IDENTITY="release@rust-audit"
CHECKS="${RA_RELEASE_CHECKS:-$SCRIPT_DIR/release_checks.py}"
CI_TIMEOUT="${RA_CI_TIMEOUT:-1800}"     # the tests job's own timeout
CI_POLL="${RA_CI_POLL:-15}"
PYPI_TIMEOUT="${RA_PYPI_TIMEOUT:-600}"   # propagation took ~1 min for 0.2.6
PYPI_POLL="${RA_PYPI_POLL:-10}"

say() { printf '%s\n' "$*"; }
die() { say "ERROR $*" >&2; exit 2; }

# The suite must have passed on the exact commit a tag points at. Without the
# `v*` trigger this is the only place that fact is checked, and it is checked
# before anything is signed or uploaded — not after, from another run.
ci_gate() {  # ci_gate REF -> 0 green, 1 not green, 2 cannot tell
  local ref="$1" sha
  git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 \
    || die "not a git checkout: $REPO_ROOT (the CI gate needs the tag's commit)"
  sha=$(git -C "$REPO_ROOT" rev-parse "$ref^{commit}" 2>/dev/null) \
    || die "no such git ref: $ref (tag the release commit first)"
  python3 "$CHECKS" ci --sha "$sha" --repo "$REPO" \
    --timeout "$CI_TIMEOUT" --interval "$CI_POLL"
}

if command -v sha256sum >/dev/null 2>&1; then SHA256_MAKE="sha256sum"
elif command -v shasum >/dev/null 2>&1; then SHA256_MAKE="shasum -a 256"
else die "missing required tool: sha256sum or shasum"; fi

edit() { sed -E "$1" "$2" > "$2.tmp" && mv "$2.tmp" "$2"; }

if [ "${1:-}" = "--cut" ]; then
  [ "$#" -eq 3 ] || die "usage: scripts/release.sh --cut TAG SIGNING_KEY"
  TAG="$2"
  KEY="$3"
  printf '%s' "$TAG" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$' \
    || die "TAG must look like v1.2.3: $TAG"
  [ -f "$KEY" ] || die "no such signing key: $KEY"
  [ -f "$KEY.pub" ] || die "missing $KEY.pub — ssh-keygen -Y sign needs the public half next to the private key"
  for tool in git ssh-keygen python3; do
    command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
  done

  new="${TAG#v}"
  edit "s/^VERSION = \".*\"/VERSION = \"$new\"/" "$REPO_ROOT/scripts/rust_audit.py"
  for doc in README.md SKILL.md; do
    edit "s/(verify_release\.sh +)v[0-9]+\.[0-9]+\.[0-9]+/\1$TAG/g" "$REPO_ROOT/$doc"
  done
  git -C "$REPO_ROOT" commit -q -m "Cut $TAG: version bump and verify-before-use pins" \
    -- scripts/rust_audit.py README.md SKILL.md || die "nothing to commit for $TAG"
  if git -C "$REPO_ROOT" log origin/main..HEAD --format=%b 2>/dev/null | grep -qiE '^co-authored-by:'; then
    die "pre-push criterion failed: a commit carries a co-author trailer"
  fi
  # Main first, then the CI gate, and only then the tag: a red suite leaves no
  # tag to yank and nothing signed, instead of a published tag nobody verified.
  git -C "$REPO_ROOT" push -q origin HEAD || die "cannot push HEAD"
  say "CI gate: the suite must end green on the cut commit before $TAG exists"
  ci_rc=0
  ci_gate HEAD || ci_rc=$?
  if [ "$ci_rc" -ne 0 ]; then
    say "NOT RELEASED  no green suite on the cut commit — no tag was created, nothing was signed or uploaded. main carries the bump: fix forward and re-run the cut." >&2
    exit "$ci_rc"
  fi
  CI_GATE_DONE=1
  git -C "$REPO_ROOT" tag "$TAG" || die "cannot tag $TAG"
  git -C "$REPO_ROOT" push -q origin "$TAG" || die "cannot push $TAG"

  STAGED_DIR=$(mktemp -d) || die "cannot create a staging dir"
  cp "$REPO_ROOT/scripts/rust_audit.py" "$STAGED_DIR/"
  grep -m1 '^release@rust-audit ' "$REPO_ROOT/SECURITY.md" > "$STAGED_DIR/allowed_signers"
  [ -s "$STAGED_DIR/allowed_signers" ] || die "cannot extract the allowed_signers line from SECURITY.md"
  ( cd "$STAGED_DIR" && $SHA256_MAKE rust_audit.py > SHA256SUMS ) || die "cannot build SHA256SUMS"
  ssh-keygen -Y sign -f "$KEY" -n file -I "$SIGN_IDENTITY" "$STAGED_DIR/SHA256SUMS" >/dev/null \
    || die "signing failed for $KEY"
else
  [ "$#" -eq 2 ] || die "usage: scripts/release.sh TAG STAGEDIR | scripts/release.sh --cut TAG SIGNING_KEY"
  TAG="$1"
  STAGED_DIR="$2"
  [ -d "$STAGED_DIR" ] || die "no such directory: $STAGED_DIR"
fi
version="${TAG#v}"
for tool in gh python3; do
  command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
done
for f in $ASSETS; do
  [ -f "$STAGED_DIR/$f" ] || die "staged assets in $STAGED_DIR are missing $f"
done

# Pre-staged assets (release.sh TAG STAGEDIR) skip the --cut ordering, so the
# CI gate runs here instead — against the tag, which must already exist.
if [ "${CI_GATE_DONE:-0}" -ne 1 ]; then
  say "CI gate on $TAG (the suite must have passed on the tagged commit)"
  ci_rc=0
  ci_gate "$TAG" || ci_rc=$?
  if [ "$ci_rc" -ne 0 ]; then
    say "NOT RELEASED  no green suite on $TAG's commit — nothing was uploaded." >&2
    exit "$ci_rc"
  fi
fi

say "Pre-publish gate on $STAGED_DIR (release $TAG)"
gate_log=$(mktemp) || die "cannot create a temp file"
bash "$SCRIPT_DIR/verify_release.sh" --dir "$STAGED_DIR" "$TAG" 2>&1 | tee "$gate_log"
rc=${PIPESTATUS[0]}
if [ "$rc" -ne 0 ]; then
  say "NOT RELEASED  the pre-publish gate did not verify the staged assets — nothing was uploaded." >&2
  exit "$rc"
fi
receipt=$(awk '/^RECEIPT  /{print $2}' "$gate_log" | tail -1)
rm -f "$gate_log"

files=""
for f in $ASSETS; do files="$files $STAGED_DIR/$f"; done
if gh release view "$TAG" -R "$REPO" >/dev/null 2>&1; then
  gh release upload "$TAG" -R "$REPO" $files \
    || die "upload failed for $TAG (gh authenticated? network?)"
else
  gh release create "$TAG" -R "$REPO" --verify-tag --title "$TAG" \
    --notes "SSH-signed release assets — verify with scripts/verify_release.sh $TAG" $files \
    || die "release creation failed for $TAG (is the tag pushed? gh authenticated?)"
fi
[ -n "$receipt" ] && [ -f "$receipt" ] || die "the gate left no verification receipt to attach"
gh release upload "$TAG" -R "$REPO" "$receipt" \
  || die "receipt upload failed for $TAG"

say "Post-publish chain on the uploaded bytes (incl. the attached receipt cross-check)"
if ! bash "$SCRIPT_DIR/verify_release.sh" "$TAG"; then
  say "NOT VERIFIED  $TAG is uploaded but failed the post-publish chain — do not trust the assets." >&2
  exit 1
fi

say "PyPI gate: rust-audit $version must be installable, with the audited bytes"
pypi_rc=0
python3 "$CHECKS" pypi --version "$version" \
  --module "$STAGED_DIR/rust_audit.py" \
  --timeout "$PYPI_TIMEOUT" --interval "$PYPI_POLL" || pypi_rc=$?
if [ "$pypi_rc" -ne 0 ]; then
  say "UPLOADED, NOT SERVED  $REPO $TAG — the assets verified, but PyPI does not serve rust-audit $version yet. Do not tell anyone to install it: re-check with scripts/release_checks.py pypi --version $version --module <signed rust_audit.py>." >&2
  exit "$pypi_rc"
fi
say "RELEASED  $REPO $TAG — the suite was green on the tagged commit, the pre-publish gate passed, the receipt is attached, the uploaded bytes passed the post-publish chain, and PyPI serves rust-audit $version with the audited rust_audit.py."
