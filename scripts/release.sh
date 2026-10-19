#!/usr/bin/env bash
# release.sh — cut a Rust Audit release: verify the staged assets BEFORE
# they are uploaded, then upload them.
#
# Usage: scripts/release.sh TAG STAGEDIR
#   TAG       the release tag; must already exist as a git tag (the gate
#             compares the staged rust_audit.py against it) and on the
#             remote (gh release create --verify-tag)
#   STAGEDIR  directory holding the four attestation assets prepared per
#             SECURITY.md: rust_audit.py SHA256SUMS SHA256SUMS.sig
#             allowed_signers
#
# 1. pre-publish gate — scripts/verify_release.sh --dir STAGEDIR TAG:
#    key pin -> SSH signature -> checksum -> tag identity against the git
#    tag, with the JSON receipt written under report/. Nothing is uploaded
#    unless this ends on VERIFIED (exit 0).
# 2. upload — only after the gate: gh release create (or gh release upload
#    when the release already exists) of the four staged assets.
#
# Exit: 0 released · 1 the gate refused the staged assets · 2 environment/
#       usage error
# Needs: gh (authenticated — the repository is private) plus what
#        verify_release.sh needs for --dir (ssh-keygen, git, shasum/sha256sum).

set -u

REPO="Doken-Tokuyama/Rust-Audit"
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ASSETS="rust_audit.py SHA256SUMS SHA256SUMS.sig allowed_signers"

say() { printf '%s\n' "$*"; }
die() { say "ERROR $*" >&2; exit 2; }

[ "$#" -eq 2 ] || die "usage: scripts/release.sh TAG STAGEDIR"
TAG="$1"
STAGED_DIR="$2"
[ -d "$STAGED_DIR" ] || die "no such directory: $STAGED_DIR"
command -v gh >/dev/null 2>&1 || die "missing required tool: gh"
for f in $ASSETS; do
  [ -f "$STAGED_DIR/$f" ] || die "staged assets in $STAGED_DIR are missing $f"
done

say "Pre-publish gate on $STAGED_DIR (release $TAG)"
bash "$SCRIPT_DIR/verify_release.sh" --dir "$STAGED_DIR" "$TAG"
rc=$?
if [ "$rc" -ne 0 ]; then
  say "NOT RELEASED  the pre-publish gate did not verify the staged assets — nothing was uploaded." >&2
  exit "$rc"
fi

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
say "RELEASED  $REPO $TAG — staged assets passed the pre-publish gate and are uploaded."
