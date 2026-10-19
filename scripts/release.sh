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
# 1. pre-publish gate — scripts/verify_release.sh --dir STAGEDIR TAG:
#    key pin -> SSH signature -> checksum -> tag identity against the git
#    tag, with the JSON receipt written under report/. Nothing is uploaded
#    unless this ends on VERIFIED (exit 0).
# 2. upload — only after the gate: gh release create (or gh release upload
#    when the release already exists) of the four staged assets, followed by
#    the gate's JSON receipt as evidence.
# 3. post-publish chain — the full verification (incl. the receipt
#    cross-check of the just-attached receipt) re-runs on the uploaded
#    bytes; RELEASED is printed only when it ends on VERIFIED.
#
# Exit: 0 released · 1 the gate refused the staged assets, or the uploaded
#       bytes failed the post-publish chain · 2 environment/usage error
# Needs: gh (authenticated — the repository is private) plus what
#        verify_release.sh needs for --dir (ssh-keygen, git, shasum/sha256sum).

set -u

REPO="Doken-Tokuyama/Rust-Audit"
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT="${RA_REPO_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"
ASSETS="rust_audit.py SHA256SUMS SHA256SUMS.sig allowed_signers"
SIGN_IDENTITY="release@rust-audit"

say() { printf '%s\n' "$*"; }
die() { say "ERROR $*" >&2; exit 2; }

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
  for tool in git ssh-keygen; do
    command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
  done

  new="${TAG#v}"
  edit "s/^VERSION = \".*\"/VERSION = \"$new\"/" "$REPO_ROOT/scripts/rust_audit.py"
  for doc in README.md SKILL.md; do
    edit "s/(verify_release\.sh +)v[0-9]+\.[0-9]+\.[0-9]+/\1$TAG/g" "$REPO_ROOT/$doc"
  done
  git -C "$REPO_ROOT" commit -q -m "Cut $TAG: version bump and verify-before-use pins" \
    -- scripts/rust_audit.py README.md SKILL.md || die "nothing to commit for $TAG"
  git -C "$REPO_ROOT" tag "$TAG" || die "cannot tag $TAG"
  if git -C "$REPO_ROOT" log origin/main..HEAD --format=%b 2>/dev/null | grep -qiE '^co-authored-by:'; then
    die "pre-push criterion failed: a commit carries a co-author trailer"
  fi
  git -C "$REPO_ROOT" push -q origin HEAD "$TAG" || die "cannot push HEAD and $TAG"

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
command -v gh >/dev/null 2>&1 || die "missing required tool: gh"
for f in $ASSETS; do
  [ -f "$STAGED_DIR/$f" ] || die "staged assets in $STAGED_DIR are missing $f"
done

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
say "RELEASED  $REPO $TAG — pre-publish gate passed, the receipt is attached, and the uploaded bytes passed the post-publish chain."
