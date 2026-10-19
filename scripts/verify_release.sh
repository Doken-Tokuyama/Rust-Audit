#!/usr/bin/env bash
# verify_release.sh — one command to verify Rust Audit releases.
#
# Downloads a release's attested assets and checks the full chain:
#   1. key pin      allowed_signers matches the fingerprint pinned below
#   2. signature    SHA256SUMS.sig is a Good ssh signature over SHA256SUMS
#   3. checksum     SHA256SUMS matches the downloaded rust_audit.py
#   4. tag identity rust_audit.py is byte-identical to the tag's scripts/rust_audit.py
#
# Usage: scripts/verify_release.sh [TAG | --all] [FILE]
#   TAG     verify one release (default: latest release)
#   --all   verify every release from v0.2.0 onward, one pass
#   FILE    verify-before-use: also check this local copy against the signed
#           manifest — execute it only when the run ends on VERIFIED
# Exit:  0 verified · 1 verification failed · 2 environment/usage error
#        (--all exits 1 if any release fails; an environment error aborts
#        the batch with 2)
# Needs: gh (authenticated — the repository is private), ssh-keygen, tar,
#        and shasum (macOS) or sha256sum (Linux).
#
# The pinned fingerprint is the trust anchor and lives here (and in
# SECURITY.md) on purpose — never in the download. RA_EXPECT_FINGERPRINT
# overrides it for test fixtures only. The tag is not itself signed: step 4
# binds the attested bytes to the reviewed source tree; the signature in
# step 2 is the anchor.

set -u

REPO="Doken-Tokuyama/Rust-Audit"
PINNED_FINGERPRINT="${RA_EXPECT_FINGERPRINT:-SHA256:v/9tBKvWLy+NKzzqtvfH9vYwqLglF2gYYJ6K79LNmjU}"
SIGN_IDENTITY="release@rust-audit"
NAMESPACE="file"
ASSETS="rust_audit.py SHA256SUMS SHA256SUMS.sig allowed_signers"
FIRST_ATTESTED="v0.2.0"

say()  { printf '%s\n' "$*"; }
pass() { say "PASS  $*"; }
fail() { say "FAIL  $*" >&2; }
die()  { say "ERROR $*" >&2; exit 2; }

[ "$#" -le 2 ] || die "usage: scripts/verify_release.sh [TAG | --all] [FILE]"
for tool in gh ssh-keygen tar; do
  command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
done
if command -v sha256sum >/dev/null 2>&1; then SHA256="sha256sum -c"
elif command -v shasum >/dev/null 2>&1; then SHA256="shasum -a 256 -c"
else die "missing required tool: sha256sum or shasum"; fi

verify_release() {
  local TAG="$1" CHECK_FILE="${2:-}" WORKDIR fp src
  say "Verifying $REPO release $TAG"
  WORKDIR=$(mktemp -d) || die "cannot create a temp dir"
  trap "rm -rf '$WORKDIR'" EXIT   # expand now: WORKDIR is local and gone at EXIT

  gh release download "$TAG" -R "$REPO" -D "$WORKDIR" >/dev/null 2>&1 \
    || die "download failed for $TAG (gh authenticated? network?)"
  for f in $ASSETS; do
    [ -f "$WORKDIR/$f" ] \
      || die "release $TAG is missing the attestation asset $f (pre-v0.2.0 releases are not attested)"
  done

  # 1. key pin
  fp=$(awk '{print $3, $4}' "$WORKDIR/allowed_signers" | ssh-keygen -lf - 2>/dev/null | awk '{print $2}')
  [ -n "$fp" ] || die "cannot read a key out of allowed_signers"
  if [ "$fp" != "$PINNED_FINGERPRINT" ]; then
    fail "signing key $fp is not the pinned key $PINNED_FINGERPRINT"
    exit 1
  fi
  pass "key pin: $fp"

  # 2. signature over the manifest
  if ssh-keygen -Y verify -f "$WORKDIR/allowed_signers" -I "$SIGN_IDENTITY" -n "$NAMESPACE" \
       -s "$WORKDIR/SHA256SUMS.sig" < "$WORKDIR/SHA256SUMS" >/dev/null 2>&1; then
    pass "signature: Good \"$NAMESPACE\" signature for $SIGN_IDENTITY"
  else
    fail "SHA256SUMS.sig does not verify against allowed_signers"
    exit 1
  fi

  # 3. checksums
  if (cd "$WORKDIR" && $SHA256 SHA256SUMS >/dev/null 2>&1); then
    pass "checksum: $(cat "$WORKDIR/SHA256SUMS")"
  else
    fail "SHA256SUMS does not match the downloaded files"
    exit 1
  fi

  # 3b. local copy (verify-before-use)
  if [ -n "$CHECK_FILE" ]; then
    [ -f "$CHECK_FILE" ] || die "no such file: $CHECK_FILE"
    mkdir "$WORKDIR/check"
    cp "$CHECK_FILE" "$WORKDIR/check/rust_audit.py"
    grep '  rust_audit\.py$' "$WORKDIR/SHA256SUMS" > "$WORKDIR/check/SHA256SUMS"
    if (cd "$WORKDIR/check" && $SHA256 SHA256SUMS >/dev/null 2>&1); then
      pass "local file: $CHECK_FILE matches the signed rust_audit.py"
    else
      fail "$CHECK_FILE does not match the signed rust_audit.py"
      exit 1
    fi
  fi

  # 4. tag identity
  gh api "repos/$REPO/tarball/$TAG" > "$WORKDIR/src.tgz" 2>/dev/null \
    || die "cannot fetch the source of $TAG"
  src=$(tar -tzf "$WORKDIR/src.tgz" | grep -m1 '/scripts/rust_audit\.py$') \
    || die "no scripts/rust_audit.py in $TAG"
  tar -xzOf "$WORKDIR/src.tgz" "$src" > "$WORKDIR/tagged.py" || die "cannot extract $src"
  if diff -q "$WORKDIR/tagged.py" "$WORKDIR/rust_audit.py" >/dev/null 2>&1; then
    pass "tag identity: rust_audit.py is byte-identical to $TAG:scripts/rust_audit.py"
  else
    fail "downloaded rust_audit.py differs from $TAG:scripts/rust_audit.py"
    exit 1
  fi

  say "VERIFIED  $REPO $TAG — rust_audit.py is the exact audited byte sequence."
}

if [ "${1:-}" = "--all" ]; then
  [ "$#" -eq 1 ] || die "--all takes no FILE"
  tags=$(gh release list -R "$REPO" --json tagName --jq '.[].tagName' 2>/dev/null) \
    || die "cannot list releases"
  batch=$(printf '%s\n' "$tags" | awk -v first="$FIRST_ATTESTED" '
    BEGIN { split(substr(first, 2), f, ".") }
    $0 ~ /^v[0-9]+\.[0-9]+\.[0-9]+$/ {
      split(substr($0, 2), t, ".")
      for (i = 1; i <= 3; i++) {
        if (t[i] + 0 > f[i] + 0) { print; next }
        if (t[i] + 0 < f[i] + 0) { next }
      }
      print
    }')
  [ -n "$batch" ] || die "no releases at or after $FIRST_ATTESTED"
  total=0
  failed=""
  for tag in $batch; do
    total=$((total + 1))
    rc=0
    ( verify_release "$tag" ) || rc=$?
    case $rc in
      0) ;;
      1) failed="$failed $tag" ;;
      *) exit $rc ;;
    esac
  done
  if [ -n "$failed" ]; then
    fail "NOT VERIFIED  failed:$failed ($total checked)"
    exit 1
  fi
  say "VERIFIED  all $total release(s) from $FIRST_ATTESTED onward."
  exit 0
fi

TAG="${1:-$(gh release view -R "$REPO" --json tagName --jq .tagName)}" \
  || die "cannot resolve the latest release tag"
verify_release "$TAG" "${2:-}"
