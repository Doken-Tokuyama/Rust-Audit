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
#        scripts/verify_release.sh --dir DIR TAG
#   TAG     verify one release (default: latest release)
#   --all   verify every release from v0.2.0 onward, one pass
#   FILE    verify-before-use: also check this local copy against the signed
#           manifest — execute it only when the run ends on VERIFIED
#   --dir DIR TAG  verify STAGED release assets in DIR before they are
#           uploaded (the pre-publish gate): the same chain, but the assets
#           come from DIR and step 4 compares against the LOCAL git tag,
#           because the release is not published yet. TAG is required.
# Exit:  0 verified · 1 verification failed · 2 environment/usage error
#        (--all exits 1 if any release fails; an environment error aborts
#        the batch with 2)
# Needs: ssh-keygen and a checksum tool (shasum on macOS, sha256sum on
#        Linux) everywhere; additionally gh + tar for downloaded releases,
#        git for --dir.
#
# Every run writes a machine-readable receipt per release —
# report/verify-release-<tag>-<utc>.json (override the directory with
# RA_RECEIPT_DIR) — with the mode, the per-check status, the result and the
# exit code: the verification evidence kept under report/.
#
# The pinned fingerprint is the trust anchor and lives here (and in
# SECURITY.md) on purpose — never in the download. RA_EXPECT_FINGERPRINT
# overrides it for test fixtures only, and so does RA_REPO_ROOT for the
# checkout --dir compares the tag against. The tag is not itself signed:
# step 4 binds the attested bytes to the reviewed source tree; the
# signature in step 2 is the anchor.

set -u

REPO="Doken-Tokuyama/Rust-Audit"
PINNED_FINGERPRINT="${RA_EXPECT_FINGERPRINT:-SHA256:v/9tBKvWLy+NKzzqtvfH9vYwqLglF2gYYJ6K79LNmjU}"
SIGN_IDENTITY="release@rust-audit"
NAMESPACE="file"
ASSETS="rust_audit.py SHA256SUMS SHA256SUMS.sig allowed_signers"
FIRST_ATTESTED="v0.2.0"
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT="${RA_REPO_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"
RECEIPT_DIR="${RA_RECEIPT_DIR:-$REPO_ROOT/report}"

say()  { printf '%s\n' "$*"; }
pass() { say "PASS  $*"; }
fail() { say "FAIL  $*" >&2; }
die()  { say "ERROR $*" >&2; exit 2; }

json_escape() {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\t'/\\t}
  s=${s//$'\r'/\\r}
  printf '%s' "$s"
}

CHECKS=""
chk() {  # chk ID STATUS DETAIL — accumulate one receipt line
  CHECKS="$CHECKS${CHECKS:+,}{\"id\":\"$1\",\"status\":\"$2\",\"detail\":\"$(json_escape "$3")\"}"
}

write_receipt() {  # write_receipt TAG MODE RESULT EXIT_CODE -> prints the path
  local tag="$1" mode="$2" result="$3" code="$4" path
  path="$RECEIPT_DIR/verify-release-$(printf '%s' "$tag" | tr -c 'A-Za-z0-9._-' '_')-$(date -u +%Y%m%d-%H%M%S).json"
  mkdir -p "$RECEIPT_DIR" 2>/dev/null || return 1
  {
    printf '{\n'
    printf '  "tool": "verify_release.sh",\n'
    printf '  "repo": "%s",\n' "$(json_escape "$REPO")"
    printf '  "tag": "%s",\n' "$(json_escape "$tag")"
    printf '  "mode": "%s",\n' "$mode"
    printf '  "verified_at": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '  "identity": "%s",\n' "$SIGN_IDENTITY"
    printf '  "fingerprint_expected": "%s",\n' "$(json_escape "$PINNED_FINGERPRINT")"
    printf '  "checks": [%s],\n' "$CHECKS"
    printf '  "result": "%s",\n' "$result"
    printf '  "exit_code": %s\n' "$code"
    printf '}\n'
  } > "$path" 2>/dev/null || return 1
  say "RECEIPT  $path"
}

finish() {  # finish TAG MODE RESULT EXIT_CODE — evidence first, verdict after
  write_receipt "$1" "$2" "$3" "$4" || {
    fail "cannot write the verification receipt under $RECEIPT_DIR"
    return 2
  }
  return "$4"
}

MODE="download" STAGED_DIR=""
if [ "${1:-}" = "--dir" ]; then
  [ "$#" -eq 3 ] || die "usage: scripts/verify_release.sh [TAG | --all] [FILE] | scripts/verify_release.sh --dir DIR TAG"
  MODE="staged"
  STAGED_DIR="$2"
  TAG="$3"
  [ -d "$STAGED_DIR" ] || die "no such directory: $STAGED_DIR"
else
  [ "$#" -le 2 ] || die "usage: scripts/verify_release.sh [TAG | --all] [FILE]"
fi
for tool in ssh-keygen; do
  command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
done
if [ "$MODE" = "download" ]; then
  for tool in gh tar; do
    command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
  done
else
  command -v git >/dev/null 2>&1 || die "missing required tool: git"
fi
if command -v sha256sum >/dev/null 2>&1; then SHA256="sha256sum -c"
elif command -v shasum >/dev/null 2>&1; then SHA256="shasum -a 256 -c"
else die "missing required tool: sha256sum or shasum"; fi

verify_release() {
  local TAG="$1" VMODE="$2" CHECK_FILE="${3:-}" WORKDIR fp src tagged
  local LBL="release-download"
  [ "$VMODE" = "staged" ] && LBL="staged-dir"
  CHECKS=""
  say "Verifying $REPO release $TAG ($LBL)"

  WORKDIR=$(mktemp -d) || {
    chk scratch error "cannot create a temp dir"
    finish "$TAG" "$LBL" "ERROR" 2; return $?
  }
  trap "rm -rf '$WORKDIR'" EXIT   # expand now: WORKDIR is local and gone at EXIT

  local ASSET_DIR="$WORKDIR"
  if [ "$VMODE" = "staged" ]; then
    ASSET_DIR="$STAGED_DIR"
    chk assets pass "staged assets read from $STAGED_DIR (no download)"
  else
    if ! gh release download "$TAG" -R "$REPO" -D "$WORKDIR" >/dev/null 2>&1; then
      chk download error "download failed for $TAG (gh authenticated? network?)"
      fail "download failed for $TAG (gh authenticated? network?)"
      finish "$TAG" "$LBL" "ERROR" 2; return $?
    fi
    chk assets pass "release assets downloaded from $REPO $TAG"
  fi
  for f in $ASSETS; do
    if [ ! -f "$ASSET_DIR/$f" ]; then
      chk assets error "missing the attestation asset $f"
      say "ERROR release $TAG is missing the attestation asset $f (pre-v0.2.0 releases are not attested)" >&2
      finish "$TAG" "$LBL" "ERROR" 2; return $?
    fi
  done

  # 1. key pin
  fp=$(awk '{print $3, $4}' "$ASSET_DIR/allowed_signers" | ssh-keygen -lf - 2>/dev/null | awk '{print $2}')
  if [ -z "$fp" ]; then
    chk key_pin error "cannot read a key out of allowed_signers"
    say "ERROR cannot read a key out of allowed_signers" >&2
    finish "$TAG" "$LBL" "ERROR" 2; return $?
  fi
  if [ "$fp" != "$PINNED_FINGERPRINT" ]; then
    chk key_pin fail "signing key $fp is not the pinned key $PINNED_FINGERPRINT"
    fail "signing key $fp is not the pinned key $PINNED_FINGERPRINT"
    finish "$TAG" "$LBL" "NOT VERIFIED" 1; return $?
  fi
  chk key_pin pass "$fp"
  pass "key pin: $fp"

  # 2. signature over the manifest
  if ssh-keygen -Y verify -f "$ASSET_DIR/allowed_signers" -I "$SIGN_IDENTITY" -n "$NAMESPACE" \
       -s "$ASSET_DIR/SHA256SUMS.sig" < "$ASSET_DIR/SHA256SUMS" >/dev/null 2>&1; then
    chk signature pass "Good \"$NAMESPACE\" signature for $SIGN_IDENTITY"
    pass "signature: Good \"$NAMESPACE\" signature for $SIGN_IDENTITY"
  else
    chk signature fail "SHA256SUMS.sig does not verify against allowed_signers"
    fail "SHA256SUMS.sig does not verify against allowed_signers"
    finish "$TAG" "$LBL" "NOT VERIFIED" 1; return $?
  fi

  # 3. checksums
  if (cd "$ASSET_DIR" && $SHA256 SHA256SUMS >/dev/null 2>&1); then
    chk checksum pass "$(cat "$ASSET_DIR/SHA256SUMS")"
    pass "checksum: $(cat "$ASSET_DIR/SHA256SUMS")"
  else
    chk checksum fail "SHA256SUMS does not match the downloaded files"
    fail "SHA256SUMS does not match the downloaded files"
    finish "$TAG" "$LBL" "NOT VERIFIED" 1; return $?
  fi

  # 3b. local copy (verify-before-use)
  if [ -n "$CHECK_FILE" ]; then
    if [ ! -f "$CHECK_FILE" ]; then
      chk local_file error "no such file: $CHECK_FILE"
      say "ERROR no such file: $CHECK_FILE" >&2
      finish "$TAG" "$LBL" "ERROR" 2; return $?
    fi
    mkdir "$WORKDIR/check"
    cp "$CHECK_FILE" "$WORKDIR/check/rust_audit.py"
    grep '  rust_audit\.py$' "$ASSET_DIR/SHA256SUMS" > "$WORKDIR/check/SHA256SUMS"
    if (cd "$WORKDIR/check" && $SHA256 SHA256SUMS >/dev/null 2>&1); then
      chk local_file pass "$CHECK_FILE matches the signed rust_audit.py"
      pass "local file: $CHECK_FILE matches the signed rust_audit.py"
    else
      chk local_file fail "$CHECK_FILE does not match the signed rust_audit.py"
      fail "$CHECK_FILE does not match the signed rust_audit.py"
      finish "$TAG" "$LBL" "NOT VERIFIED" 1; return $?
    fi
  fi

  # 4. tag identity — published release: the tagged source on GitHub;
  #    staged assets: the LOCAL git tag (the release is not uploaded yet)
  if [ "$VMODE" = "staged" ]; then
    git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 || {
      chk tag_identity error "not a git checkout: $REPO_ROOT (tag identity needs git)"
      say "ERROR not a git checkout: $REPO_ROOT (tag identity needs git)" >&2
      finish "$TAG" "$LBL" "ERROR" 2; return $?
    }
    if ! git -C "$REPO_ROOT" show "$TAG:scripts/rust_audit.py" > "$WORKDIR/tagged.py" 2>/dev/null; then
      chk tag_identity error "no scripts/rust_audit.py at git ref $TAG (tag the release commit first)"
      say "ERROR no scripts/rust_audit.py at git ref $TAG (tag the release commit first)" >&2
      finish "$TAG" "$LBL" "ERROR" 2; return $?
    fi
  else
    if ! gh api "repos/$REPO/tarball/$TAG" > "$WORKDIR/src.tgz" 2>/dev/null; then
      chk tag_identity error "cannot fetch the source of $TAG"
      say "ERROR cannot fetch the source of $TAG" >&2
      finish "$TAG" "$LBL" "ERROR" 2; return $?
    fi
    src=$(tar -tzf "$WORKDIR/src.tgz" | grep -m1 '/scripts/rust_audit\.py$') || {
      chk tag_identity error "no scripts/rust_audit.py in $TAG"
      say "ERROR no scripts/rust_audit.py in $TAG" >&2
      finish "$TAG" "$LBL" "ERROR" 2; return $?
    }
    tar -xzOf "$WORKDIR/src.tgz" "$src" > "$WORKDIR/tagged.py" || {
      chk tag_identity error "cannot extract $src"
      say "ERROR cannot extract $src" >&2
      finish "$TAG" "$LBL" "ERROR" 2; return $?
    }
  fi
  if diff -q "$WORKDIR/tagged.py" "$ASSET_DIR/rust_audit.py" >/dev/null 2>&1; then
    chk tag_identity pass "rust_audit.py is byte-identical to $TAG:scripts/rust_audit.py"
    pass "tag identity: rust_audit.py is byte-identical to $TAG:scripts/rust_audit.py"
  else
    chk tag_identity fail "rust_audit.py differs from $TAG:scripts/rust_audit.py"
    fail "$LBL rust_audit.py differs from $TAG:scripts/rust_audit.py"
    finish "$TAG" "$LBL" "NOT VERIFIED" 1; return $?
  fi

  finish "$TAG" "$LBL" "VERIFIED" 0 || return 2
  say "VERIFIED  $REPO $TAG — rust_audit.py is the exact audited byte sequence."
}

if [ "$MODE" = "staged" ]; then
  verify_release "$TAG" staged
  exit $?
fi

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
    ( verify_release "$tag" download ) || rc=$?
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
verify_release "$TAG" download "${2:-}"
