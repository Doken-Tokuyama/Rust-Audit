"""Tests for scripts/verify_release.sh — the release attestation chain.

Self-contained: a throwaway ed25519 key and a stub `gh` stand in for the real
release, so no network and no GitHub auth are needed. The pinned-key path is
covered by the live run against the published release (see SECURITY.md).
"""
import hashlib
import os
import subprocess
import tarfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "verify_release.sh"

GH_STUB = '''#!/usr/bin/env bash
case "$1" in
  release)
    if [ "$2" = "list" ]; then
      for t in ${RA_FIXTURE_TAGS:-v0.0.0-test}; do echo "$t"; done
    elif [ "$2" = "download" ]; then
      tag="$3"; shift 3; dest=.
      while [ $# -gt 0 ]; do
        if [ "$1" = "-D" ]; then dest="$2"; shift; fi
        shift
      done
      for f in rust_audit.py SHA256SUMS SHA256SUMS.sig allowed_signers; do
        [ -f "$RA_FIXTURES/$f" ] && cp "$RA_FIXTURES/$f" "$dest/"
      done
      if [ "$tag" = "${RA_UNATTESTED_TAG:-}" ]; then
        rm -f "$dest/SHA256SUMS" "$dest/SHA256SUMS.sig" "$dest/allowed_signers"
      fi
      if [ "$tag" = "${RA_TAMPER_TAG:-}" ]; then
        echo "print('tampered')" >> "$dest/rust_audit.py"
      fi
      exit 0
    else
      echo "v0.0.0-test"
    fi
    ;;
  api) cat "$RA_FIXTURES/src.tgz" ;;
  *) exit 1 ;;
esac
'''


def cmd(*argv, **kw):
    return subprocess.run([str(a) for a in argv], capture_output=True, text=True, **kw)


@pytest.fixture()
def release(tmp_path):
    """Build a throwaway attested release plus a stub gh that serves it."""
    key = tmp_path / "key"
    cmd("ssh-keygen", "-t", "ed25519", "-f", key, "-N", "", "-q")
    keytype, keydata = (tmp_path / "key.pub").read_text().split()[:2]

    fx = tmp_path / "fixtures"
    fx.mkdir()
    (fx / "rust_audit.py").write_text("print('audited bytes')\n")
    digest = hashlib.sha256((fx / "rust_audit.py").read_bytes()).hexdigest()
    (fx / "SHA256SUMS").write_text(f"{digest}  rust_audit.py\n")
    (fx / "allowed_signers").write_text(
        f'release@rust-audit namespaces="file" {keytype} {keydata}\n')
    cmd("ssh-keygen", "-Y", "sign", "-f", f"{key}.pub", "-n", "file",
        "-I", "release@rust-audit", fx / "SHA256SUMS")

    def make_tarball(text):
        src = tmp_path / "src" / "repo-abc123" / "scripts"
        src.mkdir(parents=True, exist_ok=True)
        (src / "rust_audit.py").write_text(text)
        with tarfile.open(fx / "src.tgz", "w:gz") as tf:
            tf.add(tmp_path / "src" / "repo-abc123", arcname="repo-abc123")

    make_tarball("print('audited bytes')\n")

    bin_ = tmp_path / "bin"
    bin_.mkdir()
    stub = bin_ / "gh"
    stub.write_text(GH_STUB)
    stub.chmod(0o755)

    fp = cmd("ssh-keygen", "-lf", f"{key}.pub").stdout.split()[1]

    def verify(*args, **env):
        e = {**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}",
             "RA_FIXTURES": str(fx), "RA_EXPECT_FINGERPRINT": fp, **env}
        return cmd("bash", SCRIPT, *(args or ("v0.0.0-test",)), env=e)

    return fx, verify, make_tarball


def test_chain_verifies_with_expected_key(release):
    _, verify, _ = release
    r = verify()
    assert r.returncode == 0, r.stdout + r.stderr
    assert r.stderr == ""   # no cleanup noise — catches broken EXIT traps
    for step in ("key pin:", "signature:", "checksum:", "tag identity:"):
        assert f"PASS  {step}" in r.stdout
    assert "VERIFIED" in r.stdout


def test_foreign_signing_key_fails_key_pin(release):
    _, verify, _ = release
    r = verify(RA_EXPECT_FINGERPRINT="")   # falls back to the real pinned key
    assert r.returncode == 1
    assert "not the pinned key" in r.stderr
    assert "VERIFIED" not in r.stdout


def test_corrupt_signature_fails(release):
    fx, verify, _ = release
    (fx / "SHA256SUMS.sig").write_text("not a signature\n")
    r = verify()
    assert r.returncode == 1
    assert "does not verify against allowed_signers" in r.stderr


def test_tampered_artifact_fails_checksum(release):
    fx, verify, _ = release
    with (fx / "rust_audit.py").open("a") as fh:
        fh.write("print('tampered')\n")
    r = verify()
    assert r.returncode == 1
    assert "SHA256SUMS does not match" in r.stderr


def test_tag_identity_mismatch_fails(release):
    fx, verify, make_tarball = release
    make_tarball("print('something else')\n")
    r = verify()
    assert r.returncode == 1
    assert "differs from v0.0.0-test:scripts/rust_audit.py" in r.stderr


def test_missing_asset_is_environment_error(release):
    fx, verify, _ = release
    (fx / "allowed_signers").unlink()
    r = verify()
    assert r.returncode == 2
    assert "missing the attestation asset allowed_signers" in r.stderr


def test_local_copy_checked_before_use(release):
    fx, verify, _ = release
    local = fx.parent / "downloaded.py"
    local.write_text((fx / "rust_audit.py").read_text())
    r = verify("v0.0.0-test", str(local))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "local file:" in r.stdout
    assert "matches the signed rust_audit.py" in r.stdout


def test_substituted_local_copy_fails(release):
    fx, verify, _ = release
    local = fx.parent / "downloaded.py"
    local.write_text("print('substituted')\n")
    r = verify("v0.0.0-test", str(local))
    assert r.returncode == 1
    assert "does not match the signed rust_audit.py" in r.stderr


def test_batch_verifies_every_release_from_v020_onward(release):
    _, verify, _ = release
    r = verify("--all", RA_FIXTURE_TAGS="v0.2.1 v0.2.0 v0.1.0",
               RA_UNATTESTED_TAG="v0.1.0")   # v0.1.0 ships no attestation
    assert r.returncode == 0, r.stdout + r.stderr
    assert r.stderr == ""   # per-release cleanup must be silent too
    assert r.stdout.count("VERIFIED  Doken-Tokuyama") == 2
    assert "VERIFIED  all 2 release(s) from v0.2.0 onward." in r.stdout
    assert "v0.1.0" not in r.stdout + r.stderr   # pre-attestation excluded


def test_batch_reports_the_failed_release_and_exits_1(release):
    _, verify, _ = release
    r = verify("--all", RA_FIXTURE_TAGS="v0.2.1 v0.2.0", RA_TAMPER_TAG="v0.2.0")
    assert r.returncode == 1
    assert "failed: v0.2.0" in r.stderr
    assert "VERIFIED  Doken-Tokuyama/Rust-Audit v0.2.1" in r.stdout   # good one still ran


def test_batch_environment_error_aborts_with_2(release):
    _, verify, _ = release
    r = verify("--all", RA_FIXTURE_TAGS="v0.2.1 v0.2.0",
               RA_UNATTESTED_TAG="v0.2.0")
    assert r.returncode == 2
    assert "missing the attestation asset" in r.stderr
    assert "VERIFIED  Doken-Tokuyama/Rust-Audit v0.2.1" in r.stdout   # ran before the abort
