"""Tests for scripts/verify_release.sh and scripts/release.sh — the release
attestation chain, the --dir pre-publish gate and the JSON verification
receipts.

Self-contained: a throwaway ed25519 key, a stub `gh` and a throwaway git tag
stand in for the real release, so no network and no GitHub auth are needed.
The pinned-key path is covered by the live run against the published release
(see SECURITY.md).
"""
import hashlib
import json
import os
import subprocess
import tarfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "verify_release.sh"
RELEASE = SCRIPT.parent / "release.sh"

GH_STUB = '''#!/usr/bin/env bash
echo "gh $*" >> "$RA_FIXTURES/gh-calls.log"
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
      for r in "$RA_FIXTURES"/verify-release-*.json; do   # an attached receipt
        [ -f "$r" ] && cp "$r" "$dest/"
      done
      if [ "$tag" = "${RA_UNATTESTED_TAG:-}" ]; then
        rm -f "$dest/SHA256SUMS" "$dest/SHA256SUMS.sig" "$dest/allowed_signers"
      fi
      if [ "$tag" = "${RA_TAMPER_TAG:-}" ]; then
        echo "print('tampered')" >> "$dest/rust_audit.py"
      fi
      exit 0
    elif [ "$2" = "view" ]; then
      case "${3:-}" in
        -*) echo "v0.0.0-test" ;;         # --json tagName: resolve "latest"
        *) exit "${RA_RELEASE_EXISTS:-1}" ;;  # existence probe: 1 = not found
      esac
    elif [ "$2" = "create" ] || [ "$2" = "upload" ]; then
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


def make_tag_repo(path, text, tag="v0.0.0-test"):
    """A throwaway git checkout whose tag carries scripts/rust_audit.py."""
    (path / "scripts").mkdir(parents=True)
    (path / "scripts" / "rust_audit.py").write_text(text)
    cmd("git", "init", "-q", path)
    cmd("git", "-C", path, "config", "user.email", "test@example.com")
    cmd("git", "-C", path, "config", "user.name", "test")
    cmd("git", "-C", path, "add", "-A")
    cmd("git", "-C", path, "commit", "-qm", "release")
    cmd("git", "-C", path, "tag", tag)


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
    make_tag_repo(tmp_path / "tagrepo", "print('audited bytes')\n")

    bin_ = tmp_path / "bin"
    bin_.mkdir()
    stub = bin_ / "gh"
    stub.write_text(GH_STUB)
    stub.chmod(0o755)

    fp = cmd("ssh-keygen", "-lf", f"{key}.pub").stdout.split()[1]

    def verify(*args, **env):
        e = {**verify.env, **env}
        return cmd("bash", SCRIPT, *(args or ("v0.0.0-test",)), env=e)

    verify.env = {**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}",
                  "RA_FIXTURES": str(fx), "RA_EXPECT_FINGERPRINT": fp,
                  "RA_RECEIPT_DIR": str(tmp_path / "report"),
                  "RA_REPO_ROOT": str(tmp_path / "tagrepo")}

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


# ---------------------------------------------------------------- --dir mode
# The pre-publish gate: staged assets verified before they are uploaded.


def test_staged_assets_verify_before_upload(release, tmp_path):
    fx, verify, _ = release
    r = verify("--dir", str(fx), "v0.0.0-test")
    assert r.returncode == 0, r.stdout + r.stderr
    assert r.stderr == ""
    for step in ("key pin:", "signature:", "checksum:", "tag identity:"):
        assert f"PASS  {step}" in r.stdout
    assert "VERIFIED" in r.stdout
    assert not (fx / "gh-calls.log").exists()   # nothing was downloaded


def test_staged_missing_asset_is_environment_error(release, tmp_path):
    fx, verify, _ = release
    (fx / "allowed_signers").unlink()
    r = verify("--dir", str(fx), "v0.0.0-test")
    assert r.returncode == 2
    assert "missing the attestation asset allowed_signers" in r.stderr


def test_staged_tampered_artifact_fails_checksum(release):
    fx, verify, _ = release
    with (fx / "rust_audit.py").open("a") as fh:
        fh.write("print('tampered')\n")
    r = verify("--dir", str(fx), "v0.0.0-test")
    assert r.returncode == 1
    assert "SHA256SUMS does not match" in r.stderr
    assert "VERIFIED" not in r.stdout


def test_staged_tag_identity_mismatch_fails(release, tmp_path):
    fx, verify, _ = release
    other = tmp_path / "other-tagrepo"
    make_tag_repo(other, "print('something else')\n")
    r = verify("--dir", str(fx), "v0.0.0-test", RA_REPO_ROOT=str(other))
    assert r.returncode == 1
    assert "differs from v0.0.0-test:scripts/rust_audit.py" in r.stderr


def test_staged_foreign_signing_key_fails_key_pin(release):
    fx, verify, _ = release
    r = verify("--dir", str(fx), "v0.0.0-test", RA_EXPECT_FINGERPRINT="")
    assert r.returncode == 1
    assert "not the pinned key" in r.stderr


def test_staged_missing_tag_is_environment_error(release, tmp_path):
    fx, verify, _ = release
    other = tmp_path / "untagged-repo"
    make_tag_repo(other, "print('audited bytes')\n", tag="other-tag")
    r = verify("--dir", str(fx), "v0.0.0-test", RA_REPO_ROOT=str(other))
    assert r.returncode == 2
    assert "no scripts/rust_audit.py at git ref v0.0.0-test" in r.stderr


def test_staged_requires_a_tag(release):
    _, verify, _ = release
    r = verify("--dir", "some-dir")
    assert r.returncode == 2
    assert "usage:" in r.stderr


# ------------------------------------------------------------ JSON receipts


def receipts(report_dir):
    return sorted(report_dir.glob("verify-release-*.json"))


def test_receipt_is_written_per_release(release, tmp_path):
    fx, verify, _ = release
    r = verify()
    assert r.returncode == 0, r.stdout + r.stderr
    paths = receipts(tmp_path / "report")
    assert len(paths) == 1
    receipt = json.loads(paths[0].read_text())
    assert receipt["tool"] == "verify_release.sh"
    assert receipt["repo"] == "Doken-Tokuyama/Rust-Audit"
    assert receipt["tag"] == "v0.0.0-test"
    assert receipt["mode"] == "release-download"
    assert receipt["result"] == "VERIFIED"
    assert receipt["exit_code"] == 0
    assert receipt["fingerprint_expected"].startswith("SHA256:")
    # Deliberate format update (ADR 0003): the checks list gained the
    # "receipt" cross-check of the release-attached receipt (download mode).
    assert [c["id"] for c in receipt["checks"]] == [
        "assets", "key_pin", "signature", "checksum", "tag_identity", "receipt"]
    chain = {c["id"]: c["status"] for c in receipt["checks"]}
    assert all(chain[i] == "pass" for i in
               ("assets", "key_pin", "signature", "checksum", "tag_identity"))
    assert chain["receipt"] == "absent"   # fixtures attach no receipt
    assert str(paths[0]) in r.stdout   # the receipt path is printed


def test_receipt_records_local_file_check(release, tmp_path):
    fx, verify, _ = release
    local = tmp_path / "downloaded.py"
    local.write_text((fx / "rust_audit.py").read_text())
    r = verify("v0.0.0-test", str(local))
    assert r.returncode == 0, r.stdout + r.stderr
    receipt = json.loads(receipts(tmp_path / "report")[0].read_text())
    assert [c["id"] for c in receipt["checks"]] == [
        "assets", "key_pin", "signature", "checksum", "local_file",
        "tag_identity", "receipt"]


def test_receipt_records_the_failing_check(release, tmp_path):
    fx, verify, _ = release
    (fx / "SHA256SUMS.sig").write_text("not a signature\n")
    r = verify()
    assert r.returncode == 1
    receipt = json.loads(receipts(tmp_path / "report")[0].read_text())
    assert receipt["result"] == "NOT VERIFIED"
    assert receipt["exit_code"] == 1
    by_id = {c["id"]: c["status"] for c in receipt["checks"]}
    assert by_id["signature"] == "fail"
    assert "tag_identity" not in by_id   # never claims a check it did not run
    assert "VERIFIED" not in r.stdout


def test_receipt_for_staged_gate(release, tmp_path):
    fx, verify, _ = release
    r = verify("--dir", str(fx), "v0.0.0-test")
    assert r.returncode == 0, r.stdout + r.stderr
    receipt = json.loads(receipts(tmp_path / "report")[0].read_text())
    assert receipt["mode"] == "staged-dir"
    assert receipt["result"] == "VERIFIED"


def test_batch_writes_one_receipt_per_release(release, tmp_path):
    _, verify, _ = release
    r = verify("--all", RA_FIXTURE_TAGS="v0.2.1 v0.2.0")
    assert r.returncode == 0, r.stdout + r.stderr
    got = {json.loads(p.read_text())["tag"] for p in receipts(tmp_path / "report")}
    assert got == {"v0.2.1", "v0.2.0"}


def write_attached_receipt(fx, verify, *, result="VERIFIED", tag="v0.0.0-test",
                           fingerprint=None, checksum_detail=None):
    """The receipt the gate would have attached to this release."""
    sums = (fx / "SHA256SUMS").read_text()
    receipt = {
        "tool": "verify_release.sh",
        "repo": "Doken-Tokuyama/Rust-Audit",
        "tag": tag,
        "mode": "staged-dir",
        "verified_at": "2026-01-01T00:00:00Z",
        "identity": "release@rust-audit",
        "fingerprint_expected": fingerprint or verify.env["RA_EXPECT_FINGERPRINT"],
        "checks": [{"id": i, "status": "pass", "detail": d}
                   for i, d in (("assets", ""), ("key_pin", ""),
                                ("signature", ""),
                                ("checksum", sums if checksum_detail is None
                                 else checksum_detail),
                                ("tag_identity", ""))],
        "result": result,
        "exit_code": 0 if result == "VERIFIED" else 1,
    }
    (fx / "verify-release-v0.0.0-test-20260101-000000.json").write_text(
        json.dumps(receipt))


def fresh_checks(verify):
    report = Path(verify.env["RA_RECEIPT_DIR"])
    return {c["id"]: c["status"] for c in
            json.loads(sorted(report.glob("verify-release-*.json"))[-1]
                       .read_text())["checks"]}


def test_attached_receipt_matching_the_chain_is_cross_checked(release):
    fx, verify, _ = release
    write_attached_receipt(fx, verify)
    r = verify()
    assert r.returncode == 0, r.stdout + r.stderr
    assert "receipt: the attached receipt matches this verification" in r.stdout
    assert fresh_checks(verify)["receipt"] == "pass"


def test_tampered_attached_receipt_fails(release):
    fx, verify, _ = release
    for tamper in ({"result": "NOT VERIFIED"},
                   {"checksum_detail": "0" * 64 + "  rust_audit.py\n"}):
        write_attached_receipt(fx, verify, **tamper)
        r = verify()
        assert r.returncode == 1, tamper
        assert "does not match this verification" in r.stderr
        assert "VERIFIED" not in r.stdout


def test_missing_attached_receipt_is_reported_absent(release):
    fx, verify, _ = release
    r = verify()
    assert r.returncode == 0, r.stdout + r.stderr
    assert "receipt: absent" in r.stdout
    assert fresh_checks(verify)["receipt"] == "absent"


def test_staged_mode_has_no_receipt_cross_check(release):
    fx, verify, _ = release
    write_attached_receipt(fx, verify)   # a release cannot attach one yet
    r = verify("--dir", str(fx), "v0.0.0-test")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "receipt:" not in r.stdout
    assert "receipt" not in fresh_checks(verify)


# --------------------------------------------------- release.sh (the gate)


def run_release(verify, *args, **env):
    return cmd("bash", RELEASE, *args, env={**verify.env, **env})


def test_release_uploads_only_after_the_gate_verifies(release, tmp_path):
    fx, verify, _ = release
    r = run_release(verify, "v0.0.0-test", str(fx))
    assert r.returncode == 0, r.stdout + r.stderr
    assert r.stdout.index("Pre-publish gate") < r.stdout.index("RELEASED")
    assert "VERIFIED" in r.stdout
    calls = (fx / "gh-calls.log").read_text()
    assert "release create v0.0.0-test" in calls
    for asset in ("rust_audit.py", "SHA256SUMS", "SHA256SUMS.sig", "allowed_signers"):
        assert str(fx / asset) in calls   # exactly the staged assets upload
    assert receipts(tmp_path / "report")   # the gate left its evidence


def test_release_uploads_to_an_existing_release(release):
    fx, verify, _ = release
    r = run_release(verify, "v0.0.0-test", str(fx), RA_RELEASE_EXISTS="0")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "release upload v0.0.0-test" in (fx / "gh-calls.log").read_text()


def test_release_gate_blocks_upload_on_failure(release, tmp_path):
    fx, verify, _ = release
    with (fx / "rust_audit.py").open("a") as fh:
        fh.write("print('tampered')\n")
    r = run_release(verify, "v0.0.0-test", str(fx))
    assert r.returncode == 1
    assert "NOT RELEASED" in r.stderr
    assert not (fx / "gh-calls.log").exists()   # gh was never reached


def test_release_requires_every_staged_asset(release):
    fx, verify, _ = release
    (fx / "allowed_signers").unlink()
    r = run_release(verify, "v0.0.0-test", str(fx))
    assert r.returncode == 2
    assert "are missing allowed_signers" in r.stderr
    assert not (fx / "gh-calls.log").exists()


# ------------------------------------------------- release.sh --cut mode


def make_cut_repo(path, keytype, keydata):
    """A repo wired for --cut: VERSION, verify-before-use pins, the fixture's
    allowed_signers line, and a bare origin to push to."""
    (path / "scripts").mkdir(parents=True)
    (path / "scripts" / "rust_audit.py").write_text(
        'VERSION = "0.2.0"\nprint("audited bytes")\n')
    (path / "README.md").write_text(
        "```bash\nscripts/verify_release.sh v0.2.0 ./rust_audit.py\n```\n")
    (path / "SKILL.md").write_text(
        "scripts/verify_release.sh v0.2.0 ./rust_audit.py\n")
    (path / "SECURITY.md").write_text(
        f'release@rust-audit namespaces="file" {keytype} {keydata}\n')
    cmd("git", "init", "-q", path)
    cmd("git", "-C", path, "config", "user.email", "test@example.com")
    cmd("git", "-C", path, "config", "user.name", "test")
    cmd("git", "-C", path, "add", "-A")
    cmd("git", "-C", path, "commit", "-qm", "base")
    origin = path.parent / (path.name + "-origin.git")
    cmd("git", "init", "-q", "--bare", origin)
    cmd("git", "-C", path, "remote", "add", "origin", origin)
    return origin


def cut_setup(tmp_path):
    keytype, keydata = (tmp_path / "key.pub").read_text().split()[:2]
    repo = tmp_path / "cutrepo"
    return repo, make_cut_repo(repo, keytype, keydata)


def test_cut_releases_in_one_command(release, tmp_path):
    fx, verify, _ = release
    repo, origin = cut_setup(tmp_path)
    r = run_release(verify, "--cut", "v9.9.9", str(tmp_path / "key"),
                    RA_REPO_ROOT=str(repo))
    assert r.returncode == 0, r.stdout + r.stderr
    assert 'VERSION = "9.9.9"' in (repo / "scripts" / "rust_audit.py").read_text()
    for doc in ("README.md", "SKILL.md"):
        assert "verify_release.sh v9.9.9" in (repo / doc).read_text()
    assert cmd("git", "-C", origin, "rev-parse", "v9.9.9").returncode == 0
    calls = (fx / "gh-calls.log").read_text()
    assert "release create v9.9.9" in calls
    attached = [line for line in calls.splitlines()
                if "release upload v9.9.9" in line and "verify-release-" in line]
    assert attached, f"the receipt was not uploaded: {calls}"
    assert receipts(tmp_path / "report")   # and kept under report/


def test_cut_gate_failure_blocks_the_upload(release, tmp_path):
    fx, verify, _ = release
    repo, _ = cut_setup(tmp_path)
    r = run_release(verify, "--cut", "v9.9.9", str(tmp_path / "key"),
                    RA_REPO_ROOT=str(repo), RA_EXPECT_FINGERPRINT="")
    assert r.returncode == 1
    assert "NOT RELEASED" in r.stderr
    assert not (fx / "gh-calls.log").exists()   # nothing reached gh


def test_cut_needs_the_public_half_next_to_the_key(release, tmp_path):
    fx, verify, _ = release
    repo, _ = cut_setup(tmp_path)
    lone = tmp_path / "lone.key"
    lone.write_text((tmp_path / "key").read_text())
    r = run_release(verify, "--cut", "v9.9.9", str(lone),
                    RA_REPO_ROOT=str(repo))
    assert r.returncode == 2
    assert "needs the public half next to the private key" in r.stderr
    assert 'VERSION = "0.2.0"' in (repo / "scripts" / "rust_audit.py").read_text()  # nothing mutated
    assert not (fx / "gh-calls.log").exists()
