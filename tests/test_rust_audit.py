"""Integration suite for Rust Audit: the real CLI against the real fixture.

Seam under test: the public CLI of ``scripts/rust_audit.py`` — ``scan``,
``fix`` and ``selftest`` — invoked as a subprocess exactly as documented in
SKILL.md. Assertions are on observable results only: findings in the JSON
report, artifacts on disk, file edits and process exit codes (0 clean ·
1 findings at/above --fail-on · 2 execution error).

The fixture is the specification: every planted construct in
``tests/fixtures/demo_crate`` maps to a rule id asserted below. Run with
Python 3.11+ (the tool needs ``tomllib``): ``python3 -m pytest tests/``.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "scripts" / "rust_audit.py"
FIXTURE = ROOT / "tests" / "fixtures" / "demo_crate"

# Rules planted in tests/fixtures/demo_crate (map in src/lib.rs doc comment).
PLANTED_RULES = {"R01", "R02", "R03", "R09", "R10", "R12", "R18b"}
SECRET_LITERAL = "AKIAIOSFODNN7EXAMPLE"

# Files regenerated on every run: excluded from idempotency snapshots.
NOISE_DIRS = {"target", "report"}
NOISE_FILES = {"Cargo.lock"}


def run(*args: str) -> subprocess.CompletedProcess:
    """Invoke the real CLI the way a user does."""
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True, text=True, timeout=600,
    )


def scan(target: Path, out: Path, *extra: str) -> subprocess.CompletedProcess:
    return run("scan", str(target), "--format", "terminal,md,json,sarif",
               "--out", str(out), *extra)


def report(out: Path) -> dict:
    files = sorted(out.glob("rust-audit-*.json"))
    assert files, f"no JSON report written to {out}"
    return json.loads(files[0].read_text())


def findings(out: Path) -> set[str]:
    return {f["rule_id"] for f in report(out)["findings"]}


def copy_fixture(tmp_path: Path) -> Path:
    dst = tmp_path / "demo_crate"
    shutil.copytree(FIXTURE, dst, ignore=shutil.ignore_patterns("target", "Cargo.lock"))
    return dst


def snapshot(root: Path) -> dict[str, str]:
    out = {}
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(root)
        if rel.parts[0] in NOISE_DIRS or rel.name in NOISE_FILES:
            continue
        out[str(rel)] = p.read_text(errors="replace")
    return out


def test_selftest_passes():
    p = run("selftest")
    assert p.returncode == 0, p.stdout + p.stderr
    assert "selftest PASS" in p.stdout


def test_scan_flags_every_planted_rule(tmp_path):
    p = scan(FIXTURE, tmp_path, "--fail-on", "high")
    assert p.returncode == 1, "findings at/above --fail-on high must exit 1"
    data = report(tmp_path)
    assert PLANTED_RULES <= {f["rule_id"] for f in data["findings"]}
    # R18b is planted in a file outside the module tree: the scanner must
    # still read and flag it.
    r18b = [f for f in data["findings"] if f["rule_id"] == "R18b"]
    assert [f["file"] for f in r18b] == ["src/legacy.rs"]


def test_scan_writes_all_artifacts_named_rust_audit(tmp_path):
    scan(FIXTURE, tmp_path, "--fail-on", "high")
    assert list(tmp_path.glob("rust-audit-*.md")), "Markdown report missing"
    assert list(tmp_path.glob("rust-audit-*.sarif")), "SARIF report missing"
    gap = list(tmp_path.glob("not-executed-*.md"))
    assert gap, "not-executed report missing"
    assert report(tmp_path)["tool"] == "Rust Audit"
    sarif = json.loads(sorted(tmp_path.glob("rust-audit-*.sarif"))[0].read_text())
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "Rust Audit"


def test_exit_codes_match_documented_contract(tmp_path):
    clean = tmp_path / "clean"
    (clean / "src").mkdir(parents=True)
    (clean / "Cargo.toml").write_text(
        '[package]\nname = "clean"\nversion = "0.1.0"\nedition = "2021"\n\n'
        '[lib]\npath = "src/lib.rs"\n')
    (clean / "src" / "lib.rs").write_text(
        "pub fn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n")
    out = tmp_path / "out-clean"
    p = scan(clean, out, "--fail-on", "high")
    assert p.returncode == 0, p.stdout + p.stderr
    assert report(out)["summary"]["total"] == 0

    assert scan(tmp_path / "does-not-exist", tmp_path / "out-missing").returncode == 2
    empty = tmp_path / "empty"
    empty.mkdir()
    assert scan(empty, tmp_path / "out-empty").returncode == 2


def test_config_disables_exactly_the_named_rule(tmp_path):
    scan(FIXTURE, tmp_path / "base", "--fail-on", "high")
    assert "R02" in findings(tmp_path / "base")

    cfg = tmp_path / "rust-audit.toml"
    cfg.write_text('[rules]\ndisabled = ["R02"]\n')
    scan(FIXTURE, tmp_path / "cfg", "--config", str(cfg), "--fail-on", "high")
    found = findings(tmp_path / "cfg")
    assert "R02" not in found
    assert (PLANTED_RULES - {"R02"}) <= found, "disabling one rule hid others"


def test_fix_dry_run_changes_nothing(tmp_path):
    target = copy_fixture(tmp_path)
    before = snapshot(target)
    p = run("fix", str(target), "--dry-run")
    assert p.returncode == 0, p.stdout + p.stderr
    assert snapshot(target) == before


def test_fix_applies_safe_fixes_and_is_idempotent(tmp_path):
    target = copy_fixture(tmp_path)
    p1 = run("fix", str(target))
    assert p1.returncode == 0, p1.stdout + p.stderr

    legacy = (target / "src" / "legacy.rs").read_text()
    assert "use std::fs::File;" in legacy, "R18b safe fix (qualify std path) missing"

    lib = (target / "src" / "lib.rs").read_text()
    assert SECRET_LITERAL not in lib, "leaked secret literal must be rewritten"
    assert 'std::env::var("API_KEY")' in lib, "R12 safe fix (read from env) missing"
    env = target / ".env.example"
    assert env.exists() and "API_KEY" in env.read_text(), ".env.example entry missing"

    after_first = snapshot(target)
    p2 = run("fix", str(target))
    assert p2.returncode == 0, p2.stdout + p2.stderr
    assert snapshot(target) == after_first, "second fix run must apply nothing"
