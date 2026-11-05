"""Regressions for the four issues reported from a real Windows workspace.

1. Findings were identity-less: two runs could only be compared on
   (rule, file, line), so every edited line looked like a new finding.
   Now each finding carries a line-independent `fingerprint` and
   `--baseline <report.json>` reports only what the baseline did not have.
2. R16 flagged `db.read()` on a `SqlitePool` as a lock guard (253 HIGH false
   positives in the reported project). It now needs type evidence, and
   `[rules.R16] ignore_methods` suppresses a shape exactly.
3. R09 reported `.expect("...")` at the same HIGH as a bare `.unwrap()`.
   An expect names its invariant: it is reported at medium.
4. `rust-audit.toml` was only read at the scanned path, so scanning
   `crates/` silently ignored the project config at the repository root.
   It is now discovered upward and named in every report.

Every case goes through the real CLI (`scan`) on a real Cargo workspace;
the positive controls prove the refined rules still fire on the genuine smell.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "scripts" / "rust_audit.py"

CARGO = """[package]
name = "feedback"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio = { version = "1", features = ["sync", "rt", "macros", "time"] }
"""


def workspace(tmp_path: Path, files: dict[str, str],
              config: str | None = None) -> Path:
    """A real Cargo workspace; `crates/api` is the scanned target."""
    root = tmp_path / "project"
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    (root / "Cargo.toml").write_text(CARGO, encoding="utf-8")
    if config is not None:
        (root / "rust-audit.toml").write_text(config, encoding="utf-8")
    target = root / "crates" / "api"
    target.mkdir(parents=True, exist_ok=True)
    return target


def scan(target: Path, out: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), "scan", str(target), "--no-exec",
         "--no-gap-report", "--format", "terminal,json,sarif",
         "--out", str(out), *extra],
        capture_output=True, text=True, timeout=300,
    )


def json_report(out: Path) -> dict:
    files = sorted(out.glob("rust-audit-*.json"))
    assert files, f"no JSON report in {out}"
    return json.loads(files[-1].read_text())


def findings(out: Path) -> list[dict]:
    return json_report(out)["findings"]


def by_rule(rows: list[dict], rule_id: str) -> list[dict]:
    return [row for row in rows if row["rule_id"] == rule_id]


PARSE_RS = """pub fn parse(value: &str) -> Option<u32> {
    value.parse().ok()
}

pub fn label() -> u32 {
    parse("1").unwrap()
}
"""


def test_fingerprint_survives_a_line_shift_and_baseline_reports_zero_new(tmp_path):
    target = workspace(tmp_path, {"crates/api/src/lib.rs": PARSE_RS})
    assert scan(target, tmp_path / "base").returncode in (0, 1)
    baseline = json_report(tmp_path / "base")
    before = by_rule(baseline["findings"], "R09")
    assert before, "the unwrap must be reported"
    assert all(len(f["fingerprint"]) == 16 for f in baseline["findings"])

    # A normal edit above the finding: same code, new line number.
    (target / "src" / "lib.rs").write_text(
        "// edit above the finding\n" * 6 + PARSE_RS, encoding="utf-8")
    moved = scan(target, tmp_path / "moved")
    assert moved.returncode in (0, 1)
    after = by_rule(json_report(tmp_path / "moved")["findings"], "R09")
    assert after[0]["line"] != before[0]["line"], "the line must really have moved"
    assert after[0]["fingerprint"] == before[0]["fingerprint"], (
        "line is metadata; identity must not change when code moves")

    diff = scan(target, tmp_path / "diff", "--baseline",
                str(next((tmp_path / "base").glob("rust-audit-*.json"))))
    assert diff.returncode == 0, diff.stdout + diff.stderr
    payload = json_report(tmp_path / "diff")
    assert payload["summary"]["total"] == 0, "a shifted finding is not a new finding"
    assert payload["baseline"]["added"] == 0
    assert payload["baseline"]["removed"] == 0
    assert payload["baseline"]["unchanged"] == len(baseline["findings"])
    assert "baseline:" in diff.stdout


def test_baseline_reports_a_genuinely_new_finding(tmp_path):
    target = workspace(tmp_path, {"crates/api/src/lib.rs": PARSE_RS})
    scan(target, tmp_path / "base")
    baseline = next((tmp_path / "base").glob("rust-audit-*.json"))

    (target / "src" / "lib.rs").write_text(
        PARSE_RS + "\npub fn unfinished() {\n    todo!()\n}\n", encoding="utf-8")
    diff = scan(target, tmp_path / "diff", "--baseline", str(baseline))
    assert diff.returncode == 1, "a new critical finding must fail the gate"
    payload = json_report(tmp_path / "diff")
    assert payload["summary"]["total"] == 1
    assert payload["findings"][0]["rule_id"] == "R01"
    assert payload["baseline"]["added"] == 1
    assert payload["baseline"]["removed"] == 0
    assert payload["baseline"]["unchanged"] == len(baseline.read_text() and
                                                 json.loads(baseline.read_text())["findings"])


def test_baseline_must_be_a_rust_audit_json_report(tmp_path):
    target = workspace(tmp_path, {"crates/api/src/lib.rs": PARSE_RS})
    bogus = tmp_path / "bogus.json"
    bogus.write_text('{"not": "a report"}', encoding="utf-8")
    result = scan(target, tmp_path / "out", "--baseline", str(bogus))
    assert result.returncode == 2, result.stdout + result.stderr
    assert "not a Rust Audit JSON report" in result.stderr


def test_a_baseline_without_fingerprints_still_works(tmp_path):
    """Reports written before 0.2.8 have no `fingerprint`; they stay usable."""
    target = workspace(tmp_path, {"crates/api/src/lib.rs": PARSE_RS})
    scan(target, tmp_path / "base")
    path = next((tmp_path / "base").glob("rust-audit-*.json"))
    payload = json.loads(path.read_text())
    for finding in payload["findings"]:
        finding.pop("fingerprint")
    old = tmp_path / "old-report.json"
    old.write_text(json.dumps(payload), encoding="utf-8")

    result = scan(target, tmp_path / "out", "--baseline", str(old))
    assert result.returncode == 0, result.stdout + result.stderr
    diff = json_report(tmp_path / "out")
    assert diff["baseline"]["added"] == 0
    assert diff["baseline"]["unchanged"] == len(payload["findings"])


def test_sarif_uses_the_same_fingerprint_as_json(tmp_path):
    target = workspace(tmp_path, {"crates/api/src/lib.rs": PARSE_RS})
    assert scan(target, tmp_path / "out").returncode in (0, 1)
    payload = json_report(tmp_path / "out")
    sarif = json.loads(
        sorted((tmp_path / "out").glob("rust-audit-*.sarif"))[-1].read_text())
    json_fp = {f["fingerprint"] for f in payload["findings"]}
    sarif_fp = {r["partialFingerprints"]["rustAiAudit"]
                for r in sarif["runs"][0]["results"]}
    assert sarif_fp == json_fp, (
        "a code-scanning alert and the JSON finding must share one identity")


POOL_RS = """pub struct Db;

impl Db {
    pub fn read(&self) -> &Db {
        self
    }

    pub fn write(&self) -> &Db {
        self
    }
}

pub struct Api {
    db: Db,
}

impl Api {
    pub async fn count_active_admins(&self) -> u32 {
        let db = self.db.read();
        tokio::task::yield_now().await;
        let _ = db;
        1
    }

    pub async fn create_managed(&self) -> u32 {
        let db = self.db.write();
        tokio::task::yield_now().await;
        let _ = db;
        2
    }
}
"""


def test_r16_does_not_call_a_pool_accessor_a_lock_guard(tmp_path):
    target = workspace(tmp_path, {"crates/api/src/auth/users.rs": POOL_RS})
    assert scan(target, tmp_path / "out").returncode in (0, 1)
    assert not by_rule(findings(tmp_path / "out"), "R16"), (
        "read()/write() on a pool return a reference, not a guard")


RWLOCK_RS = """use std::sync::RwLock;

pub async fn guarded(state: &RwLock<u32>) -> u32 {
    let value = state.read();
    tokio::task::yield_now().await;
    let _ = value;
    1
}
"""


def test_r16_still_fires_on_a_real_synchronous_guard(tmp_path):
    target = workspace(tmp_path, {"crates/api/src/guarded.rs": RWLOCK_RS})
    assert scan(target, tmp_path / "out").returncode in (0, 1)
    hits = by_rule(findings(tmp_path / "out"), "R16")
    assert hits, "a std::sync::RwLock guard held across .await is a deadlock risk"
    assert hits[0]["severity"] == "high"
    assert "state.read()" in hits[0]["evidence"]


def test_ignore_methods_suppresses_narrowly_and_keeps_the_rest(tmp_path):
    target = workspace(
        tmp_path,
        {
            "crates/api/src/guarded.rs": RWLOCK_RS,
            "crates/api/src/sleepy.rs": """pub async fn sleepy() {
    std::thread::sleep(std::time::Duration::from_millis(1));
}
""",
        },
        config='[rules.R16]\nignore_methods = ["state.read"]\n',
    )
    result = scan(target, tmp_path / "out")
    assert result.returncode in (0, 1)
    payload = json_report(tmp_path / "out")
    assert payload["config"]["rule_options"]["R16"]["ignore_methods"] == ["state.read"]
    hits = by_rule(payload["findings"], "R16")
    assert not [f for f in hits if "guarded.rs" in f["file"]], (
        "the configured method shape must be suppressed")
    assert [f for f in hits if "sleep" in f["message"]], (
        "the rest of R16 must keep working: disabling the whole rule is not a fix")


CONFIG_RS = """pub fn label(value: Option<u32>) -> u32 {
    value.unwrap()
}

pub fn unfinished() {
    todo!()
}
"""


def test_project_config_is_discovered_upward_and_named_in_the_report(tmp_path):
    target = workspace(
        tmp_path,
        {"crates/api/src/lib.rs": CONFIG_RS},
        config='[rules]\ndisabled = ["R09"]\n',
    )
    result = scan(target, tmp_path / "out")
    assert result.returncode == 1, result.stdout + result.stderr
    payload = json_report(tmp_path / "out")
    assert payload["config"]["origin"] == "auto-discovered"
    assert payload["config"]["path"] == str(
        (tmp_path / "project" / "rust-audit.toml").resolve())
    assert payload["config"]["disabled_rules"] == ["R09"]
    assert not by_rule(payload["findings"], "R09")
    assert by_rule(payload["findings"], "R01"), "the rest of the scan still runs"
    assert f"config: {payload['config']['path']} (auto-discovered)" in result.stdout


def test_a_named_config_that_does_not_exist_is_an_execution_error(tmp_path):
    target = workspace(tmp_path, {"crates/api/src/lib.rs": CONFIG_RS})
    result = scan(target, tmp_path / "out", "--config",
                  str(tmp_path / "missing.toml"))
    assert result.returncode == 2, (
        "silently auditing with defaults contradicts the named config")
    assert "config file not found" in result.stderr


def test_r09_expect_is_medium_while_unwrap_stays_high(tmp_path):
    target = workspace(tmp_path, {"crates/api/src/lib.rs": """pub fn bare(value: Option<u32>) -> u32 {
    value.unwrap()
}

pub fn documented(value: Option<u32>) -> u32 {
    value.expect("caller validated the value")
}
"""})
    assert scan(target, tmp_path / "out").returncode in (0, 1)
    hits = by_rule(findings(tmp_path / "out"), "R09")
    sev = {f["function"]: f["severity"] for f in hits}
    assert sev == {"bare": "high", "documented": "medium"}, sev
