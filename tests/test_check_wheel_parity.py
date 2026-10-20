"""The wheel/checkout parity check must fail for the right reasons.

`scripts/check_wheel_parity.py` is the only thing standing between "the
installed artifact audits like the code we tested" and a CI step that compares
two reports and always says OK. These tests feed it synthetic reports so each
refusal is exercised: a different findings summary, a different version, a
wheel that does not ship the audited bytes, a comparison that never installed
anything (same engine path), and an empty audit that would otherwise agree
with itself.
"""
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "check_wheel_parity.py"

SUMMARY = {
    "total": 3,
    "by_severity": {"high": 2, "low": 1},
    "by_rule": {"R01": 2, "R09": 1},
}


def report(directory: Path, *, summary=None, version="0.2.5",
           sha="a" * 64, path="/site-packages/rust_audit.py") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    payload = {
        "tool": "Rust Audit",
        "version": version,
        "engine": {"version": version, "path": path, "sha256": sha},
        "summary": SUMMARY if summary is None else summary,
        "findings": [],
    }
    (directory / "rust-audit-2026-10-20.json").write_text(json.dumps(payload))
    (directory / "not-executed-2026-10-20.md").write_text("# gaps\n")
    return directory


def run(*args) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SCRIPT), *map(str, args)],
                          capture_output=True, text=True, timeout=60)


def pair(tmp_path, **installed):
    return (report(tmp_path / "installed", path="/venv/lib/rust_audit.py",
                   **installed),
            report(tmp_path / "checkout", path="/src/scripts/rust_audit.py"))


def test_identical_reports_agree(tmp_path):
    proc = run(*pair(tmp_path))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "PARITY OK" in proc.stdout and "3 findings" in proc.stdout


def test_a_different_findings_summary_disagrees(tmp_path):
    other = {"total": 4, "by_severity": {"high": 3, "low": 1},
             "by_rule": {"R01": 3, "R09": 1}}
    proc = run(*pair(tmp_path, summary=other))
    assert proc.returncode == 1, proc.stdout
    assert "DISAGREE" in proc.stderr
    assert "installed total 4 vs checkout total 3" in proc.stderr


def test_a_different_version_disagrees(tmp_path):
    proc = run(*pair(tmp_path, version="0.2.4"))
    assert proc.returncode == 1
    assert "'0.2.4' installed vs '0.2.5'" in proc.stderr


def test_a_wheel_that_transforms_the_module_disagrees(tmp_path):
    proc = run(*pair(tmp_path, sha="b" * 64))
    assert proc.returncode == 1
    assert "does not ship the audited bytes" in proc.stderr


def test_two_runs_of_the_same_engine_prove_nothing(tmp_path):
    """The failure mode of a step that never installed anything."""
    same = tmp_path / "installed"
    report(same, path="/src/scripts/rust_audit.py")
    checkout = report(tmp_path / "checkout", path="/src/scripts/rust_audit.py")
    proc = run(same, checkout)
    assert proc.returncode == 1
    assert "nothing was installed" in proc.stderr


def test_an_empty_audit_cannot_show_agreement(tmp_path):
    empty = {"total": 0, "by_severity": {}, "by_rule": {}}
    installed, checkout = pair(tmp_path)
    report(installed, summary=empty)
    report(checkout, summary=empty)
    proc = run(installed, checkout)
    assert proc.returncode == 1
    assert "cannot show agreement" in proc.stderr


def test_usage_and_missing_reports_exit_2(tmp_path):
    assert run().returncode == 2
    assert run(tmp_path / "installed").returncode == 2
    assert run(tmp_path / "nope", tmp_path / "elsewhere").returncode == 2


def test_the_job_in_ci_actually_calls_it():
    """A helper nobody runs guards nothing."""
    workflow = (REPO / ".github" / "workflows" / "tests.yml").read_text()
    assert "scripts/check_wheel_parity.py" in workflow, (
        "tests.yml never compares the installed wheel with the checkout")
