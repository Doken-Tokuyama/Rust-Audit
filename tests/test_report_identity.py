"""Every audit report must say which engine produced it.

A 0.1.0 copy sitting in a skill tree and the released wheel print the same
shapes and the same version string; without a digest a report cannot be tied
to the bytes that produced it, so "this audit was clean" cannot be checked
against the engine someone actually ran. Each report format must carry the
version, the path and the sha256 of the file that executed — and the digest
must come from the running file, not from a constant.
"""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TOOL = REPO / "scripts" / "rust_audit.py"

LIB_RS = "pub fn demo() -> u32 {\n    todo!()\n}\n"


def tool_version() -> str:
    return re.search(r'^VERSION = "([^"]+)"', TOOL.read_text(), re.M).group(1)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def workspace(root: Path) -> Path:
    crate = root / "ws"
    (crate / "src").mkdir(parents=True)
    (crate / "Cargo.toml").write_text(
        '[package]\nname = "demo"\nversion = "0.1.0"\nedition = "2021"\n')
    (crate / "src" / "lib.rs").write_text(LIB_RS)
    return crate


def scan(engine: Path, crate: Path, out: Path):
    return subprocess.run(
        [sys.executable, str(engine), "scan", str(crate),
         "--format", "terminal,md,json,sarif", "--out", str(out)],
        capture_output=True, text=True, timeout=300)


def reports(out: Path) -> dict[str, Path]:
    """The `rust-audit-*` artefacts by suffix (not the not-executed report)."""
    found = {}
    for path in sorted(out.iterdir()):
        if path.name.startswith("rust-audit-"):
            found[path.suffix] = path
    return found


def test_every_report_format_carries_the_engine_identity(tmp_path):
    result = scan(TOOL, workspace(tmp_path), tmp_path / "report")
    assert result.returncode in (0, 1), result.stdout + result.stderr
    paths = reports(tmp_path / "report")
    identity = {"version": tool_version(), "path": str(TOOL.resolve()),
                "sha256": sha256(TOOL)}

    payload = json.loads(paths[".json"].read_text())
    assert payload["engine"] == identity
    assert payload["version"] == identity["version"]

    markdown = paths[".md"].read_text()
    assert identity["sha256"] in markdown
    assert f"tool version {identity['version']}" in markdown
    assert str(TOOL.resolve()) in markdown

    sarif = json.loads(paths[".sarif"].read_text())
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["version"] == identity["version"]
    assert driver["properties"]["rustAuditSha256"] == identity["sha256"]

    gap = next(p for p in (tmp_path / "report").iterdir()
               if p.name.startswith("not-executed-"))
    gap_text = gap.read_text()
    assert identity["sha256"] in gap_text, (
        "the not-executed report is part of the verdict and must identify "
        "the engine that produced it")


def test_the_digest_is_the_running_file_not_a_constant(tmp_path):
    """A modified copy must report its own digest, not the repository's."""
    copy = tmp_path / "engine" / "rust_audit.py"
    copy.parent.mkdir()
    copy.write_bytes(TOOL.read_bytes() + b"\n# local patch\n")
    result = scan(copy, workspace(tmp_path), tmp_path / "report")
    assert result.returncode in (0, 1), result.stderr
    payload = json.loads(reports(tmp_path / "report")[".json"].read_text())
    assert payload["engine"]["sha256"] == sha256(copy)
    assert payload["engine"]["sha256"] != sha256(TOOL)
    assert payload["engine"]["path"] == str(copy.resolve())


def test_the_terminal_summary_shows_the_digest(tmp_path):
    result = scan(TOOL, workspace(tmp_path), tmp_path / "report")
    first = result.stdout.splitlines()[0]
    assert first.startswith("Rust Audit v" + tool_version())
    assert sha256(TOOL)[:12] in first, first
