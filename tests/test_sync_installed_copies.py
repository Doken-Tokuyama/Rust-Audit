"""Contract of scripts/sync_installed_copies.py.

An agent that ships the auditor (Freebuff account skill, Cursor's agent
store, a vendored copy) runs *its own* `scripts/rust_audit.py`. The command
exists to make a stale engine visible and to refresh it, so its exit codes
must mean something: 0 nothing stale · 1 stale/drift found · 2 execution
error. These tests drive the CLI — report, `--fix`, `--force`, the error
paths — and assert the bytes that end up on disk, because "it printed fixed"
without the file changing would be the bug worth catching.
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TOOL = REPO / "scripts" / "sync_installed_copies.py"

ENGINE = b'VERSION = "2.0.0"\nprint("current engine")\n'
OLD_ENGINE = b'VERSION = "1.0.0"\nprint("old engine")\n'
CRATES = b"serde\ntokio\n"
OLD_CRATES = b"serde\n"
DENY = b"[advisories]\nyanked = \"deny\"\n"


def make_tree(root, version_engine=ENGINE):
    """A canonical checkout plus copies, laid out like a real install."""
    canonical = root / "repo" / "scripts" / "rust_audit.py"
    canonical.parent.mkdir(parents=True)
    canonical.write_bytes(version_engine)
    for rel, data in (("resources/popular_crates.txt", CRATES),
                      ("resources/suspicious_names.txt", CRATES),
                      ("templates/deny.toml", DENY)):
        path = root / "repo" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def copy(name, engine, crates=CRATES, deny=DENY):
        base = root / "agents" / name
        (base / "scripts").mkdir(parents=True)
        (base / "scripts" / "rust_audit.py").write_bytes(engine)
        for rel, data in (("resources/popular_crates.txt", crates),
                          ("resources/suspicious_names.txt", crates),
                          ("templates/deny.toml", deny)):
            path = base / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        return base

    copy("ok", ENGINE)
    copy("old", OLD_ENGINE, OLD_CRATES, b"[advisories]\n")
    copy("drift", ENGINE.replace(b"current engine", b"patched engine"))
    copy("ahead", b'VERSION = "3.0.0"\nprint("newer engine")\n')
    return canonical


def run(*args):
    return subprocess.run([sys.executable, str(TOOL), *args],
                          capture_output=True, text=True, timeout=120)


def report(root, *extra):
    result = run("--canonical", str(root / "repo" / "scripts" / "rust_audit.py"),
                 "--root", str(root / "agents"), "--json", *extra)
    return result, json.loads(result.stdout) if result.stdout else None


def statuses(model):
    return {Path(row["path"]).parent.parent.name: row["status"]
            for row in model["copies"]}


def test_report_names_every_copy_and_its_state(tmp_path):
    make_tree(tmp_path)
    result, model = report(tmp_path)
    assert result.returncode == 1, result.stderr
    assert model["canonical"]["version"] == "2.0.0"
    assert statuses(model) == {"ok": "current", "old": "stale",
                               "drift": "drift", "ahead": "newer"}
    human = run("--canonical", str(tmp_path / "repo" / "scripts" / "rust_audit.py"),
                "--root", str(tmp_path / "agents"))
    assert human.returncode == 1
    assert "rerun with --fix" in human.stdout


def test_fix_refreshes_the_engine_and_the_runtime_data(tmp_path):
    root = tmp_path
    make_tree(root)
    # Only the stale copy is present, so a clean run can exit 0.
    for name in ("drift", "ahead"):
        shutil.rmtree(root / "agents" / name)

    result, model = report(root, "--fix")
    assert result.returncode == 0, result.stderr + result.stdout
    assert statuses(model) == {"ok": "current", "old": "fixed"}
    old = root / "agents" / "old"
    assert (old / "scripts" / "rust_audit.py").read_bytes() == ENGINE
    assert (old / "resources" / "popular_crates.txt").read_bytes() == CRATES
    assert (old / "templates" / "deny.toml").read_bytes() == DENY


def test_drift_is_reported_and_never_overwritten_without_force(tmp_path):
    make_tree(tmp_path)
    patched = (tmp_path / "agents" / "drift" / "scripts" / "rust_audit.py").read_bytes()
    result, model = report(tmp_path, "--fix")
    assert result.returncode == 1
    assert statuses(model)["drift"] == "drift"
    assert (tmp_path / "agents" / "drift" / "scripts" / "rust_audit.py").read_bytes() == patched

    forced, model = report(tmp_path, "--fix", "--force")
    assert forced.returncode == 0, forced.stderr
    assert statuses(model)["drift"] == "fixed"
    assert (tmp_path / "agents" / "drift" / "scripts" / "rust_audit.py").read_bytes() == ENGINE


def test_the_canonical_engine_is_never_touched(tmp_path):
    root = tmp_path
    canonical = make_tree(root)
    before = canonical.read_bytes()
    result, model = report(root, "--fix")
    # exit 1 because the drift copy is left alone on purpose.
    assert result.returncode == 1, result.stderr
    assert canonical.read_bytes() == before
    assert all(Path(row["path"]) != canonical for row in model["copies"])


FRONTMATTER = ("---\nname: rust-audit\ndescription: demo\n"
               "metadata:\n  source: Rust-Audit-main.zip\n---\n")
SKILL_BODY = "# Rust Audit\n\nCurrent instructions.\n"
OLD_SKILL_BODY = "# Rust Audit\n\nOld instructions. 0.1.0 era.\n"


def add_instructions(root, name, body=OLD_SKILL_BODY, readme="old readme\n"):
    base = root / "agents" / name
    (base / "SKILL.md").write_text(FRONTMATTER + "\n" + body)
    (base / "README.md").write_text(readme)
    (base / "docs" / "adr").mkdir(parents=True, exist_ok=True)
    (base / "docs" / "adr" / "0001-a.md").write_text("old adr\n")
    return base


def add_repo_docs(root, body=SKILL_BODY):
    repo = root / "repo"
    (repo / "SKILL.md").write_text(body)
    (repo / "README.md").write_text("current readme\n")
    (repo / "CONTEXT.md").write_text("current context\n")
    (repo / "SECURITY.md").write_text("current security\n")
    (repo / "docs" / "adr").mkdir(parents=True, exist_ok=True)
    (repo / "docs" / "adr" / "0001-a.md").write_text("current adr\n")


def docs_tree(root):
    """A copy at the current engine whose *instructions* are from 0.1.0."""
    make_tree(root)
    add_repo_docs(root)
    shutil.rmtree(root / "agents" / "drift")   # isolate the docs behaviour
    shutil.rmtree(root / "agents" / "ahead")
    return add_instructions(root, "ok")


def test_instruction_drift_is_a_finding_even_with_a_current_engine(tmp_path):
    root = tmp_path
    docs_tree(root)
    result, model = report(root)
    row = {Path(r["path"]).parent.parent.name: r for r in model["copies"]}["ok"]
    assert result.returncode == 1, result.stdout
    assert row["status"] == "current"
    assert row["docs"] == ["SKILL.md", "README.md", "CONTEXT.md (missing)",
                           "SECURITY.md (missing)", "docs/adr/0001-a.md"]


def test_fix_aligns_the_instructions_and_keeps_the_frontmatter(tmp_path):
    root = tmp_path
    base = docs_tree(root)
    result, model = report(root, "--fix")
    assert result.returncode == 0, result.stderr + result.stdout
    text = (base / "SKILL.md").read_text()
    assert text.startswith(FRONTMATTER), "the target's identity was overwritten"
    assert text.endswith(SKILL_BODY), text[-120:]
    assert (base / "README.md").read_text() == "current readme\n"
    assert (base / "SECURITY.md").read_text() == "current security\n"
    assert (base / "docs" / "adr" / "0001-a.md").read_text() == "current adr\n"
    rows = {Path(r["path"]).parent.parent.name: r for r in model["copies"]}
    assert rows["ok"]["status"] == "fixed"
    assert rows["ok"]["docs"] == []


def test_a_document_the_readme_links_to_is_shipped_too(tmp_path):
    root = tmp_path
    base = docs_tree(root)
    (root / "repo" / "docs" / "extra.md").write_text("extra doc\n")
    readme = root / "repo" / "README.md"
    readme.write_text(readme.read_text() + "See [extra](docs/extra.md).\n")

    _, model = report(root)
    row = {Path(r["path"]).parent.parent.name: r for r in model["copies"]}["ok"]
    assert "docs/extra.md (missing)" in row["docs"], row["docs"]

    result, model = report(root, "--fix")
    assert result.returncode == 0, result.stderr
    assert (base / "docs" / "extra.md").read_text() == "extra doc\n"
    row = {Path(r["path"]).parent.parent.name: r for r in model["copies"]}["ok"]
    assert row["docs"] == []


def test_the_verify_script_the_instructions_run_is_shipped(tmp_path):
    root = tmp_path
    base = docs_tree(root)
    script = root / "repo" / "scripts" / "verify_release.sh"
    script.write_text("#!/bin/sh\necho verifying\n")
    script.chmod(0o755)

    _, model = report(root)
    row = {Path(r["path"]).parent.parent.name: r for r in model["copies"]}["ok"]
    assert "scripts/verify_release.sh (missing)" in row["docs"], row["docs"]

    result, model = report(root, "--fix")
    assert result.returncode == 0, result.stderr
    shipped = base / "scripts" / "verify_release.sh"
    assert shipped.read_text() == "#!/bin/sh\necho verifying\n"
    assert shipped.stat().st_mode & 0o111, "the verify step is invoked directly"


def test_a_bare_vendored_copy_reads_no_docs(tmp_path):
    root = tmp_path
    make_tree(root)
    add_repo_docs(root)
    # No SKILL.md in these trees: missing docs are not a finding, and no
    # documentation is invented for a tree that never shipped any.
    result, model = report(root, "--fix")
    assert result.returncode == 1  # the drift copy is still left alone
    assert all(not row["docs"] for row in model["copies"])
    assert not (root / "agents" / "ok" / "README.md").exists()
    assert not (root / "agents" / "old" / "SECURITY.md").exists()


def test_scan_skips_vcs_directories(tmp_path):
    make_tree(tmp_path)
    buried = tmp_path / "agents" / ".git" / "scripts"
    buried.mkdir(parents=True)
    (buried / "rust_audit.py").write_bytes(OLD_ENGINE)
    result, model = report(tmp_path)
    assert result.returncode == 1
    assert all(".git" not in row["path"] for row in model["copies"])


def test_bad_inputs_are_execution_errors(tmp_path):
    make_tree(tmp_path)
    missing_canonical = run("--canonical", str(tmp_path / "nope.py"),
                            "--root", str(tmp_path), "--json")
    assert missing_canonical.returncode == 2
    missing_root = run("--canonical",
                       str(tmp_path / "repo" / "scripts" / "rust_audit.py"),
                       "--root", str(tmp_path / "nope"), "--json")
    assert missing_root.returncode == 2
    blank = tmp_path / "blank.py"
    blank.write_text("print('no version here')\n")
    unversioned = run("--canonical", str(blank), "--root", str(tmp_path), "--json")
    assert unversioned.returncode == 2
