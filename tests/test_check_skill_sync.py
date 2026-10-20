"""Contract of scripts/check_skill_sync.py — the sync model's only decoder.

Fixtures build the directory layout docs/freebuff-account-skills-sync.md
describes: `current.json` (the registry, with instructions embedded), a
snapshot directory named sha256(current.json), an older snapshot as rollback
archive, and the imported.json backup trail. Each test drives the command
through its public CLI and asserts the printed classification and the exit
code (0 consistent · 1 findings · 2 execution error), including the negative
cases that make a clean verdict meaningful: stale copies, an unmaterialized
registry, orphan trees and a disappearing declared file all exit 1.
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
TOOL = REPO / "scripts" / "check_skill_sync.py"
ENGINE = REPO / "scripts" / "rust_audit.py"
ACCOUNT = "a" * 64
SKILL = b"---\nname: demo\n---\n\nBody of the skill.\n"
FAMILY = b"---\nname: other\n---\n\nOther body.\n"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run(root, *extra):
    return subprocess.run([sys.executable, str(TOOL), str(root), "--json",
                           *extra], capture_output=True, text=True,
                          timeout=120)


def terminal(root, *extra):
    """The rendered model, for the output contract."""
    return subprocess.run([sys.executable, str(TOOL), str(root), *extra],
                          capture_output=True, text=True, timeout=120)


def model(root, *extra):
    result = run(root, *extra)
    return result, json.loads(result.stdout)


def write_registry(account, skills, revision=2, imports=None, materialize=True,
                   strip_embed=True):
    """Build one account dir; `skills` maps name -> bytes of SKILL.md."""
    account.mkdir(parents=True, exist_ok=True)
    entries = [{"name": name,
                "description": f"{name} demo",
                "instructions": (body.decode().rstrip("\n") if strip_embed
                                 else body.decode()),
                "files": []} for name, body in skills.items()]
    raw = json.dumps({"revision": revision,
                      "settings": {"skills": entries}}).encode()
    (account / "current.json").write_bytes(raw)
    if materialize:
        live = account / sha(raw)
        # An earlier revision stays behind as a rollback archive.
        archive = account / ("b" * 64)
        for name, body in skills.items():
            (archive / name).mkdir(parents=True)
            (archive / name / "SKILL.md").write_bytes(body + b"older\n")
            (live / name).mkdir(parents=True)
            (live / name / "SKILL.md").write_bytes(body)
    if imports is not None:
        (account / "imported.json").write_text(json.dumps(imports["current"]))
        for name, names in imports["backups"].items():
            (account / name).write_text(json.dumps(names))
    return account


@pytest.fixture
def tree(tmp_path):
    return write_registry(tmp_path / "account-skills" / ACCOUNT,
                          {"demo": SKILL}, materialize=True)


def kinds(model_dict):
    return sorted({f["kind"] for f in model_dict["findings"]})


def test_consistent_tree_exits_zero(tree):
    root = tree.parent
    result, data = model(root)
    assert result.returncode == 0, result.stdout + result.stderr
    assert data["verdict"] == "consistent"
    assert data["findings"] == []
    assert data["accounts"][0]["live"]["materialized"] is True
    assert data["accounts"][0]["archives"][0]["name"] == "b" * 64


def test_stripped_newline_is_normalization_not_drift(tmp_path):
    """Both observed shapes are one byte class: the sync strips the trailing
    newline of the embed, of the materialized copy, or of both at once."""
    account = write_registry(tmp_path / "account-skills" / ACCOUNT,
                             {"demo": SKILL}, strip_embed=False)
    live = account / sha((account / "current.json").read_bytes())
    (live / "demo" / "SKILL.md").write_bytes(SKILL.rstrip(b"\n"))
    result, data = model(tmp_path / "account-skills")
    assert result.returncode == 0, result.stdout + result.stderr
    assert data["accounts"][0]["skills"][0]["embed_vs_live"]["state"] == \
        "newline-only"


def test_stale_copy_is_drift_and_names_the_skill(tmp_path):
    root = tmp_path / "account-skills"
    account = write_registry(root / ACCOUNT, {"demo": SKILL})
    live = account / sha((account / "current.json").read_bytes())
    (live / "demo" / "SKILL.md").write_bytes(b"---\nname: demo\n---\n\nSTALE.\n")
    result, data = model(root)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "embed-drift" in kinds(data)
    assert data["findings"][0]["skill"] == "demo"


def test_registry_without_materialized_snapshot_is_a_finding(tmp_path):
    root = tmp_path / "account-skills"
    account = write_registry(root / ACCOUNT, {"demo": SKILL}, materialize=False)
    result, data = model(root)
    assert result.returncode == 1
    assert "live-snapshot-missing" in kinds(data)
    assert not (account / sha((account / "current.json").read_bytes())).exists()


def test_orphan_tree_and_missing_registered_skill(tmp_path):
    root = tmp_path / "account-skills"
    account = write_registry(root / ACCOUNT, {"demo": SKILL, "gone": FAMILY})
    live = account / sha((account / "current.json").read_bytes())
    (live / "gone" / "SKILL.md").unlink()
    (live / "stray").mkdir()
    (live / "stray" / "SKILL.md").write_bytes(FAMILY)
    result, data = model(root)
    assert result.returncode == 1
    assert "missing-in-live" in kinds(data)
    assert "orphan-in-live" in kinds(data)


def test_declared_file_must_exist_and_match(tmp_path):
    root = tmp_path / "account-skills"
    account = write_registry(root / ACCOUNT, {"demo": SKILL})
    current = json.loads((account / "current.json").read_text())
    extra = {"path": "agents/openai.yaml", "contents": "name: demo\n"}
    current["settings"]["skills"][0]["files"] = [extra]
    raw = json.dumps(current).encode()
    (account / "current.json").write_bytes(raw)
    (account / sha(raw) / "demo").mkdir(parents=True)
    (account / sha(raw) / "demo" / "SKILL.md").write_bytes(SKILL)
    result, data = model(root)
    assert result.returncode == 1
    assert "missing-file" in kinds(data)
    (account / sha(raw) / "demo" / "agents").mkdir()
    (account / sha(raw) / "demo" / "agents" / "openai.yaml").write_text(
        "name: other\n")
    result, data = model(root)
    assert result.returncode == 1
    assert "file-drift" in kinds(data)
    (account / sha(raw) / "demo" / "agents" / "openai.yaml").write_text(
        "name: demo\n")
    result, data = model(root)
    assert result.returncode == 0, result.stdout + result.stderr


def test_imported_trail_reports_added_and_removed(tmp_path):
    root = tmp_path / "account-skills"
    write_registry(root / ACCOUNT, {"demo": SKILL}, imports={
        "current": ["demo", "added-later"],
        "backups": {"imported.json.pre-sync-2026-10-19.bak":
                    ["demo", "dropped-later"],
                    "imported.json.pre-verify-2026-10-19.bak":
                    ["demo", "added-later"]},
    })
    result, data = model(root)
    assert result.returncode == 0, result.stdout + result.stderr
    trail = {b["kind"]: b for b in data["accounts"][0]["imports"]["backups"]}
    assert trail["pre-sync"]["added"] == ["added-later"]
    assert trail["pre-sync"]["removed"] == ["dropped-later"]
    assert trail["pre-verify"]["added"] == []
    assert trail["pre-verify"]["removed"] == []


def test_repo_cross_check_flags_a_stale_canonical(tmp_path):
    root = tmp_path / "account-skills"
    account = write_registry(root / ACCOUNT, {"demo": SKILL})
    live = account / sha((account / "current.json").read_bytes())
    repo = tmp_path / "repo"
    (repo / "demo").mkdir(parents=True)
    (repo / "demo" / "SKILL.md").write_bytes(SKILL)
    result, data = model(root, "--repo", str(repo))
    assert result.returncode == 0, result.stdout + result.stderr
    assert data["accounts"][0]["skills"][0]["live_vs_repo"]["state"] == \
        "identical"
    (repo / "demo" / "SKILL.md").write_bytes(b"---\nname: demo\n---\n\nNEWER.\n")
    result, data = model(root, "--repo", str(repo))
    assert result.returncode == 1
    assert {"live-vs-repo-drift", "embed-vs-repo-drift"} <= set(kinds(data))
    assert (live / "demo" / "SKILL.md").read_bytes() == SKILL   # untouched


def test_terminal_output_renders_the_model_without_json(tmp_path):
    root = tmp_path / "account-skills"
    write_registry(root / ACCOUNT, {"demo": SKILL})
    result = terminal(root)
    assert result.returncode == 0, result.stderr
    text = result.stdout
    assert "revision 2" in text
    assert "live snapshot" in text and "name == sha256(current.json)" in text
    assert "rollback snapshot" in text
    assert "VERDICT consistent" in text
    assert "engines — canonical" in text and "none found" in text


def test_bad_json_and_missing_root_are_execution_errors(tmp_path):
    missing = subprocess.run([sys.executable, str(TOOL), str(tmp_path / "nope")],
                             capture_output=True, text=True, timeout=120)
    assert missing.returncode == 2
    assert "no account-skills directory" in missing.stderr
    root = tmp_path / "account-skills"
    (root / ACCOUNT).mkdir(parents=True)
    (root / ACCOUNT / "current.json").write_text("{not json")
    broken = run(root)
    assert broken.returncode == 2
    assert "not valid JSON" in broken.stderr
    assert broken.stdout == ""            # an error never renders a verdict


def test_empty_root_is_an_execution_error(tmp_path):
    root = tmp_path / "account-skills"
    root.mkdir()
    result = run(root)
    assert result.returncode == 2
    assert "no account registry" in result.stderr


@pytest.mark.skipif(not (Path.home() / ".config" / "freebuff-desktop" /
                         "account-skills").exists(),
                    reason="no Freebuff account registry on this machine")
def test_this_machine_is_consistent():
    """The live model on the machine running the suite must be consistent."""
    result, data = model(Path.home() / ".config" / "freebuff-desktop" /
                         "account-skills")
    assert result.returncode == 0, json.dumps(data["findings"], indent=2)
    assert data["accounts"], "no account inspected"


# --------------------------------------------------------------- engine copies
# The skills half and the engine half are one verdict: instructions that name
# a rule are useless next to an engine that predates it. These fixtures plant
# copies of the auditor inside the scanned tree, so the machine's own copies
# (Cursor's store, an installed wheel) can never decide the result.

def plant_engine(root, *parts, engine=None):
    """A copy of the auditor at <root>/<parts>/scripts/rust_audit.py."""
    scripts = root.joinpath(*parts, "scripts")
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "rust_audit.py").write_bytes(
        engine if engine is not None else ENGINE.read_bytes())
    return scripts.parent


def test_engine_copy_under_the_root_is_reported_current(tmp_path):
    root = tmp_path / "account-skills"
    write_registry(root / ACCOUNT, {"demo": SKILL})
    plant_engine(root, "bare")          # no SKILL.md: engine bytes only
    result, data = model(root)
    assert result.returncode == 0, result.stdout + result.stderr
    assert data["engines"]["canonical"]["path"] == str(ENGINE.resolve())
    assert [c["status"] for c in data["engines"]["copies"]] == ["current"]
    text = terminal(root)
    assert text.returncode == 0, text.stderr
    assert "engines — canonical" in text.stdout
    assert "current" in text.stdout


def test_stale_engine_is_a_finding_and_names_the_version(tmp_path):
    root = tmp_path / "account-skills"
    write_registry(root / ACCOUNT, {"demo": SKILL})
    plant_engine(root, "bare", engine=b'VERSION = "0.0.1"\n')
    result, data = model(root)
    assert result.returncode == 1, result.stdout + result.stderr
    assert kinds(data) == ["engine-stale"]
    assert "0.0.1" in data["findings"][0]["detail"]
    assert data["engines"]["copies"][0]["version"] == "0.0.1"


def test_engine_without_current_instructions_is_a_finding(tmp_path):
    """A current engine next to stale prose is still not up to date."""
    root = tmp_path / "account-skills"
    write_registry(root / ACCOUNT, {"demo": SKILL})
    tree = plant_engine(root, "skill", "rust-audit")
    (tree / "SKILL.md").write_bytes(SKILL)
    result, data = model(root)
    assert result.returncode == 1, result.stdout + result.stderr
    assert data["engines"]["copies"][0]["status"] == "current"
    assert "engine-docs" in kinds(data)
    assert "README.md (missing)" in data["engines"]["copies"][0]["docs"]


def test_engines_can_be_left_out(tmp_path):
    root = tmp_path / "account-skills"
    write_registry(root / ACCOUNT, {"demo": SKILL})
    plant_engine(root, "bare", engine=b'VERSION = "0.0.1"\n')
    result, data = model(root, "--no-engines")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "engines" not in data
    assert data["findings"] == []


def test_extra_engine_root_is_scanned_and_must_exist(tmp_path):
    root = tmp_path / "account-skills"
    write_registry(root / ACCOUNT, {"demo": SKILL})
    elsewhere = tmp_path / "elsewhere"
    plant_engine(elsewhere, "bare")
    result, data = model(root, "--engine-root", str(elsewhere))
    assert result.returncode == 0, result.stdout + result.stderr
    assert [c["status"] for c in data["engines"]["copies"]] == ["current"]
    assert str(elsewhere) in data["engines"]["roots"]
    missing = run(root, "--engine-root", str(tmp_path / "nope"))
    assert missing.returncode == 2
    assert "no such directory" in missing.stderr

    assert data["accounts"][0]["live"]["materialized"] is True
