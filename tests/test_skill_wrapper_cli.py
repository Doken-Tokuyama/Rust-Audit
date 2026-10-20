"""Pin the skill wrapper to the tool's real CLI and to every live copy.

Every flag the wrapper documents must exist in `rust_audit.py`'s live `--help`
surface, and the wrapper's one universal claim ("--no-exec, accepted by every
subcommand") must hold per subcommand. When argparse moves and the wrapper
does not, installs break silently — this fails instead. The installed copy is
checked too when present on the machine.

The served instructions are guarded by scripts/check_skill_sync.py (run here
through its public --json interface): the repo copy, the machine-global
install and the live Freebuff account snapshot must all carry the same
instructions, allowing only the trailing newline the sync strips.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
TOOL = REPO / "scripts" / "rust_audit.py"
REPO_WRAPPER = REPO / "skills" / "rust-audit" / "SKILL.md"
INSTALLED_WRAPPER = Path.home() / ".agents" / "skills" / "rust-audit" / "SKILL.md"


def _help(*args):
    r = subprocess.run([sys.executable, str(TOOL), *args, "--help"],
                       capture_output=True, text=True)
    assert r.returncode == 0, f"{args or ('<top>',)} --help failed: {r.stderr}"
    return r.stdout


def cli_surface():
    """(subcommands, flags) of the real CLI, read from live --help output."""
    top = _help()
    usage = next(line for line in top.splitlines() if line.startswith("usage:"))
    subs = set(re.search(r"\{([^}]*)\}", usage).group(1).split(","))
    per_sub = {sub: _help(sub) for sub in sorted(subs)}
    flags = set(re.findall(r"--[a-z][a-z0-9-]*", top + "\n".join(per_sub.values())))
    return subs, flags, per_sub


def documented_flags(text):
    """Flag tokens the wrapper mentions (verify_release.sh lines excluded:
    those flags belong to the shell tool, not rust_audit.py)."""
    return {
        token
        for line in text.splitlines()
        if "verify_release" not in line
        for token in re.findall(r"--[a-z][a-z0-9-]*", line)
    }


def test_wrapper_flags_exist_in_the_cli():
    _, flags, _ = cli_surface()
    wrappers = [REPO_WRAPPER]
    if INSTALLED_WRAPPER.exists():
        wrappers.append(INSTALLED_WRAPPER)
    for wrapper in wrappers:
        unknown = documented_flags(wrapper.read_text()) - flags
        assert not unknown, (
            f"{wrapper} documents flags the CLI lacks: {sorted(unknown)}")


def test_no_exec_claim_holds_for_every_subcommand():
    subs, _, per_sub = cli_surface()
    assert subs, "no subcommands discovered in --help output"
    missing = sorted(sub for sub, help_text in per_sub.items()
                     if "--no-exec" not in help_text)
    assert not missing, (
        f"wrapper says --no-exec is accepted by every subcommand; missing on: {missing}")


# Every LIVE copy of a skill must serve this repository's instructions: the
# machine-global install and the Freebuff account snapshot named sha256(
# current.json) (older snapshots are rollback archives, not served).
#
# The drift rule has ONE implementation, scripts/check_skill_sync.py, with
# fixtures (including the negative, stale-copy case) in
# tests/test_check_skill_sync.py. It allows exactly one byte class: the
# trailing newline the sync strips when it embeds and when it materializes a
# copy (observed 2026-10-19 and again 2026-10-20 00:55; see
# docs/freebuff-account-skills-sync.md). A second definition here used to call
# that normalization drift — a provably false positive, since the served
# instructions were identical (docs/adr/0001).

SKILLS = ("rust-audit", "rust-audit-family")
ACCOUNT_SKILLS = Path.home() / ".config" / "freebuff-desktop" / "account-skills"
INSTALL_DIR = Path.home() / ".agents" / "skills"
CHECK_SYNC = REPO / "scripts" / "check_skill_sync.py"


def sync_model():
    """(exit code, model) from the diagnostic's public --json interface."""
    if not ACCOUNT_SKILLS.exists():
        pytest.skip("no Freebuff account registry on this machine")
    result = subprocess.run([sys.executable, str(CHECK_SYNC), "--json"],
                            capture_output=True, text=True, timeout=120)
    assert result.returncode in (0, 1), (
        f"check_skill_sync.py execution error (exit {result.returncode}): "
        f"{result.stderr}")
    return result.returncode, json.loads(result.stdout)


def test_live_copies_serve_the_repo_instructions():
    code, model = sync_model()
    assert not model["findings"], (
        "a live skill copy does not serve skills/<name>/SKILL.md (only the "
        "sync-stripped trailing newline is allowed; see "
        "docs/freebuff-account-skills-sync.md):\n"
        + "\n".join(f"  {f['kind']} {f.get('skill', '')}: {f['detail']}"
                    for f in model["findings"]))
    assert code == 0, model["verdict"]
    # Non-vacuous: the wrappers were actually compared with the live surfaces.
    rows = [row for acc in model["accounts"] for row in acc["skills"]]
    for name in SKILLS:
        live = [r for r in rows
                if r["name"] == name and r.get("live_vs_repo", {}).get(
                    "state") in ("identical", "newline-only")]
        assert live, f"{name} was never compared with the live snapshot: " \
                     f"{[r for r in rows if r['name'] == name]}"
    if INSTALL_DIR.is_dir():
        compared = {row["name"] for row in model["install"]}
        missing = sorted(set(SKILLS) - compared)
        assert not missing, f"{missing} not compared in {INSTALL_DIR}"
