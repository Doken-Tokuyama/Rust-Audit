"""Pin the skill wrapper to the tool's real CLI.

Every flag the wrapper documents must exist in `rust_audit.py`'s live `--help`
surface, and the wrapper's one universal claim ("--no-exec, accepted by every
subcommand") must hold per subcommand. When argparse moves and the wrapper
does not, installs break silently — this fails instead. The installed copy is
checked too when present on the machine.
"""
import re
import subprocess
import sys
from pathlib import Path

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


# Byte identity across every LIVE copy of each skill wrapper: the repo
# (canonical), the machine-global install and the newest Freebuff account
# (Cloud-synced) snapshot per account. One drifted byte — including the
# trailing newline a sync once stripped — must fail here instead of
# silently serving stale instructions. Older snapshot dirs are rollback
# archives of previous syncs and are not served, so they are not compared.

SKILLS = ("rust-audit", "rust-audit-family")
ACCOUNT_SKILLS = Path.home() / ".config" / "freebuff-desktop" / "account-skills"


def skill_copies():
    for name in SKILLS:
        canonical = REPO / "skills" / name / "SKILL.md"
        others = [Path.home() / ".agents" / "skills" / name / "SKILL.md"]
        if ACCOUNT_SKILLS.exists():
            newest = {}   # account dir -> (snapshot mtime, SKILL.md path)
            for m in sorted(ACCOUNT_SKILLS.glob(f"**/{name}/SKILL.md")):
                account, snapshot = m.parent.parent.parent, m.parent.parent
                mtime = snapshot.stat().st_mtime
                if account not in newest or mtime > newest[account][0]:
                    newest[account] = (mtime, m)
            others += [m for _, m in newest.values()]
        yield name, canonical, [p for p in others if p.exists()]


def test_skill_copies_are_byte_identical():
    for name, canonical, others in skill_copies():
        expected = canonical.read_bytes()
        for copy in others:
            assert copy.read_bytes() == expected, (
                f"{copy} drifted from {canonical} — skill copies must be "
                f"byte-identical (including the trailing newline); restore "
                f"it from skills/{name}/")
