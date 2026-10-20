"""The CI that runs this suite must exist, keep running it, and stay pinned.

A workflow is the only thing that runs the suite without a human remembering
to, so three failure modes get a test of their own: the job disappearing or
being narrowed to a manual trigger, the job being allowed to pass on failure
(`|| true`, `continue-on-error`, a non-failing pytest invocation), and an
action reference left on a moving tag — which turns "green on this commit"
into "green on whatever upstream shipped this morning".

The last test ties the matrix to the floor `pyproject.toml` declares, so a
version bump cannot leave CI testing a Python the package no longer claims.
"""
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO / ".github" / "workflows"
SUITE = WORKFLOWS / "tests.yml"
PYPROJECT = REPO / "pyproject.toml"
USE = re.compile(r"^\s*(?:-\s+)?uses:\s*(\S+)(?:\s+#\s*(\S.*))?$")
SHA = re.compile(r"[0-9a-f]{40}")


def workflows():
    return sorted(WORKFLOWS.glob("*.yml"))


def behaviour(path):
    """The workflow's lines, minus whole-line comments: a comment runs nothing."""
    return "\n".join(line for line in path.read_text(encoding="utf-8").splitlines()
                     if not line.lstrip().startswith("#"))


def test_the_suite_runs_on_push_and_on_pull_requests():
    text = SUITE.read_text(encoding="utf-8")
    assert "python -m pytest" in text, "the CI job does not run the suite"
    assert re.search(r"^on:$", text, re.M), "tests.yml has no trigger block"
    assert "branches: [main]" in text, "pushes to main must run the suite"
    assert "pull_request:" in text, "pull requests must run the suite"
    assert "workflow_dispatch:" in text, "a maintainer must be able to run it"


def test_no_workflow_can_pass_a_failing_suite():
    for path in workflows():
        text = behaviour(path)
        assert "continue-on-error" not in text, f"{path.name} ignores failures"
        assert "|| true" not in text, f"{path.name} swallows an exit status"
        assert "--continue-on-collection-errors" not in text, (
            f"{path.name} would hide a collection error")


def test_every_action_is_pinned_to_a_commit():
    """A tag or branch can move; a 40-hex commit cannot."""
    for path in workflows():
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = USE.match(line)
            if match is None:
                continue
            ref, comment = match.group(1), match.group(2)
            where = f"{path.name}:{number}"
            assert "@" in ref, f"{where} has no version: {ref}"
            sha = ref.rsplit("@", 1)[1]
            assert SHA.fullmatch(sha), f"{where} {ref} is not pinned to a commit"
            assert comment and re.match(r"(v\d|release/)", comment), (
                f"{where} {ref} carries no readable version comment")


def test_the_suite_also_runs_on_release_tags():
    """A tag is what gets signed and published; the suite must cover it."""
    text = SUITE.read_text(encoding="utf-8")
    assert re.search(r'^\s+tags:\s*\["v\*"\]', text, re.M), (
        "release tags do not run the suite: the signed bytes would be untested")


def test_each_action_is_pinned_to_one_commit_everywhere():
    """Two majors of the same action is drift nobody decided; one is policy."""
    found = {}
    for path in workflows():
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = USE.match(line)
            if match is None:
                continue
            action, _, sha = match.group(1).partition("@")
            found.setdefault(action, []).append(
                (sha, (match.group(2) or "").strip(), f"{path.name}:{number}"))
    for action, uses in found.items():
        commits = {sha for sha, _, _ in uses}
        assert len(commits) == 1, (
            f"{action} is pinned to {len(commits)} commits: {uses}")
        versions = {version for _, version, _ in uses}
        assert len(versions) == 1, (
            f"{action} is described with {len(versions)} versions: {uses}")


def test_the_published_artifact_is_built_installed_and_audited():
    """AGENTS.md §6b: the wheel is a path of its own, so CI must walk it.

    The job is not a second copy of the goldens: it runs the same engine and
    the installed one over the same pinned workspace and requires the two to
    agree, so a wheel that lost a data file, shipped other bytes or was never
    installed (both scans naming the checkout) fails here.
    """
    _, sep, wheel = SUITE.read_text(encoding="utf-8").partition("\n  wheel:")
    assert sep, "tests.yml has no job that checks the published wheel"
    required = {
        "python -m build": "the distribution is never built",
        "--no-index --find-links dist":
            "the install is allowed to fetch something else",
        "share/rustaudit/":
            "the job never checks where the wheel put its data files",
        "selftest": "the installed command's selftest never runs",
        "report/installed": "the installed engine never scans",
        "report/checkout": "there is nothing to compare against",
        "check_wheel_parity.py": "the two engines are never compared",
        "needs: pytest":
            "the wheel job inherits the goldens from the pytest job; without "
            "`needs` a red suite no longer stops it",
    }
    missing = [why for needle, why in required.items() if needle not in wheel]
    assert not missing, " / ".join(missing)


def test_the_matrix_covers_the_declared_python_floor():
    floor = re.search(r'^requires-python\s*=\s*">=([0-9.]+)"',
                      PYPROJECT.read_text(encoding="utf-8"), re.M).group(1)
    assert f'"{floor}"' in SUITE.read_text(encoding="utf-8"), (
        f"pyproject.toml requires >= {floor} and CI never runs it")
