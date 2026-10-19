"""The pre-3.11 interpreter contract: one clear error line, exit code 2.

The tool's startup guard (the ``import tomllib`` fallback in
scripts/rust_audit.py) must turn a pre-3.11 interpreter into one clear ERROR
line and exit code 2 — never a raw ModuleNotFoundError traceback.

This runs the real CLI under a genuine pre-3.11 interpreter when one is
installed (macOS ships /usr/bin/python3 at 3.9); on a machine with only
3.11+ it reproduces the exact missing-stdlib condition by shadowing
``tomllib`` on PYTHONPATH (the interpreter then raises ModuleNotFoundError on
``import tomllib`` exactly like CPython < 3.11 does), so the same guard code
path is exercised. Which mode ran is asserted in the output — never a silent
skip. RA_LEGACY_PYTHON pins a specific interpreter.
"""
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TOOL = REPO / "scripts" / "rust_audit.py"


def _version(exe):
    r = subprocess.run([str(exe), "-c",
                        "import sys; print('%d.%d.%d' % sys.version_info[:3])"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return None
    return tuple(int(n) for n in r.stdout.split("."))


def _legacy_interpreter():
    """(path, version) of a real pre-3.11 interpreter on this machine."""
    candidates = []
    if os.environ.get("RA_LEGACY_PYTHON"):
        candidates.append(Path(os.environ["RA_LEGACY_PYTHON"]))
    for name in ("python3.9", "python3.10", "python3.8"):
        found = shutil.which(name)
        if found:
            candidates.append(Path(found))
    candidates.append(Path("/usr/bin/python3"))
    for cand in candidates:
        if cand.exists():
            v = _version(cand)
            if v and v < (3, 11):
                return cand, v
    return None


def _run_guarded(tmp_path):
    """Run `rust_audit.py selftest` as a pre-3.11 interpreter would see it."""
    found = _legacy_interpreter()
    if found:
        exe, version = found
        r = subprocess.run([str(exe), str(TOOL), "selftest"],
                           capture_output=True, text=True)
        return r, f"real pre-3.11 interpreter {exe} ({version[0]}.{version[1]}.{version[2]})", version
    # Simulate the missing stdlib module: PYTHONPATH precedes the stdlib, so
    # this tomllib is what `import tomllib` finds — and it raises exactly the
    # ModuleNotFoundError CPython < 3.11 raises.
    assert _version(sys.executable) >= (3, 11), (
        "the simulation is only valid on a 3.11+ interpreter")
    shadow = tmp_path / "shadow"
    shadow.mkdir()
    (shadow / "tomllib.py").write_text(
        'raise ModuleNotFoundError("No module named \'tomllib\'")\n')
    r = subprocess.run([sys.executable, str(TOOL), "selftest"],
                       capture_output=True, text=True,
                       env={**os.environ, "PYTHONPATH": str(shadow)})
    return r, f"simulated missing tomllib under {sys.executable}", None


def test_pre311_interpreter_fails_fast_with_clear_error_and_exit_2(tmp_path):
    r, mode, _ = _run_guarded(tmp_path)
    assert r.returncode == 2, f"{mode}: expected exit 2, got {r.returncode}"
    assert r.stdout == "", f"{mode}: expected no stdout, got {r.stdout!r}"
    lines = r.stderr.splitlines()
    assert len(lines) == 1, (
        f"{mode}: expected exactly one clear error line, got {r.stderr!r}")
    assert lines[0].startswith("ERROR Rust Audit needs Python 3.11+"), mode
    assert "Re-run with python3.13, python3.12 or python3.11" in lines[0], mode
    assert re.search(r"this interpreter is \d+\.\d+\.\d+", lines[0]), mode


def test_guard_names_the_running_interpreter(tmp_path):
    r, mode, version = _run_guarded(tmp_path)
    assert r.returncode == 2, mode
    named = re.search(r"this interpreter is (\d+\.\d+\.\d+)", r.stderr)
    assert named, mode
    running = ("%d.%d.%d" % version if version else sys.version.split()[0])
    assert named.group(1) == running, f"{mode}: guard said {named.group(1)}"
