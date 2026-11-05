"""Guard against publishing private key material.

The release signs a public checksum manifest with a key that lives outside
this repository. A private key pasted into a tracked file would end up in the
next push, so the suite fails before that can happen. The pattern is assembled
from parts to keep this test from matching itself.
"""
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
BEGIN = "-----BEGIN "
KEY = "PRIVATE KEY"
PATTERN = "|".join((
    BEGIN + r"([A-Z0-9 ]+ )?" + KEY + "-----",
    "BEGIN PGP " + KEY + " BLOCK",
    "PuTTY" + "-User-Key-File",
    "BEGIN AGE " + "SECRET KEY",
))


def test_no_private_key_material_in_tracked_files():
    if not (ROOT / ".git").exists():
        pytest.skip("not a git checkout")
    result = subprocess.run(
        ["git", "grep", "-I", "-l", "-E", "-e", PATTERN, "--", "."],
        cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 1, (
        "private key material found in tracked files:\n"
        f"{result.stdout}{result.stderr}")
