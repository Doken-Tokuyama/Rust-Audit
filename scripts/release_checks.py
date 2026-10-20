#!/usr/bin/env python3
"""The two waits a release must not skip: CI green, and PyPI serving the wheel.

`scripts/release.sh` no longer declares a release on its own say-so. Two
external facts decide it, and this module is the one place that asks for them:

  ci    a completed, successful `tests` run exists for the exact commit the
        tag points at (`gh run list --commit <sha>`). The workflow stopped
        triggering on `v*` tags because a cut pushes one commit to `main` and
        tags it, so the tag ran the identical suite a second time (v0.2.6,
        2026-10-20). The release waits on the run for that SHA instead — same
        bytes, and a stricter contract: red suite = no tag, no upload.
  pypi  https://pypi.org/simple/rust-audit/ lists
        `rust_audit-<version>-py3-none-any.whl`, the file downloads with the
        digest the index records for it, and the `rust_audit.py` inside is
        byte-identical to the signed file. The JSON API listing a version is
        not the same fact: pip resolves from the simple index, and on
        2026-10-20 `pip install rust-audit==0.2.6` answered "No matching
        distribution found" for about a minute while
        `https://pypi.org/pypi/rust-audit/0.2.6/json` already returned 200.

Both subcommands poll until a deadline and exit 1 with what was observed,
instead of printing a verdict the outside world cannot confirm yet. Neither
installs anything: `ci` shells out to `gh`, `pypi` reads the index and the
wheel over HTTPS with urllib.

Usage:
  python3 scripts/release_checks.py ci --sha <40-hex commit> [--repo OWNER/REPO]
      [--timeout 1800] [--interval 15]
  python3 scripts/release_checks.py pypi --version X.Y.Z --module scripts/rust_audit.py
      [--index https://pypi.org/simple] [--timeout 600] [--interval 10]

Exit: 0 confirmed · 1 not confirmed in time, or the evidence contradicts the
      release (a red run, a wheel whose bytes are not the audited ones) ·
      2 environment/usage error (no `gh`, unreadable module, bad arguments).
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, urlopen

REPO = "Doken-Tokuyama/Rust-Audit"
DISTRIBUTION = "rust-audit"
INDEX = "https://pypi.org/simple"
WORKFLOW = "tests.yml"
USER_AGENT = "rust-audit-release-gate"
# Conclusions that end the wait with a failure instead of a retry: the run is
# over and it did not pass, so another poll cannot change the answer.
FAILED = {"failure", "cancelled", "timed_out", "startup_failure",
          "action_required", "stale"}
WHEEL = re.compile(r"^rust_audit-(?P<version>.+)-py3-none-any\.whl$")


def say(message: str) -> None:
    print(message, flush=True)


def fail(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------- CI ---

def tests_runs(repo: str, commit: str) -> list[dict]:
    """Every `tests` run GitHub reports for one commit, or raise RuntimeError.

    `gh run list --commit` only matches the full 40-hex SHA (a short one
    silently answers `[]`), which is why the caller resolves it with
    `git rev-parse TAG^{commit}` rather than trimming it for display.
    """
    try:
        completed = subprocess.run(
            ["gh", "run", "list", "-R", repo, "-c", commit, "-w", WORKFLOW,
             "-L", "20", "--json",
             "headSha,status,conclusion,url,event,headBranch"],
            capture_output=True, text=True)
    except FileNotFoundError:
        raise RuntimeError("gh is not installed: the CI gate cannot be checked")
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip() or "no output"
        raise RuntimeError(
            f"gh run list failed (exit {completed.returncode}): {detail}")
    try:
        return json.loads(completed.stdout or "[]")
    except ValueError as exc:
        raise RuntimeError(f"gh run list printed no JSON: {exc}")


def check_ci(repo: str, commit: str, timeout: float, interval: float) -> int:
    deadline = time.monotonic() + timeout
    seen = "no run for this commit"
    while True:
        try:
            runs = [run for run in tests_runs(repo, commit)
                    if run.get("headSha") == commit]
        except RuntimeError as exc:
            fail(f"ERROR ci: {exc}")
            return 2
        green = [run for run in runs if run.get("conclusion") == "success"]
        if green:
            say(f"PASS  ci: {WORKFLOW} succeeded on {commit[:12]} "
                f"({green[0].get('url', '')})")
            return 0
        broken = [run for run in runs if run.get("status") == "completed"
                  and run.get("conclusion") in FAILED]
        if broken:
            run = broken[0]
            say(f"FAIL  ci: {WORKFLOW} ended {run.get('conclusion')} on "
                f"{commit[:12]} ({run.get('url', '')})")
            return 1
        if runs:
            seen = ", ".join(sorted({f"{run.get('status')}/{run.get('conclusion')}"
                                     for run in runs}))
        if time.monotonic() >= deadline:
            say(f"FAIL  ci: no completed successful {WORKFLOW} run for "
                f"{commit[:12]} within {timeout:g}s (saw: {seen})")
            return 1
        time.sleep(interval)


# ------------------------------------------------------------------- PyPI ---

def fetch(url: str, timeout: float = 30.0) -> bytes | None:
    """The URL's bytes, or None while it is not served (404, network, timeout).

    "Not served yet" is the normal state during the minute after an upload, so
    it is a retry and not an error; a transport failure that never clears ends
    the wait with the last reason printed.
    """
    request = Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(request, timeout=timeout) as response:
            return response.read()
    except (HTTPError, URLError, TimeoutError, OSError):
        return None


def index_page(index: str) -> tuple[str, bytes | None]:
    url = f"{index.rstrip('/')}/{DISTRIBUTION}/"
    return url, fetch(url)


def wheel_link(page: bytes, page_url: str, version: str) -> str | None:
    """The absolute URL of this version's wheel in a PEP 503 index page."""
    text = page.decode("utf-8", "replace")
    for href in re.findall(r'href="([^"]+)"', text):
        absolute = urljoin(page_url, href)
        name = urlsplit(absolute).path.rsplit("/", 1)[-1]
        match = WHEEL.match(name)
        if match and match.group("version") == version:
            return absolute
    return None


def wheel_member(data: bytes, name: str) -> bytes | None:
    """One file out of the wheel, or None when the wheel does not carry it."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as wheel:
            for member in wheel.namelist():
                if member == name:
                    return wheel.read(member)
    except (zipfile.BadZipFile, OSError):
        return None
    return None


def check_pypi(version: str, module: Path, index: str, timeout: float,
               interval: float) -> int:
    audited = module.read_bytes()
    audited_digest = sha256(audited)
    deadline = time.monotonic() + timeout
    reason = "the index was never served"
    while True:
        page_url, page = index_page(index)
        if page is not None:
            link = wheel_link(page, page_url, version)
            if link is None:
                reason = (f"{page_url} lists no "
                          f"rust_audit-{version}-py3-none-any.whl yet")
            else:
                data = fetch(link)
                if data is None:
                    reason = f"the wheel is listed but {link} is not downloadable yet"
                else:
                    recorded = urlsplit(link).fragment
                    digest = sha256(data)
                    if recorded.startswith("sha256=") and recorded[7:] != digest:
                        say(f"FAIL  pypi: {link} hashes to {digest} but the "
                            f"index records {recorded[7:]}")
                        return 1
                    inside = wheel_member(data, "rust_audit.py")
                    if inside is None:
                        say(f"FAIL  pypi: {link} does not carry rust_audit.py")
                        return 1
                    if sha256(inside) != audited_digest:
                        say(f"FAIL  pypi: {link} carries rust_audit.py "
                            f"{sha256(inside)[:12]}…, not the audited "
                            f"{audited_digest[:12]}… in {module}")
                        return 1
                    say(f"PASS  pypi: {link}")
                    say(f"PASS  pypi: the wheel's rust_audit.py is "
                        f"{audited_digest[:12]}… identical to {module}")
                    return 0
        if time.monotonic() >= deadline:
            say(f"FAIL  pypi: {DISTRIBUTION} {version} is not installable from "
                f"{index} within {timeout:g}s ({reason})")
            return 1
        time.sleep(interval)


# -------------------------------------------------------------------- CLI ---

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="release_checks.py",
        description="The external confirmations scripts/release.sh waits for: "
                    "a green CI run on the cut commit, and PyPI serving a "
                    "wheel that carries the audited bytes.")
    sub = parser.add_subparsers(dest="check", required=True)
    ci = sub.add_parser("ci", help="wait for a successful `tests` run on a commit")
    ci.add_argument("--sha", required=True,
                    help="full 40-hex commit SHA (a short SHA matches nothing)")
    ci.add_argument("--repo", default=REPO)
    ci.add_argument("--timeout", type=float, default=1800.0,
                    help="seconds to wait (default 1800: the job's own timeout)")
    ci.add_argument("--interval", type=float, default=15.0)
    pypi = sub.add_parser("pypi", help="wait for the wheel to be served by the index")
    pypi.add_argument("--version", required=True)
    pypi.add_argument("--module", required=True, type=Path,
                      help="the signed rust_audit.py the wheel must match")
    pypi.add_argument("--index", default=INDEX,
                      help="PEP 503 simple index (default: PyPI)")
    pypi.add_argument("--timeout", type=float, default=600.0)
    pypi.add_argument("--interval", type=float, default=10.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.check == "ci":
        if not re.fullmatch(r"[0-9a-f]{40}", args.sha):
            fail(f"ERROR ci: --sha must be the full 40-hex commit, got {args.sha!r}")
            return 2
        return check_ci(args.repo, args.sha, args.timeout, args.interval)
    if not re.fullmatch(r"[0-9]+(\.[0-9]+)+([.+-][0-9A-Za-z.-]+)?", args.version):
        fail(f"ERROR pypi: --version does not look like a version: {args.version!r}")
        return 2
    if not args.module.is_file():
        fail(f"ERROR pypi: no such module file: {args.module}")
        return 2
    return check_pypi(args.version, args.module, args.index, args.timeout, args.interval)


if __name__ == "__main__":
    sys.exit(main())
