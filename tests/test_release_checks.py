"""The two release gates: green CI on the cut commit, and PyPI serving the wheel.

Both are the kind of check that passes for the wrong reason if it is never
driven to failure, so every test below makes the outside world answer badly on
purpose: an index that lists a wheel it cannot serve, a wheel that carries
other bytes, a wheel whose digest the index records differently, a run that
stays `queued` forever, a `gh` that is missing or returns an error. The success
paths run against a local index and a stub `gh`; the file ends with one live
call: the version this checkout declares must be installable from PyPI and
carry exactly these bytes, which is the state 0.2.6 left behind.
"""
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import threading
import time
import zipfile
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import urlopen

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "release_checks.py"
TOOL = REPO / "scripts" / "rust_audit.py"

VERSION = "0.2.6"
MODULE = b'VERSION = "0.2.6"\nprint("audited bytes")\n'
SHA = "d4d1324aa649a49df8051870d1063e19ebbf3adc"

GH_STUB = '''#!/usr/bin/env bash
echo "gh $*" >> "$RA_GH_LOG"
n=$(( $(cat "$RA_GH_COUNT" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$RA_GH_COUNT"
line=$(sed -n "${n}p" "$RA_RUNS")
[ -n "$line" ] || line=$(tail -1 "$RA_RUNS")
printf '%s\\n' "$line"
'''


class Quiet(SimpleHTTPRequestHandler):
    def log_message(self, *args):    # a test log is not a web server log
        pass


class Lagging(Quiet):
    """404 until `until`, then the real page: the minute after an upload."""
    until = 0.0

    def do_GET(self):
        if time.monotonic() < Lagging.until:
            self.send_error(404)
            return
        super().do_GET()


def run(*args, timeout=60):
    return subprocess.run([sys.executable, str(SCRIPT), *args],
                          capture_output=True, text=True, timeout=timeout)


def wheel(module=MODULE, name="rust_audit.py"):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(name, module)
        archive.writestr("rust_audit-0.2.6.dist-info/METADATA",
                         "Name: rust-audit\nVersion: 0.2.6\n")
    return buffer.getvalue()


def publish(root, body=None, *, digest=None, downloadable=True,
            version=VERSION, listed=True):
    """A PEP 503 page for `rust-audit` and the wheel it links to."""
    body = wheel() if body is None else body
    name = f"rust_audit-{version}-py3-none-any.whl"
    page = root / "simple" / "rust-audit"
    page.mkdir(parents=True, exist_ok=True)
    if not listed:
        (page / "index.html").write_text("<html><body></body></html>\n")
        return
    files = root / "files"
    files.mkdir(parents=True, exist_ok=True)
    if downloadable:
        (files / name).write_bytes(body)
    fragment = hashlib.sha256(body).hexdigest() if digest is None else digest
    (page / "index.html").write_text(
        f'<a href="../../files/{name}#sha256={fragment}">{name}</a>\n')


def serve(root, handler=Quiet):
    server = ThreadingHTTPServer(("127.0.0.1", 0),
                                 partial(handler, directory=str(root)))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}/simple"


@pytest.fixture()
def module(tmp_path):
    path = tmp_path / "rust_audit.py"
    path.write_bytes(MODULE)
    return path


@pytest.fixture()
def pypi(tmp_path):
    root = tmp_path / "www"
    publish(root)
    server, index_url = serve(root)
    yield root, index_url
    server.shutdown()


def check_pypi(module, index_url, version=VERSION, timeout="5", interval="0.1"):
    return run("pypi", "--version", version, "--module", str(module),
               "--index", index_url, "--timeout", timeout,
               "--interval", interval)


# ------------------------------------------------------------------- PyPI ---

def test_a_wheel_that_carries_the_audited_bytes_is_confirmed(pypi, module):
    _, index_url = pypi
    r = check_pypi(module, index_url)
    assert r.returncode == 0, r.stdout + r.stderr
    assert r.stdout.count("PASS  pypi:") == 2, r.stdout
    assert f"rust_audit-{VERSION}-py3-none-any.whl" in r.stdout
    assert "identical to" in r.stdout


def test_a_version_the_index_does_not_list_fails_after_the_timeout(pypi, module):
    _, index_url = pypi
    r = check_pypi(module, index_url, version="9.9.9", timeout="1", interval="0.2")
    assert r.returncode == 1
    assert "is not installable" in r.stdout
    assert "lists no rust_audit-9.9.9-py3-none-any.whl" in r.stdout


def test_a_listed_wheel_that_cannot_be_downloaded_is_retried_not_trusted(
        tmp_path, module):
    root = tmp_path / "www"
    publish(root, downloadable=False)          # listed, not yet on the CDN
    server, index_url = serve(root)
    try:
        r = check_pypi(module, index_url, timeout="1", interval="0.2")
    finally:
        server.shutdown()
    assert r.returncode == 1
    assert "listed but" in r.stdout and "not downloadable" in r.stdout


def test_a_wheel_whose_module_differs_fails(tmp_path, module):
    root = tmp_path / "www"
    publish(root, body=wheel(module=b'print("something else")\n'))
    server, index_url = serve(root)
    try:
        r = check_pypi(module, index_url, timeout="2", interval="0.1")
    finally:
        server.shutdown()
    assert r.returncode == 1
    assert "not the audited" in r.stdout


def test_a_wheel_that_does_not_match_the_index_digest_fails(tmp_path, module):
    root = tmp_path / "www"
    publish(root, digest="0" * 64)             # the index records other bytes
    server, index_url = serve(root)
    try:
        r = check_pypi(module, index_url, timeout="2", interval="0.1")
    finally:
        server.shutdown()
    assert r.returncode == 1
    assert "index records" in r.stdout


def test_a_wheel_without_the_module_is_not_accepted(tmp_path, module):
    root = tmp_path / "www"
    publish(root, body=wheel(name="other.py"))
    server, index_url = serve(root)
    try:
        r = check_pypi(module, index_url, timeout="2", interval="0.1")
    finally:
        server.shutdown()
    assert r.returncode == 1
    assert "does not carry rust_audit.py" in r.stdout


def test_an_index_that_lags_is_waited_for(tmp_path, module):
    """404 first, then the published page: the real post-upload lag."""
    root = tmp_path / "www"
    publish(root)
    Lagging.until = time.monotonic() + 0.8
    server, index_url = serve(root, Lagging)
    try:
        r = check_pypi(module, index_url, timeout="20", interval="0.2")
    finally:
        server.shutdown()
        Lagging.until = 0.0
    assert r.returncode == 0, r.stdout + r.stderr
    assert "PASS  pypi:" in r.stdout


def test_a_missing_module_file_is_a_usage_error(tmp_path, pypi):
    _, index_url = pypi
    r = run("pypi", "--version", VERSION, "--module", str(tmp_path / "nope.py"),
            "--index", index_url)
    assert r.returncode == 2
    assert "no such module file" in r.stderr


# --------------------------------------------------------------------- CI ---

@pytest.fixture()
def gh(tmp_path):
    """A stub `gh` that replays one JSON answer per call from a file."""
    binary = tmp_path / "bin"
    binary.mkdir()
    stub = binary / "gh"
    stub.write_text(GH_STUB)
    stub.chmod(0o755)
    runs, counter, log = (tmp_path / "runs.jsonl", tmp_path / "calls",
                          tmp_path / "gh.log")
    log.touch()

    def answer(*lines):
        runs.write_text("\n".join(lines) + "\n")

    def run_ci(*args):
        env = {**os.environ, "PATH": f"{binary}:{os.environ['PATH']}",
               "RA_RUNS": str(runs), "RA_GH_COUNT": str(counter),
               "RA_GH_LOG": str(log)}
        return subprocess.run([sys.executable, str(SCRIPT), "ci", *args],
                              capture_output=True, text=True, timeout=60, env=env)

    return answer, run_ci, log, binary, counter


def ci_run(conclusion, status="completed", url="https://example.invalid/run/1",
           sha=SHA):
    return json.dumps([{"headSha": sha, "status": status,
                        "conclusion": conclusion, "url": url}])


def test_a_green_run_on_the_cut_commit_passes(gh):
    answer, run_ci, log, _, counter = gh
    answer(ci_run("success"))
    r = run_ci("--sha", SHA, "--timeout", "5", "--interval", "0.1")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "PASS  ci: tests.yml succeeded" in r.stdout
    assert SHA[:12] in r.stdout
    assert "https://example.invalid/run/1" in r.stdout
    assert counter.read_text().strip() == "1"      # one call: no needless polling
    assert "-c " + SHA in log.read_text()          # the full SHA, not a prefix


def test_a_red_run_stops_the_wait_immediately(gh):
    answer, run_ci, _, _, counter = gh
    answer(ci_run("failure", url="https://example.invalid/run/2"))
    r = run_ci("--sha", SHA, "--timeout", "30", "--interval", "1")
    assert r.returncode == 1
    assert "ended failure" in r.stdout
    assert "https://example.invalid/run/2" in r.stdout
    assert counter.read_text().strip() == "1"


def test_a_run_still_in_progress_is_polled_until_it_passes(gh):
    answer, run_ci, _, _, counter = gh
    answer(ci_run(None, status="in_progress", url="https://example.invalid/run/3"),
           ci_run("success", url="https://example.invalid/run/3"))
    r = run_ci("--sha", SHA, "--timeout", "15", "--interval", "0.1")
    assert r.returncode == 0, r.stdout + r.stderr
    assert int(counter.read_text().strip()) >= 2


def test_a_run_that_never_finishes_fails_with_what_it_saw(gh):
    answer, run_ci, _, _, _ = gh
    answer(ci_run(None, status="queued", url="https://example.invalid/run/4"))
    r = run_ci("--sha", SHA, "--timeout", "1", "--interval", "0.2")
    assert r.returncode == 1
    assert "no completed successful tests.yml run" in r.stdout
    assert "queued/None" in r.stdout


def test_a_success_for_another_commit_is_not_counted(gh):
    answer, run_ci, _, _, _ = gh
    answer(ci_run("success", sha="0" * 40))
    r = run_ci("--sha", SHA, "--timeout", "1", "--interval", "0.2")
    assert r.returncode == 1
    assert "no completed successful" in r.stdout


def test_a_missing_gh_is_an_environment_error(tmp_path):
    binary = tmp_path / "empty"
    binary.mkdir()
    r = subprocess.run([sys.executable, str(SCRIPT), "ci", "--sha", SHA],
                       capture_output=True, text=True, timeout=60,
                       env={**os.environ, "PATH": str(binary)})
    assert r.returncode == 2
    assert "gh is not installed" in r.stderr


def test_a_failing_gh_is_an_environment_error_and_shows_why(gh):
    answer, run_ci, _, binary, _ = gh
    answer("[]")
    (binary / "gh").write_text(
        '#!/usr/bin/env bash\necho "gh: not logged in" >&2\nexit 4\n')
    r = run_ci("--sha", SHA)
    assert r.returncode == 2
    assert "gh run list failed (exit 4)" in r.stderr
    assert "not logged in" in r.stderr


def test_a_short_sha_is_refused_before_asking_github(gh):
    _, run_ci, log, _, _ = gh
    r = run_ci("--sha", SHA[:7])
    assert r.returncode == 2
    assert "full 40-hex commit" in r.stderr
    assert log.read_text() == ""       # nothing was asked, so nothing can match


# -------------------------------------------------------------- live index ---

def declared_version() -> str:
    return re.search(r'^VERSION = "([^"]+)"', TOOL.read_text(), re.M).group(1)


def test_the_declared_version_is_installable_and_carries_these_bytes():
    """A release is done when PyPI serves this file's exact bytes.

    Skipped while the declared version is not published yet: `release.sh --cut`
    bumps VERSION and pushes before the wheel exists, so that commit
    legitimately finds a 404. Every other commit must find what it declares.
    """
    version = declared_version()
    try:
        with urlopen(f"https://pypi.org/pypi/rust-audit/{version}/json",
                     timeout=30) as response:
            assert response.status == 200
    except HTTPError as exc:
        if exc.code == 404:
            pytest.skip(f"rust-audit {version} is not published yet "
                        f"(the version bump precedes the release)")
        raise
    r = run("pypi", "--version", version, "--module", str(TOOL),
            "--timeout", "120", "--interval", "5")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "identical to" in r.stdout
