#!/usr/bin/env python3
"""Find every `rust_audit.py` on this machine and bring the stale ones up to date.

A skill that ships the auditor (the Freebuff account skill, Cursor's agent
store, a vendored copy in another repo) runs **its own** `scripts/rust_audit.py`
and reads **its own** instructions — not this repository's. A copy left at 0.1.0
keeps auditing with 0.1.0 rules while the release notes talk about the current
ones, and nothing in the output says so. This command makes that visible and
fixable:

    python3 scripts/sync_installed_copies.py            # report, exit 1 if stale
    python3 scripts/sync_installed_copies.py --fix      # refresh engine, data, docs
    python3 scripts/sync_installed_copies.py --json     # machine-readable

What a refresh copies:

* the **engine** and the three files it loads at runtime
  (`resources/popular_crates.txt`, `resources/suspicious_names.txt`,
  `templates/deny.toml`) — without them a fresh engine silently falls back;
* the **instructions an agent reads** (`README.md`, `CONTEXT.md`,
  `SECURITY.md` — created when missing, because the canonical `SKILL.md` links
  to them — and every `*.md` under `docs/` already present in the target),
  but only for a copy that ships a `SKILL.md`: a bare vendored tree reads no
  documentation at audit time. `SKILL.md` is special: its YAML frontmatter is
  the target's identity (name, importer metadata) and is kept — only the body
  is replaced. The scripts those instructions invoke
  (`scripts/verify_release.sh`) travel with them, executable bit included.

A copy whose VERSION already matches but whose engine bytes differ is reported
as `drift` and never overwritten without `--force`: that is either a local
patch worth keeping or a tampered engine. A copy *newer* than the canonical one
is left completely alone, docs included.

Exit: 0 everything current (or fixed) · 1 stale/drift/doc drift · 2 execution error.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ENGINE = "rust_audit.py"
# The files the engine reads at runtime: without these a fresh engine still
# degrades silently to its embedded fallbacks.
DATA = (("resources", "popular_crates.txt"),
        ("resources", "suspicious_names.txt"),
        ("templates", "deny.toml"))
# Documentation the canonical SKILL.md points at by relative path. Created when
# missing: an instruction that names a file must not dangle.
DOCS_ROOT = ("README.md", "CONTEXT.md", "SECURITY.md")
DOCS_DIR = "docs"
# Files the installed instructions tell an agent to run. A copy whose text says
# `scripts/verify_release.sh` must actually carry it, or the step dead-ends.
NAMED = ("scripts/verify_release.sh",)
VERSION_RE = re.compile(r'^VERSION = "([^"]+)"', re.M)
LINK_RE = re.compile(r"\]\((?!https?:|#|mailto:)([^)#\s]+)")
SKIP_DIRS = {".git", "node_modules", "target", ".venv", "venv", "__pycache__",
             ".mypy_cache", ".pytest_cache"}
BAD_ENGINE = {"stale", "drift", "failed", "unreadable"}


def version_of(path: Path) -> str | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    match = VERSION_RE.search(text)
    return match.group(1) if match else None


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def semver(value: str) -> tuple[int, ...]:
    """Compare versions numerically; a non-numeric part sorts as 0."""
    parts = re.findall(r"\d+", value)
    return tuple(int(part) for part in parts) or (0,)


def split_frontmatter(text: str) -> tuple[str, str]:
    """`(head, body)`; head keeps the closing `---` line and its newline."""
    if text.startswith("---"):
        end = text.find("\n---", 3)
        if end != -1:
            cut = text.find("\n", end + 4)
            if cut != -1:
                return text[:cut + 1], text[cut + 1:]
    return "", text


def discover(roots: list[Path] | None) -> list[Path]:
    """Every engine copy under `roots`, or everywhere Spotlight knows about."""
    if roots is None:
        try:
            found = subprocess.run(["mdfind", "-name", ENGINE], check=False,
                                   capture_output=True, text=True)
        except FileNotFoundError:
            raise SystemExit(
                "no --root given and Spotlight (mdfind) is unavailable: pass "
                "--root <dir> (repeatable) so the scan is bounded")
        paths = [Path(line) for line in found.stdout.splitlines() if line.strip()]
        return sorted({p.resolve() for p in paths if p.is_file()})
    seen: set[Path] = set()
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            if ENGINE in filenames:
                seen.add((Path(dirpath) / ENGINE).resolve())
    return sorted(seen)


def ships_instructions(copy: Path) -> bool:
    """A tree with a SKILL.md is a skill payload: it carries instructions.

    A bare vendored copy (only `scripts/`, or `scripts/` plus data) reads no
    documentation at audit time, so it is not reported for missing docs.
    """
    return (copy.parent.parent / "SKILL.md").is_file()


def doc_targets(copy: Path, canonical: Path) -> list[tuple[Path, Path]]:
    """`(source, target)` pairs this copy should carry, out of the repo."""
    source = canonical.parent.parent
    target = copy.parent.parent
    if not ships_instructions(copy):
        return []
    pairs = [(source / "SKILL.md", target / "SKILL.md")]
    pairs += [(source / name, target / name) for name in DOCS_ROOT]
    pairs += [(source / name, target / name) for name in NAMED]
    for src in sorted((source / DOCS_DIR).rglob("*.md")):
        rel = src.relative_to(source)
        dst = target / rel
        if dst.is_file():          # refresh what is there
            pairs.append((src, dst))
    # A shipped document must not point at a file we did not ship: copy what
    # the root docs link to, when the repository has it.
    for name in ("SKILL.md", *DOCS_ROOT):
        doc = source / name
        if not doc.is_file():
            continue
        for link in LINK_RE.findall(doc.read_text(encoding="utf-8")):
            rel = Path(link.strip())
            if rel.is_absolute() or ".." in rel.parts:
                continue
            src = source / rel
            if src.is_file() and (src, target / rel) not in pairs:
                pairs.append((src, target / rel))
    return [(src, dst) for src, dst in pairs if src.is_file()]


def doc_drift(copy: Path, canonical: Path) -> list[str]:
    """Relative paths whose instructions no longer match the repository."""
    target = copy.parent.parent
    source = canonical.parent.parent
    drift: list[str] = []
    if (target / "SKILL.md").is_file():
        _, body = split_frontmatter((target / "SKILL.md").read_text(encoding="utf-8"))
        canonical_skill = (source / "SKILL.md").read_text(encoding="utf-8")
        if body.strip() != canonical_skill.strip():
            drift.append("SKILL.md")
    for src, dst in doc_targets(copy, canonical):
        rel = src.relative_to(source).as_posix()
        if rel == "SKILL.md":
            continue
        if not dst.is_file():
            drift.append(f"{rel} (missing)")
        elif src.read_text(encoding="utf-8").rstrip() != dst.read_text(encoding="utf-8").rstrip():
            drift.append(rel)
    return drift


def refresh_engine(copy: Path, canonical: Path) -> None:
    copy.write_bytes(canonical.read_bytes())
    for parts in DATA:
        source = canonical.parent.parent.joinpath(*parts)
        target = copy.parent.parent.joinpath(*parts)
        if source.is_file() and target.is_file():
            target.write_bytes(source.read_bytes())


def refresh_docs(copy: Path, canonical: Path) -> None:
    target = copy.parent.parent
    source = canonical.parent.parent
    for src, dst in doc_targets(copy, canonical):
        if src.name == "SKILL.md" and dst.name == "SKILL.md":
            # Keep the target's frontmatter (its name and importer metadata),
            # replace only the body with the canonical one.
            head = ""
            if dst.is_file():
                head, _ = split_frontmatter(dst.read_text(encoding="utf-8"))
            body = (source / "SKILL.md").read_text(encoding="utf-8")
            dst.write_text(head + "\n" + body.lstrip("\n") if head else body,
                           encoding="utf-8")
        elif src.suffix == ".sh":
            # Keep the executable bit: the instructions invoke it directly.
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
        else:
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")


def snapshot(copy: Path, canonical: Path) -> dict:
    canonical_version = version_of(canonical)
    copied_version = version_of(copy)
    if copied_version is None:
        engine = "unreadable"
    elif copied_version == canonical_version and sha256_of(copy) == sha256_of(canonical):
        engine = "current"
    elif copied_version == canonical_version:
        engine = "drift"
    elif semver(copied_version) < semver(canonical_version):
        engine = "stale"
    else:
        engine = "newer"
    docs = [] if engine == "newer" else doc_drift(copy, canonical)
    return {"path": str(copy), "version": copied_version,
            "sha256": sha256_of(copy), "status": engine, "docs": docs}


def main(argv: list[str] | None = None) -> int:
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description="Report and refresh stale copies of the Rust Audit engine.")
    parser.add_argument("--canonical", default=str(here / ENGINE),
                        help="engine to compare against (default: this repo's)")
    parser.add_argument("--root", action="append", type=Path, default=None,
                        help="directory to scan (repeatable); default: Spotlight")
    parser.add_argument("--fix", action="store_true",
                        help="refresh stale copies (engine, runtime data, docs)")
    parser.add_argument("--force", action="store_true",
                        help="also overwrite copies reported as drift")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    canonical = Path(args.canonical).resolve()
    if not canonical.is_file():
        print(f"error: no canonical engine at {canonical}", file=sys.stderr)
        return 2
    for root in args.root or []:
        if not root.is_dir():
            print(f"error: no such directory: {root}", file=sys.stderr)
            return 2
    canonical_version = version_of(canonical)
    if canonical_version is None:
        print(f"error: {canonical} carries no VERSION", file=sys.stderr)
        return 2

    copies = [p for p in discover(args.root) if p != canonical]
    rows = [snapshot(copy, canonical) for copy in copies]

    if args.fix:
        for row in rows:
            target = Path(row["path"])
            touched = False
            if row["status"] == "stale" or (args.force and row["status"] == "drift"):
                try:
                    refresh_engine(target, canonical)
                except OSError as exc:
                    row["status"], row["error"] = "failed", str(exc)
                    continue
                touched = True
            elif row["status"] not in {"current", "newer"}:
                continue           # unreadable: nothing safe to do
            if row["docs"]:
                try:
                    refresh_docs(target, canonical)
                except OSError as exc:
                    row["status"], row["error"] = "failed", str(exc)
                    continue
                touched = True
            if touched:
                again = snapshot(target, canonical)
                row["status"] = ("fixed" if again["status"] == "current"
                                 and not again["docs"] else "failed")
                row["docs"] = again["docs"]
                if row["status"] == "failed":
                    row["error"] = "bytes still differ after copying"

    bad = [r for r in rows if r["status"] in BAD_ENGINE or r["docs"]]
    if args.json:
        print(json.dumps({"canonical": {"path": str(canonical),
                                        "version": canonical_version},
                          "copies": rows}, indent=2))
    else:
        print(f"canonical  {canonical_version}  {canonical}")
        if not rows:
            print("copies     none found")
        for row in rows:
            print(f"{row['status']:<10} {row['version'] or '?':<8} {row['path']}")
            if row["docs"]:
                print(f"           docs: {', '.join(row['docs'])}")
            if row.get("error"):
                print(f"           error: {row['error']}")
        if bad and not args.fix:
            print(f"\n{len(bad)} copy(ies) would change: rerun with --fix")
        elif bad:
            print(f"\n{len(bad)} copy(ies) still differ — see --force")
        else:
            print("\nall copies run the canonical engine and instructions")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
