#!/usr/bin/env python3
"""check_skill_sync.py — print the state of the Freebuff account-skills sync.

The sync under ~/.config/freebuff-desktop/account-skills/ is upstream-
undocumented; docs/freebuff-account-skills-sync.md decodes it from evidence.
This command prints that model for the current machine instead of making a
human re-decode the tree: the registry revision, which snapshot directory
the registry names (name == sha256(current.json)), which copies are live and
which are rollback archives, the embedded instructions against the served
files and against this repository's canonical skills, the extra files each
skill declares, and the imported.json backup trail with what each sync/verify
step added and removed.

Usage: scripts/check_skill_sync.py [ROOT] [--repo DIR] [--json]
  ROOT  account-skills directory; default $FREEBUFF_ACCOUNT_SKILLS, then
        ~/.config/freebuff-desktop/account-skills
  --repo DIR   repository whose skills/<name>/SKILL.md are canonical
               (default: the checkout this script lives in)
  --json       machine-readable model (same data the terminal output renders)

Exit: 0 consistent · 1 findings (instruction drift, a registry the sync never
      materialized, an orphan skill tree, a missing declared file) ·
      2 execution error (no such root, no account registry, unreadable JSON).
"""
import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

DEFAULT_ROOT = Path.home() / ".config" / "freebuff-desktop" / "account-skills"
INSTALL_DIR = Path.home() / ".agents" / "skills"
BACKUP = re.compile(r"^(?P<kind>pre-[a-z]+)-(?P<date>\d{4}-\d{2}-\d{2})$")


class Failure(Exception):
    """Execution error: exit 2, never a finding."""


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read_bytes(path):
    try:
        return path.read_bytes()
    except OSError as exc:
        raise Failure(f"cannot read {path}: {exc.strerror or exc}")


def read_json(path):
    try:
        return json.loads(read_bytes(path))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise Failure(f"{path} is not valid JSON: {exc}")


def classify(actual, expected):
    """Compare a served copy (actual) with its source of truth (expected).

    One byte class is normalization, not drift: the sync strips the trailing
    newline of SKILL.md when it embeds and when it materializes the copy
    (docs/freebuff-account-skills-sync.md). So the file may equal the source
    with or without that newline; every other difference is drift.
    """
    if actual == expected:
        return "identical", ""
    if expected.endswith(b"\n") and actual == expected[:-1]:
        return "newline-only", "trailing newline stripped"
    if actual.endswith(b"\n") and actual[:-1] == expected:
        return "newline-only", "extra trailing newline"
    return "drift", drift_detail(actual, expected)


def drift_detail(actual, expected):
    a = actual.decode("utf-8", "replace").splitlines()
    e = expected.decode("utf-8", "replace").splitlines()
    line = next((i for i, (x, y) in enumerate(zip(a, e), 1) if x != y),
                min(len(a), len(e)) + 1)
    return (f"{len(expected)} B expected, {len(actual)} B found, "
            f"first difference at line {line}")


def finding(kind, detail, skill=None):
    out = {"kind": kind, "detail": detail}
    if skill is not None:
        out["skill"] = skill
    return out


def account_dirs(root):
    return sorted(p for p in root.iterdir()
                  if p.is_dir() and (p / "current.json").is_file())


def compare_pair(actual, expected):
    kind, detail = classify(actual, expected)
    return {"state": kind, "detail": detail}


def inspect_skill(skill, live, name, repo, findings):
    """One registry entry against its live tree, its declared files and repo."""
    embed = (skill.get("instructions") or "").encode()
    row = {"name": name, "embed_bytes": len(embed)}
    tree = live / name if live is not None else None
    path = tree / "SKILL.md" if tree is not None else None
    if tree is not None and not tree.is_dir():
        findings.append(finding("missing-in-live",
                                f"registered but no {name}/ in the live snapshot",
                                name))
        return row
    if path is not None and not path.is_file():
        findings.append(finding("missing-in-live",
                                f"registered but the live {name}/ has no "
                                f"SKILL.md", name))
        return row
    if path is not None and path.is_file():
        served = read_bytes(path)
        row["embed_vs_live"] = compare_pair(served, embed)
        if row["embed_vs_live"]["state"] == "drift":
            findings.append(finding(
                "embed-drift",
                f"registry embed vs {path}: {row['embed_vs_live']['detail']}",
                name))
    repo_file = repo / name / "SKILL.md" if repo is not None else None
    if repo_file is not None and repo_file.is_file():
        canonical = read_bytes(repo_file)
        if path is not None and path.is_file():
            row["live_vs_repo"] = compare_pair(read_bytes(path), canonical)
        row["embed_vs_repo"] = compare_pair(embed, canonical)
        for key, label in (("live_vs_repo", "live copy"),
                           ("embed_vs_repo", "registry embed")):
            pair = row.get(key)
            if pair and pair["state"] == "drift":
                findings.append(finding(
                    key.replace("_", "-") + "-drift",
                    f"{label} of {name} vs {repo_file}: {pair['detail']}",
                    name))
    for extra in skill.get("files") or []:
        rel = extra.get("path")
        if not rel or tree is None:
            continue
        target = tree / rel
        if not target.is_file():
            findings.append(finding("missing-file",
                                    f"{name}/{rel} is declared but absent "
                                    f"from the live snapshot", name))
            continue
        content = (extra.get("contents") or "").encode()
        kind, detail = classify(read_bytes(target), content)
        if kind == "drift":
            findings.append(finding("file-drift",
                                    f"{name}/{rel}: {detail}", name))
    return row


def inspect_account(acc, repo):
    raw = read_bytes(acc / "current.json")
    registry = read_json(acc / "current.json")
    if not isinstance(registry, dict) or "settings" not in registry:
        raise Failure(f"{acc / 'current.json'} has no settings block")
    skills = registry["settings"].get("skills") or []
    names = [s.get("name") for s in skills]
    digest = sha256(raw)
    live = acc / digest
    dirs = sorted(p for p in acc.iterdir() if p.is_dir())
    findings = []
    if not live.is_dir():
        findings.append(finding(
            "live-snapshot-missing",
            f"no directory named sha256(current.json)={digest} — the registry "
            f"revision has no materialized copy", None))
    archives = [d for d in dirs if d.name != digest]
    model = {
        "account": acc.name,
        "registry": {
            "path": str(acc / "current.json"),
            "bytes": len(raw),
            "sha256": digest,
            "revision": registry.get("revision"),
            "skills": len(skills),
        },
        "live": {
            "name": digest,
            "materialized": live.is_dir(),
            "skills": len([p for p in live.iterdir() if p.is_dir()])
            if live.is_dir() else 0,
        },
        "archives": [{"name": d.name,
                      "skills": len([p for p in d.iterdir() if p.is_dir()])}
                     for d in archives],
        "skills": [],
        "imports": None,
        "findings": findings,
    }
    live_names = ({p.name for p in live.iterdir() if p.is_dir()}
                  if live.is_dir() else set())
    for skill in skills:
        model["skills"].append(inspect_skill(
            skill, live if live.is_dir() else None, skill.get("name"),
            repo, findings))
    for orphan in sorted(live_names - {n for n in names if n}):
        findings.append(finding("orphan-in-live",
                                f"{orphan}/ is materialized but the registry "
                                f"does not list it", orphan))
    model["imports"] = inspect_imports(acc, findings)
    return model


def inspect_imports(acc, findings):
    current = acc / "imported.json"
    if not current.is_file():
        return None
    names = read_json(current)
    if not isinstance(names, list):
        raise Failure(f"{current} is not a JSON list of skill names")
    trail = []
    for backup in sorted(acc.glob("imported.json.*.bak")):
        stem = backup.name[len("imported.json."):-len(".bak")]
        match = BACKUP.match(stem)
        old = read_json(backup)
        if not isinstance(old, list):
            raise Failure(f"{backup} is not a JSON list of skill names")
        trail.append({
            "name": backup.name,
            "kind": match.group("kind") if match else "unknown",
            "date": match.group("date") if match else None,
            "names": len(old),
            "added": [n for n in names if n not in old],
            "removed": [n for n in old if n not in names],
        })
    return {"path": str(current), "names": len(names),
            "skills": names, "backups": trail}


def inspect_install(repo, findings):
    """The machine-global install copies: also live instructions."""
    if repo is None or not INSTALL_DIR.is_dir():
        return []
    rows = []
    for canonical in sorted(repo.glob("*/SKILL.md")):
        installed = INSTALL_DIR / canonical.parent.name / "SKILL.md"
        if not installed.is_file():
            continue
        state = compare_pair(read_bytes(installed), read_bytes(canonical))
        row = {"name": canonical.parent.name, "path": str(installed), **state}
        if state["state"] == "drift":
            findings.append(finding("install-drift",
                                    f"{installed} vs {canonical}: "
                                    f"{state['detail']}", row["name"]))
        rows.append(row)
    return rows


def build(root, repo):
    if not root.is_dir():
        raise Failure(f"no account-skills directory at {root}")
    accounts = account_dirs(root)
    if not accounts:
        raise Failure(f"no account registry (current.json) under {root}")
    model = {"root": str(root), "repo": str(repo) if repo else None,
             "accounts": [], "findings": [], "install": []}
    for acc in accounts:
        entry = inspect_account(acc, repo)
        model["accounts"].append(entry)
        model["findings"].extend(entry["findings"])
    model["install"] = inspect_install(repo, model["findings"])
    model["verdict"] = "consistent" if not model["findings"] else "findings"
    return model


def render(model):
    out = [f"Freebuff account-skills — {model['root']}"]
    for acc in model["accounts"]:
        reg, live, imports = acc["registry"], acc["live"], acc["imports"]
        out.append("")
        out.append(f"account {acc['account'][:12]}…   revision "
                   f"{reg['revision']} · {reg['skills']} skills · "
                   f"current.json {reg['bytes']} B · sha256 {reg['sha256'][:12]}…")
        if live["materialized"]:
            out.append(f"  live snapshot  {live['name'][:12]}…  "
                       f"({live['skills']} trees)   name == sha256(current.json)")
        else:
            out.append(f"  live snapshot  MISSING — no directory named "
                       f"{live['name']}")
        if acc["archives"]:
            names = ", ".join(f"{a['name'][:12]}…" for a in acc["archives"])
            out.append(f"  archives       {len(acc['archives'])} rollback "
                       f"snapshot(s): {names}")
        else:
            out.append("  archives       none")
        compared = [s for s in acc["skills"]
                    if "embed_vs_live" in s or "embed_vs_repo" in s]
        notable = [s for s in compared
                   if any(s[key]["state"] != "identical"
                          for key in ("embed_vs_live", "live_vs_repo",
                                      "embed_vs_repo") if s.get(key))]
        out.append(f"  skills         {len(acc['skills'])} embedded, "
                   f"{len(compared)} compared"
                   + (f" ({len(compared) - len(notable)} identical)"
                      if len(notable) < len(compared) else ""))
        for row in notable:
            pairs = [(label, row[key]) for key, label in
                     (("embed_vs_live", "embed↔live"),
                      ("live_vs_repo", "live↔repo"),
                      ("embed_vs_repo", "embed↔repo")) if row.get(key)]
            parts = [f"{label} {pair['state']}" for label, pair in pairs]
            bad = any(pair["state"] == "drift" for _, pair in pairs)
            mark = "!!" if bad else "  "
            out.append(f"    {mark}{row['name']:<22} "
                       f"{' · '.join(parts)}")
        if imports:
            out.append(f"  imports        {imports['names']} names in "
                       f"imported.json")
            for backup in imports["backups"]:
                delta = [f"+{n}" for n in backup["added"]] + \
                        [f"-{n}" for n in backup["removed"]]
                text = " ".join(delta) if delta else "(no change)"
                out.append(f"    {backup['kind']:<11} {backup['date'] or '?'}  "
                           f"{backup['names']} names  {text}")
    if model["install"]:
        out.append("")
        out.append(f"install copies — {INSTALL_DIR}")
        for row in model["install"]:
            out.append(f"  {row['name']:<22} {row['state']}")
    out.append("")
    findings = model["findings"]
    if not findings:
        out.append("VERDICT consistent — 0 findings")
    else:
        out.append(f"VERDICT findings — {len(findings)}")
        for item in findings:
            out.append(f"  {item['kind']}: {item['detail']}")
    return "\n".join(out)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="check_skill_sync.py",
        description="Print the Freebuff account-skills sync model for a "
                    "machine and flag instruction drift.")
    parser.add_argument("root", nargs="?",
                        default=os.environ.get("FREEBUFF_ACCOUNT_SKILLS")
                        or str(DEFAULT_ROOT),
                        help="account-skills directory (default: %(default)s)")
    parser.add_argument("--repo", help="checkout whose skills/ are canonical "
                                       "(default: this script's checkout)")
    parser.add_argument("--json", action="store_true",
                        help="print the model as JSON")
    args = parser.parse_args(argv)
    default_repo = Path(__file__).resolve().parent.parent
    repo = Path(args.repo).expanduser() if args.repo else None
    if repo is not None and not repo.is_dir():
        print(f"ERROR no such repository: {repo}", file=sys.stderr)
        return 2
    repo = repo or (default_repo if (default_repo / "skills").is_dir()
                    else None)
    if repo is not None:   # accept the checkout root or its skills/ dir
        repo = repo / "skills" if (repo / "skills").is_dir() else repo
    try:
        model = build(Path(args.root).expanduser(), repo)
    except Failure as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 2
    print(json.dumps(model, indent=2) if args.json else render(model))
    return 0 if model["verdict"] == "consistent" else 1


if __name__ == "__main__":
    sys.exit(main())
