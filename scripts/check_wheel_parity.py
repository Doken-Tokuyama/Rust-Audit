#!/usr/bin/env python3
"""The installed wheel and the audited checkout must agree on the findings.

`AGENTS.md` §6b makes the published artifact its own path: a green checkout
says nothing about the wheel, where the resources are found through
``<sys.prefix>/share/rustaudit/`` instead of a sibling ``resources/`` directory.
The wheel job therefore scans the same pinned workspace twice — once with the
installed command, once with the checkout — and this compares the two JSON
reports.

What the comparison is worth depends on what it refuses:

- a different ``summary`` (total, per severity, per rule) means the artifact
  does not audit like the code the suite validated;
- a different ``version`` means the wheel was built from other bytes;
- a different ``engine.sha256`` means the wheel does not ship the audited
  module verbatim — packaging started transforming it;
- the same ``engine.path`` means both scans ran the same engine, so the
  comparison was vacuous (the usual cause is an install that never happened
  and two invocations of the checkout);
- two empty reports mean the workspace did not parse: an empty scan proves
  nothing about agreement.

Usage: check_wheel_parity.py INSTALLED_DIR CHECKOUT_DIR

Exit: 0 agree · 1 disagree · 2 usage or unreadable report.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


class ReportError(Exception):
    """A directory that does not hold exactly one JSON audit report."""


def load(directory: Path) -> dict:
    if not directory.is_dir():
        raise ReportError(f"no such report directory: {directory}")
    found = sorted(directory.glob("rust-audit-*.json"))
    if len(found) != 1:
        raise ReportError(
            f"expected one rust-audit-*.json under {directory}, found {len(found)}")
    try:
        return json.loads(found[0].read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReportError(f"cannot read {found[0]}: {exc}") from exc


def disagree(message: str) -> str:
    return f"DISAGREE  {message}"


def compare(installed: dict, checkout: dict) -> list[str]:
    """Every reason the two reports are not the same audit. Empty means agree."""
    problems = []
    if installed.get("version") != checkout.get("version"):
        problems.append(disagree(
            f"version {installed.get('version')!r} installed vs "
            f"{checkout.get('version')!r} in the checkout"))
    installed_summary = installed.get("summary") or {}
    checkout_summary = checkout.get("summary") or {}
    if installed_summary != checkout_summary:
        differing = sorted(
            key for key in set(installed_summary) | set(checkout_summary)
            if installed_summary.get(key) != checkout_summary.get(key))
        problems.append(disagree(
            f"findings differ in {', '.join(differing)}: "
            f"installed total {installed_summary.get('total')} vs "
            f"checkout total {checkout_summary.get('total')}"))
    installed_engine = installed.get("engine") or {}
    checkout_engine = checkout.get("engine") or {}
    if installed_engine.get("sha256") != checkout_engine.get("sha256"):
        problems.append(disagree(
            "the wheel does not ship the audited bytes: engine sha256 "
            f"{installed_engine.get('sha256')} installed vs "
            f"{checkout_engine.get('sha256')} in the checkout"))
    if installed_engine.get("path") == checkout_engine.get("path"):
        problems.append(disagree(
            "both reports name the same engine path "
            f"({installed_engine.get('path')}): nothing was installed, so the "
            "comparison proves nothing"))
    if not checkout_summary.get("total"):
        problems.append(disagree(
            "both scans found nothing: an empty audit cannot show agreement"))
    return problems


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: check_wheel_parity.py INSTALLED_DIR CHECKOUT_DIR",
              file=sys.stderr)
        return 2
    try:
        installed, checkout = (load(Path(path)) for path in argv)
    except ReportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    problems = compare(installed, checkout)
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1
    summary = checkout["summary"]
    print(f"PARITY OK  {summary['total']} findings, identical summary "
          f"({len(summary.get('by_severity') or {})} severities, "
          f"{len(summary.get('by_rule') or {})} rules), version "
          f"{checkout['version']}, engine sha256 "
          f"{checkout['engine']['sha256'][:12]}… shipped verbatim")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
