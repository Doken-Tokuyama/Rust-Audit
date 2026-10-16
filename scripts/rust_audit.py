#!/usr/bin/env python3
"""Rust Audit -- static auditor and auto-fixer for AI-generated Rust code.

Detects stubs, fakes, demo code, fake tests, panic/unsafe misuse, swallowed
errors, async pitfalls and hallucinated / typosquatted / fake dependencies.

Python 3.11+ standard library only. All output is in English.

Subcommands:
    scan   static analysis (offline by default, --online for registry checks)
    fix    apply safe fixes transactionally (validated, idempotent) or emit
           assisted patch proposals as unified diffs
    cargo  evidence pipeline over real Rust tooling (clippy JSON, mutants,
           coverage, OSV, guarddog, ...); missing tools are "skipped"
    full   scan + cargo merged report
    selftest built-in rule smoke test
"""
from __future__ import annotations

import argparse
import bisect
import dataclasses
import difflib
import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

VERSION = "0.1.0"
TOOL_NAME = "Rust Audit"

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# --------------------------------------------------------------------------
# Rule catalog. fix: "safe" (auto-applicable), "assisted" (diff proposal
# only), "none" (never auto-fixed: behaviour, concurrency, security).
# --------------------------------------------------------------------------
RULES: dict[str, dict] = {
    "R01": {"tier": 1, "title": "Unimplemented stub", "severity": "critical", "fix": "none"},
    "R02": {"tier": 1, "title": "Fake / meaningless test", "severity": "high", "fix": "none"},
    "R03": {"tier": 1, "title": "Stubbed logic", "severity": "high", "fix": "none"},
    "R04": {"tier": 1, "title": "Placeholder data used as real", "severity": "high", "fix": "none"},
    "R05": {"tier": 1, "title": "Demo code", "severity": "medium", "fix": "none"},
    "R06": {"tier": 1, "title": "Fake/test double outside tests", "severity": "medium", "fix": "none"},
    "R07": {"tier": 1, "title": "Over-mocking / mock-only tests", "severity": "low", "fix": "none"},
    "R08": {"tier": 1, "title": "Flaky / order-dependent test", "severity": "medium", "fix": "none"},
    "R09": {"tier": 2, "title": "unwrap/expect/panic in production code", "severity": "high", "fix": "assisted"},
    "R10": {"tier": 2, "title": "Swallowed error", "severity": "medium", "fix": "assisted"},
    "R11": {"tier": 2, "title": "unsafe without justification", "severity": "high", "fix": "none"},
    "R12": {"tier": 2, "title": "Hardcoded secret", "severity": "critical", "fix": "safe"},
    "R13": {"tier": 2, "title": "Missing input validation", "severity": "medium", "fix": "none"},
    "R14": {"tier": 3, "title": "clone() abuse", "severity": "medium", "fix": "none"},
    "R15": {"tier": 3, "title": "Invented lifetimes", "severity": "low", "fix": "none"},
    "R16": {"tier": 3, "title": "Async misuse (Tokio)", "severity": "high", "fix": "assisted"},
    "R17": {"tier": 3, "title": "Arc<Mutex<>> overuse", "severity": "low", "fix": "none"},
    "R18a": {"tier": 4, "title": "Unresolved external crate reference", "severity": "high", "fix": "none"},
    "R18b": {"tier": 4, "title": "Standard module used as external crate", "severity": "high", "fix": "safe"},
    "R18c": {"tier": 4, "title": "Near-miss crate name", "severity": "high", "fix": "none"},
    "R18d": {"tier": 4, "title": "Suspicious / nonexistent / impossible crate or version", "severity": "critical", "fix": "none"},
    "R18e": {"tier": 4, "title": "Declared dependency never used", "severity": "low", "fix": "none"},
    "R19": {"tier": 4, "title": "Slopsquatting window (recently registered crate)", "severity": "high", "fix": "none"},
    "R20": {"tier": 4, "title": "Potential typosquat of a popular crate", "severity": "high", "fix": "none"},
    "R21": {"tier": 4, "title": "Risky build.rs / proc-macro", "severity": "high", "fix": "none"},
}

# Modules commonly hallucinated as standalone crates (arxiv 2606.08444: 45% of
# crate hallucinations are std/internal modules referenced as external crates).
STD_MODULES = {
    "alloc", "any", "arch", "ascii", "borrow", "boxed", "cell", "char", "clone",
    "cmp", "collections", "convert", "default", "env", "error", "f32", "f64",
    "ffi", "fmt", "fs", "future", "hash", "i8", "i16", "i32", "i64", "i128",
    "io", "isize", "iter", "marker", "mem", "net", "num", "ops", "option",
    "os", "panic", "path", "pin", "prelude", "process", "ptr", "rc", "result",
    "slice", "str", "string", "sync", "task", "thread", "time", "u8", "u16",
    "u32", "u64", "u128", "unit", "usize", "vec",
}
STD_CRATES = {"std", "core", "alloc", "proc_macro", "test"}

# Known major versions of popular crates: offline "impossible version" check.
KNOWN_MAJORS = {
    "tokio": 1, "serde": 1, "serde_json": 1, "axum": 0, "hyper": 1,
    "reqwest": 0, "clap": 4, "anyhow": 1, "thiserror": 1, "rand": 0,
    "regex": 1, "log": 0, "env_logger": 0, "chrono": 0, "uuid": 1,
    "once_cell": 1, "tracing": 0, "tower": 0, "tonic": 0, "prost": 0,
    "sqlx": 0, "diesel": 2, "rocket": 0, "actix-web": 4, "warp": 0,
    "futures": 0, "bytes": 1, "libc": 0, "parking_lot": 0, "lazy_static": 1,
    "itertools": 0, "tempfile": 3, "url": 2, "semver": 1, "toml": 0,
    "indexmap": 2, "hashbrown": 0, "smallvec": 1, "bitflags": 2, "syn": 2,
    "quote": 1, "proc-macro2": 1, "async-trait": 0, "pin-project": 1,
    "dashmap": 5, "criterion": 0, "cc": 1, "serde_derive": 1,
}

SUSPICIOUS_NAME_RE = re.compile(
    r"(?i)^(rust|async|simple|easy|smart|fast)[-_].*$|"
    r".*[-_](utils?|helpers?|extensions?|extra|lite|lib|core)$"
)

GENERIC_TEST_NAME_RE = re.compile(
    r"(?i)^(test|it)[_-]?\d+$|^test_(ok|works|fine|good|basic|simple|pass|passes|it|kind)$"
    r"|^works$|^test$"
)

TEST_ATTR_RE = re.compile(
    r"#\[\s*(?:tokio::|async_std::|core::prelude::v1::)?"
    r"(?:test|bench|rstest|quickcheck|proptest)\b"
)


@dataclass
class Finding:
    rule_id: str
    severity: str
    message: str
    file: str
    line: int
    function: str = ""
    evidence: str = ""
    source: str = "static"
    confidence: str = "high"
    fix: str = "none"
    fix_hint: str = ""

    @property
    def tier(self) -> int:
        return RULES.get(self.rule_id, {}).get("tier", 0)

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["tier"] = self.tier
        return d


@dataclass
class EvidenceRun:
    tool: str
    command: str
    status: str  # pass | fail | findings | skipped | error
    exit_code: int | None = None
    duration_s: float = 0.0
    excerpt: str = ""
    notes: str = ""

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


# --------------------------------------------------------------------------
# Masking lexer: blanks comments and/or string/char literals while keeping
# offsets and line numbers intact, so pattern rules never match inside
# comments or string contents.
# --------------------------------------------------------------------------
def _blank(seg: str) -> str:
    return "".join("\n" if c == "\n" else " " for c in seg)


def mask_source(src: str, mask_strings: bool = True, mask_comments: bool = True) -> str:
    out: list[str] = []
    i, n = 0, len(src)
    while i < n:
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "*":
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(_blank(src[i:j]) if mask_comments else src[i:j])
            i = j
        elif ch == "/" and nxt == "/":
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(_blank(src[i:j]) if mask_comments else src[i:j])
            i = j
        elif ch == "b" and nxt in ("r", '"', "'"):
            out.append(ch)
            i += 1
        elif ch == "r" and (nxt == '"' or nxt == "#"):
            k, hashes = i + 1, 0
            while k < n and src[k] == "#":
                hashes += 1
                k += 1
            if k < n and src[k] == '"':
                end = '"' + "#" * hashes
                j = src.find(end, k + 1)
                j = n if j < 0 else j + len(end)
                out.append(_blank(src[i:j]) if mask_strings else src[i:j])
                i = j
            else:
                out.append(ch)
                i += 1
        elif ch == '"':
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == '"':
                    j += 1
                    break
                j += 1
            out.append(_blank(src[i:j]) if mask_strings else src[i:j])
            i = j
        elif ch == "'":
            if i + 1 < n and src[i + 1] == "\\":
                j = src.find("'", i + 2)
                j = n if j < 0 else j + 1
                out.append(_blank(src[i:j]) if mask_strings else src[i:j])
                i = j
            elif i + 2 < n and src[i + 2] == "'":
                out.append(_blank(src[i:i + 3]) if mask_strings else src[i:i + 3])
                i += 3
            else:
                out.append(ch)  # lifetime
                i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


class Source:
    """One Rust source file with masked views and offset->line mapping."""

    def __init__(self, path: str, text: str):
        self.path = path
        self.text = text
        self.masked_all = mask_source(text, True, True)      # code only
        self.masked_comments = mask_source(text, False, True)  # strings visible
        self.line_starts = [0]
        for idx, c in enumerate(text):
            if c == "\n":
                self.line_starts.append(idx + 1)

    def line_of(self, offset: int) -> int:
        return bisect.bisect_right(self.line_starts, offset)

    def line_text(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.line_starts):
            start = self.line_starts[lineno - 1]
            end = self.text.find("\n", start)
            end = len(self.text) if end < 0 else end
            return self.text[start:end].strip()
        return ""


def match_pair(text: str, open_idx: int) -> int:
    """Index of the bracket matching text[open_idx] (parens/brackets/braces)."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    opener = text[open_idx]
    closer = pairs.get(opener)
    if closer is None:
        return -1
    depth = 0
    i, n = open_idx, len(text)
    while i < n:
        c = text[i]
        if c == opener:
            depth += 1
        elif c == closer:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


@dataclass
class FnInfo:
    name: str
    start: int
    end: int
    sig: str
    body: str
    body_start_line: int
    attrs: list[str]
    is_test: bool
    is_async: bool
    line: int


@dataclass
class FileUnit:
    rel: str
    path: Path
    src: Source
    kind: str  # lib | build | example | test | bench | other
    fns: list[FnInfo]
    test_regions: list[tuple[int, int]]
    contract_regions: list[tuple[int, int]]  # impl Trait for X / trait blocks


FN_RE = re.compile(r"\bfn\s+([A-Za-z_]\w*)\s*")
MOD_RE = re.compile(r"\bmod\s+([A-Za-z_]\w*)\s*\{")


def _attrs_above(src: Source, line: int) -> list[str]:
    attrs: list[str] = []
    i = line - 1
    while i >= 1:
        text = src.line_text(i)
        stripped = text.strip()
        if stripped.startswith("#[") or stripped.startswith("#!["):
            attrs.append(stripped)
            i -= 1
        elif stripped.startswith("//"):
            i -= 1
        elif stripped == "":
            break
        else:
            break
    return attrs


def _file_kind(rel: str) -> str:
    p = rel.replace("\\", "/")
    if p.endswith("build.rs") or re.search(r"(^|/)build-[^/]*\.rs$", p):
        return "build"
    if "/examples/" in f"/{p}" or p.startswith("examples/"):
        return "example"
    if "/benches/" in f"/{p}" or p.startswith("benches/"):
        return "bench"
    if "/tests/" in f"/{p}" or p.startswith("tests/"):
        return "test"
    return "lib"


def parse_file(rel: str, path: Path, text: str) -> FileUnit:
    src = Source(rel, text)
    masked = src.masked_all
    kind = _file_kind(rel)

    test_regions: list[tuple[int, int]] = []
    for m in MOD_RE.finditer(masked):
        name = m.group(1)
        lookback = masked[max(0, m.start() - 200): m.start()]
        cfg_test = "#[cfg(test)]" in lookback
        if cfg_test or name in ("tests", "test"):
            open_idx = masked.index("{", m.start())
            close_idx = match_pair(masked, open_idx)
            if close_idx > 0:
                test_regions.append((m.start(), close_idx))

    # Regions where a constant return or an ignored parameter fulfils a
    # documented contract: `impl Trait for Type` blocks and `trait` blocks
    # (default methods).
    contract_regions: list[tuple[int, int]] = []
    for m in re.finditer(r"\b(?:impl\b[^{};]*\bfor\b[^{};]*|trait\b[^{};]*)\{", masked):
        close_idx = match_pair(masked, m.end() - 1)
        if close_idx > 0:
            contract_regions.append((m.start(), close_idx))

    fns: list[FnInfo] = []
    for m in FN_RE.finditer(masked):
        name = m.group(1)
        # find parameter list
        i = m.end()
        n = len(masked)
        while i < n and masked[i] != "(":
            if masked[i] in ";{":
                i = -1
                break
            i += 1
        if i < 0 or i >= n:
            continue
        close_paren = match_pair(masked, i)
        if close_paren < 0:
            continue
        # find body open brace (or ';' for declarations without body)
        j = close_paren + 1
        depth = 0
        open_brace = -1
        is_decl = False
        while j < n:
            c = masked[j]
            if depth == 0 and c == "{":
                open_brace = j
                break
            if depth == 0 and c == ";":
                is_decl = True
                break
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
                if depth < 0:
                    break
            j += 1
        if is_decl or open_brace < 0:
            continue
        close_brace = match_pair(masked, open_brace)
        if close_brace < 0:
            continue
        sig = masked[m.start():open_brace]
        body = masked[open_brace + 1: close_brace]
        line = src.line_of(m.start())
        attrs = _attrs_above(src, line)
        attr_blob = " ".join(attrs)
        in_test_region = any(a <= m.start() <= b for a, b in test_regions)
        is_test = bool(
            TEST_ATTR_RE.search(attr_blob)
            or "#[cfg(test)]" in attr_blob
            or in_test_region
            or kind == "test"
        )
        pre = masked[max(0, m.start() - 40): m.start()]
        is_async = bool(re.search(r"\basync\s*$", pre))
        fns.append(FnInfo(
            name=name, start=m.start(), end=close_brace, sig=sig, body=body,
            body_start_line=src.line_of(open_brace), attrs=attrs,
            is_test=is_test, is_async=is_async, line=line,
        ))
    # Inner functions are local helpers: inherit the enclosing function's
    # context (e.g. compile-time type assertions inside a #[test] fn).
    for i, fn in enumerate(fns):
        for j, outer in enumerate(fns):
            if i != j and outer.start < fn.start and fn.end <= outer.end \
                    and outer.is_test:
                fn.is_test = True
                break
    return FileUnit(rel=rel, path=path, src=src, kind=kind, fns=fns,
                    test_regions=test_regions,
                    contract_regions=contract_regions)


def locate_fn(fns: list[FnInfo], offset: int) -> FnInfo | None:
    best = None
    for fn in fns:
        if fn.start <= offset <= fn.end:
            if best is None or (fn.end - fn.start) < (best.end - best.start):
                best = fn
    return best


def macro_calls(masked: str, *names: str) -> list[tuple[str, int, int, str]]:
    """(macro_name, start, end, arg_text) for each macro invocation."""
    res: list[tuple[str, int, int, str]] = []
    for name in names:
        for m in re.finditer(r"\b" + re.escape(name) + r"!\s*\(", masked):
            open_idx = masked.index("(", m.start())
            close_idx = match_pair(masked, open_idx)
            if close_idx > 0:
                res.append((name, m.start(), close_idx, masked[open_idx + 1: close_idx]))
    return res


# --------------------------------------------------------------------------
# Cargo.toml / Cargo.lock parsing
# --------------------------------------------------------------------------
def _norm(name: str) -> str:
    return name.replace("-", "_")


@dataclass
class Dep:
    key: str            # key in Cargo.toml
    package: str        # registry name (respects `package = "..."`)
    alias: str          # name used in Rust code
    kind: str           # normal | dev | build | workspace
    version_req: str
    features: list[str]
    optional: bool


def parse_manifest(manifest_path: Path) -> tuple[list[Dep], dict]:
    try:
        data = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        return [], {}
    deps: list[Dep] = []
    sections = [
        ("dependencies", "normal"),
        ("dev-dependencies", "dev"),
        ("build-dependencies", "build"),
    ]
    for sec, kind in sections:
        for key, val in (data.get(sec) or {}).items():
            deps.append(_mk_dep(key, val, kind))
    for key, val in ((data.get("workspace") or {}).get("dependencies") or {}).items():
        deps.append(_mk_dep(key, val, "workspace"))
    for target in (data.get("target") or {}).values():
        for sec, kind in sections:
            for key, val in (target.get(sec) or {}).items():
                deps.append(_mk_dep(key, val, kind))
    return deps, data


def _mk_dep(key: str, val, kind: str) -> Dep:
    if isinstance(val, str):
        return Dep(key=key, package=key, alias=_norm(key), kind=kind,
                   version_req=val, features=[], optional=False)
    if isinstance(val, dict):
        package = val.get("package", key)
        return Dep(
            key=key, package=package, alias=_norm(key), kind=kind,
            version_req=str(val.get("version", "")),
            features=list(val.get("features") or []),
            optional=bool(val.get("optional", False)),
        )
    return Dep(key=key, package=key, alias=_norm(key), kind=kind,
               version_req="", features=[], optional=False)


def parse_lock(lock_path: Path) -> dict[str, str]:
    """crate name -> resolved version (first entry wins)."""
    out: dict[str, str] = {}
    if not lock_path.exists():
        return out
    try:
        data = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    except Exception:
        return out
    for pkg in data.get("package") or []:
        name = pkg.get("name")
        if name and name not in out:
            out[name] = str(pkg.get("version", ""))
    return out


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a or not b:
        return max(len(a), len(b))
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


# --------------------------------------------------------------------------
# Bundled resources (also loadable from the skill's resources/ directory)
# --------------------------------------------------------------------------
def _resource_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "resources"


def load_name_list(filename: str, fallback: set[str]) -> set[str]:
    p = _resource_dir() / filename
    if p.exists():
        return {
            line.strip()
            for line in p.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        }
    return set(fallback)


FALLBACK_POPULAR = {
    "serde", "serde_json", "tokio", "rand", "clap", "anyhow", "thiserror",
    "regex", "log", "chrono", "uuid", "tracing", "axum", "hyper", "reqwest",
    "futures", "bytes", "libc", "parking_lot", "itertools", "once_cell",
    "async-trait", "syn", "quote", "proc-macro2", "tempfile", "url", "toml",
    "env_logger", "indexmap", "hashbrown", "smallvec", "bitflags", "cc",
    "tower", "tonic", "prost", "sqlx", "diesel", "rocket", "actix-web",
    "warp", "mime", "semver", "criterion", "lazy_static", "pin-project",
    "dashmap", "tracing-subscriber", "serde_derive", "dotenv", "base64",
    "hex", "sha2", "md5", "num-traits", "rayon", "crossbeam", "mio",
    "socket2", "trust-dns-resolver", "rustls", "openssl", "native-tls",
}
FALLBACK_SUSPICIOUS = {
    "rust-http-client", "rust-database", "rust-utils", "async-utils",
    "async-helpers", "file-utils", "rust-orm", "rust-helpers", "easy-utils",
    "tokio-utils-extra", "serde-helpers", "axum-extensions", "simple-crud",
    "async-database-pool", "rust-file-utils", "smart-cache", "fast-json",
}


class Registry:
    def __init__(self, deps: list[Dep], corpus_extra: set[str] | None = None):
        self.deps = deps
        self.by_alias = {_norm(d.alias): d for d in deps}
        self.by_package = {_norm(d.package): d for d in deps}
        self.popular = load_name_list("popular_crates.txt", FALLBACK_POPULAR)
        self.suspicious = load_name_list("suspicious_names.txt", FALLBACK_SUSPICIOUS)
        if corpus_extra:
            self.suspicious |= corpus_extra

    def known_roots(self) -> set[str]:
        roots = set(self.by_alias) | set(self.by_package)
        roots |= {_norm(k) for k in self.by_alias}
        return roots


# --------------------------------------------------------------------------
# Rule checks (per file)
# --------------------------------------------------------------------------
def _ctx_label(unit: FileUnit, fn: FnInfo | None) -> tuple[str, str]:
    if fn is not None:
        return fn.name, ("test" if fn.is_test else unit.kind)
    return "", unit.kind


def _prod_severity(unit: FileUnit, fn: FnInfo | None, prod: str, test: str = "info",
                   example: str = "info") -> str | None:
    """Severity by context; None means 'do not report'."""
    if fn is not None and fn.is_test:
        return None if test == "skip" else test
    if unit.kind in ("example", "bench"):
        return example
    return prod


def check_r01(unit: FileUnit, out: list[Finding]) -> None:
    masked = unit.src.masked_all
    for m in re.finditer(r"\b(todo!|unimplemented!)\s*\(", masked):
        fn = locate_fn(unit.fns, m.start())
        sev = _prod_severity(unit, fn, "critical", "info", "info")
        if sev is None:
            continue
        name, _ = _ctx_label(unit, fn)
        out.append(Finding(
            "R01", sev,
            f"`{m.group(1)}!()` marks this code as unimplemented (stub).",
            unit.rel, unit.src.line_of(m.start()), name,
            evidence=masked[m.start(): m.start() + 40].strip(),
            fix="none",
            fix_hint="Implement the behaviour or return an explicit error; never ship todo!()/unimplemented!().",
        ))
    strings = unit.src.masked_comments
    for m in re.finditer(r"panic!\s*\(\s*\"(?:not implemented|unimplemented|TODO|FIXME)\"", strings):
        fn = locate_fn(unit.fns, m.start())
        sev = _prod_severity(unit, fn, "critical", "info", "info")
        if sev is None:
            continue
        name, _ = _ctx_label(unit, fn)
        out.append(Finding(
            "R01", sev, 'Placeholder panic!("not implemented").',
            unit.rel, unit.src.line_of(m.start()), name,
            evidence=m.group(0), fix="none",
            fix_hint="Implement the behaviour or return a typed error.",
        ))


def _only_asserts_between(text: str, spans: list[tuple[int, int]],
                          e1: int, s2: int) -> bool:
    """True when only other assert calls (and ; { }) separate the two spots."""
    pos = e1
    for a_start, a_end in spans:
        if e1 <= a_start and a_end <= s2:
            if not re.fullmatch(r"[\s;{}]*", text[pos:a_start]):
                return False
            pos = a_end
    return bool(re.fullmatch(r"[\s;{}]*", text[pos:s2]))


def check_r02(unit: FileUnit, out: list[Finding]) -> None:
    for fn in unit.fns:
        # Only functions carrying a real test attribute are tests: helpers
        # inside test regions cannot be "tests that cannot fail".
        if not fn.is_test or not TEST_ATTR_RE.search(" ".join(fn.attrs)):
            continue
        body, masked = fn.body, unit.src.masked_all
        open_idx = masked.find("{", fn.start)
        raw_body = unit.src.text[open_idx + 1: fn.end] if open_idx >= 0 else body
        # Assertions are compared with their string literals visible: masked
        # literals make distinct asserts look identical (false duplicates) and
        # hide failure messages from the roulette check.
        body_vis = mask_source(raw_body, False, True)
        asserts = macro_calls(body_vis, "assert", "assert_eq", "assert_ne")
        has_panic = bool(re.search(r"\b(panic!|unreachable!)\s*\(", body))
        returns_result = "Result" in fn.sig
        has_try = bool(re.search(r"\?\s*;", body))
        # #[should_panic]: the panic IS the oracle. unwrap()/expect() panic on
        # bad behaviour, so they are oracles too ("cannot fail" would be wrong).
        should_panic = any("should_panic" in a for a in fn.attrs)
        has_unwrap = bool(re.search(r"\.(?:unwrap|expect)\s*\(", body))
        if not asserts and not has_panic and not should_panic \
                and not has_unwrap and not (returns_result and has_try):
            if "(" not in body:
                # No call and no oracle: the test literally cannot fail.
                out.append(Finding(
                    "R02", "high",
                    f"Test `{fn.name}` cannot fail (empty body: no call, no assertion).",
                    unit.rel, fn.line, fn.name, evidence="no call, no oracle in body",
                    fix="none",
                    fix_hint="Assert an observable behaviour; a test that cannot fail proves nothing.",
                ))
            else:
                # It calls helpers whose assertions may be the oracle; the tool
                # cannot see through the call, so it reports only what is true.
                out.append(Finding(
                    "R02", "low",
                    f"Test `{fn.name}` has no direct oracle in its body "
                    f"(assertions may live in helpers: verify it can fail).",
                    unit.rel, fn.line, fn.name, evidence="no assert*/panic! in body",
                    fix="none",
                    fix_hint="Assert an observable behaviour here, or rely on the "
                             "helper's assertions knowingly.",
                ))
        for _, start, _, args in asserts:
            compact = re.sub(r"\s+", " ", args).strip()
            # Bare `false` is NOT tautological: in #[should_panic] tests it is
            # the "fail if we got here" guard. Only always-PASSING forms count.
            if re.fullmatch(
                    r"true|true\s*==\s*true|false\s*==\s*false|1\s*==\s*1|0\s*==\s*0",
                    compact) or re.fullmatch(r"(.+?)\s*,\s*\1", compact):
                out.append(Finding(
                    "R02", "high",
                    f"Tautological assertion in test `{fn.name}` (always passes regardless of behaviour).",
                    unit.rel, fn.line + body[:start].count("\n"), fn.name,
                    evidence=compact[:60], fix="none",
                    fix_hint="Assert the real expected value of the behaviour under test.",
                ))
        if GENERIC_TEST_NAME_RE.match(fn.name):
            out.append(Finding(
                "R02", "low",
                f"Generic test name `{fn.name}` (does not state the behaviour being verified).",
                unit.rel, fn.line, fn.name, evidence=fn.name, fix="none",
                fix_hint="Rename to `test_<behaviour>_<condition>_<expected>`.",
            ))
        # Assertion roulette: 3+ bare `assert!` without messages. In Rust,
        # assert_eq!/assert_ne! print left/right values and every panic
        # carries file:line, so they cannot be roulette.
        no_msg = 0
        for name, _, _, args in asserts:
            if name == "assert" and not re.search(r",\s*\"", args):
                no_msg += 1
        if no_msg >= 3:
            out.append(Finding(
                "R02", "low",
                f"Assertion roulette in `{fn.name}`: {no_msg} assertions without failure messages.",
                unit.rel, fn.line, fn.name, evidence=f"{no_msg} bare asserts", fix="none",
                fix_hint="Give each assertion an explanatory message.",
            ))
        # Duplicate assertion: identical asserts repeated inside ONE scenario
        # (nothing but other asserts between them). The catalog's fix is
        # "vary the input" — a statement between the repeats means a new
        # scenario, where repeating the expectation is intentional (ADR 0002).
        # macro_calls groups by macro name, so sort by position; the key keeps
        # the macro name (assert_ne! vs assert_eq! assert OPPOSITES). Its `end`
        # is the INDEX of the closing paren, so spans grow by one to cover it:
        # the gap between two calls must not start inside the first one.
        asserts.sort(key=lambda t: t[1])
        spans = [(s, e + 1) for _, s, e, _ in asserts]
        occ: dict[str, list[tuple[int, int]]] = {}
        for name, start, end, args in asserts:
            key = name + "!(" + re.sub(r"\s+", " ", args) + ")"
            if key:
                occ.setdefault(key, []).append((start, end + 1))
        for key, spots in occ.items():
            if len(spots) < 2:
                continue
            run = best = 1
            for (_, e1), (s2, _) in zip(spots, spots[1:]):
                if _only_asserts_between(body_vis, spans, e1, s2):
                    run += 1
                    best = max(best, run)
                else:
                    run = 1
            if best >= 2:
                # The repeat itself is provable; REDUNDANCY is not: assert
                # arguments can advance state (e.g. `stream.next().await`).
                # ADR 0001: claim only what is provable, with accurate wording.
                out.append(Finding(
                    "R02", "low",
                    f"Duplicate assertion in `{fn.name}` ({best}x identical "
                    f"back-to-back; redundant only if the interleaved asserts "
                    f"do not advance state).",
                    unit.rel, fn.line, fn.name, evidence=key[:60], fix="none",
                    fix_hint="Remove the redundancy or vary the tested input.",
                ))

        # magic numbers in expected results
        magic = [a for _, _, _, a in asserts if re.search(r"^\s*-?\d+\s*,|\,\s*-?\d+\s*$", re.sub(r"\s+", " ", a))]
        if len(magic) >= 2:
            out.append(Finding(
                "R02", "low",
                f"Magic number test in `{fn.name}`: {len(magic)} assertions compare against bare numeric literals.",
                unit.rel, fn.line, fn.name, evidence=str(len(magic)), fix="none",
                fix_hint="Derive expected values from named constants or the specification.",
            ))
    ignores = len(re.findall(r"#\[\s*ignore\s*\]", unit.src.masked_all))
    if ignores >= 3:
        out.append(Finding(
            "R02", "low",
            f"{ignores} tests marked #[ignore] in one file (suite is systematically disabled).",
            unit.rel, 1, "", evidence=f"{ignores}x #[ignore]", fix="none",
            fix_hint="Fix and re-enable ignored tests or delete them.",
        ))


def check_r03(unit: FileUnit, out: list[Finding]) -> None:
    for fn in unit.fns:
        if fn.is_test or unit.kind in ("example", "bench"):
            continue
        masked = unit.src.masked_all
        open_idx = masked.find("{", fn.start)
        raw_body = unit.src.text[open_idx + 1: fn.end] if open_idx >= 0 else fn.body
        # In `impl Trait for Type` blocks and `trait` default methods a
        # constant return or a no-op body fulfils the documented contract
        # (metadata getters, deliberate defaults), not stubbed logic.
        in_contract = any(a <= fn.start <= b for a, b in unit.contract_regions)
        # An empty generic fn is the compile-time type-assertion idiom
        # (`fn check<T: Send>() {}`), not a stub.
        is_type_assert = "<" in fn.sig.split("(", 1)[0]
        # Only a truly empty `{}` is a stub: a body carrying a comment is a
        # documented no-op and a literal body is a real return value.
        if not raw_body.strip() and not in_contract and not is_type_assert:
            out.append(Finding(
                "R03", "high", f"Function `{fn.name}` has an empty body (stub).",
                unit.rel, fn.line, fn.name, evidence="{}", fix="none",
                fix_hint="Implement the function or make it return a typed 'unsupported' error.",
            ))
            continue
        visible = mask_source(raw_body, False, True)  # strings visible, comments hidden
        if not in_contract and re.fullmatch(
                r"(?:return\s+)?(?:true|false|-?\d+(?:\.\d+)?[a-z]*|\"[^\"\n]*\"|"
                r"'(?:\\.|[^\\'])'|Self|[A-Z][A-Z0-9_]{2,})\s*;?",
                visible.strip()):
            out.append(Finding(
                "R03", "high",
                f"Function `{fn.name}` always returns a constant (stubbed logic).",
                unit.rel, fn.line, fn.name,
                evidence=re.sub(r"\s+", " ", visible)[:60], fix="none",
                fix_hint="Implement the real computation or document why a constant is correct.",
            ))
        if re.search(r"\bif\s+(false|0\s*==\s*1|1\s*==\s*0)\b", fn.body):
            out.append(Finding(
                "R03", "high",
                f"Function `{fn.name}` contains a placeholder `if false` branch (dead stub path).",
                unit.rel, fn.line, fn.name, evidence="if false {", fix="none",
                fix_hint="Remove the placeholder branch or wire the real feature flag.",
            ))
        # Scoped to the parameter list so return types and where-clauses
        # (`F: FnOnce...`, `S::Error`) never invent phantom params;
        # underscore-prefixed params are intentional ignores, not stubs.
        params = re.findall(r"(?:^|,)\s*(?:mut\s+)?([A-Za-z_]\w*)\s*:(?!:)",
                            fn.sig.split("(", 1)[-1].split(")", 1)[0])
        params = [p for p in params if p not in ("self",) and not p.startswith("_")]
        # `#[allow(unused_variables)]` declares the ignored params intentional.
        if params and len(re.findall(r"\w+", fn.body)) < 30 \
                and not any("unused_variables" in a for a in fn.attrs):
            missing = [p for p in params if not re.search(r"\b" + re.escape(p) + r"\b", fn.body)]
            if len(missing) == len(params):
                out.append(Finding(
                    "R03", "high",
                    f"Function `{fn.name}` ignores all of its parameters (stub signature).",
                    unit.rel, fn.line, fn.name,
                    evidence=f"unused params: {', '.join(params)}", fix="none",
                    fix_hint="Use the parameters or remove them from the signature.",
                ))


def check_r04(unit: FileUnit, out: list[Finding]) -> None:
    strings = unit.src.masked_comments
    for m in re.finditer(r"\"([^\"\\\n]{3,120})\"", strings):
        val = m.group(1)
        if re.search(r"(?i)\b(lorem ipsum|lorem|dummy|placeholder|sample value|test data|foo bar|fixme|xxx)\b", val) \
           or val in ("example.com", "example.org", "example.net"):
            fn = locate_fn(unit.fns, m.start())
            sev = _prod_severity(unit, fn, "high", "skip", "info")
            if sev is None:
                continue
            name, _ = _ctx_label(unit, fn)
            out.append(Finding(
                "R04", sev,
                f"Placeholder string used as real data: \"{val[:50]}\".",
                unit.rel, unit.src.line_of(m.start()), name,
                evidence=val[:60], fix="none",
                fix_hint="Use real data or read the value from configuration/env.",
            ))


def check_r05(unit: FileUnit, out: list[Finding]) -> None:
    stem = Path(unit.rel).stem.lower()
    if re.search(r"(?i)^(demo|sample|placeholder|dummy)", stem):
        out.append(Finding(
            "R05", "low", f"Demo-style file name `{Path(unit.rel).name}`.",
            unit.rel, 1, "", evidence=stem, fix="none",
            fix_hint="Keep demo code out of production trees.",
        ))
    for fn in unit.fns:
        if fn.is_test:
            continue
        if re.search(r"(?i)^(demo|sample|placeholder|dummy|foo|bar)(_|$)|_(demo|sample|placeholder|dummy)$", fn.name):
            sev = "info" if unit.kind in ("example", "bench") else "medium"
            out.append(Finding(
                "R05", sev, f"Demo-style function name `{fn.name}`.",
                unit.rel, fn.line, fn.name, evidence=fn.name, fix="none",
                fix_hint="Rename to describe the real behaviour or remove it.",
            ))
        body = fn.body.strip()
        if fn.name == "main" and body and re.fullmatch(
                r"((println!|print!|dbg!|eprintln!)\s*\([^;]*\)\s*;\s*)+", re.sub(r"\s+", " ", body)):
            out.append(Finding(
                "R05", "info", "Trivial `fn main` that only prints (demo code).",
                unit.rel, fn.line, fn.name, evidence=body[:40], fix="none",
                fix_hint="Replace with the real entry point.",
            ))


def check_r06(unit: FileUnit, out: list[Finding]) -> None:
    for m in re.finditer(
            r"\b(?:struct|enum|type|trait)\s+((?:Fake|Mock|InMemory|Dummy|Stub)[A-Za-z0-9_]*|"
            r"(?:fake|mock|in_memory|dummy|stub)_[A-Za-z0-9_]*)\b", unit.src.masked_all):
        fn = locate_fn(unit.fns, m.start())
        if fn is not None and fn.is_test:
            continue
        if unit.kind in ("test",) or any(a <= m.start() <= b for a, b in unit.test_regions):
            continue
        out.append(Finding(
            "R06", "medium",
            f"Test double `{m.group(1)}` declared outside test code (fake leaking into production).",
            unit.rel, unit.src.line_of(m.start()), "", evidence=m.group(1), fix="none",
            fix_hint="Move fakes/mocks under #[cfg(test)] or a tests/ module.",
        ))


def check_r07(unit: FileUnit, out: list[Finding]) -> None:
    for fn in unit.fns:
        if not fn.is_test:
            continue
        hits = re.findall(
            r"\bMock[A-Za-z0-9_]*\b|\bmock!\s*\(|\bassert_called\w*\b|\.verify\s*\(|\bwithf\s*\(",
            fn.body)
        if len(hits) > THRESHOLDS.get("mocks_per_test", 5):
            out.append(Finding(
                "R07", "low",
                f"Over-mocking in test `{fn.name}`: {len(hits)} mock interactions/verifications.",
                unit.rel, fn.line, fn.name, evidence=f"{len(hits)} mock hits", fix="none",
                fix_hint="Mock external boundaries only; assert observable behaviour, not call internals.",
            ))
        if re.search(r"\bassert\w*!\s*\(\s*(?:\w+\.)?is_ok\(\)\s*\)", fn.body) and "Mock" in fn.body:
            out.append(Finding(
                "R07", "low",
                f"Test `{fn.name}` only asserts mock setup results (mock-only test).",
                unit.rel, fn.line, fn.name, evidence="assert!(mock.is_ok())", fix="none",
                fix_hint="Assert on real interactions with the system under test.",
            ))


def check_r08(unit: FileUnit, out: list[Finding]) -> None:
    for fn in unit.fns:
        if not fn.is_test:
            continue
        checks = [
            (r"\b(?:std::)?thread::sleep\s*\(|\bSleep\b", "medium",
             "Sleep in test (timing dependence -> flaky)."),
            (r"\bInstant::now\s*\(|\bSystemTime::now\s*\(", "medium",
             "Wall-clock/monotonic time read in test (flaky on slow machines)."),
            (r"\b(?:rand::|random\s*\()", "low",
             "Randomness in test without fixed seed (flaky)."),
            (r"\bstd::env::(?:set_var|remove_var)\b", "medium",
             "Test mutates process environment (order-dependent, unsafe in parallel tests)."),
            (r"\b(?:HashMap|HashSet)[^;]*\.iter\s*\(\)", "low",
             "Iteration over unordered HashMap/HashSet in test (order dependence)."),
        ]
        for pattern, sev, msg in checks:
            if re.search(pattern, fn.body):
                out.append(Finding(
                    "R08", sev, f"{msg} (`{fn.name}`)",
                    unit.rel, fn.line, fn.name,
                    evidence=re.search(pattern, fn.body).group(0)[:50], fix="none",
                    fix_hint="Use deterministic time/random injection and sorted collections.",
                ))


def check_r09(unit: FileUnit, out: list[Finding]) -> None:
    for m in re.finditer(r"\.\s*(unwrap|expect)\s*\(|\bpanic!\s*\(", unit.src.masked_all):
        fn = locate_fn(unit.fns, m.start())
        sev = _prod_severity(unit, fn, "high", "skip", "info")
        if sev is None:
            continue
        name, _ = _ctx_label(unit, fn)
        what = m.group(0).strip()
        out.append(Finding(
            "R09", sev,
            f"`{what}` turns an Option/Result into a panic in production code.",
            unit.rel, unit.src.line_of(m.start()), name, evidence=what, fix="assisted",
            fix_hint="Propagate with `?`, match on the error, or provide a default explicitly.",
        ))


def check_r10(unit: FileUnit, out: list[Finding]) -> None:
    masked = unit.src.masked_all
    patterns = [
        (r"\blet\s+_\s*=", "Discarded value (`let _ =`) hides errors/ignored Results."),
        (r"\bif\s+let\s+Ok\s*\(\s*_\w*\s*\)", "Error branch silently ignored (`if let Ok(_)`)"),
        (r"\.ok\s*\(\)\s*;", "Result flattened with `.ok()` and dropped."),
        (r"unwrap_or_default\s*\(\)", "Failure converted to a silent default."),
    ]
    for pattern, msg in patterns:
        for m in re.finditer(pattern, masked):
            fn = locate_fn(unit.fns, m.start())
            sev = _prod_severity(unit, fn, "medium", "skip", "info")
            if sev is None:
                continue
            name, _ = _ctx_label(unit, fn)
            out.append(Finding(
                "R10", sev, msg, unit.rel, unit.src.line_of(m.start()), name,
                evidence=m.group(0), fix="assisted",
                fix_hint="Handle or propagate the error explicitly; only discard with a stated reason.",
            ))


UNSAFE_RE = re.compile(
    r"\bunsafe\b|\btransmute(?:_copy)?\s*\(|\bfrom_raw_parts(?:_mut)?\s*\(|"
    r"\*(?:const|mut)\b|extern\s+\"[^\"]*\"|\bstd::ptr\b|\bcore::ptr\b"
)


def check_r11(unit: FileUnit, out: list[Finding]) -> None:
    for m in UNSAFE_RE.finditer(unit.src.masked_all):
        line = unit.src.line_of(m.start())
        above = "\n".join(unit.src.line_text(i) for i in range(max(1, line - 3), line))
        if re.search(r"(?i)\bSAFETY\b", above) or above.strip().startswith("///"):
            continue
        fn = locate_fn(unit.fns, m.start())
        sev = _prod_severity(unit, fn, "high", "skip", "info")
        if sev is None:
            continue
        name, _ = _ctx_label(unit, fn)
        out.append(Finding(
            "R11", sev,
            f"`{m.group(0).strip()}` used without a SAFETY justification comment.",
            unit.rel, line, name, evidence=m.group(0).strip(), fix="none",
            fix_hint="Avoid unsafe; if unavoidable, add `// SAFETY: ...` and test with Miri.",
        ))


SECRET_PATTERNS = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "GitHub token"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"), "private key"),
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "API secret key"),
]
SECRET_ASSIGN_RE = re.compile(
    r"(?i)\b(api[_-]?key|apikey|secret[_-]?key|access[_-]?key|password|passwd|auth[_-]?token|token)\s*[:=]\s*\"([^\"]{8,})\""
)
SECRET_LITERAL_RE = re.compile(r"\"[A-Za-z0-9+/=_%\-]{40,}\"|\"[0-9a-fA-F]{32,}\"")


def check_r12(unit: FileUnit, out: list[Finding]) -> None:
    raw = unit.src.text
    for pattern, label in SECRET_PATTERNS:
        for m in pattern.finditer(raw):
            out.append(Finding(
                "R12", "critical", f"Hardcoded {label} in source.",
                unit.rel, unit.src.line_of(m.start()), "",
                evidence=m.group(0)[:12] + "…", fix="none",
                fix_hint="Move to an environment variable or secret manager and rotate the leaked value.",
            ))
    for m in SECRET_ASSIGN_RE.finditer(raw):
        if "env::var" in raw[max(0, m.start() - 40): m.start()]:
            continue
        if unit.kind in ("test",):
            continue
        out.append(Finding(
            "R12", "critical",
            f"Hardcoded credential in assignment `{m.group(1)}`.",
            unit.rel, unit.src.line_of(m.start()), "",
            evidence=f"{m.group(1)} = \"…\"", fix="safe",
            fix_hint="Read from std::env::var (fix --safe rewrites the assignment and fills .env.example).",
        ))
    for m in SECRET_LITERAL_RE.finditer(raw):
        fn = locate_fn(unit.fns, m.start())
        if fn is not None and fn.is_test:
            continue
        if unit.kind in ("test", "bench"):
            continue
        out.append(Finding(
            "R12", "critical", "Long high-entropy literal that looks like a hardcoded secret.",
            unit.rel, unit.src.line_of(m.start()), "",
            evidence=m.group(0)[:12] + "…", fix="none",
            fix_hint="Confirm it is not a credential; if it is, move it to env/secret store.",
            confidence="medium",
        ))


def check_r13(unit: FileUnit, out: list[Finding]) -> None:
    for fn in unit.fns:
        if fn.is_test or unit.kind in ("example", "bench"):
            continue
        body = fn.body
        if re.search(r"\benv::args\s*\(", body) and re.search(r"\.unwrap\s*\(|\.expect\s*\(|\[[^\]]+\]", body):
            out.append(Finding(
                "R13", "medium",
                f"`{fn.name}` reads CLI args without validation (panic on empty/invalid input).",
                unit.rel, fn.line, fn.name, evidence="env::args + unwrap/index", fix="none",
                fix_hint="Validate presence, type and bounds of every argument; return a typed error.",
            ))
        for m in re.finditer(r"(from_str\s*\([^;]*?\)|\.parse\s*::<[^>]*>\s*\([^;]*?\))\s*\.\s*(unwrap|expect)\s*\(", body):
            out.append(Finding(
                "R13", "medium",
                f"`{fn.name}` parses untrusted input with unchecked `{m.group(2)}`.",
                unit.rel, fn.line + body[: m.start()].count("\n"), fn.name,
                evidence=re.sub(r"\s+", " ", m.group(0))[:60], fix="none",
                fix_hint="Handle the parse error explicitly and validate ranges/formats.",
            ))


def check_r14(unit: FileUnit, out: list[Finding]) -> None:
    for fn in unit.fns:
        if fn.is_test or unit.kind in ("example", "bench"):
            continue
        clones = re.findall(r"\.clone\s*\(\)", fn.body)
        if len(clones) > THRESHOLDS.get("clones_per_fn", 3):
            out.append(Finding(
                "R14", "medium",
                f"`{fn.name}` calls `.clone()` {len(clones)} times (borrow-checker fight, hidden cost).",
                unit.rel, fn.line, fn.name, evidence=f"{len(clones)}x .clone()", fix="none",
                fix_hint="Prefer borrowing (&/&mut) or restructure ownership; clone only with a real need.",
            ))


def check_r15(unit: FileUnit, out: list[Finding]) -> None:
    for fn in unit.fns:
        lifetimes = re.findall(r"'[a-z][a-z0-9_]*\b", fn.sig.split(")")[0] if ")" in fn.sig else fn.sig)
        uniq = set(lifetimes)
        if len(uniq) >= THRESHOLDS.get("lifetimes_per_fn", 3):
            out.append(Finding(
                "R15", "low",
                f"`{fn.name}` declares {len(uniq)} lifetimes (invented lifetimes to appease the borrow checker).",
                unit.rel, fn.line, fn.name, evidence=", ".join(sorted(uniq)), fix="none",
                fix_hint="Restructure the data instead of adding lifetimes.",
            ))


TOKIO_FEATURE_NEEDS = {
    "net": "net", "time": "time", "fs": "fs", "sync": "sync", "process": "process",
    "io": "io-util", "signal": "signal", "stream": "stream",
}


def check_r16(unit: FileUnit, out: list[Finding], deps: list[Dep]) -> None:
    for fn in unit.fns:
        if fn.is_async and not fn.is_test:
            if re.search(r"\b(?:std::)?thread::sleep\s*\(", fn.body):
                out.append(Finding(
                    "R16", "high",
                    f"`{fn.name}` blocks the Tokio runtime with `std::thread::sleep`.",
                    unit.rel, fn.line, fn.name, evidence="thread::sleep in async fn", fix="assisted",
                    fix_hint="Use `tokio::time::sleep(d).await` or `spawn_blocking` for blocking work.",
                ))
            if re.search(r"\bstd::fs::|\bfs::read_to_string|\bfs::write\b", fn.body):
                out.append(Finding(
                    "R16", "medium",
                    f"`{fn.name}` performs blocking filesystem I/O inside async code.",
                    unit.rel, fn.line, fn.name, evidence="std::fs in async fn", fix="none",
                    fix_hint="Use tokio::fs or move the work to `tokio::task::spawn_blocking`.",
                ))
            if re.search(r"\bblock_on\b", fn.body):
                out.append(Finding(
                    "R16", "medium",
                    f"`{fn.name}` calls `block_on` from inside async code (deadlock risk).",
                    unit.rel, fn.line, fn.name, evidence="block_on", fix="none",
                    fix_hint="Await the future instead of blocking the runtime thread.",
                ))
            lock_m = re.search(r"\.(?:lock|read|write)\s*\(\s*\)", fn.body)
            if lock_m and ".await" in fn.body[lock_m.end():]:
                out.append(Finding(
                    "R16", "high",
                    f"`{fn.name}` holds a synchronous Mutex/RwLock guard across `.await` (deadlock/blocking).",
                    unit.rel, fn.line, fn.name, evidence="lock() … .await", fix="none",
                    fix_hint="Drop the guard before the await or use tokio::sync primitives.",
                ))
        if not fn.is_test and re.search(r"\bfor\b[^{]*\{", fn.body):
            for_m = re.search(r"\bfor\b", fn.body)
            spawn_m = re.search(r"\btokio::spawn\s*\(", fn.body)
            if for_m and spawn_m and spawn_m.start() > for_m.start():
                out.append(Finding(
                    "R16", "medium",
                    f"`{fn.name}` spawns one task per loop iteration without bounds.",
                    unit.rel, fn.line, fn.name, evidence="tokio::spawn in loop", fix="none",
                    fix_hint="Bound concurrency with a Semaphore, worker pool or batches.",
                ))
    # tokio feature completeness (cross-cutting, one finding per missing feature)
    tokio_dep = next((d for d in deps if _norm(d.package) == "tokio"), None)
    if tokio_dep is not None:
        features = {f.replace("-", "_") for f in tokio_dep.features}
        if "full" not in features and features != {"full"}:
            used = set()
            for m in re.finditer(r"\btokio::([a-z_]+)", unit.src.masked_all):
                used.add(m.group(1))
            if re.search(r"#\[\s*tokio::(main|test)\s*\]", unit.src.masked_all):
                used.update({"macros"})
            if re.search(r"\btokio::spawn\s*\(", unit.src.masked_all):
                used.add("rt")
            needed = set()
            for u in used:
                if u in TOKIO_FEATURE_NEEDS:
                    needed.add(TOKIO_FEATURE_NEEDS[u])
                elif u in ("main", "test", "macros"):
                    needed.add("macros")
                elif u in ("spawn", "rt"):
                    needed.add("rt-multi-thread")
            if "rt" in used and "rt_multi_thread" not in features and "rt" not in features:
                needed.add("rt-multi-thread")
            missing = sorted(n for n in needed if n.replace("-", "_") not in features)
            if missing:
                out.append(Finding(
                    "R16", "medium",
                    f"Tokio features used but not declared in Cargo.toml: {', '.join(missing)}.",
                    unit.rel, 1, "", evidence=f"used: {sorted(used)}", fix="none",
                    fix_hint=f'Add features = [{", ".join(repr(f) for f in missing)}] to the tokio dependency.',
                ))


def check_r17(unit: FileUnit, out: list[Finding]) -> None:
    hits = re.findall(
        r"Arc\s*<\s*Mutex\s*<|Arc\s*<\s*std::sync::Mutex|Arc::new\s*\(\s*(?:std::sync::)?Mutex::new",
        unit.src.masked_all)
    if len(hits) >= THRESHOLDS.get("arc_mutex_per_file", 4):
        out.append(Finding(
            "R17", "low",
            f"`Arc<Mutex<..>>` used {len(hits)} times in one file (shared mutable state everywhere).",
            unit.rel, 1, "", evidence=f"{len(hits)} occurrences", fix="none",
            fix_hint="Prefer message passing (channels), actors or immutable shared data.",
        ))


def check_r21(unit: FileUnit, out: list[Finding]) -> None:
    if unit.kind != "build" and "proc-macro" not in unit.rel:
        # proc-macro crates are flagged at manifest level below
        pass
    if unit.kind == "build":
        for pattern, msg in [
            (r"Command::new\s*\(", "build.rs executes an external command at compile time"),
            (r"\bTcpStream\b|\bUdpSocket\b|\breqwest\b|\bhyper::|curl", "build.rs opens network connections"),
            (r"fs::write\b|File::create\s*\(|OpenOptions", "build.rs writes files during build"),
        ]:
            m = re.search(pattern, unit.src.masked_all)
            if m:
                out.append(Finding(
                    "R21", "high", f"{msg} (supply-chain risk: code runs on every build).",
                    unit.rel, unit.src.line_of(m.start()), "main",
                    evidence=m.group(0), fix="none",
                    fix_hint="Inspect build.rs line by line; a hallucinated dependency often hides here.",
                ))


# --------------------------------------------------------------------------
# Cross-file crate reference rules (R18a-e, R20)
# --------------------------------------------------------------------------
USE_ROOT_RE = re.compile(r"\buse\s+([A-Za-z_]\w*)\s*::")
EXTERN_RE = re.compile(r"\bextern\s+crate\s+([A-Za-z_]\w*)")


def collect_use_roots(units: list[FileUnit]) -> dict[str, list[tuple[str, int, str]]]:
    roots: dict[str, list[tuple[str, int, str]]] = {}
    for unit in units:
        for m in list(USE_ROOT_RE.finditer(unit.src.masked_all)) + \
                list(EXTERN_RE.finditer(unit.src.masked_all)):
            root = m.group(1)
            roots.setdefault(root, []).append(
                (unit.rel, unit.src.line_of(m.start()), m.group(0)))
    return roots


def local_modules(units: list[FileUnit]) -> set[str]:
    mods: set[str] = set()
    for unit in units:
        for m in MOD_RE.finditer(unit.src.masked_all):
            mods.add(m.group(1))
        stem = Path(unit.rel).stem
        if stem != "main" and stem != "lib":
            mods.add(_norm(stem))
    return mods


def check_crate_refs(units: list[FileUnit], reg: Registry, out: list[Finding]) -> None:
    roots = collect_use_roots(units)
    mods = local_modules(units)
    known = reg.known_roots()
    popular = reg.popular

    for root, sites in sorted(roots.items()):
        if root in STD_CRATES or root in {"self", "super", "crate"} or root in mods:
            continue
        rel, line, evidence = sites[0]
        if root in STD_MODULES:
            out.append(Finding(
                "R18b", "high",
                f"`{root}` is a standard-library module, not an external crate "
                f"(namespace confusion; {len(sites)} reference(s)).",
                rel, line, "", evidence=evidence, fix="safe",
                fix_hint=f"Qualify the path: `use std::{root}::...`.",
            ))
            continue
        if _norm(root) in {_norm(p) for p in popular}:
            continue
        # near-miss against declared deps and popular crates
        best, best_dist = None, 99
        for cand in list(known) + [_norm(p) for p in popular]:
            if cand == _norm(root):
                continue  # never compare a name against itself
            d = levenshtein(_norm(root), cand)
            if d < best_dist:
                best, best_dist = cand, d
        if best is not None and 0 < best_dist <= 2:
            out.append(Finding(
                "R18c", "high",
                f"Crate `{root}` does not exist but is within {best_dist} edit(s) of `{best}` "
                f"(near-miss / hallucinated name).",
                rel, line, "", evidence=f"{root} ~ {best}", fix="none",
                fix_hint=f"Verify on https://crates.io/crates/{best} and https://docs.rs/{best}; "
                         f"never rename automatically.",
            ))
            continue
        if SUSPICIOUS_NAME_RE.match(root) or root in reg.suspicious:
            out.append(Finding(
                "R18d", "critical",
                f"Crate `{root}` matches a hallucinated/generic naming pattern "
                f"(possible slopsquatting bait; declared or not, verify before use).",
                rel, line, "", evidence=root, fix="none",
                fix_hint="Do not add this dependency. Verify the real crate on crates.io/docs.rs first.",
            ))
            continue
        if root in known:
            continue
        out.append(Finding(
            "R18a", "high",
            f"`use {root}::...` references a crate that is not declared in Cargo.toml "
            f"(unresolved external identifier; compilation will fail).",
            rel, line, "", evidence=evidence, fix="none",
            fix_hint=f"Add a verified dependency (crates.io/docs.rs) or fix the path.",
        ))

    # declared-but-unused and version checks
    all_text = "\n".join(u.src.masked_all for u in units)
    build_text = "\n".join(u.src.masked_all for u in units if u.kind == "build")
    for dep in reg.deps:
        if dep.kind == "dev":
            probe = all_text
        elif dep.kind == "build":
            probe = build_text
        else:
            probe = all_text
        used = re.search(r"\b" + re.escape(_norm(dep.package)) + r"\b", probe) or \
               re.search(r"\b" + re.escape(_norm(dep.key)) + r"\b", probe) or \
               re.search(r"\b" + re.escape(dep.package.replace("-", "_")) + r"\b", probe)
        if not used and dep.package not in ("serde",):
            out.append(Finding(
                "R18e", "low",
                f"Dependency `{dep.package}` is declared but never referenced "
                f"(possibly an invented or leftover dependency).",
                "Cargo.toml", 1, "", evidence=f"{dep.kind}-dependency {dep.package}", fix="none",
                fix_hint="Remove it or confirm with `cargo machete` / `cargo udeps`.",
                source="static", confidence="medium",
            ))
        # impossible version requirements
        m = re.match(r"\s*(?:\^|>=)?\s*(\d+)", dep.version_req or "")
        if m:
            major = int(m.group(1))
            known_major = KNOWN_MAJORS.get(_norm(dep.package))
            if major > 100 or (known_major is not None and major > known_major):
                out.append(Finding(
                    "R18d", "critical",
                    f"Impossible version requirement `{dep.version_req}` for `{dep.package}` "
                    f"(published majors end at {known_major if known_major is not None else '2 digits'}).",
                    "Cargo.toml", 1, "", evidence=f"{dep.package} = \"{dep.version_req}\"",
                    fix="none",
                    fix_hint="Check the real version on crates.io/docs.rs; the AI likely invented it.",
                ))

    # typosquat similarity (R20)
    for dep in reg.deps:
        name = _norm(dep.package)
        if name in {_norm(p) for p in popular}:
            continue
        best, best_dist = None, 99
        for p in popular:
            d = levenshtein(name, _norm(p))
            if d < best_dist:
                best, best_dist = p, d
        if best is not None and best_dist <= 2:
            out.append(Finding(
                "R20", "high",
                f"Dependency `{dep.package}` is not popular but is {best_dist} edit(s) away from "
                f"`{best}` (potential typosquat).",
                "Cargo.toml", 1, "", evidence=f"{dep.package} ~ {best}", fix="none",
                fix_hint=f"Confirm you meant https://crates.io/crates/{best}; check downloads, "
                         f"repository and age of `{dep.package}` before using it.",
            ))


# --------------------------------------------------------------------------
# Online checks (crates.io API, sparse index, docs.rs, OSV) -- --online only
# --------------------------------------------------------------------------
UA = {"User-Agent": f"{TOOL_NAME}/{VERSION} (dependency verification)"}


def _http_json(url: str, payload: dict | None = None, timeout: float = 12.0):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, headers={**UA, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _sparse_index(name: str) -> list[dict]:
    n = name.replace("-", "_").lower()
    if len(n) == 1:
        prefix = f"1"
    elif len(n) == 2:
        prefix = f"2"
    elif len(n) == 3:
        prefix = f"3/{n[0]}"
    else:
        prefix = f"{n[:2]}/{n[2:4]}"
    url = f"https://index.crates.io/{prefix}/{n}"
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=12.0) as resp:
        return [json.loads(line) for line in resp.read().decode("utf-8").splitlines() if line.strip()]


def online_check_deps(deps: list[Dep], locked: dict[str, str], out: list[Finding]) -> list[dict]:
    """Registry verification table + R18d/R19/OSV findings."""
    table: list[dict] = []
    for dep in deps:
        name = dep.package
        row: dict = {"crate": name, "version_req": dep.version_req,
                     "crates.io": "", "docs.rs": "", "features": "", "status": ""}
        try:
            data = _http_json(f"https://crates.io/api/v1/crates/{name}")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                row["status"] = "NOT FOUND on crates.io"
                out.append(Finding(
                    "R18d", "critical",
                    f"Crate `{name}` does not exist on crates.io (hallucinated/slopsquat candidate).",
                    "Cargo.toml", 1, "", evidence=f"HTTP 404 for {name}",
                    source="crates.io", fix="none",
                    fix_hint="Remove the dependency. If an attacker registered this name, it is malware bait.",
                ))
                table.append(row)
                continue
            row["status"] = f"crates.io error HTTP {e.code}"
            table.append(row)
            continue
        except Exception as e:  # network failure must not fake a pass
            row["status"] = f"check failed: {e}"
            table.append(row)
            continue

        crate = data.get("crate") or {}
        versions = data.get("versions") or []
        row["crates.io"] = f"https://crates.io/crates/{name}"
        row["downloads"] = crate.get("downloads")
        row["updated_at"] = crate.get("updated_at")
        row["repository"] = (crate.get("repository") or "")

        resolved = locked.get(name) or locked.get(name.replace("_", "-")) or crate.get("max_version")
        row["version"] = resolved
        row["docs.rs"] = f"https://docs.rs/{name}/{resolved}" if resolved else f"https://docs.rs/{name}"

        # yanked resolved version
        for v in versions:
            if str(v.get("num")) == str(resolved) and v.get("yanked"):
                out.append(Finding(
                    "R18d", "high", f"Resolved version {name}@{resolved} is yanked.",
                    "Cargo.lock", 1, "", evidence=f"{name} {resolved} yanked",
                    source="crates.io", fix="none",
                    fix_hint="Move to a non-yanked version and review why it was yanked.",
                ))
                row["status"] = "yanked"

        # slopsquatting window: brand-new crate + tiny downloads + generic name
        created = [v.get("created_at") or "" for v in versions]
        first = min(created) if created else ""
        try:
            first_ts = time.mktime(time.strptime(first[:10], "%Y-%m-%d"))
            age_days = (time.time() - first_ts) / 86400
        except Exception:
            age_days = None
        downloads = crate.get("downloads") or 0
        if age_days is not None and age_days < 90 and downloads < 10000 and \
                (SUSPICIOUS_NAME_RE.match(name) or name in Registry(deps).suspicious):
            out.append(Finding(
                "R19", "high",
                f"Crate `{name}` was first published {int(age_days)} days ago with "
                f"{downloads} downloads and a generic name (classic slopsquatting window).",
                "Cargo.toml", 1, "", evidence=f"first publish: {first[:10]}",
                source="crates.io", fix="none",
                fix_hint="Require human review of the crate source, repository and publisher before merging.",
            ))
            row["status"] = (row["status"] + "; recent+suspicious").strip("; ")

        # feature verification via sparse index
        try:
            entries = _sparse_index(name)
            entry = next((e for e in entries if e.get("vers") == resolved), entries[-1] if entries else None)
            if entry is not None:
                feats = set((entry.get("features") or {}).keys())
                feats |= {f.replace("-", "_") for f in feats}
                row["features"] = ", ".join(sorted(feats))[:120]
                missing = [f for f in dep.features
                           if f not in feats and f.replace("-", "_") not in feats and f != "full"]
                if missing and dep.features:
                    out.append(Finding(
                        "R18d", "high",
                        f"Features {missing} do not exist in {name}@{entry.get('vers')} "
                        f"(invented feature names).",
                        "Cargo.toml", 1, "", evidence=f"available: {sorted(set(feats))[:8]}",
                        source="crates.io-index", fix="none",
                        fix_hint="Check the exact feature list on docs.rs for that version.",
                    ))
        except Exception:
            row["features"] = "unverified (index unreachable)"

        # docs.rs probe
        try:
            req = urllib.request.Request(row["docs.rs"], method="HEAD", headers=UA)
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                row["docs.rs status"] = resp.status
        except urllib.error.HTTPError as e:
            if e.code == 404:
                out.append(Finding(
                    "R18d", "medium",
                    f"docs.rs has no build for {name}@{resolved} (unverifiable API).",
                    "Cargo.toml", 1, "", evidence=row["docs.rs"],
                    source="docs.rs", fix="none", confidence="medium",
                    fix_hint="Confirm the API you use exists in this exact version.",
                ))
                row["docs.rs status"] = 404
        except Exception:
            row["docs.rs status"] = "unreachable"

        # OSV advisories for the resolved version
        if resolved:
            try:
                osv = _http_json("https://api.osv.dev/v1/query",
                                 {"package": {"name": name, "ecosystem": "crates.io"},
                                  "version": str(resolved)})
                vulns = osv.get("vulns") or []
                row["osv"] = [v.get("id") for v in vulns]
                for v in vulns:
                    out.append(Finding(
                        "R19", "high",
                        f"OSV advisory {v.get('id')} affects {name}@{resolved}.",
                        "Cargo.lock", 1, "", evidence=str(v.get("summary", ""))[:120],
                        source="osv", fix="none",
                        fix_hint="Upgrade to a fixed version or apply the advisory's guidance.",
                    ))
            except Exception:
                row["osv"] = "unverified"
        table.append(row)
    return table


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
THRESHOLDS: dict = {
    "clones_per_fn": 3,
    "lifetimes_per_fn": 3,
    "arc_mutex_per_file": 4,
    "mocks_per_test": 5,
}

DEFAULT_CONFIG = {
    "rules": {"disabled": []},
    "thresholds": dict(THRESHOLDS),
    "exclude": ["target/*", "*/target/*", ".git/*", "*/.git/*", "report/*", "*/node_modules/*"],
    "corpus": "",
}


def load_config(root: Path, explicit: str | None) -> dict:
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    candidates += [root / "rust-audit.toml", root / ".rust-audit.toml"]
    for candidate in candidates:
        if candidate.exists():
            try:
                data = tomllib.loads(candidate.read_text(encoding="utf-8"))
            except Exception as exc:
                print(f"warning: cannot parse {candidate}: {exc}", file=sys.stderr)
                continue
            for key in ("rules", "thresholds", "exclude", "corpus"):
                if key in data:
                    if isinstance(data[key], dict) and isinstance(cfg.get(key), dict):
                        cfg[key].update(data[key])
                    else:
                        cfg[key] = data[key]
            break
    THRESHOLDS.update(cfg.get("thresholds") or {})
    return cfg


# --------------------------------------------------------------------------
# Scan engine
# --------------------------------------------------------------------------
PER_FILE_CHECKS = [
    check_r01, check_r02, check_r03, check_r04, check_r05, check_r06,
    check_r07, check_r08, check_r09, check_r10, check_r11, check_r12,
    check_r13, check_r14, check_r15, check_r17, check_r21,
]


def run_scan(root: Path, cfg: dict, online: bool = False):
    findings: list[Finding] = []
    units: list[FileUnit] = []
    excludes = list(cfg.get("exclude") or [])

    def excluded(rel: str) -> bool:
        return any(fnmatch.fnmatch(rel, g) for g in excludes)

    for path in sorted(root.rglob("*.rs")):
        rel = path.relative_to(root).as_posix()
        if excluded(rel):
            continue
        if path.with_suffix(".stderr").exists():
            continue  # trybuild compile-fail fixture: it must NOT compile, so
                      # no code-quality verdict on it means anything
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        unit = parse_file(rel, path, text)
        units.append(unit)
        for check in PER_FILE_CHECKS:
            if check is check_r16:
                continue
            check(unit, findings)

    deps: list[Dep] = []
    locked: dict[str, str] = {}
    for manifest in sorted(root.rglob("Cargo.toml")):
        rel = manifest.relative_to(root).as_posix()
        if excluded(rel):
            continue
        found, _ = parse_manifest(manifest)
        deps += found
    for lock in sorted(root.rglob("Cargo.lock")):
        if not excluded(lock.relative_to(root).as_posix()):
            locked.update(parse_lock(lock))
    # de-duplicate deps by (package, kind)
    seen: set[tuple[str, str]] = set()
    uniq_deps: list[Dep] = []
    for d in deps:
        key = (_norm(d.package), d.kind)
        if key not in seen:
            seen.add(key)
            uniq_deps.append(d)
    deps = uniq_deps

    for unit in units:
        check_r16(unit, findings, deps)

    corpus: set[str] = set()
    corpus_file = cfg.get("corpus") or ""
    if corpus_file and Path(corpus_file).exists():
        corpus = {ln.strip() for ln in Path(corpus_file).read_text(encoding="utf-8").splitlines()
                  if ln.strip() and not ln.startswith("#")}
    reg = Registry(deps, corpus)
    check_crate_refs(units, reg, findings)

    online_table: list[dict] = []
    if online:
        online_table = online_check_deps(deps, locked, findings)

    disabled = set(cfg.get("rules", {}).get("disabled") or [])
    findings = [f for f in findings if f.rule_id not in disabled]
    findings.sort(key=lambda f: (-SEVERITY_RANK.get(f.severity, 0), f.file, f.line, f.rule_id))
    return findings, units, reg, online_table


def summarize(findings: list[Finding]) -> dict:
    by_sev = {s: 0 for s in SEVERITY_ORDER}
    by_rule: dict[str, int] = {}
    by_tier = {1: 0, 2: 0, 3: 0, 4: 0}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
        by_tier[f.tier] = by_tier.get(f.tier, 0) + 1
    return {"total": len(findings), "by_severity": by_sev, "by_rule": by_rule,
            "by_tier": by_tier}


# --------------------------------------------------------------------------
# Report writers: terminal, Markdown, JSON, SARIF 2.1.0
# --------------------------------------------------------------------------
def render_terminal(findings: list[Finding], online_table: list[dict],
                    evidence: list[EvidenceRun], limit: int = 25) -> str:
    lines: list[str] = []
    summary = summarize(findings)
    lines.append(f"{TOOL_NAME} v{VERSION} — summary: {summary['total']} finding(s)")
    for sev in SEVERITY_ORDER:
        if summary["by_severity"].get(sev):
            lines.append(f"  {sev.upper():8s} {summary['by_severity'][sev]}")
    lines.append("")
    for f in findings[:limit]:
        fn = f" ({f.function})" if f.function else ""
        lines.append(f"{f.severity.upper():8s} [{f.rule_id}] {f.file}:{f.line}{fn}")
        lines.append(f"          {f.message}")
        if f.fix_hint:
            lines.append(f"          fix: {f.fix_hint}")
    if len(findings) > limit:
        lines.append(f"... {len(findings) - limit} more finding(s) in the report files")
    if online_table:
        lines.append("")
        lines.append("dependency verification table:")
        for row in online_table:
            lines.append(f"  {row.get('crate')}: {row.get('status') or 'ok'} "
                         f"{row.get('crates.io', '')}")
    if evidence:
        lines.append("")
        lines.append("evidence runs:")
        for ev in evidence:
            lines.append(f"  [{ev.status}] {ev.tool} ({ev.command}) exit={ev.exit_code}")
    return "\n".join(lines)


def render_markdown(findings: list[Finding], online_table: list[dict],
                    evidence: list[EvidenceRun], target: str) -> str:
    summary = summarize(findings)
    lines = [
        f"# {TOOL_NAME} report — `{target}`",
        "",
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')} — tool version {VERSION}",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    for sev in SEVERITY_ORDER:
        lines.append(f"| {sev} | {summary['by_severity'].get(sev, 0)} |")
    lines += ["", "| Tier | Count |", "|---|---|"]
    for tier in (1, 2, 3, 4):
        lines.append(f"| Tier {tier} | {summary['by_tier'].get(tier, 0)} |")

    for tier, title in [(1, "Stubs, fakes, demo code and fake tests"),
                        (2, "Panics, unsafe, swallowed errors, security"),
                        (3, "Idiom and quality"),
                        (4, "Fake/hallucinated dependencies and supply chain")]:
        tier_findings = [f for f in findings if f.tier == tier]
        if not tier_findings:
            continue
        lines += ["", f"## Tier {tier}: {title}", ""]
        for f in tier_findings:
            fn = f" in `{f.function}`" if f.function else ""
            lines += [
                f"### [{f.rule_id} · {f.severity}] {f.file}:{f.line}{fn}",
                "",
                f"- **Problem:** {f.message}",
                f"- **Evidence:** `{f.evidence}`" if f.evidence else "- **Evidence:** (see source)",
                f"- **Source:** {f.source} (confidence: {f.confidence})",
                f"- **Fix ({f.fix}):** {f.fix_hint}" if f.fix_hint else "",
                "",
            ]

    if online_table:
        lines += ["## Dependency verification table", "",
                  "| Crate | Version | crates.io | docs.rs | Features | Status |",
                  "|---|---|---|---|---|---|"]
        for row in online_table:
            crate = str(row.get("crate", ""))
            version = str(row.get("version", row.get("version_req", "")))
            crates_io = str(row.get("crates.io", ""))
            docs_rs = str(row.get("docs.rs", ""))
            features = str(row.get("features", ""))[:60]
            status = str(row.get("status") or "ok")
            lines.append(f"| {crate} | {version} | {crates_io} | {docs_rs} | {features} | {status} |")
        lines.append("")

    if evidence:
        lines += ["## Evidence runs (tool pipeline)", "",
                  "| Tool | Command | Status | Exit | Duration |",
                  "|---|---|---|---|---|"]
        for ev in evidence:
            lines.append(f"| {ev.tool} | `{ev.command}` | {ev.status} | {ev.exit_code} | "
                         f"{ev.duration_s:.1f}s |")
        lines.append("")
        for ev in evidence:
            if ev.excerpt:
                lines += [f"<details><summary>{ev.tool} output excerpt</summary>", "",
                          "```", ev.excerpt[:3000], "```", "", "</details>", ""]
    return "\n".join(lines)


def render_json(findings: list[Finding], online_table: list[dict],
                evidence: list[EvidenceRun], target: str) -> str:
    payload = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "target": target,
        "summary": summarize(findings),
        "findings": [f.to_dict() for f in findings],
        "online": online_table,
        "evidence_runs": [e.to_dict() for e in evidence],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_sarif(findings: list[Finding]) -> str:
    level_map = {"critical": "error", "high": "error", "medium": "warning",
                 "low": "note", "info": "note"}
    rules = []
    for rid, meta in RULES.items():
        rules.append({
            "id": rid,
            "shortDescription": {"text": meta["title"]},
            "defaultConfiguration": {"level": level_map.get(meta["severity"], "warning")},
            "properties": {"tags": [f"tier{meta['tier']}", "rust", "ai-generated-code"],
                           "precision": "medium"},
        })
    results = []
    for f in findings:
        fp = hashlib.sha1(
            f"{f.rule_id}|{f.file}|{f.line}|{f.evidence}".encode("utf-8")).hexdigest()[:16]
        results.append({
            "ruleId": f.rule_id,
            "level": level_map.get(f.severity, "warning"),
            "message": {"text": f.message},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.file.replace("\\", "/")},
                "region": {"startLine": max(1, f.line)},
            }}],
            "partialFingerprints": {"rustAiAudit": fp},
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {
            "name": TOOL_NAME,
            "version": VERSION,
            "informationUri": "https://github.com/rust-secure-code/",
            "rules": rules,
        }}, "results": results}],
    }, indent=2)


# --------------------------------------------------------------------------
# Auto-fix: safe (transactional + validated + idempotent) and assisted diffs
# --------------------------------------------------------------------------
DENY_TEMPLATE = """[advisories]
vulnerability = "deny"
unmaintained = "warn"
yanked = "deny"

[bans]
multiple-versions = "warn"
wildcards = "deny"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
"""

SECRET_FIX_RE = re.compile(
    r"(?i)\blet\s+(api[_-]?key|apikey|secret[_-]?key|access[_-]?key|password|passwd|"
    r"auth[_-]?token|token)\s*=\s*\"[^\"]{8,}\"")


def _unified(rel: str, old: str, new: str) -> str:
    return "".join(difflib.unified_diff(
        old.splitlines(keepends=True), new.splitlines(keepends=True),
        fromfile=f"a/{rel}", tofile=f"b/{rel}"))


def plan_safe_fixes(units: list[FileUnit], findings: list[Finding]) -> tuple[dict[str, str], dict[str, str]]:
    """Returns ({rel: new_text}, {rel: unified_diff}) without touching disk."""
    edits: dict[str, str] = {}
    env_additions: set[str] = set()
    texts = {u.rel: u.src.text for u in units}
    by_rel = {u.rel: u for u in units}

    for f in findings:
        if f.rule_id == "R18b" and f.fix == "safe":
            m = re.search(r"use\s+([A-Za-z_]\w*)\s*::", f.evidence or "")
            if not m:
                m = re.search(r"`([A-Za-z_]\w*)`", f.message)
            if not m:
                continue
            root = m.group(1)
            unit = by_rel.get(f.file)
            if unit is None:
                continue
            if re.search(r"\bmod\s+" + re.escape(root) + r"\b", unit.src.masked_all):
                continue  # real local module: do not touch
            current = edits.get(f.file, texts[f.file])
            new = re.sub(r"(?m)^(\s*use\s+)" + re.escape(root) + r"(?=\s*::)",
                         r"\1std::" + root, current)
            if new != current:
                edits[f.file] = new
        elif f.rule_id == "R12" and f.fix == "safe":
            unit = by_rel.get(f.file)
            if unit is None:
                continue
            current = edits.get(f.file, texts[f.file])

            def _env_sub(m: re.Match) -> str:
                name = m.group(1)
                env_name = re.sub(r"[^A-Za-z0-9]", "_", name).upper()
                env_additions.add(f"{env_name}=")
                return f'let {name} = std::env::var("{env_name}").unwrap_or_default()'

            new = SECRET_FIX_RE.sub(_env_sub, current)
            if new != current:
                edits[f.file] = new

    diffs = {rel: _unified(rel, texts[rel], new) for rel, new in edits.items()}
    return edits, diffs, env_additions


def _rewrite_sleeps(body: str) -> str:
    """thread::sleep(EXPR) -> tokio::time::sleep(EXPR).await (proposal text)."""
    out = body
    while True:
        m = re.search(r"\b(?:std::)?thread::sleep\s*\(", out)
        if not m:
            return out
        open_idx = out.find("(", m.start())
        close_idx = match_pair(out, open_idx)
        if close_idx < 0:
            return out
        arg = out[open_idx + 1: close_idx]
        out = out[:m.start()] + f"tokio::time::sleep({arg}).await" + out[close_idx + 1:]


def plan_assisted_fixes(units: list[FileUnit], findings: list[Finding]) -> list[str]:
    """Behaviour-changing rewrites are proposals only: unified diffs for review.

    All edits are computed against the original text and applied in reverse
    offset order, so sequential rewrites never corrupt each other's offsets.
    """
    diffs: list[str] = []
    wanted = {f.rule_id for f in findings}
    for unit in units:
        text = unit.src.text
        masked = unit.src.masked_all
        edits: list[tuple[int, int, str]] = []  # (start, end, replacement) on text
        for fn in unit.fns:
            if fn.is_test:
                continue
            open_idx = masked.find("{", fn.start)
            close_idx = match_pair(masked, open_idx) if open_idx >= 0 else -1
            if open_idx < 0 or close_idx < 0:
                continue
            body = text[open_idx + 1: close_idx]
            new_body = body
            if "R09" in wanted and re.search(r"\b(Result|Option)\b", fn.sig):
                new_body = re.sub(r"\.unwrap\(\)", "?", new_body)
                new_body = re.sub(r"\.expect\s*\([^)]*\)", "?", new_body)
            if "R10" in wanted and re.search(r"\bResult\b", fn.sig):
                new_body = re.sub(r"let\s+_\s*=\s*([^;]+);", r"\1?;", new_body, count=2)
            if "R16" in wanted and fn.is_async:
                new_body = _rewrite_sleeps(new_body)
            if new_body != body:
                edits.append((open_idx + 1, close_idx, new_body))
        if not edits:
            continue
        changed = text
        for start, end, repl in sorted(edits, key=lambda e: -e[0]):
            changed = changed[:start] + repl + changed[end:]
        if changed != text:
            diffs.append(_unified(unit.rel, text, changed))
    return diffs


def run_validators(root: Path, budget: int = 600) -> list[EvidenceRun]:
    runs: list[EvidenceRun] = []
    if not (root / "Cargo.toml").exists() or not shutil.which("cargo"):
        runs.append(EvidenceRun("validation", "cargo fmt/check/test", "skipped",
                                notes="no Cargo.toml or cargo toolchain; edits kept without compile validation"))
        return runs
    for name, argv in [("cargo fmt", ["cargo", "fmt", "--", "--check"]),
                       ("cargo check", ["cargo", "check", "--all-targets"]),
                       ("cargo test", ["cargo", "test"])]:
        t0 = time.time()
        try:
            proc = subprocess.run(argv, cwd=root, capture_output=True, text=True,
                                  encoding="utf-8", errors="replace", timeout=budget)
            excerpt = ((proc.stdout or "") + (proc.stderr or ""))[-3000:]
            runs.append(EvidenceRun(name, " ".join(argv),
                                    "pass" if proc.returncode == 0 else "fail",
                                    proc.returncode, time.time() - t0, excerpt))
            if proc.returncode != 0:
                break
        except Exception as exc:
            runs.append(EvidenceRun(name, " ".join(argv), "error", None,
                                    time.time() - t0, str(exc)))
            break
    return runs


def _rust_digest(root: Path) -> str:
    """Content fingerprint of all .rs sources (fixer change detection)."""
    h = hashlib.sha256()
    for p in sorted(root.rglob("*.rs")):
        rel = p.relative_to(root)
        if p.is_symlink() or rel.parts[0] in {".git", "target"}:
            continue
        h.update(rel.as_posix().encode("utf-8"))
        h.update(p.read_bytes())
    return h.hexdigest()


def run_safe_fixes(root: Path, findings: list[Finding], units: list[FileUnit],
                   dry_run: bool = False, use_cargo: bool = True) -> dict:
    edits, diffs, env_additions = plan_safe_fixes(units, findings)
    report: dict = {"applied": [], "diffs": list(diffs.values()), "reverted": [],
                    "evidence": [], "created": []}
    if dry_run:
        report["evidence"].append(EvidenceRun("fix --safe", "dry-run", "pass",
                                              notes="no files written"))
        return report

    backups: dict[Path, str] = {}
    backup_dir = root / "report" / f"backup-{time.strftime('%Y%m%d-%H%M%S')}"
    try:
        for rel, new in edits.items():
            path = root / rel
            backups[path] = path.read_text(encoding="utf-8")
            backup_dir.mkdir(parents=True, exist_ok=True)
            (backup_dir / rel.replace("/", "__")).write_text(backups[path], encoding="utf-8")
            path.write_text(new, encoding="utf-8")
            report["applied"].append(rel)
        if env_additions:
            env_file = root / ".env.example"
            existing = env_file.read_text(encoding="utf-8") if env_file.exists() else ""
            add = "\n".join(sorted(a for a in env_additions if a.split("=")[0] not in existing))
            if add:
                env_file.write_text(existing + ("\n" if existing else "") + add + "\n",
                                    encoding="utf-8")
                report["created"].append(".env.example")
        tier4 = any(f.tier == 4 for f in findings)
        deny = root / "deny.toml"
        if tier4 and not deny.exists():
            template = Path(__file__).resolve().parent.parent / "templates" / "deny.toml"
            deny.write_text(template.read_text(encoding="utf-8") if template.exists() else DENY_TEMPLATE,
                            encoding="utf-8")
            report["created"].append("deny.toml")
        if use_cargo and shutil.which("cargo") and (root / "Cargo.toml").exists():
            def _fixer(argv: list[str]) -> None:
                try:
                    proc = subprocess.run(argv, cwd=root, capture_output=True, text=True,
                                          encoding="utf-8", errors="replace", timeout=900)
                    report["evidence"].append(EvidenceRun(
                        argv[1], " ".join(argv), "pass" if proc.returncode == 0 else "fail",
                        proc.returncode, excerpt=((proc.stdout or "") + (proc.stderr or ""))[-1500:]))
                except Exception as exc:
                    report["evidence"].append(EvidenceRun(argv[1], " ".join(argv), "error",
                                                          notes=str(exc)))

            # clippy --fix splices suggestions unformatted and can need extra
            # passes for overlapping fixes; loop it to a fixpoint (bounded) and
            # run fmt LAST, so one `fix` run converges and a second one applies
            # nothing (the documented idempotency).
            for _ in range(3):
                before = _rust_digest(root)
                _fixer(["cargo", "clippy", "--fix", "--allow-dirty",
                        "--allow-staged", "--allow-no-vcs", "--all-targets"])
                if _rust_digest(root) == before:
                    break
            _fixer(["cargo", "fmt"])
        validations = run_validators(root)
        report["evidence"].extend(validations)
        if any(v.status in ("fail", "error") for v in validations):
            for path, original in backups.items():
                path.write_text(original, encoding="utf-8")
                report["reverted"].append(path.relative_to(root).as_posix())
            report["applied"] = []
    except Exception as exc:
        for path, original in backups.items():
            path.write_text(original, encoding="utf-8")
        report["reverted"] = [str(p.relative_to(root)) for p in backups]
        report["applied"] = []
        report["evidence"].append(EvidenceRun("fix --safe", "apply", "error", notes=str(exc)))
    return report


# --------------------------------------------------------------------------
# Evidence pipeline (cargo subcommand)
# --------------------------------------------------------------------------
CLIPPY_LINT_MAP = {
    "clippy::unwrap_used": "R09", "clippy::expect_used": "R09", "clippy::panic": "R09",
    "clippy::todo": "R01", "clippy::unimplemented": "R01",
    "clippy::indexing_slicing": "R13", "clippy::arithmetic_side_effects": "R13",
    "clippy::await_holding_lock": "R16", "clippy::mem_forget": "R11",
    "clippy::transmute_undefined_repr": "R11", "clippy::rc_buffer": "R17",
}

CLIPPY_FLAGS = ["--", "-W", "clippy::unwrap_used", "-W", "clippy::expect_used",
                "-W", "clippy::panic", "-W", "clippy::indexing_slicing",
                "-W", "clippy::todo", "-W", "clippy::unimplemented",
                "-W", "clippy::arithmetic_side_effects", "-W", "clippy::await_holding_lock"]


def _run_cmd(argv: list[str], cwd: Path, timeout: int) -> tuple[int | None, str, float]:
    t0 = time.time()
    try:
        # utf-8 + replace: cargo emits UTF-8 progress output that breaks cp1252
        proc = subprocess.run(argv, cwd=cwd, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=timeout)
        return proc.returncode, ((proc.stdout or "") + (proc.stderr or "")), time.time() - t0
    except FileNotFoundError:
        return None, "", 0.0
    except subprocess.TimeoutExpired:
        return -9, "TIMEOUT", time.time() - t0
    except Exception as exc:
        return None, str(exc), time.time() - t0


def _parse_clippy_json(output: str, findings: list[Finding]) -> None:
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if obj.get("reason") != "compiler-message":
            continue
        msg = obj.get("message") or {}
        code = ((msg.get("code") or {}).get("code") or "") if isinstance(msg.get("code"), dict) else ""
        rid = CLIPPY_LINT_MAP.get(code)
        if not rid:
            continue
        span = next((s for s in (msg.get("spans") or []) if s.get("is_primary")), None)
        rel = span.get("file_name", "") if span else ""
        line_no = span.get("line_start", 1) if span else 1
        findings.append(Finding(
            rid, RULES[rid]["severity"], f"clippy {code}: {msg.get('message', '')}",
            rel, line_no, evidence=code, source="clippy", fix="none",
            fix_hint="Address the clippy diagnostic; it corroborates the static scan."))


def collect_evidence(root: Path, deep: bool = False, supply_chain: bool = False,
                     release: bool = False, miri: bool = False, budget: int = 600,
                     findings: list[Finding] | None = None) -> list[EvidenceRun]:
    findings = findings if findings is not None else []
    runs: list[EvidenceRun] = []
    if not (root / "Cargo.toml").exists():
        runs.append(EvidenceRun("cargo", "cargo", "skipped", notes="no Cargo.toml in target"))
        return runs
    if not shutil.which("cargo"):
        runs.append(EvidenceRun("cargo", "cargo", "skipped", notes="cargo toolchain not installed"))
        return runs

    # Tier A
    code, out, dur = _run_cmd(["cargo", "fmt", "--", "--check"], root, min(budget, 300))
    runs.append(EvidenceRun("cargo fmt", "cargo fmt -- --check",
                            "pass" if code == 0 else ("skipped" if code is None else "fail"),
                            code, dur, out[-2000:]))
    code, out, dur = _run_cmd(["cargo", "clippy", "--all-targets", "--message-format=json"] + CLIPPY_FLAGS,
                              root, budget)
    before = len(findings)
    if code is not None:
        _parse_clippy_json(out, findings)
    runs.append(EvidenceRun("cargo clippy", "cargo clippy --all-targets --message-format=json",
                            "findings" if len(findings) > before else
                            ("pass" if code == 0 else ("skipped" if code is None else "fail")),
                            code, dur, out[-2000:], notes=f"{len(findings) - before} lint finding(s)"))
    code, out, dur = _run_cmd(["cargo", "test"], root, budget)
    runs.append(EvidenceRun("cargo test", "cargo test",
                            "pass" if code == 0 else ("skipped" if code is None else "fail"),
                            code, dur, out[-2000:]))
    if release:
        code, out, dur = _run_cmd(["cargo", "build", "--release"], root, budget)
        runs.append(EvidenceRun("cargo build --release", "cargo build --release",
                                "pass" if code == 0 else ("skipped" if code is None else "fail"),
                                code, dur, out[-1500:]))

    # Tier B (deep)
    if deep:
        code, out, dur = _run_cmd(["cargo", "llvm-cov", "--json", "--output-path",
                                   str(root / "report" / "coverage.json")], root, budget)
        runs.append(EvidenceRun("cargo llvm-cov", "cargo llvm-cov --json",
                                "pass" if code == 0 else ("skipped" if code is None else "fail"),
                                code, dur, out[-1500:]))
        code, out, dur = _run_cmd(["cargo", "mutants", "--no-shuffle"], root, budget)
        status = "pass" if code == 0 else ("skipped" if code is None else "fail")
        outcomes = root / "mutants.out" / "outcomes.json"
        if outcomes.exists():
            try:
                data = json.loads(outcomes.read_text(encoding="utf-8"))
                missed = [o for o in data.get("outcomes", []) if o.get("outcome") == "missed"]
                if missed:
                    status = "findings"
                    findings.append(Finding(
                        "R02", "high",
                        f"{len(missed)} mutants survived the test suite (tests do not constrain behaviour).",
                        "mutants.out/outcomes.json", 1, evidence=f"{len(missed)} missed mutants",
                        source="mutants", fix="none",
                        fix_hint="Add assertions that fail when the mutated behaviour changes."))
            except Exception:
                pass
        runs.append(EvidenceRun("cargo mutants", "cargo mutants --no-shuffle", status, code, dur,
                                out[-1500:]))
        code, out, dur = _run_cmd(["cargo", "machete", "--json"], root, 300)
        if code is not None:
            try:
                data = json.loads(out)
                for manifest, unused in (data.get("unused_crates") or {}).items():
                    for name in unused:
                        findings.append(Finding(
                            "R18e", "low", f"`{name}` declared in {manifest} but never used (cargo-machete).",
                            manifest, 1, evidence=name, source="machete", fix="none",
                            fix_hint="Remove the dependency or confirm with cargo udeps."))
            except Exception:
                pass
        runs.append(EvidenceRun("cargo machete", "cargo machete --json",
                                "pass" if code == 0 else ("skipped" if code is None else "fail"),
                                code, dur, out[-1200:]))
    if miri:
        code, out, dur = _run_cmd(["cargo", "+nightly", "miri", "test"], root, budget)
        runs.append(EvidenceRun("cargo miri", "cargo +nightly miri test",
                                "pass" if code == 0 else ("skipped" if code is None else "fail"),
                                code, dur, out[-1500:]))

    # Tier C (supply chain)
    if supply_chain:
        chain = [
            ("cargo audit", ["cargo", "audit"]),
            ("cargo deny", ["cargo", "deny", "check"]),
            ("cargo vet", ["cargo", "vet", "check", "--output-format=json"]),
            ("cargo unmaintained", ["cargo", "unmaintained"]),
            ("cargo supply-chain", ["cargo", "supply-chain", "list-owners"]),
            ("guarddog", ["guarddog", "crates", "verify", "Cargo.lock"]),
            ("osv-scanner", ["osv-scanner", "scan", "source", "-r", ".", "--format", "json"]),
        ]
        for name, argv in chain:
            if not shutil.which(argv[0]):
                runs.append(EvidenceRun(name, " ".join(argv), "skipped",
                                        notes=f"{argv[0]} not installed"))
                continue
            code, out, dur = _run_cmd(argv, root, min(budget, 300))
            runs.append(EvidenceRun(name, " ".join(argv),
                                    "pass" if code == 0 else ("findings" if code == 1 else "fail"),
                                    code, dur, out[-1500:]))
    return runs


# --------------------------------------------------------------------------
# Selftest (embedded micro-corpus; one snippet per offline rule)
# --------------------------------------------------------------------------
SELFTEST_CARGO = """[package]
name = "selftest"
version = "0.1.0"
edition = "2021"

[dependencies]
serdee = "1"
itertools = "0.10"
tokio = { version = "25", features = ["http"] }
"""

SELFTEST_FILES: dict[str, str] = {
    "src/r01.rs": "pub fn a() -> u32 { todo!(\"x\") }",
    "src/r02.rs": """#[cfg(test)]
mod tests {
    #[test]
    fn test_ok() { assert!(true); }
}
""",
    "src/r03.rs": "pub fn is_valid(input: &str, limit: usize) -> bool { true }",
    "src/r04.rs": "pub fn bio() -> String { \"lorem ipsum\".to_string() }",
    "src/r05.rs": "pub fn demo_response() -> &'static str { \"ok\" }",
    "src/r06.rs": "pub struct InMemoryStore { pub rows: Vec<u8> }",
    "src/r07.rs": """#[cfg(test)]
mod tests {
    #[test]
    fn heavy() {
        let m1 = MockA; let m2 = MockB; let m3 = MockC;
        let m4 = MockD; let m5 = MockE; let m6 = MockF;
        assert!(m1.ready());
    }
}
""",
    "src/r08.rs": """#[cfg(test)]
mod tests {
    #[test]
    fn flaky() {
        std::thread::sleep(std::time::Duration::from_millis(1));
        assert!(true == true);
    }
}
""",
    "src/r09.rs": "pub fn parse(raw: &str) -> u32 { raw.parse::<u32>().unwrap() }",
    "src/r10.rs": "pub fn save(p: &str) -> std::io::Result<()> { let _ = std::fs::write(p, \"x\"); Ok(()) }",
    "src/r11.rs": "pub fn deref(p: *const u8) -> u8 { unsafe { std::ptr::read(p) } }",
    "src/r12.rs": "pub fn connect() { let password = \"supersecretpassword123\"; drop(password); }",
    "src/r13.rs": "pub fn port() -> u16 { let a: Vec<String> = std::env::args().collect(); a[1].parse::<u16>().unwrap() }",
    "src/r14.rs": "pub fn cl(v: Vec<u8>) -> Vec<u8> { let a = v.clone(); let b = a.clone(); let c = b.clone(); let d = c.clone(); d }",
    "src/r15.rs": "pub fn pick<'a, 'b, 'c>(x: &'a str, _y: &'b str, _z: &'c str) -> &'a str { x }",
    "src/r16.rs": "pub async fn slow() { std::thread::sleep(std::time::Duration::from_secs(1)); }",
    "src/r17.rs": """use std::sync::{Arc, Mutex};
pub fn shared() -> Vec<Arc<Mutex<u32>>> {
    vec![Arc::new(Mutex::new(1)), Arc::new(Mutex::new(2)),
         Arc::new(Mutex::new(3)), Arc::new(Mutex::new(4))]
}
""",
    "src/r18a.rs": """use quantum_cache::Cache;
pub fn q(_c: Cache) {}
""",
    "src/r18b.rs": """use fs::File;
pub fn open() -> Option<File> { None }
""",
    "src/r18c.rs": """use serdee::Serialize;
pub fn s<T: Serialize>(_t: T) {}
""",
    "src/r20.rs": "pub fn nothing() {}",
    "src/r21.rs": "fn main() { std::process::Command::new(\"curl\").status().unwrap(); }",
}

SELFTEST_EXPECT = ["R01", "R02", "R03", "R04", "R05", "R06", "R07", "R08", "R09",
                   "R10", "R11", "R12", "R13", "R14", "R15", "R16", "R17",
                   "R18a", "R18b", "R18c", "R18d", "R18e", "R20", "R21"]


def cmd_selftest(_args) -> int:
    with tempfile.TemporaryDirectory(prefix="rust-audit-") as tmp:
        root = Path(tmp)
        (root / "src").mkdir()
        (root / "Cargo.toml").write_text(SELFTEST_CARGO, encoding="utf-8")
        (root / "build.rs").write_text(
            'fn main() { std::fs::write("out.bin", "x").unwrap(); }\n', encoding="utf-8")
        for rel, content in SELFTEST_FILES.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(content, encoding="utf-8")
        cfg = load_config(root, None)
        findings, _, _, _ = run_scan(root, cfg, online=False)
        found = {f.rule_id for f in findings}
        missing = [r for r in SELFTEST_EXPECT if r not in found]
        print(f"selftest: {len(found)}/{len(SELFTEST_EXPECT)} rule ids triggered")
        for rid in sorted(found):
            print(f"  [ok] {rid}")
        print("  [skipped] R19 (online-only: run `scan --online`)")
        if missing:
            print(f"FAIL: rules not triggered: {missing}")
            return 1
        print("selftest PASS")
        return 0


# --------------------------------------------------------------------------
# Tool inventory, best-effort installer (setup) and the dated
# "not-executed checks" report required for honest audit reporting.
# --------------------------------------------------------------------------
# (tool id, what check it unlocks, rule ids, how to enable it)
TOOL_INVENTORY: list[tuple[str, str, str, str]] = [
    ("cargo-mutants",
     "Mutation testing: proves whether tests can fail (detects tests that prove nothing)",
     "R02 evidence",
     "python rust_audit.py setup  (or: cargo install cargo-mutants), then `cargo --deep`"),
    ("cargo-llvm-cov",
     "Coverage: prioritise stub functions that no test ever exercises",
     "R01/R03 evidence",
     "python rust_audit.py setup  (or: cargo install cargo-llvm-cov), then `cargo --deep`"),
    ("cargo-udeps",
     "Unused-dependency confirmation (declared but never used)",
     "R18e evidence",
     "python rust_audit.py setup  (or: cargo install cargo-udeps; run with `cargo +nightly udeps`)"),
    ("guarddog",
     "Malicious-crate scan of Cargo.lock (source + metadata heuristics)",
     "R19 evidence",
     "python rust_audit.py setup  (or: pipx install guarddog), then `cargo --supply-chain`"),
    ("osv-scanner",
     "OSV advisory scan of the dependency tree",
     "R19 evidence",
     "python rust_audit.py setup  (or install from https://github.com/google/osv-scanner/releases)"),
    ("cargo-miri",
     "Undefined-behaviour detection for unsafe code (use-after-free, aliasing, ...)",
     "R11 evidence",
     "rustup +nightly component add miri, then `cargo --miri`"),
    ("typomania",
     "Rust Foundation typosquatting corpus checks (R20 backend)",
     "R20 evidence",
     "library-only crate (no binary): the built-in similarity engine stays active as R20"),
]

# (tool id, install strategies tried in order, note)
INSTALL_TARGETS: list[tuple[str, list[list[str]], str]] = [
    ("cargo-mutants",
     [["cargo", "install", "cargo-mutants", "--locked"], ["cargo", "install", "cargo-mutants"]],
     "large dependency tree; first install compiles for several minutes"),
    ("cargo-llvm-cov",
     [["cargo", "install", "cargo-llvm-cov", "--locked"], ["cargo", "install", "cargo-llvm-cov"]],
     "requires the llvm-tools component for full coverage"),
    ("cargo-udeps",
     [["cargo", "install", "cargo-udeps", "--locked"], ["cargo", "install", "cargo-udeps"],
      ["cargo", "+nightly", "install", "cargo-udeps"]],
     "must be RUN with nightly: `cargo +nightly udeps`"),
    ("guarddog",
     [[sys.executable, "-m", "pip", "install", "--user", "guarddog"],
      ["pipx", "install", "guarddog"],
      [sys.executable, "-m", "pip", "install", "guarddog"]],
     "Python package (DataDog); pipx gives the cleanest install"),
    ("osv-scanner",
     [["go", "install", "github.com/google/osv-scanner/v2/cmd/osv-scanner@latest"]],
     "Go binary: requires a Go toolchain, otherwise download the release binary"),
    ("cargo-miri",
     [["rustup", "component", "add", "miri", "--toolchain", "nightly"],
      ["rustup", "component", "add", "miri"]],
     "needs the nightly toolchain"),
    ("typomania",
     [["cargo", "install", "typomania"],
      ["cargo", "install", "--git", "https://github.com/rustfoundation/typomania"]],
     "library-only crate: install is expected to report 'no binaries'; R20 built-in engine covers the check"),
]


def _excerpt(out: str, limit: int = 220) -> str:
    """Single-line head+tail excerpt of a tool output, surfacing the real error.

    Single-line and pipe-free: the value goes straight into a Markdown table
    cell, where newlines and `|` would break the row.
    """
    lines = [ln for ln in out.strip().splitlines()
             if not ln.strip().startswith("[notice]")]
    text = "\n".join(lines).strip()
    body = text if len(text) <= limit * 2 else f"{text[:limit]} … {text[-limit:]}"
    specific = [ln.strip() for ln in lines if re.search(
        r"(?i)error\[E\d+\]|cannot find|externally-managed|permission denied|"
        r"failed to build|could not build|no space left|command not found", ln)]
    generic = [ln.strip() for ln in lines
               if re.search(r"(?i)\berror\b|cannot", ln)
               and not re.match(r"(?i)\s*(note:|this error originates)", ln)]
    pick = specific or generic
    if pick and pick[-1] not in body:
        body = f"{pick[-1][:limit]} ⏎ {body}"
    return body.replace("\n", " ⏎ ").replace("|", "/")


def _attempts_file(out_dir: Path) -> Path:
    return out_dir / f"setup-attempts-{time.strftime('%Y-%m-%d')}.json"


def _load_attempts(out_dir: Path) -> list[dict]:
    af = _attempts_file(out_dir)
    if af.exists():
        try:
            return json.loads(af.read_text(encoding="utf-8"))
        except Exception:
            return []
    return []


def _run_probe(argv: list[str], timeout: int = 25) -> tuple[bool, str]:
    code, out, _dur = _run_cmd(argv, Path.cwd(), timeout)
    if code is None:
        return False, "runner not available"
    first = next((ln.strip() for ln in out.splitlines() if ln.strip()), "")
    return code == 0, first[:80]


def collect_tool_rows() -> list[dict]:
    """Probe the optional tooling once (cheap) for the not-executed report."""
    installed_cargo_bins: dict[str, str] = {}
    if shutil.which("cargo"):
        code, out, _ = _run_cmd(["cargo", "install", "--list"], Path.cwd(), 30)
        if code == 0:
            for ln in out.splitlines():
                m = re.match(r"^\s*([A-Za-z0-9_-]+)\s+(v?[0-9][^:]*)\s*:", ln)
                if m:
                    installed_cargo_bins[m.group(1)] = m.group(2).strip()
    rows: list[dict] = []
    for tool_id, purpose, rules, hint in TOOL_INVENTORY:
        status = "NOT INSTALLED"
        if tool_id in installed_cargo_bins:
            status = f"installed ({installed_cargo_bins[tool_id]})"
        elif tool_id == "cargo-miri":
            ok, ver = _run_probe(["cargo", "+nightly", "miri", "--version"])
            status = f"installed ({ver})" if ok else "NOT INSTALLED (nightly component missing)"
        elif tool_id == "typomania":
            status = "NOT INSTALLED (library-only crate; built-in R20 engine active)"
        elif shutil.which(tool_id):
            ok, ver = _run_probe([tool_id, "--version"])
            status = f"installed ({ver})" if ok else "installed (version unknown)"
        rows.append({"tool": tool_id, "purpose": purpose, "rules": rules,
                     "status": status, "enable": hint})
    return rows


def write_gap_report(out_dir: Path, cmd: str, target: str,
                     evidence: list[EvidenceRun], flags: dict,
                     attempts: list[dict] | None = None) -> Path:
    """Regenerate `not-executed-<date>.md`: every check that did NOT run, and why."""
    out_dir.mkdir(parents=True, exist_ok=True)
    date = time.strftime("%Y-%m-%d")
    path = out_dir / f"not-executed-{date}.md"
    if attempts is None:
        attempts = _load_attempts(out_dir)  # accumulate across runs of the day
    rows = collect_tool_rows()
    lines = [
        f"# {TOOL_NAME} — NOT-EXECUTED checks report ({date})",
        "",
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')} — tool {VERSION} — command: `{cmd}` — target: `{target}`",
        "",
        "This file lists every check that could **not** be executed in this run",
        "(missing tool, network not used, or feature not requested) together with",
        "the reason and how to enable it. Regenerated on each run for the same date.",
        "",
        "## Optional tooling status",
        "",
        "| Tool | Unlocks | Rules | Status | How to enable |",
        "|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(f"| {r['tool']} | {r['purpose']} | {r['rules']} | {r['status']} | {r['enable']} |")

    lines += ["", "## Checks not executed in this run", ""]
    not_run: list[tuple[str, str]] = []
    if not flags.get("online"):
        not_run.append((
            "Live registry verification: crate existence, yanked versions, feature "
            "names, docs.rs builds, OSV advisories (R18d/R19 online)",
            "run `scan --online` (requires network)"))
    if not flags.get("deep"):
        not_run.append(("Mutation testing + coverage + unused-deps evidence (`--deep`)",
                        "run `cargo --deep` with the optional tools installed"))
    if not flags.get("miri"):
        not_run.append(("Miri undefined-behaviour run for unsafe code (R11 evidence)",
                        "run `cargo --miri` with the nightly component installed"))
    if not flags.get("supply_chain"):
        not_run.append(("Supply-chain evidence: cargo-audit/deny/vet, guarddog, osv-scanner",
                        "run `cargo --supply-chain`"))
    if flags.get("fix_validation_skipped"):
        not_run.append(("Compile validation of auto-fixes (fmt/check/test)",
                        "run `fix` inside a compilable crate with the cargo toolchain installed"))
    for check, how in not_run:
        lines.append(f"- **{check}** — how to enable: {how}")

    skipped = [e for e in evidence if e.status == "skipped"]
    lines += ["", "## Skipped tool runs (evidence pipeline)", ""]
    if skipped:
        lines += ["| Tool | Command | Reason |", "|---|---|---|"]
        for e in skipped:
            lines.append(f"| {e.tool} | `{e.command}` | {e.notes or 'not available'} |")
    else:
        lines.append("(none — every requested tool in the pipeline ran)")

    lines += ["", "## Install attempts (setup)", ""]
    if attempts:
        lines += ["| Tool | Attempted | Result |", "|---|---|---|"]
        for a in attempts:
            result = str(a["result"]).replace("\n", " ⏎ ").replace("|", "/")
            attempt = str(a.get("attempt", "—"))
            lines.append(f"| {a['tool']} | `{attempt}` | {result} |")
    else:
        lines.append("(no install attempts in this run — use `python rust_audit.py setup`)")

    cargo_ok, cargo_ver = _run_probe(["cargo", "--version"])
    lines += [
        "", "## Environment", "",
        f"- python: {sys.version.split()[0]} ({sys.platform})",
        f"- cargo: {cargo_ver if cargo_ok else 'NOT INSTALLED'}",
        f"- {TOOL_NAME}: {VERSION}",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def cmd_setup(args) -> int:
    """Best-effort installer for the optional evidence tools + not-executed report."""
    try:
        sys.stdout.reconfigure(line_buffering=True)  # live progress in CI logs
    except Exception:
        pass
    only = {t.strip() for t in (args.only or "").split(",") if t.strip()}
    skip = {t.strip() for t in (args.skip or "").split(",") if t.strip()}
    attempts: list[dict] = []
    existing = {r["tool"]: r["status"] for r in collect_tool_rows()}
    print(f"{TOOL_NAME} setup — installing optional evidence tools (best effort)")
    for tool_id, strategies, note in INSTALL_TARGETS:
        if only and tool_id not in only:
            continue
        if tool_id in skip:
            continue
        if existing.get(tool_id, "").startswith("installed") and not args.reinstall:
            attempts.append({"tool": tool_id, "attempt": "—", "result": "already installed"})
            print(f"  [ok]      {tool_id}: already installed")
            continue
        if args.dry_run:
            shown = " | ".join(" ".join(s) for s in strategies)
            attempts.append({"tool": tool_id, "attempt": shown, "result": "dry-run: not attempted"})
            print(f"  [plan]    {tool_id}: would try: {shown}")
            continue
        done = False
        for argv in strategies:
            if not shutil.which(argv[0]):
                attempts.append({"tool": tool_id, "attempt": " ".join(argv),
                                 "result": f"skipped: `{argv[0]}` runner not available"})
                continue
            print(f"  [running] {tool_id}: {' '.join(argv)}")
            code, out, dur = _run_cmd(argv, Path.cwd(), args.timeout)
            if code == 0:
                attempts.append({"tool": tool_id, "attempt": " ".join(argv),
                                 "result": f"installed OK ({dur:.0f}s)"})
                print(f"  [ok]      {tool_id}: installed ({dur:.0f}s)")
                done = True
                break
            reason = ("timed out" if code == -9 else f"exit {code}")
            attempts.append({"tool": tool_id, "attempt": " ".join(argv),
                             "result": f"FAILED ({reason}): {_excerpt(out)}"})
        if not done and not any(a["tool"] == tool_id and a["result"].startswith("installed")
                                for a in attempts):
            if not any(a["tool"] == tool_id and a["result"].startswith("dry-run")
                       for a in attempts):
                print(f"  [failed]  {tool_id}: could not install — see not-executed report")
        print(f"            note: {note}")
    out_dir = Path(args.out or "report")
    out_dir.mkdir(parents=True, exist_ok=True)
    history = _load_attempts(out_dir) + attempts
    _attempts_file(out_dir).write_text(
        json.dumps(history, indent=2, ensure_ascii=False), encoding="utf-8")
    gap = write_gap_report(
        out_dir, "setup", str(Path(args.root).resolve()),
        [], {"online": False, "deep": False, "miri": False, "supply_chain": False},
        attempts=history)
    print(f"not-executed report: {gap}")
    return 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def _filter_rules(findings: list[Finding], rules_arg: str | None) -> list[Finding]:
    if not rules_arg:
        return findings
    wanted = {r.strip().upper() for r in rules_arg.split(",") if r.strip()}
    return [f for f in findings if f.rule_id in wanted or any(f.rule_id.startswith(w) for w in wanted)]


def _emit_reports(findings, online_table, evidence, args) -> None:
    formats = [f.strip() for f in (args.format or "terminal").split(",") if f.strip()]
    out_dir = Path(args.out or "report")
    stamp = time.strftime("%Y%m%d-%H%M%S")
    target = str(args.root)
    if "terminal" in formats:
        print(render_terminal(findings, online_table, evidence))
    if "md" in formats or "markdown" in formats:
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"rust-audit-{stamp}.md"
        path.write_text(render_markdown(findings, online_table, evidence, target), encoding="utf-8")
        print(f"wrote {path}")
    if "json" in formats:
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"rust-audit-{stamp}.json"
        path.write_text(render_json(findings, online_table, evidence, target), encoding="utf-8")
        print(f"wrote {path}")
    if "sarif" in formats:
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"rust-audit-{stamp}.sarif"
        path.write_text(render_sarif(findings), encoding="utf-8")
        print(f"wrote {path}")


def _require_root(root: Path, need_sources: bool) -> int | None:
    """Exit-code 2 contract: refuse to silently audit the wrong directory."""
    if not root.is_dir():
        print(f"error: target directory not found: {root}", file=sys.stderr)
        return 2
    if need_sources and not any(root.rglob("*.rs")) and not any(root.rglob("Cargo.toml")):
        print(f"error: no Rust sources or Cargo.toml under {root} (wrong path?)",
              file=sys.stderr)
        return 2
    return None


def cmd_scan(args) -> int:
    root = Path(args.root).resolve()
    bad = _require_root(root, need_sources=True)
    if bad is not None:
        return bad
    cfg = load_config(root, args.config)
    if args.exclude:
        cfg["exclude"] = list(cfg.get("exclude") or []) + [g.strip() for g in args.exclude.split(",")]
    findings, units, _, online_table = run_scan(root, cfg, online=args.online)
    findings = _filter_rules(findings, args.rules)
    _emit_reports(findings, online_table, [], args)
    if not args.no_gap_report:
        gap = write_gap_report(Path(args.out or "report"), "scan", str(root), [],
                               {"online": args.online, "deep": False, "miri": False,
                                "supply_chain": False})
        print(f"not-executed report: {gap}")
    fail_on = "medium" if args.strict else (args.fail_on or "high")
    if any(SEVERITY_RANK.get(f.severity, 0) >= SEVERITY_RANK[fail_on] for f in findings):
        return 1
    return 0


def cmd_fix(args) -> int:
    root = Path(args.root).resolve()
    bad = _require_root(root, need_sources=True)
    if bad is not None:
        return bad
    cfg = load_config(root, args.config)
    findings, units, _, _ = run_scan(root, cfg, online=False)
    findings = _filter_rules(findings, args.rules)
    rc = 0
    fix_report: dict = {"evidence": []}
    if args.assisted:
        diffs = plan_assisted_fixes(units, findings)
        print("assisted patch proposals (NOT applied; review each diff):")
        for d in diffs:
            print(d)
        if not diffs:
            print("(no assisted fixes applicable)")
    else:
        report = run_safe_fixes(root, findings, units, dry_run=args.dry_run,
                                use_cargo=not args.no_cargo)
        fix_report = report
        print(f"safe fixes applied: {len(report['applied'])} file(s)")
        for rel in report["applied"]:
            print(f"  edited {rel}")
        for rel in report["created"]:
            print(f"  created {rel}")
        for rel in report["reverted"]:
            print(f"  REVERTED {rel} (validation failed)")
            rc = 1
        if args.dry_run or args.diff:
            for d in report["diffs"]:
                print(d)
        for ev in report["evidence"]:
            print(f"  [{ev.status}] {ev.tool}: {ev.notes or ev.command}")
        # idempotency check: a second planning pass must produce no edits
        if not args.dry_run and report["applied"]:
            findings2, units2, _, _ = run_scan(root, cfg, online=False)
            edits2, _, _ = plan_safe_fixes(units2, findings2)
            if edits2:
                print(f"warning: {len(edits2)} file(s) still have applicable safe fixes (not idempotent)")
            else:
                print("idempotency check: no further safe fixes apply")
    if not args.no_gap_report:
        validation_skipped = args.assisted or args.no_cargo or args.dry_run or any(
            e.status == "skipped" for e in fix_report.get("evidence", []))
        gap = write_gap_report(Path(args.out or "report"), "fix", str(root),
                               fix_report.get("evidence", []),
                               {"online": False, "deep": False, "miri": False,
                                "supply_chain": False,
                                "fix_validation_skipped": validation_skipped})
        print(f"not-executed report: {gap}")
    return rc


def cmd_cargo(args) -> int:
    root = Path(args.root).resolve()
    bad = _require_root(root, need_sources=False)
    if bad is not None:
        return bad
    findings: list[Finding] = []
    runs = collect_evidence(root, deep=args.deep, supply_chain=args.supply_chain,
                            release=args.release, miri=args.miri, budget=args.budget,
                            findings=findings)
    _emit_reports(findings, [], runs, args)
    if not args.no_gap_report:
        gap = write_gap_report(Path(args.out or "report"), "cargo", str(root), runs,
                               {"online": False, "deep": args.deep, "miri": args.miri,
                                "supply_chain": args.supply_chain})
        print(f"not-executed report: {gap}")
    return 1 if any(SEVERITY_RANK.get(f.severity, 0) >= SEVERITY_RANK[args.fail_on or "high"]
                    for f in findings) else 0


def cmd_full(args) -> int:
    root = Path(args.root).resolve()
    bad = _require_root(root, need_sources=True)
    if bad is not None:
        return bad
    cfg = load_config(root, args.config)
    findings, units, _, online_table = run_scan(root, cfg, online=args.online)
    runs = collect_evidence(root, deep=args.deep, supply_chain=True,
                            release=args.release, miri=args.miri, budget=args.budget,
                            findings=findings)
    findings = _filter_rules(findings, args.rules)
    findings.sort(key=lambda f: (-SEVERITY_RANK.get(f.severity, 0), f.file, f.line, f.rule_id))
    _emit_reports(findings, online_table, runs, args)
    if not args.no_gap_report:
        gap = write_gap_report(Path(args.out or "report"), "full", str(root), runs,
                               {"online": args.online, "deep": args.deep, "miri": args.miri,
                                "supply_chain": True})
        print(f"not-executed report: {gap}")
    fail_on = "medium" if args.strict else (args.fail_on or "high")
    return 1 if any(SEVERITY_RANK.get(f.severity, 0) >= SEVERITY_RANK[fail_on]
                    for f in findings) else 0


def _add_common(p) -> None:
    p.add_argument("root", nargs="?", default=".", help="target directory (default: .)")
    p.add_argument("--format", default="terminal", help="terminal,md,json,sarif (comma list)")
    p.add_argument("--out", default="report", help="report output directory")
    p.add_argument("--fail-on", default="high", choices=list(SEVERITY_RANK),
                   help="exit 1 when findings reach this severity")
    p.add_argument("--rules", help="only these rule ids (comma list, prefixes ok)")
    p.add_argument("--config", help="path to rust-audit.toml")
    p.add_argument("--exclude", help="extra exclude globs (comma list)")
    p.add_argument("--strict", action="store_true", help="fail on medium and above")
    p.add_argument("--no-gap-report", action="store_true",
                   help="do not write the dated not-executed checks report")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog=TOOL_NAME, description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="static analysis of Rust sources and Cargo manifests")
    _add_common(p_scan)
    p_scan.add_argument("--online", action="store_true",
                        help="verify crates against crates.io/docs.rs/OSV (network)")
    p_scan.set_defaults(func=cmd_scan)

    p_fix = sub.add_parser("fix", help="apply safe fixes or propose assisted patches")
    _add_common(p_fix)
    p_fix.add_argument("--safe", action="store_true", help="apply machine-safe fixes (default)")
    p_fix.add_argument("--assisted", action="store_true",
                       help="emit unified diffs for behaviour-changing fixes (never applied)")
    p_fix.add_argument("--dry-run", action="store_true", help="show diffs, write nothing")
    p_fix.add_argument("--diff", action="store_true", help="print the diffs of applied fixes")
    p_fix.add_argument("--no-cargo", action="store_true",
                       help="skip cargo fmt/clippy --fix integration")
    p_fix.set_defaults(func=cmd_fix)

    p_cargo = sub.add_parser("cargo", help="evidence pipeline over installed Rust tooling")
    _add_common(p_cargo)
    p_cargo.add_argument("--release", action="store_true", help="also cargo build --release")
    p_cargo.add_argument("--miri", action="store_true", help="also cargo +nightly miri test")
    p_cargo.add_argument("--deep", action="store_true",
                         help="coverage, mutation testing and unused-dependency checks")
    p_cargo.add_argument("--supply-chain", action="store_true",
                         help="audit, deny, vet, guarddog, osv-scanner")
    p_cargo.add_argument("--budget", type=int, default=600, help="per-tool timeout seconds")
    p_cargo.set_defaults(func=cmd_cargo)

    p_full = sub.add_parser("full", help="scan + cargo merged report")
    _add_common(p_full)
    p_full.add_argument("--online", action="store_true")
    p_full.add_argument("--release", action="store_true")
    p_full.add_argument("--miri", action="store_true")
    p_full.add_argument("--deep", action="store_true")
    p_full.add_argument("--budget", type=int, default=600)
    p_full.set_defaults(func=cmd_full)

    p_setup = sub.add_parser(
        "setup", help="best-effort install of the optional evidence tools "
                     "(cargo-mutants, cargo-llvm-cov, cargo-udeps, guarddog, "
                     "osv-scanner, miri, typomania) + not-executed report")
    p_setup.add_argument("root", nargs="?", default=".")
    p_setup.add_argument("--out", default="report", help="report output directory")
    p_setup.add_argument("--timeout", type=int, default=600,
                         help="per-tool install timeout in seconds")
    p_setup.add_argument("--only", help="comma list of tool ids to install")
    p_setup.add_argument("--skip", help="comma list of tool ids to skip")
    p_setup.add_argument("--reinstall", action="store_true",
                         help="attempt install even if already present")
    p_setup.add_argument("--dry-run", action="store_true",
                         help="show what would be attempted, install nothing")
    p_setup.set_defaults(func=cmd_setup)

    p_self = sub.add_parser("selftest", help="built-in rule smoke test")
    p_self.set_defaults(func=cmd_selftest)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

