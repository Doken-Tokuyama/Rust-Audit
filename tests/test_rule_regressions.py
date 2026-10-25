"""Regressions for R03/R04/R12/R16/R18 false positives (2026-10-25).

Each case is a code shape observed in a real workspace (EQProxy) that the
rule misread as a stub, secret or hallucinated crate. The positive controls
at the end prove the same rule still fires on the genuine smell, so the
refinement removes a wrong claim instead of weakening the rule (ADR 0001).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "scripts" / "rust_audit.py"

CARGO = """[package]
name = "regressions"
version = "0.1.0"
edition = "2021"

[workspace]
members = ["local-core"]

[dependencies]
serde = { version = "1", features = ["derive"] }
thiserror = "2"
h2 = "0.4"
http = "1"
h3 = "0.0.8"
md5 = { package = "md-5", version = "0.10" }
tokio = { version = "1", features = ["sync", "rt"] }
local-core = { path = "local-core" }
serdee = "1"
"""

FILES = {
    "local-core/Cargo.toml": """[package]
name = "local-core"
version = "0.1.0"
edition = "2021"
""",
    "local-core/src/lib.rs": "pub struct Marker;\n",
    # serde's documented way to name a constant default.
    "src/defaults.rs": """use serde::Deserialize;

fn default_maxconn() -> u32 {
    1024
}

#[derive(Deserialize)]
pub struct Limits {
    #[serde(default = "default_maxconn")]
    pub maxconn: u32,
}
""",
    # Parameters used only through inline format captures.
    "src/format_params.rs": """pub fn explain(feature: &str, phase: &str) -> String {
    format!("{feature} lands in {phase}")
}
""",
    # Error messages that mention the word "placeholder".
    "src/error_message.rs": """pub fn reject(value: &str) -> Result<(), String> {
    Err(format!("unknown placeholder in value: {value:?}"))
}

pub fn reject_plain() -> Result<(), String> {
    Err("unknown placeholder in value".to_owned())
}
""",
    # RFC 4648 base64 alphabet: a protocol table, not a credential.
    "src/alphabet.rs": """const TABLE: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn table() -> &'static [u8; 64] {
    TABLE
}
""",
    # Declared protocol crates and a workspace member used from the crate.
    "src/crates.rs": """use h2::client;
use h3::server;
use http::HeaderMap;
use local_core::Marker;

pub fn marker() -> Marker {
    Marker
}
""",
    # A tokio::sync::Mutex guard is meant to be held across an await.
    "src/async_gate.rs": """pub async fn wait(gate: &tokio::sync::Mutex<()>) {
    let _guard = gate.lock().await;
}
""",
    # Test fixture: "example.com" is corpus data, not production config.
    "tests/fixture.rs": """const HOST: &str = "example.com";

#[test]
fn fixture_is_not_production() {
    assert_eq!(HOST, "example.com");
}
""",
    # Positive controls: every refined rule must still catch its smell.
    "src/positive.rs": """use std::sync::Mutex;

use serde_jsonn::Value;

pub fn always(input: &str) -> bool {
    true
}

pub fn bio() -> String {
    "lorem ipsum".to_owned()
}

pub async fn bad(lock: &Mutex<()>) {
    let _guard = lock.lock().unwrap();
    tokio::task::yield_now().await;
}
""",
}


def scan(tmp_path: Path) -> list[dict]:
    root = tmp_path / "project"
    for rel, content in FILES.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    (root / "Cargo.toml").write_text(CARGO, encoding="utf-8")
    out = tmp_path / "report"
    proc = subprocess.run(
        [sys.executable, str(TOOL), "scan", str(root), "--format", "json",
         "--no-exec", "--no-gap-report", "--out", str(out)],
        capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode in (0, 1), proc.stderr
    reports = sorted(out.glob("rust-audit-*.json"))
    assert reports, proc.stdout + proc.stderr
    return json.loads(reports[-1].read_text())["findings"]


def test_refined_rules_do_not_fire_on_real_shapes(tmp_path):
    findings = scan(tmp_path)

    def hits(rule: str, **kw) -> list[dict]:
        return [f for f in findings
                if f["rule_id"] == rule
                and all(f.get(k) == v for k, v in kw.items())]

    assert not hits("R03", file="src/defaults.rs"), \
        "#[serde(default = ...)] helpers return the documented default"
    assert not hits("R03", file="src/format_params.rs"), \
        "inline format captures use their parameters"
    assert not hits("R04", file="src/error_message.rs"), \
        "error messages are not placeholder data"
    assert not hits("R04", file="tests/fixture.rs"), \
        "a tests/ fixture is not production data"
    assert not hits("R12", file="src/alphabet.rs"), \
        "the base64 alphabet is not a secret"
    assert not hits("R16", file="src/async_gate.rs"), \
        "a tokio::sync::Mutex guard is async, not a blocking lock"
    assert not hits("R18c", file="src/crates.rs"), \
        "a declared dependency cannot be a hallucinated crate"
    assert not hits("R18d", file="src/crates.rs"), \
        "a workspace member is not slopsquatting bait"
    assert not hits("R18d", file="Cargo.toml"), \
        "thiserror 2 is a published major"
    known_crates = ("`h2`", "`http`", "`h3`", "`md-5`")
    assert not [f for f in hits("R20", file="Cargo.toml")
                if any(name in f["message"] for name in known_crates)], \
        "h2/http/h3/md-5 are well-known crates"
    assert not hits("R18a", file="src/crates.rs"), \
        "declared crates are resolved"


def test_positive_controls_still_fire(tmp_path):
    findings = scan(tmp_path)

    def has(rule: str, **kw) -> bool:
        return any(f["rule_id"] == rule
                   and all(f.get(k) == v for k, v in kw.items())
                   for f in findings)

    assert has("R03", file="src/positive.rs", function="always"), \
        "a constant return is still stubbed logic"
    assert has("R04", file="src/positive.rs", function="bio"), \
        "a lorem-ipsum value is still a placeholder"
    assert has("R16", file="src/positive.rs", function="bad"), \
        "a std::sync::Mutex guard across await is still a deadlock risk"
    assert has("R18c", file="src/positive.rs"), \
        "an undeclared near-miss is still a hallucination"
    assert any("`serdee`" in f["message"] for f in findings
               if f["rule_id"] == "R20" and f["file"] == "Cargo.toml"), \
        "a declared typo is still a typosquat candidate"
