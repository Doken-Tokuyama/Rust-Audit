"""The PyPI artifact must be the same tool this repo runs and tests.

`scripts/rust_audit.py` is the single source of truth — it is what the suite
executes, what the release signs, and (via `py-modules`) what the wheel ships.
These checks fail when the metadata and the module drift apart: a distribution
whose entry point, version or data path is wrong is broken for everyone who
installs it, and nothing else in the suite would notice.
"""
import importlib.util
import re
import shutil
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TOOL = REPO / "scripts" / "rust_audit.py"
PYPROJECT = REPO / "pyproject.toml"
ALIAS = REPO / "packaging" / "rustaudit-alias" / "pyproject.toml"


def load_module(path=TOOL, name="rust_audit_probe"):
    # sys.modules first: the module defines dataclasses, and the decorator
    # resolves its own namespace through sys.modules.
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def tool_version():
    return re.search(r'^VERSION = "([^"]+)"', TOOL.read_text(), re.M).group(1)


def test_distribution_ships_the_tool_module():
    project = tomllib.loads(PYPROJECT.read_text())
    assert project["project"]["name"] == "rust-audit"
    setuptools = project["tool"]["setuptools"]
    assert setuptools["py-modules"] == ["rust_audit"]
    assert setuptools["package-dir"][""] == "scripts"
    assert setuptools["dynamic"]["version"] == {"attr": "rust_audit.VERSION"}
    assert "version" not in project["project"], (
        "the version lives in scripts/rust_audit.py only; a literal here would "
        "let the wheel and the signed asset disagree")


def test_both_commands_run_the_same_entry_point():
    project = tomllib.loads(PYPROJECT.read_text())
    scripts = project["project"]["scripts"]
    assert scripts["rust-audit"] == "rust_audit:main"
    assert scripts["rustaudit"] == "rust_audit:main"
    assert re.search(r"^def main\(", TOOL.read_text(), re.M), (
        "the entry point names a function the module does not define")


def test_alias_reserves_the_one_word_name():
    alias = tomllib.loads(ALIAS.read_text())
    version = tool_version()
    assert alias["project"]["name"] == "rustaudit"
    assert alias["project"]["version"] == version
    assert alias["project"]["dependencies"] == [f"rust-audit>={version}"]
    assert alias["tool"]["setuptools"]["packages"] == []
    assert "scripts" not in alias["project"], (
        "the alias must install no commands of its own, or it could shadow the "
        "real package's entry points")


def test_declared_data_files_exist():
    project = tomllib.loads(PYPROJECT.read_text())
    declared = project["tool"]["setuptools"]["data-files"]
    files = [path for paths in declared.values() for path in paths]
    assert files, "the wheel would install no resources at all"
    missing = [path for path in files if not (REPO / path).is_file()]
    assert not missing, f"data-files point at missing paths: {missing}"


def test_resource_lookup_prefers_the_repo_data():
    module = load_module()
    assert module._resource_dir() == REPO / "resources"
    assert module._template_dir() == REPO / "templates"
    curated = module.load_name_list("suspicious_names.txt", set())
    assert len(curated) > len(module.FALLBACK_SUSPICIOUS), (
        "the curated list must beat the embedded fallback, or the packaged "
        "data was lost and dependency detection silently degraded")


def test_installed_layout_reads_data_from_the_prefix(tmp_path, monkeypatch):
    """The wheel's shape: module in site-packages, data under share/."""
    site = tmp_path / "site-packages"
    site.mkdir()
    installed = site / "rust_audit.py"
    shutil.copyfile(TOOL, installed)          # no sibling resources here
    prefix = tmp_path / "prefix"
    data = prefix / "share" / "rustaudit" / "resources"
    data.mkdir(parents=True)
    (data / "popular_crates.txt").write_text("demo_crate\n")
    templates = prefix / "share" / "rustaudit" / "templates"
    templates.mkdir(parents=True)
    (templates / "deny.toml").write_text("[advisories]\n")
    module = load_module(installed, "rust_audit_installed")
    monkeypatch.setattr(module.sys, "prefix", str(prefix))
    assert module._resource_dir() == data
    assert module._template_dir() == templates
    assert module.load_name_list("popular_crates.txt", set()) == {"demo_crate"}
