import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENV_PATTERN = re.compile(r"WEBX_[A-Z0-9_]+")


def _documented_envs(name):
    return set(ENV_PATTERN.findall((ROOT / name).read_text(encoding="utf-8")))


def _production_envs():
    found = set()
    for path in ROOT.rglob("*.py"):
        if "tests" in path.parts or ".git" in path.parts:
            continue
        found.update(ENV_PATTERN.findall(path.read_text(encoding="utf-8")))
    return found


def _structure(name):
    lines = (ROOT / name).read_text(encoding="utf-8").splitlines()
    return {
        "h2": sum(line.startswith("## ") for line in lines),
        "h3": sum(line.startswith("### ") for line in lines),
        "h4": sum(line.startswith("#### ") for line in lines),
        "fences": sum(line.startswith("```") for line in lines),
        "env_tables": sum(line.startswith("| Var |") for line in lines),
    }


def test_english_and_vietnamese_readmes_document_the_same_env_names():
    assert _documented_envs("README.md") == _documented_envs("README.vi.md")


def test_both_readmes_cover_every_production_webx_variable():
    production = _production_envs()
    assert production <= _documented_envs("README.md")
    assert production <= _documented_envs("README.vi.md")


def test_translated_readmes_keep_parallel_document_structure():
    assert _structure("README.md") == _structure("README.vi.md")
