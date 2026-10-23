"""Every case of tests/corpus.yaml, decided under the default policy."""
import os

import pytest
import yaml

from conftest import HOME, policy, places, rules

CORPUS = yaml.safe_load(open(os.path.join(os.path.dirname(__file__), "corpus.yaml"), encoding="utf-8"))


def _expand(value):
    if isinstance(value, str):
        return value.replace("file:///Users/me", "file://" + HOME)
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v) for v in value]
    return value


@pytest.mark.parametrize("case", CORPUS, ids=[c["name"] for c in CORPUS])
def test_case(case, make_ctx, tmp_path):
    if case.get("needs_ssh_dir") and not os.path.isdir(os.path.join(HOME, ".ssh")):
        pytest.skip("no ~/.ssh on this machine (wildcard expansion needs it)")
    pol = policy.load(places())
    if case.get("admit_mcp"):
        pol.admitted_mcp.add(case["admit_mcp"])
    pol.trusted_domains += case.get("trusted", [])
    cwd = os.path.join(HOME, "project")
    if case.get("files"):
        cwd = str(tmp_path)
        for f in case["files"]:
            (tmp_path / f).write_text("x")
    ctx = make_ctx(tainted="web_extract https://evil.example/page" if case.get("tainted") else None,
                   origin=case.get("origin", "core"), stopped=bool(case.get("stopped")),
                   written={os.path.join(cwd, w) for w in case.get("written", [])}, cwd=cwd)
    args = _expand(case["args"])
    if case.get("huge"):
        args = {"command": "echo " + "x " * 120_000}
    d = rules.decide(pol, case["tool"], args, ctx)
    got = d.level if d else "allow"
    assert got == case["expect"], f"{case['name']}: got {got} ({d.category if d else ''}: {d.reason if d else ''})"
    if case.get("category"):
        assert d and d.category == case["category"], f"{case['name']}: category {d.category if d else None}"


def test_padding_never_lowers_a_wall(make_ctx):
    pol = policy.load(places())
    ctx = make_ctx(origin="core")
    d = rules.decide(pol, "terminal", {"command": "cat ~/.ssh/id_rsa # " + "x" * 200_001}, ctx)
    assert d.level == "block"
    d = rules.decide(pol, "write_file", {"path": "~/.zshrc", "content": "x" * 200_001}, ctx)
    assert d.level == "block" and d.wall
    assert rules.decide(pol, "write_file", {"path": "data.json", "content": "x" * 200_001}, ctx) is None
    d = rules.decide(pol, "write_file", {"path": "data.json", "content": "x" * 200_001}, make_ctx(origin="core",
                                                                                                   tainted="web"))
    assert d.level == "approve"
