"""``hermes airlock`` subcommands."""
import argparse

import pytest

from conftest import airlock
from test_plugin import FakeCtx, plugin  # noqa: F401  (fixture)

cli = __import__(f"{airlock.__name__}.cli", fromlist=["cli"])


def run(*argv):
    parser = argparse.ArgumentParser()
    cli.setup(parser)
    args = parser.parse_args(list(argv))
    cli.run(args)


def test_check_clean_and_tainted(plugin, capsys):
    run("check", "git status")
    assert capsys.readouterr().out.strip() == "verdict  : allow"
    run("check", "git push")
    out = capsys.readouterr().out
    assert "verdict  : approve" in out and "category : publish" in out and "rule     : egress.git-push" in out
    run("check", "--tainted", "--args", '{"action": "add", "content": "x"}', "memory")
    assert "category : persistence" in capsys.readouterr().out
    run("check", "curl -s https://example.com/x")
    assert "taints   : https://example.com/x" in capsys.readouterr().out


def test_demo_runs_nothing_and_seals(plugin, capsys):
    run("demo")
    out = capsys.readouterr().out
    assert out.count("→     BLOCK") == 4 and out.count("→     ASKS YOU") == 1 and "now sealed" in out
    assert not (plugin.data / "journal.jsonl").exists() and not (plugin.data / "taint.json").exists()


def test_stop_resume_and_status(plugin, capsys):
    run("stop")
    assert (plugin.data / "STOP").exists()
    run("status")
    assert "stop switch: ON" in capsys.readouterr().out
    run("resume")
    assert not (plugin.data / "STOP").exists()


def test_log_and_policy(plugin, capsys):
    plugin.hooks["pre_tool_call"](tool_name="terminal", args={"command": "git push"}, session_id="s")
    run("log", "-n", "5")
    assert "approve" in capsys.readouterr().out
    (plugin.home / "airlock.yaml").write_text("actions: [broken\n")
    run("policy")
    out = capsys.readouterr().out
    assert "# ERROR" in out and "mode: enforce" in out
