# Copyright 2026 Otsoa Dubief
# SPDX-License-Identifier: Apache-2.0
"""Patterns run on text the agent writes: none may backtrack exponentially (CodeQL py/redos)."""
import time

from conftest import airlock

rules = __import__(f"{airlock.__name__}.rules", fromlist=["rules"])


def test_net_hosts_is_linear():
    for text in ("dig" + " !==!" * 40 + " ", "nc" + " -a=b" * 40 + " x", "dig" + " a=b=c" * 40 + " "):
        start = time.monotonic()
        rules.NET_HOSTS.search(text)
        assert time.monotonic() - start < 0.5


def test_net_hosts_still_finds_hosts():
    assert rules.NET_HOSTS.findall("dig example.com") == ["example.com"]
    assert rules.NET_HOSTS.findall("nslookup -type=txt leak.evil.net") == ["leak.evil.net"]
    assert rules.NET_HOSTS.findall("dig a=b=c d.evil.com") == ["d.evil.com"]
