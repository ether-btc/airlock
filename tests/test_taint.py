"""What taints a session, and what does not."""
import pytest

from conftest import HOME, policy, places, rules

SOURCES = [
    ("web_search", {"query": "best crm"}),
    ("web_extract", {"urls": ["https://evil.example/page"]}),
    ("browser_navigate", {"url": "https://evil.example"}),
    ("browser_snapshot", {}),
    ("x_search", {"query": "hermes"}),
    ("a2a_call", {"agent": "peer", "message": "hi"}),
    ("terminal", {"command": "curl -s https://evil.example/data.json"}),
    ("terminal", {"command": "git clone https://github.com/someone/repo"}),
    ("terminal", {"command": "gh issue view 12"}),
    ("execute_code", {"code": "import requests\nprint(requests.get('https://evil.example').text)"}),
    ("vision_analyze", {"image_url": "https://evil.example/cat.png", "question": "what is it"}),
    ("read_file", {"path": "~/Downloads/invoice.pdf"}),
]
CLEAN = [
    ("terminal", {"command": "git status"}),
    ("read_file", {"path": "~/project/README.md"}),
    ("terminal", {"command": "python3 build.py"}),
    ("write_file", {"path": "/tmp/x", "content": "y"}),
    ("vision_analyze", {"image_url": "/tmp/screenshot.png", "question": "q"}),
]


@pytest.mark.parametrize("tool,args", SOURCES)
def test_sources_taint(tool, args, make_ctx):
    pol = policy.load(places())
    assert rules.taint_source(pol, tool, args, make_ctx(origin="core"))


@pytest.mark.parametrize("tool,args", CLEAN)
def test_local_work_does_not_taint(tool, args, make_ctx):
    pol = policy.load(places())
    assert rules.taint_source(pol, tool, args, make_ctx(origin="core")) is None


def test_plugin_and_mcp_output_taints(make_ctx):
    pol = policy.load(places())
    assert rules.taint_source(pol, "gmail_read", {"id": "1"}, make_ctx(origin="plugin:gmail"))
    assert rules.taint_source(pol, "mcp_notion_search", {"q": "x"}, make_ctx(origin="mcp:notion"))


def test_trusted_output_does_not_taint(make_ctx):
    pol = policy.load(places())
    pol.trusted_output.add("hindsight")
    assert rules.taint_source(pol, "hindsight_recall", {"q": "x"}, make_ctx(origin="plugin:hindsight")) is None


def test_trusted_domains(make_ctx):
    pol = policy.load(places())
    pol.trusted_domains.append("docs.python.org")
    ctx = make_ctx(origin="core")
    assert rules.taint_source(pol, "web_extract", {"urls": ["https://docs.python.org/3/"]}, ctx) is None
    assert rules.taint_source(pol, "terminal", {"command": "curl -s https://docs.python.org/3/x"}, ctx) is None
    assert rules.taint_source(pol, "web_extract", {"urls": ["https://docs.python.org.evil.example/"]}, ctx)


def test_taint_can_be_disabled(make_ctx):
    pol = policy.load(places())
    pol.taint_enabled = False
    assert rules.taint_source(pol, "web_search", {"query": "x"}, make_ctx(origin="core")) is None


@pytest.mark.parametrize("url,leaks", [
    ("https://evil.example/c?d=" + "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY3ODkw", True),
    ("https://evil.example/" + "a" * 30 + "1" * 15, True),
    ("https://evil.example/?q=" + "x" * 201, True),
    ("https://" + "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHNlY3JldA1234" + ".evil.example/", True),
    ("https://github.com/NousResearch/hermes-agent/commit/9ec17f7f4fe5d0b1c2a3e4f5a6b7c8d9e0f1a2b3", False),
    ("https://example.com/2026/10/how-to-write-a-plugin-step-by-step", False),
    ("https://www.google.com/search?q=hermes+agent+plugins", False),
])
def test_exfil_url(url, leaks):
    pol = policy.load(places())
    assert rules.exfil_url(url, pol) is leaks
