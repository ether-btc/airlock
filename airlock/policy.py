"""Loading the policy: the shipped default, merged with the owner's file, placeholders expanded, patterns compiled.

A broken user policy never weakens the guard: airlock reports the error and keeps the default policy.
"""
from __future__ import annotations

import copy
import os
import re
from dataclasses import dataclass, field

from . import _yaml as yaml

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_FILE = os.path.join(HERE, "default_policy.yaml")
LEVELS = ("allow", "log", "approve", "block")
CATEGORIES = ("message", "network_write", "publish", "remote", "install", "persistence", "delegation", "browser_input",
              "exfil_url", "detach", "written_script", "unadmitted_tool", "bypass")


def merge(base, extra):
    """Mappings merge key by key, lists are appended (without duplicates), anything else is replaced."""
    if isinstance(base, dict) and isinstance(extra, dict):
        out = dict(base)
        for k, v in extra.items():
            out[k] = merge(base[k], v) if k in base else copy.deepcopy(v)
        return out
    if isinstance(base, list) and isinstance(extra, list):
        return base + [x for x in extra if x not in base]
    return copy.deepcopy(extra)


@dataclass
class Policy:
    raw: dict
    places: dict
    errors: list = field(default_factory=list)
    source: str = "default"

    # --- plain settings
    @property
    def mode(self):
        return "observe" if str(self.raw.get("mode", "enforce")).lower() == "observe" else "enforce"

    @property
    def profiles(self):
        return [str(p) for p in self.raw.get("profiles") or []]

    def action(self, category, tainted):
        a = (self.raw.get("actions") or {}).get(category) or {}
        level = str(a.get("tainted" if tainted else "clean", "approve")).lower()
        return level if level in LEVELS else "approve"

    # --- compiled parts, built once
    def __post_init__(self):
        disabled = set(str(x) for x in self.raw.get("disable") or [])
        walls = self.raw.get("walls") or {}
        self.read_write = [p for p in (self._place(x) for x in walls.get("read_write") or []) if p]
        self.write_only = [p for p in (self._place(x) for x in walls.get("write") or []) if p]
        self.secret_files = self._compile(walls.get("secret_files") or [], "walls.secret_files")
        self.secret_except = self._compile(walls.get("secret_files_except") or [], "walls.secret_files_except")
        self.isolate_profiles = bool(walls.get("isolate_profiles", True))
        self.words = self._compile(walls.get("words") or [], "walls.words", flags=re.I)
        self.commands = []
        for c in walls.get("commands") or []:
            if not isinstance(c, dict) or c.get("id") in disabled:
                continue
            rx = self._compile([c.get("pattern", "")], f"walls.commands.{c.get('id')}", flags=re.I)
            if rx:
                self.commands.append((c.get("id"), rx[0], str(c.get("reason") or "forbidden command")))
        self.destructive = self._compile([self._place(x, keep_unknown=True) for x in walls.get("destructive") or []],
                                         "walls.destructive")
        self.egress = []
        for e in self.raw.get("egress") or []:
            if not isinstance(e, dict) or e.get("id") in disabled:
                continue
            cat = str(e.get("category") or "")
            if cat not in CATEGORIES:
                self.errors.append(f"egress.{e.get('id')}: unknown category {cat!r}")
                continue
            rx = self._compile([e.get("pattern", "")], f"egress.{e.get('id')}")
            on = "raw" if str(e.get("match") or "").lower() == "raw" else "views"
            if rx:
                self.egress.append((str(e.get("id")), cat, rx[0], on))
        self.persistence_paths = [x for x in (self._place(v) for v in self.raw.get("persistence_paths") or []) if x]
        self.tool_categories = {str(k): str(v) for k, v in (self.raw.get("tool_categories") or {}).items()
                                if str(v) in CATEGORIES}
        self.read_actions = {str(k): {str(a) for a in v or []}
                             for k, v in (self.raw.get("read_actions") or {}).items()}
        taint = self.raw.get("taint") or {}
        self.taint_enabled = bool(taint.get("enabled", True))
        self.source_tools = {str(t) for t in taint.get("source_tools") or []}
        self.source_patterns = self._compile(taint.get("source_patterns") or [], "taint.source_patterns")
        self.trusted_domains = [str(d).lower().lstrip(".") for d in taint.get("trusted_domains") or []]
        self.untrusted_paths = [p for p in (self._place(x) for x in taint.get("untrusted_paths") or []) if p]
        self.taint_platforms = {str(p).lower() for p in taint.get("platforms") or []}
        self.taint_ttl = float(taint.get("ttl_hours") or 72) * 3600
        tools = self.raw.get("tools") or {}
        self.admitted_plugins = {str(p).replace("_", "-") for p in tools.get("admitted_plugins") or []}
        self.admitted_mcp = {str(p) for p in tools.get("admitted_mcp_servers") or []}
        self.admitted_tools = {str(p) for p in tools.get("admitted_tools") or []}
        self.trusted_output = {str(p).replace("_", "-") for p in tools.get("trusted_output") or []}
        self.owner_channels = [str(c) for c in self.raw.get("owner_channels") or []]
        self.approvals_off = "follow" if str(self.raw.get("approvals_off", "block")).lower() == "follow" else "block"
        journal = self.raw.get("journal") or {}
        self.journal_enabled = bool(journal.get("enabled", True))
        self.journal_args = str(journal.get("args", "full")).lower() != "none"
        self.journal_max = float(journal.get("max_mb") or 20) * 1024 * 1024

    def _place(self, value, keep_unknown=False):
        """Expand {placeholders}; an entry whose placeholder is empty (no policy file yet) is dropped."""
        value = str(value)
        missing = []

        def sub(m):
            k = m.group(1)
            if k in self.places:
                if not self.places[k]:
                    missing.append(k)
                return re.escape(self.places[k]) if keep_unknown else self.places[k]
            return m.group(0)
        out = re.sub(r"\{(\w+)\}", sub, value)
        if missing:
            return "" if not keep_unknown else out
        return os.path.realpath(os.path.expanduser(out)) if not keep_unknown else out

    def _compile(self, patterns, where, flags=0):
        out = []
        for p in patterns:
            if not p:
                continue
            try:
                out.append(re.compile(str(p), flags))
            except re.error as e:
                self.errors.append(f"{where}: invalid pattern {p!r} ({e})")
        return out


def load(places: dict, user_file: str | None = None) -> Policy:
    """The default policy merged with ``user_file`` (if it exists). Errors are kept on the policy, never raised."""
    with open(DEFAULT_FILE, encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    errors, source = [], "default"
    if user_file and os.path.exists(user_file):
        try:
            with open(user_file, encoding="utf-8") as f:
                extra = yaml.safe_load(f) or {}
            if not isinstance(extra, dict):
                raise ValueError("the policy file must be a mapping")
            unknown = set(extra) - set(raw) - {"disable"}
            if unknown:
                errors.append(f"{user_file}: unknown keys {sorted(unknown)} (ignored)")
                extra = {k: v for k, v in extra.items() if k not in unknown}
            raw = merge(raw, extra)
            source = user_file
        except Exception as e:                      # a broken file keeps the default policy, never a weaker one
            errors.append(f"{user_file}: {e} (default policy kept)")
    pol = Policy(raw=raw, places=dict(places), source=source)
    pol.errors[:0] = errors
    return pol
