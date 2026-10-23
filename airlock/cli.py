"""``hermes airlock`` (owner's terminal) and ``/airlock`` (inside a conversation)."""
from __future__ import annotations

import json
import os
import time

from . import rules

LOCAL_SURFACES = {"cli", "tui", "desktop", "local"}


def _core():
    import sys
    return sys.modules[__package__]          # the plugin package itself (__init__.py)


def setup(subparser):
    subs = subparser.add_subparsers(dest="airlock_command")
    subs.add_parser("status", help="Policy in force, guarded profile, stop switch, tainted sessions")
    p = subs.add_parser("check", help="Dry run: what airlock would do with a command or a tool call")
    p.add_argument("command", help="a shell command, or a tool name with --args")
    p.add_argument("--args", help="tool arguments as JSON (then COMMAND is the tool name)")
    p.add_argument("--tainted", action="store_true", help="decide as in a session that read untrusted content")
    p = subs.add_parser("log", help="Last journal entries")
    p.add_argument("-n", type=int, default=20)
    p.add_argument("--type", help="only this entry type (block, approve, log, taint, approval, would_block...)")
    subs.add_parser("stop", help="Stop switch on: every outbound action is blocked until `hermes airlock resume`")
    subs.add_parser("resume", help="Stop switch off")
    p = subs.add_parser("clear", help="Clear the taint of a session after reviewing what it read")
    p.add_argument("session")
    subs.add_parser("policy", help="The merged policy airlock enforces, and any error in your policy file")
    subparser.set_defaults(func=run)


def run(args):
    core = _core()
    pol = core.get_policy()
    sub = getattr(args, "airlock_command", None) or "status"
    if sub == "status":
        print(status_text(core, pol))
    elif sub == "check":
        if args.args:
            tool, targs = args.command, json.loads(args.args)
        else:
            tool, targs = "terminal", {"command": args.command}
        ctx = core._context(pol, {}, tool)
        ctx.tainted = "a dry run marked tainted" if args.tainted else None
        d = rules.decide(pol, tool, targs, ctx)
        if not d:
            print("allow — nothing to report")
        else:
            print(f"{d.level} — {d.category}: {d.reason}  [{d.rule}]")
        src = rules.taint_source(pol, tool, targs, ctx)
        if src:
            print(f"taints the session: {src}")
    elif sub == "log":
        try:
            with open(core.journal_file(), encoding="utf-8") as f:
                lines = f.readlines()
        except OSError:
            lines = []
        rows = [json.loads(x) for x in lines if x.strip()]
        if args.type:
            rows = [r for r in rows if r.get("type") == args.type]
        for r in rows[-args.n:]:
            what = r.get("reason") or r.get("source") or r.get("choice") or ""
            print(f"{r.get('at')}  {r.get('type'):<15} {r.get('tool') or '':<16} {what}")
    elif sub in ("stop", "resume"):
        f = os.path.join(core._data_dir(), "STOP")
        if sub == "stop":
            open(f, "w").write(time.strftime("%Y-%m-%dT%H:%M:%S"))
            core.journal(pol, {"type": "stop_on"})
            print("Stop switch ON: every outbound action is blocked. `hermes airlock resume` to lift it.")
        else:
            if os.path.exists(f):
                os.remove(f)
            core.journal(pol, {"type": "stop_off"})
            print("Stop switch OFF.")
    elif sub == "clear":
        print("cleared" if core.clear(args.session, pol) else "that session was not tainted")
    elif sub == "policy":
        print(f"# source: {pol.source}  mode: {pol.mode}")
        for e in pol.errors:
            print(f"# ERROR: {e}")
        from . import _yaml
        print(_yaml.safe_dump(pol.raw, sort_keys=False, allow_unicode=True))


def status_text(core, pol, session=None):
    core._load_taint(pol)
    now = time.time()
    live = {k: v for k, v in core.S.taint.items() if now - float(v.get("at", 0)) < pol.taint_ttl}
    lines = [f"airlock — mode {pol.mode}, profile {core._profile()} "
             f"({'guarded' if core._guarded(pol) else 'not guarded by this policy'})",
             f"policy: {pol.source}" + (f" — {len(pol.errors)} error(s), see `hermes airlock policy`" if pol.errors
                                        else ""),
             f"stop switch: {'ON' if core._stopped() else 'off'}",
             f"tainted sessions: {len(live)}"]
    if session:
        src = core.tainted(session, pol)
        lines.append(f"this conversation: {'tainted by ' + src if src else 'clean'}")
    return "\n".join(lines)


def slash(raw_args="", *, session_id="", platform="", source=None, **kwargs):
    core = _core()
    pol = core.get_policy()
    arg = (raw_args or "").strip().lower()
    if arg == "clear":
        # Only the owner lifts a taint: from a local surface, or from one of the owner's own chats.
        owner = str(platform or "").lower() in LOCAL_SURFACES or (
            source is not None and str(getattr(source, "chat_id", "")) in core._owners(pol))
        if not owner:
            return "airlock: only the owner can clear a conversation's taint, from their own chat or terminal."
        return "airlock: this conversation is clean again." if core.clear(str(session_id), pol) else \
            "airlock: this conversation was not tainted."
    return status_text(core, pol, str(session_id or "")) + "\n/airlock clear — clear this conversation's taint " \
                                                           "(owner only)"
