# Changelog

## 0.1.0 — unreleased

First public version.

- Taint: web, browser, MCP and plugin output, network reads in commands and code, untrusted paths, customer-facing
  platforms. Subagents inherit their parent's taint; a child's taint reaches its parent. Saved across restarts.
- Outbound categories with clean and tainted levels: message, network_write, publish, remote, install, persistence,
  delegation, browser_input, exfil_url, detach, written_script, unadmitted_tool, bypass.
- Walls: credential paths and secret file names, guard and configuration files, startup files, other profiles,
  forbidden words, commands that disable the guard or change identity, destructive deletions.
- Shell reading: quoting, heredocs, `sh -c`, `eval`, `find -exec`, inline code, decoding piped to interpreters,
  computed program names, aliases, wildcard program names, files written then executed.
- `hermes airlock` (status, check, demo, log, stop, resume, clear, policy) and `/airlock`.
- Observe mode, journal, stop switch, exact-call approval keys, fail-closed on internal errors.
