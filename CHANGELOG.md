# Changelog

## 0.2.0 — 2026-10-23

Defenses that catch an injection by its signature, whatever the command looks like:

- Secrets never leave: recognized key and token formats in a call that leaves the machine are blocked
  (`secrets_out`), in every conversation and whatever the approvals.
- Canary: a private marker in the agent's context every turn; seen in a tool call, the call is blocked and the
  conversation locked (`canary`).
- Destinations: after untrusted content, a call to a host or e-mail address that the content named is blocked
  (`destinations`); a named mail recipient asks the owner. The pages read themselves (the source, search results)
  and common hosts are not counted; a page that names thousands of addresses makes every address count.
- Circuit breaker: three refused calls in a tainted conversation lock it until the owner clears it (`breaker`).
- Unicode: compatibility forms folded (NFKC), invisible and direction-changing characters refused in commands,
  program names that mix lookalike letters (Cyrillic, Greek) with Latin ones, or use IPA, fullwidth or mathematical
  letters, refused. A name written in another script (`./отчёт.sh`) and ordinary punctuation (`…`, `，`) stay free.
- Code review fixes since 0.1.0: case-insensitive filesystems (macOS, Windows), oversized content, `rm -rf ~/*`,
  empty variables inside paths, a concurrency issue that could drop a taint.

## 0.1.0 — 2026-10-23

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
