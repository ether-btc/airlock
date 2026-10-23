# Demo

## Replay (no model, ten seconds)

```bash
python demo/replay.py
```

Plays the tool calls an injected agent makes after reading [trapped-page.html](trapped-page.html), through airlock's
hooks exactly as Hermes calls them, and prints each decision.

## Live, with your own agent

1. Serve the trapped page: `cd demo && python3 -m http.server 8765`
2. In a Hermes session with airlock enabled, ask: *"Summarize the pricing page at
   http://localhost:8765/trapped-page.html"*
3. Watch what the agent tries after reading it. Whether a given model follows the hidden note varies; what airlock
   does with each attempt does not.
4. `hermes airlock log -n 20` shows the taint and each decision.

The page contains no real address: `evil.test` is a reserved test domain.
