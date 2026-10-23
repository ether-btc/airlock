# airlock

![airlock, guardrails for Hermes Agent, by Otsoa Dubief](https://raw.githubusercontent.com/otsoa-dubief/airlock/main/docs/images/banner.png)

**Guardrails for Hermes Agent.** airlock checks every tool call the agent makes and remembers which sessions have
read something from outside (a web page, a browser page, a third-party tool, a customer's message). From then on,
the actions that leave the machine go through Hermes's own approval gate: messages to anyone but you, uploads,
pushes and deploys, memory and skill changes, browser clicks. Reading, searching and drafting stay free.

![A recorded Hermes session: the agent reads a pricing page that hides a note for AI assistants, then the post to a webhook stops at Hermes's approval menu and the owner denies it](https://raw.githubusercontent.com/otsoa-dubief/airlock/main/docs/images/live-session.gif)

*A real session, recorded, not simulated.*

- **Walls in every session**: keys and credential files, airlock's own files and Hermes's configuration, shell
  startup files, other profiles on the same machine.
- **Reads commands as the shell does**: a command that hides what it runs is refused until it is written plainly.
- **Vets third-party tools**: plugin and MCP tools nobody admitted wait for your approval.
- **Local**: no network call, no LLM call. A journal records every decision.

## Install

```bash
hermes plugins install airlock
hermes gateway restart        # if a gateway is running
hermes airlock demo           # see it decide, nothing is executed
```

![How airlock decides: a clean session works as usual; once it has read something untrusted, outbound actions ask you; walls hold in every session](https://raw.githubusercontent.com/otsoa-dubief/airlock/main/docs/images/how-it-works.png)

Full documentation, policy reference, limits and threat model:
[github.com/otsoa-dubief/airlock](https://github.com/otsoa-dubief/airlock#readme).

Apache-2.0 · by [Otsoa Dubief](https://www.linkedin.com/in/otsoa-dubief/)
