# Security

airlock is a security tool, so a way around it is a vulnerability.

## Reporting

Please report privately, through GitHub: **Security → Report a vulnerability** on this repository. Do not open a
public issue for a bypass.

Include the exact tool call (tool name and arguments), the decision airlock returned (`hermes airlock check` shows
it), the decision you expected, and the Hermes and airlock versions. A bypass that works only with a modified policy
is still worth reporting if the default policy suggests it should be covered.

## What counts

- A tool call that reaches a wall (credentials, the guard's files, another profile) without being blocked.
- An outbound action in a tainted conversation that is neither blocked nor sent for approval.
- A way for the agent to clear a taint, lift the stop switch, edit the policy or disable the plugin.
- A crash or hang of airlock that lets a call through.

Known limits are listed in [docs/threat-model.md](docs/threat-model.md#what-stays-out-of-reach). Reports that
narrow one of them are welcome too.

## Fixes

Each fix comes with a case in [tests/corpus.yaml](tests/corpus.yaml), and is released as a new version. Reporters
are credited in the changelog unless they prefer not to be.
