# airlock is installed

**Guardrails for Hermes Agent** by **Otsoa Dubief** · https://github.com/otsoa-dubief/airlock

1. Restart a running gateway so it loads the plugin: `hermes gateway restart`
2. See it work, nothing is executed: `hermes airlock demo`
3. Check what is in force: `hermes airlock status`

Want to watch before it acts? Put `mode: observe` in `<HERMES_HOME>/airlock.yaml`, then read
`hermes airlock log` after a few days of real work.

Policy reference, limits and threat model: https://github.com/otsoa-dubief/airlock#readme
