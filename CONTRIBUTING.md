# Contributing

Bug reports, bypasses (privately, see [SECURITY.md](SECURITY.md)), false positives and new detectors are welcome.

## Run the tests

```bash
python3 -m venv .venv && .venv/bin/pip install pytest pyyaml ruamel.yaml
cd tests && ../.venv/bin/python -m pytest -q
```

With Docker, `scripts/test_in_hermes_image.sh` runs catalog validation, the plugin doctor and an end-to-end hook test
in a throwaway container of the official Hermes image.

## README images

They come from real output: `docs/images/src/capture.sh` runs airlock in a throwaway container of the official Hermes
image and saves what it prints; `docs/images/src/render.cjs` (Playwright, ffmpeg) turns that into the PNGs and the GIF.
No image is drawn by hand from imagined output.

## Rules of the house

- **Every change to a decision comes with a case** in [tests/corpus.yaml](tests/corpus.yaml): the attack it stops,
  or the everyday command it stops bothering.
- **No network, no LLM call, no new dependency** in the plugin. Decisions must be fast, local and predictable.
- **Fail closed.** When a command cannot be read with confidence, airlock treats it as suspicious, not as safe.
- **Messages to the agent say what to do instead.** A refusal the model cannot act on makes it retry or give up.
- **Keep clean conversations quiet.** A detector that asks for approval on ordinary work trains people to approve
  without reading. Prefer `tainted`-only levels when the risk comes from untrusted content.
