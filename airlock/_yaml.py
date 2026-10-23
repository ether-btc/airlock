# Copyright 2026 Otsoa Dubief
# SPDX-License-Identifier: Apache-2.0
"""YAML reading: ruamel.yaml (shipped with Hermes, read with the YAML 1.1 rules Hermes uses for config.yaml) when
present, PyYAML otherwise (tests and tools outside Hermes)."""
import io

try:
    from ruamel.yaml import YAML as _YAML
except ImportError:                                  # outside Hermes
    _YAML = None
    import yaml as _pyyaml


def safe_load(stream):
    if _YAML is None:
        return _pyyaml.safe_load(stream)
    y = _YAML(typ="safe", pure=True)
    y.version = (1, 1)
    return y.load(stream if isinstance(stream, (str, bytes)) else stream.read())


def safe_dump(data, sort_keys=False, allow_unicode=True):
    if _YAML is None:
        return _pyyaml.safe_dump(data, sort_keys=sort_keys, allow_unicode=allow_unicode)
    y = _YAML(typ="safe", pure=True)
    y.default_flow_style = False
    out = io.StringIO()
    y.dump(data, out)
    return out.getvalue()
