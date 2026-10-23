"""Test setup: airlock is imported as a package from the repository's airlock/ directory, with a policy whose places
point at the real home directory (paths in the corpus use ~) and ~/.hermes as the default profile's Hermes home."""
import importlib
import os
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
PKG = "airlock"

airlock = importlib.import_module(PKG)
policy = importlib.import_module(f"{PKG}.policy")
rules = importlib.import_module(f"{PKG}.rules")
shell = importlib.import_module(f"{PKG}.shell")

HOME = os.path.realpath(os.path.expanduser("~"))
HERMES = os.path.join(HOME, ".hermes")


def places(**over):
    p = {"home": HOME, "hermes_home": HERMES, "hermes_root": HERMES,
         "plugin_dir": os.path.join(HERMES, "plugins", "airlock"), "policy_file": os.path.join(HERMES, "airlock.yaml"),
         "data_dir": os.path.join(HERMES, "plugin-data", "airlock")}
    p.update(over)
    return p


@pytest.fixture
def pol():
    return policy.load(places())


@pytest.fixture
def make_ctx():
    def make(**kw):
        base = dict(cwd=os.path.join(HOME, "project"), home=HOME, hermes_home=HERMES, hermes_root=HERMES,
                    profile="default", owners={"123456"})
        base.update(kw)
        return rules.Context(**base)
    return make
