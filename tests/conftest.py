from datetime import date
from pathlib import Path

import pytest

from zeijaku_kakunin.config import load_config
from zeijaku_kakunin.models import Advisory, Component, EnvInventory

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
TODAY = date(2026, 11, 20)


@pytest.fixture
def config():
    return load_config(None)


@pytest.fixture
def examples():
    return EXAMPLES


def make_env(name="env1", exposure="internal", os_family="linux", components=(), **kwargs):
    env = EnvInventory(name=name, exposure=exposure, os_family=os_family, registered=True,
                       full_collection=True, **kwargs)
    env.components = list(components)
    return env


def make_advisory(**kwargs):
    kwargs.setdefault("advisory_id", "ADV-T")
    return Advisory(**kwargs)


def comp(name, version="", **kwargs):
    return Component(name=name, version=version, **kwargs)
