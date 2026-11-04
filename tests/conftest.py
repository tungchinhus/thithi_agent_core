import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault("THITHI_ROLES", str(ROOT / "config" / "roles.yaml"))
os.chdir(ROOT)


@pytest.fixture
def policy():
    from thithi.gateway.labels import LabelPolicy

    return LabelPolicy.from_yaml(ROOT / "config" / "labels.yaml")


@pytest.fixture
def agents():
    from thithi.orchestrator.agents import load_agents

    return load_agents(ROOT / "agents")


@pytest.fixture
def registry():
    from thithi.orchestrator.registry import default_registry

    return default_registry()
