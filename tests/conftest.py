import json
from pathlib import Path

import pytest

from generator import build

FIXTURES = Path(__file__).parent / "fixtures"
SNAPSHOT = FIXTURES / "snapshot.json"
ALLOWLIST = FIXTURES / "allowlist.txt"


@pytest.fixture
def snapshot_raw() -> dict:
    return json.loads(SNAPSHOT.read_text())


@pytest.fixture
def out(tmp_path) -> Path:
    target = tmp_path / "out"
    build.build(SNAPSHOT, target, allowlist=ALLOWLIST)
    return target
