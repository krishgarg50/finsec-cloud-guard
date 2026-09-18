"""Shared pytest fixtures.

Also puts the project root on ``sys.path`` so ``import p2_scoring`` works from a
bare checkout with no install step -- P2's owner should be able to clone, run
``pytest``, and get a result.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DATA_DIR = ROOT / "data"
SEED_DIR = DATA_DIR / "seed"

RAW_MOCK_PATH = DATA_DIR / "mock_findings.raw.json"
HANDCRAFTED_PATH = SEED_DIR / "mock_findings.handcrafted.json"


def _load(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


@pytest.fixture(scope="session")
def raw_mocks() -> list[dict[str, Any]]:
    """P1-shaped raw findings (12 of them, covering all 12 rules)."""
    return _load(RAW_MOCK_PATH)


@pytest.fixture(scope="session")
def handcrafted_findings() -> list[dict[str, Any]]:
    """The Week-0 hand-authored enriched findings, frozen as a regression fixture."""
    return _load(HANDCRAFTED_PATH)


@pytest.fixture(scope="session")
def raws_by_id(raw_mocks: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {f["finding_id"]: f for f in raw_mocks}


@pytest.fixture(scope="session")
def handcrafted_by_id(handcrafted_findings: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {f["finding_id"]: f for f in handcrafted_findings}
