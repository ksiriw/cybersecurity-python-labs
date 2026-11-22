import json
from pathlib import Path

import pytest

SAMPLE_PATH = Path(__file__).resolve().parent.parent / "data" / "nvd_sample.json"


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    """Заборонити справжні запити Requests і прибрати успадкований ключ."""
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delattr("requests.sessions.Session.request")


@pytest.fixture
def sample_path() -> Path:
    """Шлях до синтетичної відповіді NVD."""
    return SAMPLE_PATH


@pytest.fixture
def sample_payload() -> dict:
    """Новий словник із синтетичною відповіддю для кожного тесту."""
    return json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))
