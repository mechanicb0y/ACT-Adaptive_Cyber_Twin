#provides shared test settings and paths. Pytest loads it automatically, 
#allowing tests to import the backend code correctly from any location.

import sys
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).resolve().parents[1]

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

LOGS_DIR = Path(__file__).resolve().parent / "logs"

from app.analyzer.normalizer import EventNormalizer  # noqa: E402
from app.ingestion.parsers.linux_parser import LinuxParser  # noqa: E402
from app.storage.event_store import EventStore  # noqa: E402


@pytest.fixture(autouse=True)
def _no_local_llm(monkeypatch):
    """Keep the suite hermetic.

    ``LlmAnalyst`` auto-detects a local Ollama when one is reachable, which would
    make tests hit a real model - slow, and dependent on what is installed on the
    dev machine. Default every test to the no-LLM path; a test that wants a
    provider still sets ``ACT_LLM_PROVIDER`` itself and that wins.
    """
    monkeypatch.setenv("ACT_LLM_PROVIDER", "none")


@pytest.fixture
def logs_dir() -> Path:
    return LOGS_DIR


@pytest.fixture
def bruteforce_log(logs_dir: Path) -> Path:
    return logs_dir / "auth_bruteforce.log"


@pytest.fixture
def parser() -> LinuxParser:
    return LinuxParser()


@pytest.fixture
def normalizer() -> EventNormalizer:
    return EventNormalizer()


@pytest.fixture
def store() -> EventStore:
    return EventStore()
