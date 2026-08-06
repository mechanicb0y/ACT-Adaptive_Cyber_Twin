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
