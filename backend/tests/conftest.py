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


#Secrets and deployment pointers that backend/.env may hold. Since the core
#modules now load .env on import (app.core.settings -> app.config.env), those
#values would otherwise leak into the suite and make tests depend on the dev
#machine's .env. Strip them for every test; a test that needs one sets it itself.
_NEUTRALISED_ENV = (
    "ACT_LLM_PROVIDER",
    "TELEGRAM_BOT_TOKEN",
    "TELEGRAM_CHAT_ID",
    "GEMINI_API_KEY",
    "ANTHROPIC_API_KEY",
    "DATABASE_URL",
    "ACT_LOG_FILE",
    "ACT_ADMIN_PASSWORD",
    "ACT_OAUTH_GOOGLE_CLIENT_ID",
    "ACT_OAUTH_GOOGLE_CLIENT_SECRET",
    "ACT_OAUTH_GITHUB_CLIENT_ID",
    "ACT_OAUTH_GITHUB_CLIENT_SECRET",
    "ACT_OAUTH_ALLOWED_DOMAINS",
)


@pytest.fixture(autouse=True)
def _hermetic_env(monkeypatch):
    """Keep the suite hermetic and independent of ``backend/.env``.

    ``LlmAnalyst`` auto-detects a local Ollama when one is reachable, which would
    make tests hit a real model - slow, and dependent on what is installed on the
    dev machine. Force the no-LLM path, clear the alert / cloud-key / DB / OAuth
    variables so a populated ``.env`` cannot change a test's outcome, and default
    authentication OFF (the historic prototype behaviour every non-auth test
    expects). ``test_auth.py`` turns auth back on explicitly.
    """
    for name in _NEUTRALISED_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ACT_LLM_PROVIDER", "none")
    monkeypatch.setenv("ACT_AUTH_ENABLED", "false")
    monkeypatch.setenv("ACT_JWT_SECRET", "test-secret-not-for-production-0123456789")

    from app.core.settings import reload_settings
    reload_settings()


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


@pytest.fixture
def db_session(monkeypatch, tmp_path):
    """A throwaway SQLite database in a temp file, one per test.

    A file (not ``:memory:``) so a second session or a bare ``engine.connect()``
    in the same test sees the same data without fighting over one shared
    connection. ``reset_engine`` / ``reload_settings`` on the way in and out keep
    the process-wide caches from leaking between tests.
    """
    from app.core.settings import reload_settings
    from app.db import get_sessionmaker, init_db, reset_engine

    db_path = tmp_path / "act_test.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    reload_settings()
    reset_engine()
    init_db()

    session = get_sessionmaker()()
    try:
        yield session
    finally:
        session.rollback()
        session.close()
        reset_engine()
        reload_settings()
