"""Structured logging: JSON output shape and rotating-file wiring."""

import json
import logging

import pytest

from app.core.logging import JsonFormatter, configure_logging
from app.core.settings import reload_settings


def test_json_formatter_emits_one_object_with_extras():
    formatter = JsonFormatter(service="act")
    record = logging.LogRecord(
        name="app.test", level=logging.INFO, pathname=__file__, lineno=1,
        msg="hello %s", args=("world",), exc_info=None,
    )
    record.attacker_ip = "10.0.0.9"
    record.risk = 87

    payload = json.loads(formatter.format(record))

    assert payload["message"] == "hello world"
    assert payload["level"] == "INFO"
    assert payload["logger"] == "app.test"
    assert payload["service"] == "act"
    assert payload["attacker_ip"] == "10.0.0.9"
    assert payload["risk"] == 87
    assert "ts" in payload


def test_json_formatter_includes_exception_text():
    formatter = JsonFormatter()
    try:
        raise ValueError("nope")
    except ValueError:
        import sys
        record = logging.LogRecord(
            name="app.test", level=logging.ERROR, pathname=__file__, lineno=1,
            msg="failed", args=(), exc_info=sys.exc_info(),
        )
    payload = json.loads(formatter.format(record))
    assert "ValueError: nope" in payload["exception"]


def test_configure_logging_json_and_rotating_file(tmp_path, monkeypatch):
    log_file = tmp_path / "act.log"
    monkeypatch.setenv("ACT_LOG_FORMAT", "json")
    monkeypatch.setenv("ACT_LOG_FILE", str(log_file))
    monkeypatch.setenv("ACT_LOG_LEVEL", "DEBUG")
    reload_settings()

    try:
        configure_logging(force=True)
        logging.getLogger("app.phase1").info("wired", extra={"k": "v"})
        for handler in logging.getLogger().handlers:
            handler.flush()

        assert log_file.exists()
        line = log_file.read_text(encoding="utf-8").strip().splitlines()[-1]
        payload = json.loads(line)
        assert payload["message"] == "wired"
        assert payload["k"] == "v"
    finally:
        monkeypatch.undo()
        reload_settings()
        configure_logging(force=True)


@pytest.fixture(autouse=True)
def _restore_root_logging():
    yield
    reload_settings()
    configure_logging(force=True)
