"""Structured logging for the long-running service.

Two formats, chosen by ``ACT_LOG_FORMAT``:

* ``console`` (default) - short human lines, what the CLI has always printed.
* ``json`` - one JSON object per line, for journald / Docker / a log shipper.

``ACT_LOG_FILE`` adds a rotating file handler alongside the console
(``ACT_LOG_FILE_MAX_BYTES`` / ``ACT_LOG_FILE_BACKUP_COUNT`` control rotation).

Call :func:`configure_logging` once, early, from an entry point. Importing this
module does nothing on its own, so tests and the detection core are unaffected.
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Any, Optional

from app.core.settings import Settings, get_settings

_CONFIGURED = False

# Attributes already present on every LogRecord - anything not in here that a
# caller passed via ``extra=`` is treated as a structured field.
_RESERVED = set(
    logging.makeLogRecord({}).__dict__.keys()
) | {"message", "asctime", "taskName"}


class JsonFormatter(logging.Formatter):
    """Render a record as a single-line JSON object."""

    def __init__(self, *, service: str = "act") -> None:
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": _dt.datetime.fromtimestamp(
                record.created, tz=_dt.timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "service": self.service,
            "message": record.getMessage(),
        }

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack"] = self.formatStack(record.stack_info)

        for key, value in record.__dict__.items():
            if key in _RESERVED or key.startswith("_"):
                continue
            payload[key] = _coerce(value)

        return json.dumps(payload, default=str, ensure_ascii=False)


def _coerce(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple, dict)):
        return value
    return str(value)


class ConsoleFormatter(logging.Formatter):
    def __init__(self) -> None:
        super().__init__(
            fmt="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
            datefmt="%H:%M:%S",
        )


def configure_logging(settings: Optional[Settings] = None, *, force: bool = False) -> None:
    """Install ACT's handlers on the root logger. Safe to call more than once."""
    global _CONFIGURED
    if _CONFIGURED and not force:
        return

    settings = settings or get_settings()
    root = logging.getLogger()
    root.setLevel(settings.log_level)

    for handler in list(root.handlers):
        root.removeHandler(handler)

    formatter: logging.Formatter
    if settings.log_format == "json":
        formatter = JsonFormatter(service="act")
    else:
        formatter = ConsoleFormatter()

    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(formatter)
    root.addHandler(stream)

    if settings.log_file:
        path = Path(settings.log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            path,
            maxBytes=settings.log_file_max_bytes,
            backupCount=settings.log_file_backup_count,
            encoding="utf-8",
        )
        # A log file is almost always read by a shipper - always JSON there.
        file_handler.setFormatter(JsonFormatter(service="act"))
        root.addHandler(file_handler)

    # uvicorn installs its own handlers; let ours own the output instead.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        lg = logging.getLogger(name)
        lg.handlers.clear()
        lg.propagate = True

    _CONFIGURED = True
    logging.getLogger("app.core.logging").debug(
        "logging configured", extra={"format": settings.log_format, "level": settings.log_level}
    )


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
