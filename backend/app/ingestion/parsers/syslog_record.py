import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from app.utils.time_parser import parse_timestamp

SYSLOG_PATTERN = re.compile(
    r"^(?P<timestamp>"
    r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"  # Jul 30 21:51:43
    r"|"
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"  # 2026-08-06T14:12:03
    r"(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"  # optional ms / timezone
    r")\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[\w\-./]+)"
    r"(?:\[(?P<pid>\d+)\])?"
    r":\s+"
    r"(?P<message>.*)$"
)


@dataclass(slots=True)
class SyslogRecord:
    #One log line after the envelope has been split from the message

    timestamp: datetime

    host: str

    process: str

    message: str

    raw_line: str

    pid: Optional[int] = None

    # False when the line had no recognisable syslog envelope
    # (for example `journalctl -o cat`, which prints the message only).
    envelope_parsed: bool = True

    @classmethod
    def from_line(
        cls,
        line: str,
        default_host: str = "unknown",
    ) -> "SyslogRecord":

        raw = line.rstrip("\n")

        match = SYSLOG_PATTERN.match(raw.strip())

        if not match:
            # Not a framed syslog line. Treat the whole thing as the message
            # so rules can still try to match it.
            return cls(
                timestamp=datetime.now(),
                host=default_host,
                process="unknown",
                message=raw.strip(),
                raw_line=raw,
                envelope_parsed=False,
            )

        pid = match.group("pid")

        return cls(
            timestamp=parse_timestamp(match.group("timestamp")),
            host=match.group("host"),
            process=match.group("process"),
            message=match.group("message"),
            raw_line=raw,
            pid=int(pid) if pid else None,
        )

    def base_fields(self) -> dict:
        """Envelope fields every rule copies into its output dictionary."""

        return {
            "source": "Linux",
            "timestamp": self.timestamp,
            "host": self.host,
            "process": self.process,
            "raw_log": self.raw_line,
        }
