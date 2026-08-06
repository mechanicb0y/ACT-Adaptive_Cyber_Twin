#New local account created.
import re

from app.ingestion.parsers.rules.base_rule import BaseRule
from app.ingestion.parsers.syslog_record import SyslogRecord
from app.models.event_types import EventType


class UserAddedRule(BaseRule):

    name = "user-added"
    process_hint = "useradd"

    PATTERN = re.compile(
        r"new user:\s*name=(?P<user>[^,\s]+)"
        r"(?:.*?\bUID=(?P<uid>\d+))?"
        r"(?:.*?\bhome=(?P<home>[^,\s]+))?"
        r"(?:.*?\bshell=(?P<shell>[^,\s]+))?"
    )

    def matches(self, record: SyslogRecord) -> bool:

        if not self.handles_process(record):
            return False

        return self.PATTERN.search(record.message) is not None

    def parse(self, record: SyslogRecord) -> dict:

        match = self.PATTERN.search(record.message)

        if not match:
            raise ValueError("Unable to parse useradd log.")

        return {
            **record.base_fields(),
            "event_type": EventType.ACCOUNT_CREATED,
            "user": match.group("user"),
            "description": (
                f"New local account created: '{match.group('user')}'"
            ),
            "metadata": {
                "service": "useradd",
                "uid": int(match.group("uid")) if match.group("uid") else None,
                "home": match.group("home"),
                "shell": match.group("shell"),
                "pid": record.pid,
            },
        }
