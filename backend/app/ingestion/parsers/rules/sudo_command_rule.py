import re

from app.ingestion.parsers.rules.base_rule import BaseRule
from app.ingestion.parsers.syslog_record import SyslogRecord
from app.models.event_types import EventType


class SudoCommandRule(BaseRule):

    name = "sudo-command"
    process_hint = "sudo"

    PATTERN = re.compile(
        r"^\s*(?P<user>\S+)\s*:\s*"
        r"TTY=(?P<tty>\S*)\s*;\s*"
        r"PWD=(?P<pwd>\S*)\s*;\s*"
        r"USER=(?P<target_user>\S+)\s*;\s*"
        r"COMMAND=(?P<command>.+)$"
    )

    def matches(self, record: SyslogRecord) -> bool:

        if not self.handles_process(record):
            return False

        return self.PATTERN.search(record.message) is not None

    def parse(self, record: SyslogRecord) -> dict:

        match = self.PATTERN.search(record.message)

        if not match:
            raise ValueError("Unable to parse sudo command log.")

        return {
            **record.base_fields(),
            "event_type": EventType.SUDO_COMMAND,
            "user": match.group("user"),
            "description": (
                f"User '{match.group('user')}' ran a command as "
                f"'{match.group('target_user')}': {match.group('command')}"
            ),
            "metadata": {
                "service": "sudo",
                "command": match.group("command"),
                "target_user": match.group("target_user"),
                "tty": match.group("tty"),
                "cwd": match.group("pwd"),
                "pid": record.pid,
            },
        }
