import re

from app.ingestion.parsers.rules.base_rule import BaseRule
from app.ingestion.parsers.syslog_record import SyslogRecord
from app.models.event_types import EventType


class SudoAuthFailureRule(BaseRule):

    name = "sudo-auth-failure"
    process_hint = "sudo"

    PATTERN = re.compile(
        r"pam_unix\(sudo:auth\): authentication failure;.*?"
        r"(?:\buser=(?P<user>\S+))"
    )

    RHOST_PATTERN = re.compile(r"rhost=(?P<rhost>\S+)")

    def matches(self, record: SyslogRecord) -> bool:

        if not self.handles_process(record):
            return False

        return self.PATTERN.search(record.message) is not None

    def parse(self, record: SyslogRecord) -> dict:

        match = self.PATTERN.search(record.message)

        if not match:
            raise ValueError("Unable to parse sudo auth failure log.")

        rhost_match = self.RHOST_PATTERN.search(record.message)
        rhost = rhost_match.group("rhost") if rhost_match else None

        return {
            **record.base_fields(),
            "event_type": EventType.SUDO_FAILURE,
            "user": match.group("user"),
            "ip_address": rhost or None,
            "description": (
                f"Failed sudo authentication by user "
                f"'{match.group('user')}'"
            ),
            "metadata": {
                "service": "sudo",
                "pid": record.pid,
            },
        }
