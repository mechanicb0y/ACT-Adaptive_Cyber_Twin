#This detects SSH login attempts using usernames that do not exist. 
#It is a strong sign of brute-force or username enumeration attacks.

import re

from app.ingestion.parsers.rules.base_rule import BaseRule
from app.ingestion.parsers.syslog_record import SyslogRecord
from app.models.event_types import EventType, FailureReason


class SSHInvalidUserRule(BaseRule):

    name = "ssh-invalid-user"
    process_hint = "sshd"

    PATTERN = re.compile(
        r"Invalid user (?P<user>\S+) from (?P<ip>\S+)(?: port (?P<port>\d+))?"
    )

    def matches(self, record: SyslogRecord) -> bool:

        if not self.handles_process(record):
            return False

        # "Failed password for invalid user x" belongs to the failed-login
        # rule, not this one. Only the standalone notice is ours.
        if "Failed password" in record.message:
            return False

        return self.PATTERN.search(record.message) is not None

    def parse(self, record: SyslogRecord) -> dict:

        match = self.PATTERN.search(record.message)

        if not match:
            raise ValueError("Unable to parse SSH invalid user log.")

        port = match.group("port")

        return {
            **record.base_fields(),
            "event_type": EventType.FAILED_LOGIN,
            "user": match.group("user"),
            "ip_address": match.group("ip"),
            "description": (
                f"SSH login attempt for non-existent user "
                f"'{match.group('user')}' from {match.group('ip')}"
            ),
            "metadata": {
                "service": "ssh",
                "port": int(port) if port else None,
                "failure_reason": FailureReason.INVALID_USER,
                "pid": record.pid,
            },
        }
