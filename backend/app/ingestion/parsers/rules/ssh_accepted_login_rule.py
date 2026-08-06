#This detects successful SSH logins. A single success is normal, 
#but if it happens after many failed attempts from the same IP, it may indicate a successful compromise.

import re

from app.ingestion.parsers.rules.base_rule import BaseRule
from app.ingestion.parsers.syslog_record import SyslogRecord
from app.models.event_types import EventType


class SSHAcceptedLoginRule(BaseRule):

    name = "ssh-accepted-login"
    process_hint = "sshd"

    PATTERN = re.compile(
        r"Accepted (?P<method>password|publickey|keyboard-interactive\S*) for "
        r"(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
    )

    def matches(self, record: SyslogRecord) -> bool:

        if not self.handles_process(record):
            return False

        return self.PATTERN.search(record.message) is not None

    def parse(self, record: SyslogRecord) -> dict:

        match = self.PATTERN.search(record.message)

        if not match:
            raise ValueError("Unable to parse SSH accepted login log.")

        return {
            **record.base_fields(),
            "event_type": EventType.SUCCESSFUL_LOGIN,
            "user": match.group("user"),
            "ip_address": match.group("ip"),
            "description": (
                f"Successful SSH login for user "
                f"'{match.group('user')}' from {match.group('ip')}"
            ),
            "metadata": {
                "service": "ssh",
                "port": int(match.group("port")),
                "auth_method": match.group("method"),
                "pid": record.pid,
            },
        }
