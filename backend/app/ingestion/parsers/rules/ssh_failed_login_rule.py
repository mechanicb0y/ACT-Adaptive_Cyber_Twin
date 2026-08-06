import re

from app.ingestion.parsers.rules.base_rule import BaseRule
from app.ingestion.parsers.syslog_record import SyslogRecord
from app.models.event_types import EventType, FailureReason


class SSHFailedLoginRule(BaseRule):

    name = "ssh-failed-login"
    process_hint = "sshd"

    PATTERN = re.compile(
        r"Failed (?P<method>password|publickey) for "
        r"(?P<invalid>invalid user )?"
        r"(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
    )

    def matches(self, record: SyslogRecord) -> bool:

        if not self.handles_process(record):
            return False

        return self.PATTERN.search(record.message) is not None

    def parse(self, record: SyslogRecord) -> dict:

        match = self.PATTERN.search(record.message)

        if not match:
            raise ValueError("Unable to parse SSH failed login log.")

        invalid = match.group("invalid") is not None

        return {
            **record.base_fields(),
            "event_type": EventType.FAILED_LOGIN,
            "user": match.group("user"),
            "ip_address": match.group("ip"),
            "description": (
                f"SSH authentication failed for user "
                f"'{match.group('user')}' from {match.group('ip')}"
            ),
            "metadata": {
                "service": "ssh",
                "port": int(match.group("port")),
                "auth_method": match.group("method"),
                "failure_reason": (
                    FailureReason.INVALID_USER
                    if invalid
                    else FailureReason.BAD_PASSWORD
                ),
                "pid": record.pid,
            },
        }
