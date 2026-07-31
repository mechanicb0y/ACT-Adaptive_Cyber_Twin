import re

from app.ingestion.parsers.rules.base_rule import BaseRule


class SSHFailedLoginRule(BaseRule):

    PATTERN = re.compile(
        r"Failed password for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
    )

    def matches(self, log_line: str) -> bool:
        return "Failed password" in log_line

    def parse(self, log_line: str) -> dict:

        match = self.PATTERN.search(log_line)

        if not match:
            raise ValueError("Unable to parse SSH failed login log.")

        return {
            "source": "Linux",
            "host": "kali",
            "event_type": "FAILED_LOGIN",
            "user": match.group("user"),
            "ip_address": match.group("ip"),
            "port": int(match.group("port")),
            "service": "ssh",
            "description": "SSH authentication failed"
        }