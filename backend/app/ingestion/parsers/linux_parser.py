from app.ingestion.parsers.base_parser import BaseParser
from app.ingestion.parsers.rules.ssh_failed_login_rule import (
    SSHFailedLoginRule,
)


class LinuxParser(BaseParser):

    def __init__(self):

        self.rules = [
            SSHFailedLoginRule()
        ]

    def parse(self, log_line: str) -> dict:

        for rule in self.rules:

            if rule.matches(log_line):

                return rule.parse(log_line)

        raise ValueError("No parser rule matched this log.")