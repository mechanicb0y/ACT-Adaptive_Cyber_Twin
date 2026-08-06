#LinuxParser only separates the syslog structure and sends the record to the correct rule.
#he rules handle the meaning of each log, so adding new event support does not require changing the parser.

from typing import Iterable, Optional

from app.ingestion.parsers.base_parser import BaseParser
from app.ingestion.parsers.rules import default_linux_rules
from app.ingestion.parsers.rules.base_rule import BaseRule
from app.ingestion.parsers.syslog_record import SyslogRecord


class LinuxParser(BaseParser):

    def __init__(
        self,
        rules: Optional[Iterable[BaseRule]] = None,
        default_host: str = "unknown",
    ):
        # Rules are injected, not hard-coded, so tests can run one rule in
        # isolation and future sources can reuse the same parser shell.
        self.rules: list[BaseRule] = list(
            rules if rules is not None else default_linux_rules()
        )

        self.default_host = default_host

    def parse(self, log_line: str) -> Optional[dict]:
        """Parse one raw log line. Returns None when nothing matched."""

        if not log_line or not log_line.strip():
            return None

        record = SyslogRecord.from_line(
            log_line,
            default_host=self.default_host,
        )

        return self.parse_record(record)

    def parse_record(self, record: SyslogRecord) -> Optional[dict]:
        """Parse an already framed record. First matching rule wins."""

        for rule in self.rules:

            if rule.matches(record):
                result = rule.parse(record)
                result.setdefault("matched_rule", rule.name)
                return result

        return None
