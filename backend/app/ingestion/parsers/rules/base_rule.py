#Each rule checks if a log line matches and converts it into a raw event dictionary. Rules only handle text
#conversion and do not manage files, storage, or event objects. Adding a new log type only requires adding a new rule.

from abc import ABC, abstractmethod

from app.ingestion.parsers.syslog_record import SyslogRecord


class BaseRule(ABC):

    # Human readable name, used in logs and tests.
    name: str = "unnamed-rule"

    # The syslog process this rule cares about ("sshd", "sudo", ...).
    # None means "any process".
    process_hint: str | None = None

    def handles_process(self, record: SyslogRecord) -> bool:
        """Cheap pre-filter so we do not run regex on irrelevant lines."""

        if self.process_hint is None:
            return True

        if not record.envelope_parsed:
            return True  # cannot tell, let the rule decide for itself

        return self.process_hint in record.process

    @abstractmethod
    def matches(self, record: SyslogRecord) -> bool:
        """Return True if this rule can parse the record."""

    @abstractmethod
    def parse(self, record: SyslogRecord) -> dict:
        """Return the raw event dictionary for the EventNormalizer."""
