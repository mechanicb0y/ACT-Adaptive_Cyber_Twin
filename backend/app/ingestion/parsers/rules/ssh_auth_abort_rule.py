#Real brute-force tools (hydra, medusa, ncrack, patator) rarely leave a tidy
#"Failed password for X" line for every guess. With the default MaxAuthTries a
#connection is dropped after a few tries and sshd logs one of:
#
#   error: maximum authentication attempts exceeded for root from IP port N ssh2 [preauth]
#   Connection closed by authenticating user root IP port N [preauth]
#   Connection reset by authenticating user root IP port N [preauth]
#   Disconnected from authenticating user root IP port N [preauth]
#
#Without this rule a 300-attempt attack can produce almost no FAILED_LOGIN
#events, so the brute-force / enumeration / compromise correlators never fire.
#The phrase "authenticating user" is the key: it means credentials were tried,
#which separates a real guess from a plain port probe.

import re

from app.ingestion.parsers.rules.base_rule import BaseRule
from app.ingestion.parsers.syslog_record import SyslogRecord
from app.models.event_types import EventType, FailureReason


class SSHAuthAbortRule(BaseRule):

    name = "ssh-auth-abort"
    process_hint = "sshd"

    MAX_TRIES = re.compile(
        r"maximum authentication attempts exceeded for "
        r"(?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
    )

    AUTH_DROP = re.compile(
        r"(?:Connection closed|Connection reset|Disconnected) (?:by|from) "
        r"authenticating user (?P<user>\S+) (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
    )

    def _match(self, message: str):
        return self.MAX_TRIES.search(message) or self.AUTH_DROP.search(message)

    def matches(self, record: SyslogRecord) -> bool:

        if not self.handles_process(record):
            return False

        return self._match(record.message) is not None

    def parse(self, record: SyslogRecord) -> dict:

        match = self._match(record.message)

        if not match:
            raise ValueError("Unable to parse SSH auth-abort log.")

        groups = match.groupdict()
        user = groups["user"]
        ip_address = groups["ip"]
        invalid = bool(groups.get("invalid"))

        maxed = match.re is self.MAX_TRIES

        return {
            **record.base_fields(),
            "event_type": EventType.FAILED_LOGIN,
            "user": user,
            "ip_address": ip_address,
            "description": (
                f"SSH brute-force attempt against user '{user}' from {ip_address} "
                + ("(hit MaxAuthTries)" if maxed else "(connection dropped at authentication)")
            ),
            "metadata": {
                "service": "ssh",
                "port": int(groups["port"]),
                "failure_reason": (
                    FailureReason.INVALID_USER if invalid else FailureReason.BAD_PASSWORD
                ),
                "auth_abort": "max_tries" if maxed else "dropped",
                "pid": record.pid,
            },
        }
