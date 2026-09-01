#A new local account was created.
#This is how an attacker keeps his access after the original password is changed.
#Creating a user is a normal admin task, so what matters is the context:
#if a remote login happened shortly before, this is very likely a backdoor.

from typing import List

from app.analyzer.correlation.base_correlation_rule import BaseCorrelationRule
from app.analyzer.correlation.time_window import (
    events_within,
    group_by,
    is_remote_ip,
    sort_by_time,
)
from app.config.detection_config import RuleSettings
from app.models.behavior import Behavior
from app.models.event_types import EventType
from app.storage.event_store import EventStore


class PersistenceRule(BaseCorrelationRule):

    name = "persistence"
    behavior_name = "Suspicious Account Creation"
    base_score = 60
    base_confidence = 0.85

    default_settings = RuleSettings(threshold=1, window_seconds=900)

    def detect(self, store: EventStore, settings: RuleSettings) -> List[Behavior]:

        created = store.get_by_type(EventType.ACCOUNT_CREATED)
        logins = store.get_by_type(EventType.SUCCESSFUL_LOGIN)

        behaviors: List[Behavior] = []

        for host, events in group_by(created, lambda e: e.host).items():

            if len(events) < settings.threshold:
                continue

            accounts = sorted({event.user for event in events if event.user})

            first = sort_by_time(events)[0]

            before = events_within(logins, first.timestamp, settings.window_seconds)

            remote = [login for login in before if is_remote_ip(login.ip_address)]

            source_ip = remote[-1].ip_address if remote else None

            behaviors.append(
                self.build_behavior(
                    description=(
                        f"New account(s) created on {host}: {', '.join(accounts)}"
                        + (f", shortly after a login from {source_ip}" if source_ip else "")
                    ),
                    evidence=events,
                    attributes={
                        "host": host,
                        "accounts": accounts,
                        "ip_address": source_ip,
                        "after_remote_login": bool(remote),
                        "persistence": True,
                    },
                )
            )

        return behaviors
