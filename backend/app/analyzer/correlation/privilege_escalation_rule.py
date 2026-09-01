#Failed sudo attempts, meaning someone is trying to become root.
#On its own a failed sudo is often just a typo, so this rule scores low by default.
#But if the same user logged in remotely just before, it becomes much more serious,
#and the risk engine raises the score for exactly that reason.

from typing import List

from app.analyzer.correlation.base_correlation_rule import BaseCorrelationRule
from app.analyzer.correlation.time_window import (
    events_within,
    find_bursts,
    group_by,
    is_remote_ip,
)
from app.config.detection_config import RuleSettings
from app.models.behavior import Behavior
from app.models.event_types import EventType
from app.storage.event_store import EventStore


class PrivilegeEscalationRule(BaseCorrelationRule):

    name = "privilege-escalation"
    behavior_name = "Privilege Escalation Attempt"
    base_score = 30
    base_confidence = 0.7

    default_settings = RuleSettings(threshold=1, window_seconds=300)

    def detect(self, store: EventStore, settings: RuleSettings) -> List[Behavior]:

        sudo_failures = store.get_by_type(EventType.SUDO_FAILURE)
        logins = store.get_by_type(EventType.SUCCESSFUL_LOGIN)

        behaviors: List[Behavior] = []

        for user, events in group_by(sudo_failures, lambda e: e.user).items():

            for burst in find_bursts(events, settings.window_seconds, settings.threshold):

                #was this user logged in from outside just before?
                user_logins = [login for login in logins if login.user == user]

                before = events_within(
                    user_logins,
                    burst[0].timestamp,
                    settings.window_seconds,
                )

                remote = [
                    login for login in before if is_remote_ip(login.ip_address)
                ]

                source_ip = remote[-1].ip_address if remote else None

                behaviors.append(
                    self.build_behavior(
                        description=(
                            f"{len(burst)} failed sudo attempt(s) by user '{user}'"
                            + (f", logged in from {source_ip}" if source_ip else "")
                        ),
                        evidence=burst,
                        attributes={
                            "target_user": user,
                            "ip_address": source_ip,
                            "attempt_count": len(burst),
                            "after_remote_login": bool(remote),
                        },
                    )
                )

        return behaviors
