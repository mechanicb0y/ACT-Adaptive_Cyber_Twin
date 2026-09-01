#One ip trying MANY DIFFERENT usernames in a short time.
#This is the attacker looking for which accounts exist before attacking one of them.
#Counting events cannot see it, so this rule counts distinct usernames instead.

from typing import List

from app.analyzer.correlation.base_correlation_rule import BaseCorrelationRule
from app.analyzer.correlation.time_window import find_distinct_burst, group_by
from app.config.detection_config import RuleSettings
from app.models.behavior import Behavior
from app.models.event_types import EventType, FailureReason
from app.storage.event_store import EventStore


class UserEnumerationRule(BaseCorrelationRule):

    name = "user-enumeration"
    behavior_name = "SSH User Enumeration"
    base_score = 40
    base_confidence = 0.8

    default_settings = RuleSettings(threshold=3, window_seconds=300)

    def detect(self, store: EventStore, settings: RuleSettings) -> List[Behavior]:

        failures = store.get_by_type(EventType.FAILED_LOGIN)

        behaviors: List[Behavior] = []

        for ip_address, events in group_by(failures, lambda e: e.ip_address).items():

            burst = find_distinct_burst(
                events,
                settings.window_seconds,
                settings.threshold,
                key=lambda event: event.user,
            )

            if not burst:
                continue

            users = sorted({event.user for event in burst if event.user})

            #usernames that do not exist on the machine are the strongest signal
            invalid = sorted(
                {
                    event.user
                    for event in burst
                    if event.metadata.get("failure_reason") == FailureReason.INVALID_USER
                }
            )

            behaviors.append(
                self.build_behavior(
                    description=(
                        f"{ip_address} tried {len(users)} different usernames "
                        f"({', '.join(users)})"
                    ),
                    evidence=burst,
                    attributes={
                        "ip_address": ip_address,
                        "distinct_users": len(users),
                        "users": users,
                        "invalid_users": invalid,
                    },
                )
            )

        return behaviors
