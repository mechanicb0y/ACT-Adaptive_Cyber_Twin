#The most important rule in ACT so far.
#A successful login on its own is normal. A successful login right after many
#failures from the same ip means the attacker got in. Only correlation can see
#this, because neither event is suspicious alone.

from typing import List

from app.analyzer.correlation.base_correlation_rule import BaseCorrelationRule
from app.analyzer.correlation.time_window import (
    events_within,
    group_by,
    sort_by_time,
)
from app.config.detection_config import RuleSettings
from app.models.behavior import Behavior
from app.models.event_types import EventType
from app.storage.event_store import EventStore


class SuccessfulBruteForceRule(BaseCorrelationRule):

    name = "successful-brute-force"
    behavior_name = "Account Compromise After Brute Force"
    base_score = 85
    base_confidence = 0.95

    default_settings = RuleSettings(threshold=3, window_seconds=300)

    def detect(self, store: EventStore, settings: RuleSettings) -> List[Behavior]:

        successes = store.get_by_type(EventType.SUCCESSFUL_LOGIN)
        failures = store.get_by_type(EventType.FAILED_LOGIN)

        behaviors: List[Behavior] = []

        failures_by_ip = group_by(failures, lambda event: event.ip_address)

        for ip_address, logins in group_by(successes, lambda e: e.ip_address).items():

            attacker_failures = failures_by_ip.get(ip_address, [])

            if not attacker_failures:
                continue

            #the first success that follows enough failures is the moment of the breach
            for success in sort_by_time(logins):

                recent = events_within(
                    attacker_failures,
                    success.timestamp,
                    settings.window_seconds,
                )

                if len(recent) < settings.threshold:
                    continue

                evidence = sort_by_time(recent + [success])

                behaviors.append(
                    self.build_behavior(
                        description=(
                            f"User '{success.user}' logged in successfully from "
                            f"{ip_address} after {len(recent)} failed attempts"
                        ),
                        evidence=evidence,
                        attributes={
                            "ip_address": ip_address,
                            "target_user": success.user,
                            "failed_before_success": len(recent),
                            "compromised": True,
                        },
                    )
                )

                break   #one compromise per attacker address is enough

        return behaviors
