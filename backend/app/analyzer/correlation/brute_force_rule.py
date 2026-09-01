#Many failed logins for the SAME user from the SAME ip, inside one time window.
#Week 1 counted failures forever, so a user who mistyped his password five times
#over three months looked identical to an attack. Now the window decides.

from typing import List

from app.analyzer.correlation.base_correlation_rule import BaseCorrelationRule
from app.analyzer.correlation.time_window import find_bursts, group_by
from app.config.detection_config import RuleSettings
from app.models.behavior import Behavior
from app.models.event_types import EventType
from app.storage.event_store import EventStore


class BruteForceRule(BaseCorrelationRule):

    name = "brute-force"
    behavior_name = "Possible Brute Force Attack"
    base_score = 45
    base_confidence = 0.85

    default_settings = RuleSettings(threshold=5, window_seconds=120)

    def detect(self, store: EventStore, settings: RuleSettings) -> List[Behavior]:

        failures = store.get_by_type(EventType.FAILED_LOGIN)

        behaviors: List[Behavior] = []

        groups = group_by(failures, lambda event: (event.user, event.ip_address))

        for (user, ip_address), events in groups.items():

            for burst in find_bursts(events, settings.window_seconds, settings.threshold):

                seconds = (burst[-1].timestamp - burst[0].timestamp).total_seconds()

                behaviors.append(
                    self.build_behavior(
                        description=(
                            f"{len(burst)} failed logins for user '{user}' "
                            f"from {ip_address} in {seconds:.0f} seconds"
                        ),
                        evidence=burst,
                        attributes={
                            "ip_address": ip_address,
                            "target_user": user,
                            "attempt_count": len(burst),
                        },
                    )
                )

        return behaviors
