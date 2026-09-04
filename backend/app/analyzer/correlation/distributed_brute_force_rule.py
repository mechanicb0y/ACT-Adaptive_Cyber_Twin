#One username attacked from MANY DIFFERENT ips.
#Attackers spread attempts over many machines exactly so that a per-ip counter
#never reaches its threshold. Grouping by user instead of by ip catches that.

from typing import List

from app.analyzer.correlation.base_correlation_rule import BaseCorrelationRule
from app.analyzer.correlation.time_window import find_distinct_burst, group_by
from app.config.detection_config import RuleSettings
from app.models.behavior import Behavior
from app.models.event_types import EventType
from app.storage.event_store import EventStore


class DistributedBruteForceRule(BaseCorrelationRule):

    name = "distributed-brute-force"
    behavior_name = "Distributed Brute Force Attack"
    base_score = 55
    base_confidence = 0.75

    default_settings = RuleSettings(threshold=3, window_seconds=600)

    def detect(self, store: EventStore, settings: RuleSettings) -> List[Behavior]:

        failures = store.get_by_type(EventType.FAILED_LOGIN)

        behaviors: List[Behavior] = []

        for user, events in group_by(failures, lambda e: e.user).items():

            burst = find_distinct_burst(
                events,
                settings.window_seconds,
                settings.threshold,
                key=lambda event: event.ip_address,
            )

            if not burst:
                continue

            ips = sorted({event.ip_address for event in burst if event.ip_address})

            behaviors.append(
                self.build_behavior(
                    description=(
                        f"User '{user}' attacked from {len(ips)} different "
                        f"addresses ({', '.join(ips)})"
                    ),
                    evidence=burst,
                    attributes={
                        "target_user": user,
                        "distinct_ips": len(ips),
                        "ip_addresses": ips,
                    },
                )
            )

        return behaviors
