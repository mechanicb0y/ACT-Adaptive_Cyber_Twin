#Turns an attacker's activity into a plain vector of numbers.
#
#Machine learning cannot read a SecurityEvent, it can only read numbers. This
#module is the bridge: it summarises everything one attacker did into a fixed
#list of features that the anomaly model can score.
#
#Keeping this separate means the model never touches ACT's objects directly,
#so the model can be swapped without changing anything else.

from dataclasses import dataclass
from typing import List

from app.analyzer.correlation.time_window import events_per_minute, is_external_ip
from app.models.behavior import Behavior
from app.models.event_types import EventType
from app.models.security_event import SecurityEvent

PRIVILEGED_USERS = {"root", "admin", "administrator", "ubuntu", "ec2-user"}

#the order of the numbers in the vector, also used as column names by the model
FEATURE_NAMES = [
    "total_events",
    "failed_logins",
    "distinct_users",
    "distinct_ips",
    "events_per_minute",
    "off_hours",
    "external_source",
    "privileged_target",
    "compromised",
    "deepest_stage",
]


@dataclass(slots=True)
class FeatureVector:

    actor: str
    values: List[float]

    def as_dict(self) -> dict:
        return dict(zip(FEATURE_NAMES, self.values))


class FeatureExtractor:

    def __init__(self, night_hours=range(0, 6), privileged=PRIVILEGED_USERS):
        self.night_hours = night_hours
        self.privileged = privileged

    def extract(
        self,
        actor: str,
        events: List[SecurityEvent],
        behaviors: List[Behavior],
    ) -> FeatureVector:

        failed = [e for e in events if e.event_type == EventType.FAILED_LOGIN]

        users = {e.user for e in events if e.user}
        ips = {e.ip_address for e in events if e.ip_address}

        first_hour = min((e.timestamp.hour for e in events), default=12)

        compromised = any(b.attributes.get("compromised") for b in behaviors)

        deepest = max((b.stage for b in behaviors), default=0)

        target_users = {
            str(b.attributes.get("target_user", "")).lower() for b in behaviors
        }

        values = [
            float(len(events)),
            float(len(failed)),
            float(len(users)),
            float(len(ips)),
            round(events_per_minute(events), 3),
            1.0 if first_hour in self.night_hours else 0.0,
            1.0 if is_external_ip(actor) else 0.0,
            1.0 if target_users & self.privileged else 0.0,
            1.0 if compromised else 0.0,
            float(deepest),
        ]

        return FeatureVector(actor=actor, values=values)
