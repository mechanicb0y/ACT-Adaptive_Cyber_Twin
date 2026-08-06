from uuid import uuid4

from app.storage.event_store import EventStore
from app.models.behavior import Behavior


class BehaviorCorrelator:

    def __init__(self, event_store: EventStore):

        self.event_store = event_store


    def detect_brute_force(self):

        failed_events = self.event_store.get_by_type(
            "FAILED_LOGIN"
        )


        suspicious_groups = {}


        for event in failed_events:

            key = (
                event.user,
                event.ip_address
            )

            if key not in suspicious_groups:
                suspicious_groups[key] = []

            suspicious_groups[key].append(event)



        behaviors = []


        for key, events in suspicious_groups.items():

            if len(events) >= 5:

                behavior = Behavior(
                    id=str(uuid4()), #just for testing now
                    name="Possible Brute Force Attack",
                    description=(
                        f"Detected {len(events)} failed "
                        f"login attempts from {key[1]}"
                    ),
                    severity="High",
                    confidence=0.90,
                    evidence=events
                )

                behaviors.append(behavior)


        return behaviors