from uuid import uuid4

from app.models.behavior import Behavior
from app.models.security_event import SecurityEvent


class BehaviorExtractor:

    def extract(self, event: SecurityEvent) -> Behavior:

        if event.event_type == "FAILED_LOGIN":

            return Behavior(
                id=str(uuid4()),
                name="Failed Authentication Attempt",
                description="A login attempt failed.",
                severity="Low",
                confidence=1.0,
                evidence=[event]
            )

        return Behavior(
            id=str(uuid4()),
            name="Unknown Behavior",
            description="No behavior rule matched.",
            severity="Low",
            confidence=0.0,
            evidence=[event]
        )