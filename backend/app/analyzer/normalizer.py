from datetime import datetime
from uuid import uuid4

from app.models.security_event import SecurityEvent


class EventNormalizer:

    def normalize(self, raw_event: dict) -> SecurityEvent:

        return SecurityEvent(
            id=str(uuid4()),
            timestamp=datetime.now(),
            source=raw_event.get("source", "Unknown"),
            host=raw_event.get("host", "Unknown"),
            event_type=raw_event.get("event_type", "UNKNOWN"),
            description=raw_event.get("description", ""),
            user=raw_event.get("user"),
            process=raw_event.get("process"),
            ip_address=raw_event.get("ip_address")
        )