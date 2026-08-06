#The normalizer converts raw log dictionaries into ACT’s standard SecurityEvent format. 
#It handles missing or incorrect fields safely so one bad log does not stop the whole system.

from datetime import datetime
from typing import Any, Dict
from uuid import uuid4

from app.models.event_types import EventType
from app.models.security_event import SecurityEvent
from app.utils.time_parser import parse_timestamp

# Fields that get their own attribute on SecurityEvent.
# Anything else a parser returns is swept into `metadata`.
KNOWN_FIELDS = {
    "timestamp",
    "source",
    "host",
    "event_type",
    "description",
    "user",
    "process",
    "ip_address",
    "metadata",
    "raw_log",
}


class EventNormalizer:

    def normalize(self, raw_event: Dict[str, Any]) -> SecurityEvent:

        now = datetime.now()

        # Real log time when the parser found one, otherwise ingestion time.
        timestamp = parse_timestamp(
            raw_event.get("timestamp"),
            reference=now,
            fallback=now,
        )

        metadata = dict(raw_event.get("metadata") or {})

        # Any extra key a parser invented is preserved instead of dropped.
        for key, value in raw_event.items():
            if key not in KNOWN_FIELDS and value is not None:
                metadata.setdefault(key, value)

        return SecurityEvent(
            id=str(uuid4()),
            timestamp=timestamp,
            source=raw_event.get("source", "Unknown"),
            host=raw_event.get("host", "Unknown"),
            event_type=raw_event.get("event_type", EventType.UNKNOWN),
            description=raw_event.get("description", ""),
            user=raw_event.get("user"),
            process=raw_event.get("process"),
            ip_address=raw_event.get("ip_address"),
            metadata=metadata,
            raw_log=raw_event.get("raw_log"),
            ingested_at=now,
        )
