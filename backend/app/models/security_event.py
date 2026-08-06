# Represents a single normalized security event.
# Only facts. No prediction, no scoring, no interpretation.
#
# Every source (Linux, Windows, Sysmon, Wazuh, firewalls) is converted into
# this shape. SecurityEvent is the common language of ACT: everything after
# ingestion speaks it and nothing after ingestion knows where the data came from.

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional


@dataclass(slots=True)
class SecurityEvent:

    id: str

    # When the event happened on the monitored host,
    # NOT when ACT read it.
    timestamp: datetime

    source: str  # "Linux", "Windows", "Wazuh", ...

    host: str  # which machine produced the event

    event_type: str  # one of app.models.event_types.EventType

    description: str

    user: Optional[str] = None

    process: Optional[str] = None

    ip_address: Optional[str] = None

    # Source-specific details that do not deserve a top-level field
    # (ssh port, sudo command, failure reason, pid, ...).
    # This keeps SecurityEvent stable while letting new parsers stay expressive.
    metadata: Dict[str, Any] = field(default_factory=dict)

    # The original log line, kept as forensic evidence.
    raw_log: Optional[str] = None

    # When ACT actually ingested the event. Differs from `timestamp`
    # when replaying historical logs.
    ingested_at: Optional[datetime] = None
