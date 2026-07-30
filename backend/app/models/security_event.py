#this to represents a single normalized security event#
#only facts no prediction#
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(slots=True)
class SecurityEvent:
    
    id: str

    timestamp: datetime

    source: str

    host: str #host is like which computer produced the event

    event_type: str #undone work...#

    description: str

    user: Optional[str] = None

    process: Optional[str] = None

    ip_address: Optional[str] = None