from dataclasses import dataclass, field
from typing import List

from app.models.security_event import SecurityEvent


@dataclass(slots=True)
class Behavior:

    id: str

    name: str

    description: str

    severity: str

    confidence: float

    evidence: List[SecurityEvent] = field(default_factory=list)