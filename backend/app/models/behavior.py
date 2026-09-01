#A Behavior is several events understood as one attacker activity.
#Week 2 added the risk fields: the score, the reasons behind it, and the time span it covers.
#Week 3 added the MITRE ATT&CK techniques and the kill chain stage.

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from app.models.mitre import MitreTechnique
from app.models.risk_factor import RiskFactor
from app.models.security_event import SecurityEvent


@dataclass(slots=True)
class Behavior:

    id: str

    name: str

    description: str

    severity: str

    confidence: float

    evidence: List[SecurityEvent] = field(default_factory=list)

    #0 to 100, produced by the RiskEngine
    risk_score: int = 0

    #why the score is what it is
    risk_factors: List[RiskFactor] = field(default_factory=list)

    #which rule produced this behavior
    rule: Optional[str] = None

    #time span covered by the evidence
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    #structured facts the risk engine and the future attack graph read
    #(ip, users, counts, compromised flag, ...)
    attributes: Dict[str, Any] = field(default_factory=dict)

    #MITRE ATT&CK techniques this behavior matches, filled by the MitreMapper
    techniques: List[MitreTechnique] = field(default_factory=list)

    #how deep into the attack this stage is, 0 means not mapped
    stage: int = 0
    stage_name: Optional[str] = None

    @property
    def duration_seconds(self) -> float:

        if not self.first_seen or not self.last_seen:
            return 0.0

        return (self.last_seen - self.first_seen).total_seconds()

    @property
    def technique_ids(self) -> List[str]:
        return [technique.id for technique in self.techniques]

    @property
    def tactics(self) -> List[str]:
        #unique tactics, keeping the order they were listed in
        seen = []
        for technique in self.techniques:
            if technique.tactic not in seen:
                seen.append(technique.tactic)
        return seen
