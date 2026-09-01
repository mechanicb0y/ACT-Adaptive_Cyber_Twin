#Contract for every correlation rule. Same idea as the parsing rules from Week 1.
#A parsing rule says what one log line means. A correlation rule says what several
#events mean together. Adding a new detection is one new file, nothing else changes.

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Sequence
from uuid import uuid4

from app.config.detection_config import RuleSettings
from app.models.behavior import Behavior
from app.models.security_event import SecurityEvent
from app.models.severity import Severity
from app.storage.event_store import EventStore
from app.analyzer.correlation.time_window import time_span


class BaseCorrelationRule(ABC):

    #id used in the config file and in the output
    name: str = "unnamed-rule"

    #what the produced behavior is called
    behavior_name: str = "Unnamed Behavior"

    #starting risk points before the risk engine adds its own
    base_score: int = 30

    #how sure we are in the pattern itself, separate from how dangerous it is
    base_confidence: float = 0.8

    #used when the rule is missing from the config file
    default_settings: RuleSettings = RuleSettings()

    def settings(self, config) -> RuleSettings:
        return config.for_rule(self.name, self.default_settings)

    @abstractmethod
    def detect(
        self,
        store: EventStore,
        settings: RuleSettings,
    ) -> List[Behavior]:
        """Look at the stored events and return the behaviors found."""

    def build_behavior(
        self,
        description: str,
        evidence: Sequence[SecurityEvent],
        attributes: Optional[Dict[str, Any]] = None,
        confidence: Optional[float] = None,
    ) -> Behavior:
        #shared construction so every rule fills the same fields the same way

        evidence = list(evidence)

        first_seen, last_seen = time_span(evidence) if evidence else (None, None)

        attributes = dict(attributes or {})
        attributes.setdefault("base_score", self.base_score)

        return Behavior(
            id=str(uuid4()),
            name=self.behavior_name,
            description=description,
            #severity is a placeholder, the RiskEngine sets the real one
            severity=Severity.LOW,
            confidence=confidence if confidence is not None else self.base_confidence,
            evidence=evidence,
            rule=self.name,
            first_seen=first_seen,
            last_seen=last_seen,
            attributes=attributes,
        )
