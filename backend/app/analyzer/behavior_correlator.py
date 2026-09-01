#The correlator contains no detection logic of its own.
#It runs every correlation rule, scores the results with the risk engine, labels
#them with MITRE ATT&CK, and sorts. Detection lives in app/analyzer/correlation,
#danger lives in the risk engine, vocabulary lives in the mapper, and this file
#only puts the three together.

from typing import Iterable, List, Optional

from app.analyzer.attack_graph_builder import AttackGraphBuilder
from app.analyzer.correlation import default_correlation_rules
from app.analyzer.correlation.base_correlation_rule import BaseCorrelationRule
from app.analyzer.mitre_mapper import MitreMapper
from app.analyzer.risk_engine import RiskEngine
from app.config.detection_config import DetectionConfig
from app.models.attack_graph import AttackGraph
from app.models.behavior import Behavior
from app.models.severity import Severity
from app.storage.event_store import EventStore


class BehaviorCorrelator:

    def __init__(
        self,
        event_store: EventStore,
        rules: Optional[Iterable[BaseCorrelationRule]] = None,
        config: Optional[DetectionConfig] = None,
        risk_engine: Optional[RiskEngine] = None,
        mitre_mapper: Optional[MitreMapper] = None,
    ):
        self.event_store = event_store

        #injected, so a test can run one rule alone
        self.rules: List[BaseCorrelationRule] = list(
            rules if rules is not None else default_correlation_rules()
        )

        self.config = config or DetectionConfig.load()
        self.risk_engine = risk_engine or RiskEngine()
        self.mitre_mapper = mitre_mapper or MitreMapper()

    def detect(self) -> List[Behavior]:
        #run every enabled rule, score the results, label them, most dangerous first

        behaviors: List[Behavior] = []

        for rule in self.rules:

            settings = rule.settings(self.config)

            if not settings.enabled:
                continue

            for behavior in rule.detect(self.event_store, settings):
                self.risk_engine.apply(behavior)
                self.mitre_mapper.map(behavior)
                behaviors.append(behavior)

        behaviors.sort(
            key=lambda item: (item.risk_score, Severity.rank(item.severity)),
            reverse=True,
        )

        return behaviors

    def build_attack_graph(
        self,
        behaviors: Optional[List[Behavior]] = None,
    ) -> AttackGraph:
        #connect the behaviors into attack paths

        behaviors = behaviors if behaviors is not None else self.detect()

        builder = AttackGraphBuilder(
            mapper=self.mitre_mapper,
            max_gap_seconds=int(
                self.config.option("graph", "max_gap_seconds", 3600)
            ),
        )

        return builder.build(behaviors)

    def detect_brute_force(self) -> List[Behavior]:
        #kept so older code and tests keep working
        return [
            behavior
            for behavior in self.detect()
            if behavior.rule == "brute-force"
        ]
