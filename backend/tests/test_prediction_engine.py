from datetime import datetime, timedelta
from uuid import uuid4

from app.intelligence.anomaly_model import (
    StatisticalScorer,
    build_anomaly_scorer,
)
from app.intelligence.feature_extractor import FEATURE_NAMES, FeatureExtractor
from app.intelligence.prediction_engine import PredictionEngine
from app.models.attack_graph import AttackGraph, AttackNode, AttackPath
from app.models.behavior import Behavior
from app.models.security_event import SecurityEvent
from app.models.severity import Severity

START = datetime(2026, 8, 6, 21, 0, 0)


def behavior(rule, stage, stage_name, offset=0, attrs=None):
    return Behavior(
        id=str(uuid4()),
        name=rule,
        description=rule,
        severity=Severity.HIGH,
        confidence=0.8,
        rule=rule,
        risk_score=70,
        stage=stage,
        stage_name=stage_name,
        first_seen=START + timedelta(seconds=offset),
        last_seen=START + timedelta(seconds=offset + 5),
        attributes=attrs or {"ip_address": "192.168.1.50"},
    )


def path_from(behaviors, actor="192.168.1.50"):
    nodes = [AttackNode(id=b.id, behavior=b) for b in behaviors]
    return AttackPath(nodes=nodes, edges=[], total_stages=6)


def test_predicts_the_next_kill_chain_stage():

    path = path_from([
        behavior("user-enumeration", 1, "Discovery", 0),
        behavior("brute-force", 2, "Credential Access", 10),
    ])

    prediction = PredictionEngine().predict(path)

    assert prediction.current_stage == 2
    assert prediction.most_likely.stage == 3               # Initial Access next
    assert prediction.most_likely.stage_name == "Initial Access"
    assert 0 < prediction.most_likely.probability <= 0.95


def test_a_completed_attack_predicts_lateral_movement():

    path = path_from([
        behavior("successful-brute-force", 3, "Initial Access", 0, {"ip_address": "1.2.3.4", "compromised": True}),
        behavior("persistence", 6, "Persistence", 30, {"ip_address": "1.2.3.4"}),
    ], actor="1.2.3.4")

    prediction = PredictionEngine().predict(path)

    assert prediction.current_stage == 6
    assert prediction.most_likely.stage == 7
    assert "Lateral" in prediction.most_likely.stage_name


def test_prediction_has_a_summary_and_confidence():

    path = path_from([behavior("brute-force", 2, "Credential Access", 0)])

    prediction = PredictionEngine().predict(path)

    assert prediction.actor == "192.168.1.50"
    assert prediction.summary
    assert 0 <= prediction.confidence <= 1
    assert prediction.model == "statistical"


def test_more_abnormal_activity_scores_higher():

    scorer = StatisticalScorer()

    quiet = FeatureExtractor().extract("10.0.0.5", [], [])
    loud_path = path_from([
        behavior("brute-force", 2, "Credential Access", i * 2, {"ip_address": "8.8.8.8", "target_user": "root"})
        for i in range(20)
    ])
    loud = FeatureExtractor().extract(
        "8.8.8.8",
        [
            SecurityEvent(
                id=str(uuid4()), timestamp=START + timedelta(seconds=i),
                source="Linux", host="kali", event_type="FAILED_LOGIN",
                description="x", user="root", ip_address="8.8.8.8",
            )
            for i in range(30)
        ],
        [n.behavior for n in loud_path.nodes],
    )

    assert scorer.score(loud) > scorer.score(quiet)


def test_feature_vector_has_every_named_feature():

    vector = FeatureExtractor().extract("10.0.0.1", [], [])

    assert len(vector.values) == len(FEATURE_NAMES)
    assert set(vector.as_dict()) == set(FEATURE_NAMES)


def test_scorer_falls_back_gracefully_and_scores_in_range():

    scorer = build_anomaly_scorer()   # statistical here (no sklearn in CI)

    vector = FeatureExtractor().extract("8.8.8.8", [], [])
    score = scorer.score(vector)

    assert 0.0 <= score <= 1.0
    assert scorer.name in ("statistical", "isolation-forest")
