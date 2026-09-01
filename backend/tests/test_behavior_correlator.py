from datetime import datetime, timedelta
from uuid import uuid4

from app.analyzer.behavior_correlator import BehaviorCorrelator
from app.analyzer.correlation import BruteForceRule
from app.config.detection_config import DetectionConfig
from app.models.event_types import EventType
from app.models.security_event import SecurityEvent
from app.models.severity import Severity
from app.storage.event_store import EventStore

START = datetime(2026, 8, 6, 21, 0, 0)


def failed_login(offset, user="kali", ip="192.168.1.50"):
    return SecurityEvent(
        id=str(uuid4()),
        timestamp=START + timedelta(seconds=offset),
        source="Linux",
        host="kali",
        event_type=EventType.FAILED_LOGIN,
        description="SSH authentication failed",
        user=user,
        ip_address=ip,
    )


def store_with(events):
    store = EventStore()
    for event in events:
        store.add(event)
    return store


def test_five_fast_failures_trigger_brute_force():

    store = store_with([failed_login(i) for i in range(5)])

    behaviors = BehaviorCorrelator(store).detect_brute_force()

    assert len(behaviors) == 1

    behavior = behaviors[0]

    assert behavior.name == "Possible Brute Force Attack"
    assert behavior.rule == "brute-force"
    assert len(behavior.evidence) == 5
    assert behavior.risk_score > 0
    assert behavior.severity in Severity.ORDER


def test_four_failures_are_not_enough():

    store = store_with([failed_login(i) for i in range(4)])

    assert BehaviorCorrelator(store).detect_brute_force() == []


def test_slow_failures_are_not_a_brute_force_anymore():

    #five failures spread over five hours, the Week 1 correlator called this an attack
    store = store_with([failed_login(i * 3600) for i in range(5)])

    assert BehaviorCorrelator(store).detect_brute_force() == []


def test_failures_are_grouped_per_user_and_ip():

    events = (
        [failed_login(i, "kali", "10.0.0.1") for i in range(5)]
        + [failed_login(i, "root", "10.0.0.2") for i in range(6)]
        + [failed_login(i, "test", "10.0.0.3") for i in range(2)]
    )

    behaviors = BehaviorCorrelator(store_with(events)).detect_brute_force()

    assert sorted(len(b.evidence) for b in behaviors) == [5, 6]


def test_results_are_sorted_most_dangerous_first():

    events = [failed_login(i, "kali") for i in range(5)]
    events += [failed_login(i, "root") for i in range(8)]

    behaviors = BehaviorCorrelator(store_with(events)).detect()

    scores = [behavior.risk_score for behavior in behaviors]

    assert scores == sorted(scores, reverse=True)


def test_every_behavior_is_scored_and_explained():

    store = store_with([failed_login(i, "root") for i in range(6)])

    for behavior in BehaviorCorrelator(store).detect():
        assert 0 < behavior.risk_score <= 100
        assert behavior.risk_factors
        assert behavior.first_seen and behavior.last_seen


def test_rules_can_be_injected():

    store = store_with([failed_login(i) for i in range(5)])

    correlator = BehaviorCorrelator(store, rules=[BruteForceRule()])

    assert len(correlator.rules) == 1
    assert len(correlator.detect()) == 1


def test_a_disabled_rule_produces_nothing():

    store = store_with([failed_login(i) for i in range(5)])

    config = DetectionConfig.from_dict({"rules": {"brute-force": {"enabled": False}}})

    correlator = BehaviorCorrelator(store, rules=[BruteForceRule()], config=config)

    assert correlator.detect() == []
