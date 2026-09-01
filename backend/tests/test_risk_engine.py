from datetime import datetime, timedelta
from uuid import uuid4

from app.analyzer.risk_engine import RiskEngine
from app.models.behavior import Behavior
from app.models.event_types import EventType
from app.models.security_event import SecurityEvent
from app.models.severity import Severity

START = datetime(2026, 8, 6, 21, 0, 0)


def event(offset, user="kali", ip="192.168.1.50"):
    return SecurityEvent(
        id=str(uuid4()),
        timestamp=START + timedelta(seconds=offset),
        source="Linux",
        host="kali",
        event_type=EventType.FAILED_LOGIN,
        description="test",
        user=user,
        ip_address=ip,
    )


def behavior(attributes=None, count=5, spacing=1, first=START):
    events = [event(i * spacing) for i in range(count)]

    return Behavior(
        id=str(uuid4()),
        name="Test Behavior",
        description="test",
        severity=Severity.LOW,
        confidence=0.8,
        evidence=events,
        first_seen=first,
        last_seen=first + timedelta(seconds=(count - 1) * spacing),
        attributes=attributes or {},
    )


def test_score_starts_from_the_rule_base():

    score, factors = RiskEngine().score(behavior({"base_score": 45}))

    assert score >= 45
    assert factors[0].name == "base"


def test_score_is_capped_at_100():

    attributes = {
        "base_score": 85,
        "compromised": True,
        "credential_access": True,
        "persistence": True,
        "after_remote_login": True,
        "target_user": "root",
        "ip_address": "8.8.8.8",
    }

    score, _ = RiskEngine().score(behavior(attributes, count=30))

    assert score == 100


def test_attacking_root_scores_higher_than_a_normal_user():

    normal, _ = RiskEngine().score(behavior({"base_score": 45, "target_user": "kali"}))
    admin, _ = RiskEngine().score(behavior({"base_score": 45, "target_user": "root"}))

    assert admin > normal


def test_an_outside_address_scores_higher_than_the_local_network():

    inside, _ = RiskEngine().score(behavior({"base_score": 45, "ip_address": "192.168.1.50"}))
    outside, _ = RiskEngine().score(behavior({"base_score": 45, "ip_address": "8.8.8.8"}))

    assert outside > inside


def test_a_successful_attack_scores_higher_than_a_failed_one():

    failed, _ = RiskEngine().score(behavior({"base_score": 45}))
    worked, _ = RiskEngine().score(behavior({"base_score": 45, "compromised": True}))

    assert worked > failed


def test_fast_attacks_score_higher_than_slow_ones():

    #same 10 events, one is a script and one is a human
    script, _ = RiskEngine().score(behavior({"base_score": 40}, count=10, spacing=1))
    human, _ = RiskEngine().score(behavior({"base_score": 40}, count=10, spacing=120))

    assert script > human


def test_night_time_adds_points():

    day, _ = RiskEngine().score(
        behavior({"base_score": 40}, first=datetime(2026, 8, 6, 14, 0, 0))
    )
    night, _ = RiskEngine().score(
        behavior({"base_score": 40}, first=datetime(2026, 8, 6, 3, 0, 0))
    )

    assert night > day


def test_every_point_has_a_written_reason():

    _, factors = RiskEngine().score(
        behavior({"base_score": 45, "target_user": "root", "compromised": True})
    )

    names = {factor.name for factor in factors}

    assert "privileged_target" in names
    assert "compromised" in names
    assert all(factor.detail for factor in factors)


def test_apply_sets_score_and_severity():

    item = RiskEngine().apply(behavior({"base_score": 85, "compromised": True}))

    assert item.risk_score > 0
    assert item.severity == Severity.CRITICAL
    assert item.risk_factors


def test_severity_comes_from_the_score():

    assert Severity.from_score(95) == Severity.CRITICAL
    assert Severity.from_score(65) == Severity.HIGH
    assert Severity.from_score(40) == Severity.MEDIUM
    assert Severity.from_score(10) == Severity.LOW
