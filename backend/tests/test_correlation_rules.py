"""One test per correlation rule, using events built by hand so the
time relationships are exact."""

from datetime import datetime, timedelta
from uuid import uuid4

import pytest

from app.analyzer.correlation import (
    BruteForceRule,
    DistributedBruteForceRule,
    PersistenceRule,
    PrivilegeEscalationRule,
    SensitiveFileAccessRule,
    SuccessfulBruteForceRule,
    UserEnumerationRule,
    default_correlation_rules,
)
from app.models.event_types import EventType, FailureReason
from app.models.security_event import SecurityEvent
from app.storage.event_store import EventStore

START = datetime(2026, 8, 6, 21, 0, 0)


def make_event(
    offset,
    event_type=EventType.FAILED_LOGIN,
    user="kali",
    ip="192.168.1.50",
    metadata=None,
):
    return SecurityEvent(
        id=str(uuid4()),
        timestamp=START + timedelta(seconds=offset),
        source="Linux",
        host="kali",
        event_type=event_type,
        description="test event",
        user=user,
        ip_address=ip,
        metadata=metadata or {},
    )


def store_with(events) -> EventStore:
    store = EventStore()
    for item in events:
        store.add(item)
    return store


def run(rule, events):
    return rule.detect(store_with(events), rule.default_settings)


def test_brute_force_needs_events_close_in_time():

    rule = BruteForceRule()

    fast = [make_event(i) for i in range(5)]
    assert len(run(rule, fast)) == 1

    slow = [make_event(i * 3600) for i in range(5)]
    assert run(rule, slow) == []


def test_brute_force_keeps_user_and_ip_in_attributes():

    behavior = run(BruteForceRule(), [make_event(i, user="root") for i in range(6)])[0]

    assert behavior.attributes["target_user"] == "root"
    assert behavior.attributes["ip_address"] == "192.168.1.50"
    assert behavior.attributes["attempt_count"] == 6
    assert behavior.rule == "brute-force"
    assert len(behavior.evidence) == 6


def test_user_enumeration_needs_different_usernames():

    rule = UserEnumerationRule()

    many = [
        make_event(0, user="admin", metadata={"failure_reason": FailureReason.INVALID_USER}),
        make_event(1, user="root"),
        make_event(2, user="test", metadata={"failure_reason": FailureReason.INVALID_USER}),
    ]

    behavior = run(rule, many)[0]

    assert behavior.attributes["distinct_users"] == 3
    assert behavior.attributes["invalid_users"] == ["admin", "test"]

    # same amount of events, one username only
    one = [make_event(i, user="kali") for i in range(10)]

    assert run(rule, one) == []


def test_distributed_brute_force_needs_different_addresses():

    rule = DistributedBruteForceRule()

    spread = [
        make_event(0, ip="10.0.0.1"),
        make_event(60, ip="10.0.0.2"),
        make_event(120, ip="10.0.0.3"),
    ]

    behavior = run(rule, spread)[0]

    assert behavior.attributes["distinct_ips"] == 3

    single = [make_event(i, ip="10.0.0.1") for i in range(10)]

    assert run(rule, single) == []


def test_successful_brute_force_is_the_compromise():

    rule = SuccessfulBruteForceRule()

    events = [make_event(i) for i in range(5)]
    events.append(make_event(10, event_type=EventType.SUCCESSFUL_LOGIN))

    behavior = run(rule, events)[0]

    assert behavior.attributes["compromised"] is True
    assert behavior.attributes["failed_before_success"] == 5
    assert len(behavior.evidence) == 6


def test_a_normal_login_is_not_a_compromise():

    rule = SuccessfulBruteForceRule()

    events = [make_event(0, event_type=EventType.SUCCESSFUL_LOGIN)]

    assert run(rule, events) == []


def test_old_failures_do_not_count_as_compromise():

    rule = SuccessfulBruteForceRule()

    # failures happened yesterday, the login today is unrelated
    events = [make_event(-86400 - i) for i in range(5)]
    events.append(make_event(0, event_type=EventType.SUCCESSFUL_LOGIN))

    assert run(rule, events) == []


def test_privilege_escalation_notices_a_recent_remote_login():

    rule = PrivilegeEscalationRule()

    events = [
        make_event(0, event_type=EventType.SUCCESSFUL_LOGIN),
        make_event(30, event_type=EventType.SUDO_FAILURE),
    ]

    behavior = run(rule, events)[0]

    assert behavior.attributes["after_remote_login"] is True
    assert behavior.attributes["ip_address"] == "192.168.1.50"


def test_sensitive_file_access_looks_at_the_command():

    rule = SensitiveFileAccessRule()

    dangerous = make_event(
        0,
        event_type=EventType.SUDO_COMMAND,
        metadata={"command": "/usr/bin/cat /etc/shadow"},
    )

    normal = make_event(
        1,
        event_type=EventType.SUDO_COMMAND,
        metadata={"command": "/usr/bin/apt update"},
    )

    behaviors = run(rule, [dangerous, normal])

    assert len(behaviors) == 1
    assert behaviors[0].attributes["credential_access"] is True
    assert len(behaviors[0].evidence) == 1

    assert run(rule, [normal]) == []


def test_persistence_flags_an_account_made_after_a_login():

    rule = PersistenceRule()

    events = [
        make_event(0, event_type=EventType.SUCCESSFUL_LOGIN),
        make_event(60, event_type=EventType.ACCOUNT_CREATED, user="backdoor"),
    ]

    behavior = run(rule, events)[0]

    assert behavior.attributes["accounts"] == ["backdoor"]
    assert behavior.attributes["after_remote_login"] is True
    assert behavior.attributes["persistence"] is True


@pytest.mark.parametrize("rule", default_correlation_rules())
def test_every_rule_returns_nothing_for_an_empty_store(rule):

    assert rule.detect(EventStore(), rule.default_settings) == []


def test_registry_has_all_rules():

    names = {rule.name for rule in default_correlation_rules()}

    assert names == {
        "brute-force",
        "user-enumeration",
        "distributed-brute-force",
        "successful-brute-force",
        "privilege-escalation",
        "sensitive-file-access",
        "persistence",
    }
