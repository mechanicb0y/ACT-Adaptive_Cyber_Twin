from datetime import datetime, timedelta
from uuid import uuid4

from app.analyzer.correlation.time_window import (
    events_per_minute,
    events_within,
    find_bursts,
    find_distinct_burst,
    group_by,
    is_external_ip,
    is_remote_ip,
)
from app.models.event_types import EventType
from app.models.security_event import SecurityEvent

START = datetime(2026, 8, 6, 21, 0, 0)


def event(offset_seconds, user="kali", ip="192.168.1.50"):
    return SecurityEvent(
        id=str(uuid4()),
        timestamp=START + timedelta(seconds=offset_seconds),
        source="Linux",
        host="kali",
        event_type=EventType.FAILED_LOGIN,
        description="test",
        user=user,
        ip_address=ip,
    )


def test_group_by_splits_into_buckets():

    events = [event(0, "kali"), event(1, "root"), event(2, "kali")]

    groups = group_by(events, lambda e: e.user)

    assert len(groups["kali"]) == 2
    assert len(groups["root"]) == 1


def test_burst_found_when_events_are_close_together():

    events = [event(i) for i in range(0, 25, 5)]  # 5 events over 20 seconds

    bursts = find_bursts(events, window_seconds=60, threshold=5)

    assert len(bursts) == 1
    assert len(bursts[0]) == 5


def test_no_burst_when_events_are_spread_out():

    # same 5 events, but one per hour
    events = [event(i * 3600) for i in range(5)]

    assert find_bursts(events, window_seconds=60, threshold=5) == []


def test_this_is_the_week_2_difference():

    # 4 failures now and 4 failures tomorrow is not an attack,
    # even though it is 8 failures in total
    events = [event(i) for i in range(4)] + [event(86400 + i) for i in range(4)]

    assert find_bursts(events, window_seconds=120, threshold=5) == []


def test_two_separate_attacks_are_reported_separately():

    first = [event(i) for i in range(5)]
    second = [event(10000 + i) for i in range(5)]

    bursts = find_bursts(first + second, window_seconds=60, threshold=5)

    assert len(bursts) == 2


def test_one_long_attack_is_reported_once():

    events = [event(i * 2) for i in range(20)]  # 20 events over 38 seconds

    bursts = find_bursts(events, window_seconds=60, threshold=5)

    assert len(bursts) == 1
    assert len(bursts[0]) == 20


def test_distinct_burst_counts_values_not_events():

    # ten events, but only one username -> not enumeration
    same_user = [event(i, user="kali") for i in range(10)]

    assert find_distinct_burst(same_user, 300, 3, key=lambda e: e.user) == []

    # three events with three usernames -> enumeration
    many_users = [
        event(0, user="admin"),
        event(1, user="root"),
        event(2, user="test"),
    ]

    found = find_distinct_burst(many_users, 300, 3, key=lambda e: e.user)

    assert len(found) == 3


def test_events_within_looks_backwards_only():

    events = [event(0), event(60), event(120)]

    before = events_within(events, START + timedelta(seconds=70), 120)

    assert len(before) == 2


def test_events_per_minute_measures_speed():

    fast = [event(i) for i in range(10)]  # 10 events in 9 seconds

    assert events_per_minute(fast) > 50

    slow = [event(i * 600) for i in range(10)]  # one every 10 minutes

    assert events_per_minute(slow) < 2

    assert events_per_minute([event(0)]) == 0.0


def test_remote_and_external_are_different_questions():

    # from another machine on the same network
    assert is_remote_ip("192.168.1.50") is True
    assert is_external_ip("192.168.1.50") is False

    # from the internet
    assert is_remote_ip("8.8.8.8") is True
    assert is_external_ip("8.8.8.8") is True

    # from the machine itself
    assert is_remote_ip("::1") is False
    assert is_external_ip("127.0.0.1") is False

    assert is_remote_ip(None) is False
    assert is_external_ip("not-an-ip") is False
