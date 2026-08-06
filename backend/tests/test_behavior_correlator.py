from app.analyzer.behavior_correlator import BehaviorCorrelator
from app.models.event_types import EventType


def failed_login(user="kali", ip="::1"):
    return {
        "source": "Linux",
        "host": "kali",
        "event_type": EventType.FAILED_LOGIN,
        "description": "SSH authentication failed",
        "user": user,
        "ip_address": ip,
    }


def fill(store, normalizer, raw, count):
    for _ in range(count):
        store.add(normalizer.normalize(raw))


def test_five_failures_trigger_brute_force(store, normalizer):

    fill(store, normalizer, failed_login(), 5)

    behaviors = BehaviorCorrelator(store).detect_brute_force()

    assert len(behaviors) == 1

    behavior = behaviors[0]

    assert behavior.name == "Possible Brute Force Attack"
    assert behavior.severity == "High"
    assert behavior.confidence == 0.90
    assert len(behavior.evidence) == 5


def test_four_failures_are_not_enough(store, normalizer):

    fill(store, normalizer, failed_login(), 4)

    assert BehaviorCorrelator(store).detect_brute_force() == []


def test_failures_are_grouped_per_user_and_ip(store, normalizer):

    fill(store, normalizer, failed_login("kali", "10.0.0.1"), 5)
    fill(store, normalizer, failed_login("root", "10.0.0.2"), 6)
    fill(store, normalizer, failed_login("test", "10.0.0.3"), 2)

    behaviors = BehaviorCorrelator(store).detect_brute_force()

    assert len(behaviors) == 2

    sizes = sorted(len(behavior.evidence) for behavior in behaviors)

    assert sizes == [5, 6]


def test_successful_logins_are_ignored(store, normalizer):

    raw = failed_login()
    raw["event_type"] = EventType.SUCCESSFUL_LOGIN

    fill(store, normalizer, raw, 10)

    assert BehaviorCorrelator(store).detect_brute_force() == []
