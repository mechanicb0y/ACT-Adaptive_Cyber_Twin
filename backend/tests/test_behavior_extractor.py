from app.analyzer.behavior_extractor import BehaviorExtractor
from app.models.event_types import EventType


def test_failed_login_becomes_a_low_severity_behavior(normalizer):

    event = normalizer.normalize(
        {
            "source": "Windows",
            "host": "PC-01",
            "event_type": EventType.FAILED_LOGIN,
            "description": "Administrator failed to login",
            "user": "Administrator",
        }
    )

    behavior = BehaviorExtractor().extract(event)

    assert behavior.name == "Failed Authentication Attempt"
    assert behavior.severity == "Low"
    assert behavior.evidence == [event]


def test_unrecognised_event_returns_unknown_behavior(normalizer):

    event = normalizer.normalize({"event_type": "SOMETHING_ELSE"})

    behavior = BehaviorExtractor().extract(event)

    assert behavior.name == "Unknown Behavior"
    assert behavior.confidence == 0.0
