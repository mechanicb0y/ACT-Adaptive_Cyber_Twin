from datetime import datetime

from app.models.event_types import EventType
from app.models.security_event import SecurityEvent


def test_normalizes_a_raw_dictionary(normalizer):

    raw = {
        "source": "Windows",
        "host": "PC-01",
        "event_type": EventType.FAILED_LOGIN,
        "description": "Administrator failed to login",
        "user": "Administrator",
        "ip_address": "192.168.1.15",
    }

    event = normalizer.normalize(raw)

    assert isinstance(event, SecurityEvent)
    assert event.id
    assert event.source == "Windows"
    assert event.host == "PC-01"
    assert event.event_type == EventType.FAILED_LOGIN
    assert event.user == "Administrator"
    assert event.ip_address == "192.168.1.15"


def test_missing_fields_get_safe_defaults(normalizer):

    event = normalizer.normalize({})

    assert event.source == "Unknown"
    assert event.host == "Unknown"
    assert event.event_type == EventType.UNKNOWN
    assert event.description == ""
    assert event.user is None
    assert event.metadata == {}


def test_real_log_timestamp_is_preserved(normalizer):

    event = normalizer.normalize({"timestamp": "Aug  6 21:11:09"})

    assert event.timestamp.month == 8
    assert event.timestamp.day == 6
    assert event.timestamp.hour == 21
    assert event.timestamp.minute == 11


def test_datetime_timestamp_is_used_as_is(normalizer):

    moment = datetime(2026, 8, 6, 21, 11, 9)

    assert normalizer.normalize({"timestamp": moment}).timestamp == moment


def test_missing_timestamp_falls_back_to_ingestion_time(normalizer):

    before = datetime.now()
    event = normalizer.normalize({"source": "Linux"})

    assert before <= event.timestamp
    assert event.ingested_at is not None


def test_unknown_keys_are_kept_in_metadata(normalizer):

    event = normalizer.normalize(
        {
            "source": "Linux",
            "matched_rule": "ssh-failed-login",
            "metadata": {"port": 22},
        }
    )

    assert event.metadata["port"] == 22
    assert event.metadata["matched_rule"] == "ssh-failed-login"
