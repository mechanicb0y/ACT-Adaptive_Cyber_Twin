import pytest

from app.models.event_types import EventType

EVENTS = [
    {
        "source": "Linux",
        "host": "kali",
        "event_type": EventType.FAILED_LOGIN,
        "description": "SSH authentication failed",
        "user": "kali",
        "ip_address": "::1",
    },
    {
        "source": "Linux",
        "host": "kali",
        "event_type": EventType.FAILED_LOGIN,
        "description": "SSH authentication failed",
        "user": "kali",
        "ip_address": "::1",
    },
    {
        "source": "Linux",
        "host": "kali",
        "event_type": EventType.SUCCESSFUL_LOGIN,
        "description": "Successful login",
        "user": "admin",
        "ip_address": "::2",
    },
]


@pytest.fixture
def filled_store(store, normalizer):

    for raw in EVENTS:
        store.add(normalizer.normalize(raw))

    return store


def test_all_returns_everything(filled_store):

    assert len(filled_store.all()) == 3


def test_get_by_type(filled_store):

    assert len(filled_store.get_by_type(EventType.FAILED_LOGIN)) == 2
    assert len(filled_store.get_by_type(EventType.SUCCESSFUL_LOGIN)) == 1
    assert filled_store.get_by_type("NOT_A_TYPE") == []


def test_get_by_user(filled_store):

    assert len(filled_store.get_by_user("kali")) == 2
    assert len(filled_store.get_by_user("admin")) == 1
    assert filled_store.get_by_user("nobody") == []


def test_get_by_ip(filled_store):

    assert len(filled_store.get_by_ip("::1")) == 2
    assert len(filled_store.get_by_ip("::2")) == 1


def test_get_recent_uses_the_event_timestamp(filled_store):

    # These events were normalized with no timestamp, so they carry
    # ingestion time and all of them count as recent.
    assert len(filled_store.get_recent(60)) == 3
    assert filled_store.get_recent(0) == []
