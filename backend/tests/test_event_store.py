from app.models.event_types import EventType

RAW = {
    "source": "Linux",
    "host": "kali",
    "event_type": EventType.FAILED_LOGIN,
    "description": "SSH authentication failed",
    "user": "kali",
    "ip_address": "::1",
}


def test_add_and_read_back(store, normalizer):

    event = normalizer.normalize(RAW)

    store.add(event)

    assert store.all() == [event]


def test_store_starts_empty(store):

    assert store.all() == []


def test_store_preserves_insertion_order(store, normalizer):

    events = [normalizer.normalize(RAW) for _ in range(3)]

    for event in events:
        store.add(event)

    assert store.all() == events
