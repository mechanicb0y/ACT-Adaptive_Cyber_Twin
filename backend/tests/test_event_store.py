from app.analyzer.normalizer import EventNormalizer
from app.storage.event_store import EventStore
from app.utils.json_printer import print_json

store = EventStore()

normalizer = EventNormalizer()

raw = {
    "source": "Linux",
    "host": "kali",
    "event_type": "FAILED_LOGIN",
    "description": "SSH authentication failed",
    "user": "kali",
    "ip_address": "::1"
}

event = normalizer.normalize(raw)

store.add(event)

print("=" * 60)
print("Event Store Test")
print("=" * 60)

print_json(store.all())