from app.analyzer.normalizer import EventNormalizer
from app.analyzer.behavior_correlator import BehaviorCorrelator
from app.storage.event_store import EventStore
from app.utils.json_printer import print_json


store = EventStore()

normalizer = EventNormalizer()


for i in range(5):

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



correlator = BehaviorCorrelator(store)


behaviors = correlator.detect_brute_force()


print("=" * 60)
print("Behavior Correlator Test")
print("=" * 60)


print_json(behaviors)