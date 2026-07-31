from app.analyzer.normalizer import EventNormalizer
from app.analyzer.behavior_extractor import BehaviorExtractor
from app.utils.json_printer import print_json

raw = {
    "source": "Windows",
    "host": "PC-01",
    "event_type": "FAILED_LOGIN",
    "description": "Administrator failed to login",
    "user": "Administrator"
}

normalizer = EventNormalizer()
event = normalizer.normalize(raw)

extractor = BehaviorExtractor()
behavior = extractor.extract(event)

print("=" * 60)
print("Behavior Extractor Test")
print("=" * 60)

print_json(behavior)