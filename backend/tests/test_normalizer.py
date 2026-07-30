from app.analyzer.normalizer import EventNormalizer
from app.utils.json_printer import print_json

normalizer = EventNormalizer()

raw = {
    "source": "Windows",
    "host": "PC-01",
    "event_type": "FAILED_LOGIN",
    "description": "Administrator failed to login",
    "user": "Administrator",
    "ip_address": "192.168.1.15"
}

event = normalizer.normalize(raw)

print("=" * 60)
print("Event Normalizer Test")
print("=" * 60)

print_json(event)