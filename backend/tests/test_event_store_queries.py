from app.analyzer.normalizer import EventNormalizer
from app.storage.event_store import EventStore
from app.utils.json_printer import print_json


store = EventStore()

normalizer = EventNormalizer()


events = [
    {
        "source": "Linux",
        "host": "kali",
        "event_type": "FAILED_LOGIN",
        "description": "SSH authentication failed",
        "user": "kali",
        "ip_address": "::1"
    },

    {
        "source": "Linux",
        "host": "kali",
        "event_type": "FAILED_LOGIN",
        "description": "SSH authentication failed",
        "user": "kali",
        "ip_address": "::1"
    },

    {
        "source": "Linux",
        "host": "kali",
        "event_type": "SUCCESS_LOGIN",
        "description": "Successful login",
        "user": "admin",
        "ip_address": "::2"
    }
]


for raw in events:

    event = normalizer.normalize(raw)

    store.add(event)


print("=" * 60)
print("ALL EVENTS")
print("=" * 60)

print_json(store.all())


print("=" * 60)
print("FAILED LOGIN EVENTS")
print("=" * 60)

print_json(
    store.get_by_type("FAILED_LOGIN")
)


print("=" * 60)
print("USER: kali")
print("=" * 60)

print_json(
    store.get_by_user("kali")
)


print("=" * 60)
print("IP: ::1")
print("=" * 60)

print_json(
    store.get_by_ip("::1")
)