"""A real brute-force tool (hydra/medusa/ncrack) rarely leaves a tidy
'Failed password' line per guess. With the default MaxAuthTries the connection
is dropped and sshd logs 'maximum authentication attempts exceeded' or
'Connection closed by authenticating user'. ACT must still see the attack.
"""

from datetime import datetime, timedelta

from app.analyzer.behavior_correlator import BehaviorCorrelator
from app.analyzer.normalizer import EventNormalizer
from app.ingestion.parsers.linux_parser import LinuxParser
from app.models.event_types import EventType
from app.storage.event_store import EventStore

BASE = datetime(2026, 9, 1, 10, 0, 0)


def _ingest(lines):
    parser = LinuxParser()
    normalizer = EventNormalizer()
    store = EventStore()
    for raw in lines:
        parsed = parser.parse(raw)
        if parsed:
            store.add(normalizer.normalize(parsed))
    return store


def _hydra_burst(user, ip, start, n):
    """What sshd actually logs for `n` fast guesses that hit MaxAuthTries."""
    out = []
    for i in range(n):
        t = (start + timedelta(seconds=i)).strftime("%Y-%m-%dT%H:%M:%S+0000")
        port = 40000 + i
        if i % 3 == 0:
            out.append(f"{t} kali sshd-session[{1000+i}]: error: maximum "
                       f"authentication attempts exceeded for {user} from {ip} "
                       f"port {port} ssh2 [preauth]")
        elif i % 3 == 1:
            out.append(f"{t} kali sshd-session[{1000+i}]: Connection closed by "
                       f"authenticating user {user} {ip} port {port} [preauth]")
        else:
            out.append(f"{t} kali sshd-session[{1000+i}]: Failed password for "
                       f"{user} from {ip} port {port} ssh2")
    return out


def test_a_hydra_style_burst_is_detected_as_brute_force():

    store = _ingest(_hydra_burst("root", "192.168.10.9", BASE, 30))

    failures = store.get_by_type(EventType.FAILED_LOGIN)
    assert len(failures) == 30              # every line became an event

    behaviors = BehaviorCorrelator(store).detect()
    rules = {b.rule for b in behaviors}

    assert "brute-force" in rules
    bf = next(b for b in behaviors if b.rule == "brute-force")
    assert bf.attributes["ip_address"] == "192.168.10.9"
    assert bf.risk_score > 0


def test_compromise_is_seen_even_when_guesses_are_abort_lines():

    lines = _hydra_burst("kali", "192.168.10.9", BASE, 20)
    got_in = (BASE + timedelta(seconds=25)).strftime("%Y-%m-%dT%H:%M:%S+0000")
    lines.append(f"{got_in} kali sshd-session[2100]: Accepted password for "
                 f"kali from 192.168.10.9 port 40099 ssh2")

    store = _ingest(lines)
    behaviors = BehaviorCorrelator(store).detect()

    compromise = [b for b in behaviors if b.rule == "successful-brute-force"]
    assert compromise, "a login after 20 failed guesses must be flagged as a compromise"
    assert compromise[0].attributes["compromised"] is True
