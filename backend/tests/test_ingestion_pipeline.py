"""End-to-end: real log file -> events -> behavior."""

from app.analyzer.behavior_correlator import BehaviorCorrelator
from app.analyzer.normalizer import EventNormalizer
from app.ingestion.parsers.linux_parser import LinuxParser
from app.ingestion.pipeline import IngestionPipeline
from app.ingestion.readers.file_log_reader import FileLogReader
from app.models.event_types import EventType
from app.storage.event_store import EventStore


def build_pipeline(log_path, store=None, on_event=None):

    store = store if store is not None else EventStore()

    pipeline = IngestionPipeline(
        reader=FileLogReader(log_path),
        parser=LinuxParser(),
        event_store=store,
        normalizer=EventNormalizer(),
        on_event=on_event,
    )

    return pipeline, store


def test_pipeline_ingests_the_attack_log(bruteforce_log):

    pipeline, store = build_pipeline(bruteforce_log)

    stats = pipeline.run()

    assert stats.lines_read == 35
    assert stats.parse_errors == 0
    assert stats.events_created == len(store.all())
    assert stats.lines_unmatched > 0  # session/cron noise was correctly skipped
    assert 0 < stats.coverage < 1


def test_pipeline_produces_every_expected_event_type(bruteforce_log):

    pipeline, store = build_pipeline(bruteforce_log)
    pipeline.run()

    types = {event.event_type for event in store.all()}

    assert types == {
        EventType.FAILED_LOGIN,
        EventType.SUCCESSFUL_LOGIN,
        EventType.SUDO_FAILURE,
        EventType.SUDO_COMMAND,
        EventType.ACCOUNT_CREATED,
    }


def test_events_keep_the_real_log_timestamp_not_ingestion_time(bruteforce_log):

    pipeline, store = build_pipeline(bruteforce_log)
    pipeline.run()

    events = store.all()

    # The log is from August 6th, 21:1x. If timestamps were datetime.now()
    # this assertion would fail on every day except the day of the attack.
    attack_events = [e for e in events if e.ip_address == "192.168.1.50"]

    assert attack_events
    assert all(e.timestamp.month == 8 and e.timestamp.day == 6 for e in attack_events)
    assert all(e.timestamp.hour == 21 for e in attack_events)

    # ingested_at is the separate "when ACT saw it" clock
    assert all(e.ingested_at is not None for e in events)
    assert all(e.raw_log for e in events)


def test_on_event_callback_fires_for_every_event(bruteforce_log):

    seen = []

    pipeline, store = build_pipeline(bruteforce_log, on_event=seen.append)
    stats = pipeline.run()

    assert len(seen) == stats.events_created


def test_correlator_detects_brute_force_from_the_real_log(bruteforce_log):

    pipeline, store = build_pipeline(bruteforce_log)
    pipeline.run()

    behaviors = BehaviorCorrelator(store).detect_brute_force()

    assert behaviors, "expected at least one brute force behavior"

    attacker = [
        behavior
        for behavior in behaviors
        if "192.168.1.50" in behavior.description
    ]

    assert attacker
    assert all(b.name == "Possible Brute Force Attack" for b in behaviors)
    assert all(len(b.evidence) >= 5 for b in behaviors)


def test_a_broken_line_does_not_stop_ingestion(tmp_path):

    log = tmp_path / "mixed.log"
    log.write_text(
        "\n".join(
            [
                "this line is complete garbage",
                "Aug  6 21:11:09 kali sshd-session[7611]: "
                "Failed password for root from 192.168.1.50 port 51412 ssh2",
                "another useless line",
            ]
        ),
        encoding="utf-8",
    )

    pipeline, store = build_pipeline(log)
    stats = pipeline.run()

    assert stats.lines_read == 3
    assert stats.events_created == 1
    assert stats.lines_unmatched == 2
