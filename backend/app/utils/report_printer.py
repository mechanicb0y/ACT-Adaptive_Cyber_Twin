#This module handles ACT’s console formatting separately from main.py so it can be reused later. 
#It keeps the output simple with plain lines and indentation for structure.

from typing import Iterable, List

from app.ingestion.pipeline import IngestionStats
from app.models.behavior import Behavior
from app.models.security_event import SecurityEvent

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def format_event(event: SecurityEvent) -> str:
    """One event on one line, most important facts first."""

    return (
        f"{event.timestamp:{TIME_FORMAT}}  "
        f"{event.event_type}  "
        f"{event.description}"
    )


def print_header(target: str, follow: bool) -> None:

    mode = " (live, following)" if follow else ""

    print(f"ACT ingestion from {target}{mode}")
    print()


def print_stats(stats: IngestionStats) -> None:

    print(
        f"{stats.lines_read} lines read, "
        f"{stats.events_created} events created, "
        f"{stats.lines_unmatched} skipped, "
        f"{stats.parse_errors} parse errors, "
        f"coverage {stats.coverage:.1%}"
    )
    print()


def print_events(events: Iterable[SecurityEvent]) -> None:

    events = list(events)

    if not events:
        print("No events.")
        print()
        return

    print(f"{len(events)} events")

    for event in events:
        print(f"    {format_event(event)}")

    print()


def print_behaviors(
    behaviors: List[Behavior],
    evidence_limit: int = 10,
    show_raw: bool = False,
) -> None:
    """Print every behavior together with the events that prove it."""

    if not behaviors:
        print("No behaviors detected.")
        return

    print(f"{len(behaviors)} behaviors detected")
    print()

    for index, behavior in enumerate(behaviors, start=1):

        print(f"{index}. {behavior.name} [{behavior.severity}]")
        print(f"    {behavior.description}")
        print(
            f"    confidence {behavior.confidence}, "
            f"evidence {len(behavior.evidence)} events"
        )

        shown = behavior.evidence

        if evidence_limit > 0:
            shown = behavior.evidence[:evidence_limit]

        for event in shown:
            print(f"        {format_event(event)}")

            if show_raw and event.raw_log:
                print(f"            {event.raw_log}")

        hidden = len(behavior.evidence) - len(shown)

        if hidden > 0:
            print(f"        and {hidden} more events")

        print()
