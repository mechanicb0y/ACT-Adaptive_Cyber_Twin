#Time window helpers, the core of Week 2.
#"5 failed logins ever" is not an attack. "5 failed logins in 60 seconds" is.
#This is only possible because Week 1 fixed the event timestamps.

import ipaddress
from datetime import datetime
from typing import Callable, Dict, Hashable, List, Sequence

from app.models.security_event import SecurityEvent


def group_by(
    events: Sequence[SecurityEvent],
    key: Callable[[SecurityEvent], Hashable],
) -> Dict[Hashable, List[SecurityEvent]]:
    #split events into buckets, for example one bucket per (user, ip)

    groups: Dict[Hashable, List[SecurityEvent]] = {}

    for event in events:
        groups.setdefault(key(event), []).append(event)

    return groups


def sort_by_time(events: Sequence[SecurityEvent]) -> List[SecurityEvent]:
    return sorted(events, key=lambda event: event.timestamp)


def find_bursts(
    events: Sequence[SecurityEvent],
    window_seconds: int,
    threshold: int,
) -> List[List[SecurityEvent]]:
    """Return every group of at least `threshold` events that fit inside `window_seconds`.

    Sliding window with two pointers. `right` walks forward, `left` is pushed
    forward until the pair fits in the window. Whenever the window holds enough
    events we have a burst; overlapping bursts are merged so one attack is
    reported once instead of many times.
    """

    ordered = sort_by_time(events)

    if threshold <= 0 or len(ordered) < threshold:
        return []

    bursts: List[tuple[int, int]] = []
    current: tuple[int, int] | None = None
    left = 0

    for right in range(len(ordered)):

        while (
            ordered[right].timestamp - ordered[left].timestamp
        ).total_seconds() > window_seconds:
            left += 1

        if right - left + 1 < threshold:
            continue

        if current is not None and left <= current[1]:
            current = (current[0], right)      #still the same attack, extend it
        else:
            if current is not None:
                bursts.append(current)
            current = (left, right)

    if current is not None:
        bursts.append(current)

    return [ordered[start:end + 1] for start, end in bursts]


def find_distinct_burst(
    events: Sequence[SecurityEvent],
    window_seconds: int,
    threshold: int,
    key: Callable[[SecurityEvent], Hashable],
) -> List[SecurityEvent]:
    """Same sliding window, but counting DISTINCT values instead of events.

    Ten failures for one username is guessing a password. Ten failures for ten
    different usernames is someone hunting for accounts that exist. Both are
    ten events, so counting events cannot tell them apart.
    """

    ordered = sort_by_time(events)

    start = None
    end = None
    left = 0

    for right in range(len(ordered)):

        while (
            ordered[right].timestamp - ordered[left].timestamp
        ).total_seconds() > window_seconds:
            left += 1

        distinct = {key(event) for event in ordered[left:right + 1]}

        if len(distinct) >= threshold:
            if start is None:
                start = left
            end = right

    if start is None:
        return []

    return ordered[start:end + 1]


def events_within(
    events: Sequence[SecurityEvent],
    moment: datetime,
    window_seconds: int,
) -> List[SecurityEvent]:
    #events that happened in the `window_seconds` before `moment`

    return [
        event
        for event in events
        if 0 <= (moment - event.timestamp).total_seconds() <= window_seconds
    ]


def time_span(events: Sequence[SecurityEvent]) -> tuple[datetime, datetime]:

    ordered = sort_by_time(events)

    return ordered[0].timestamp, ordered[-1].timestamp


def events_per_minute(events: Sequence[SecurityEvent]) -> float:
    #speed of the attack, a human types slowly and a script does not

    if len(events) < 2:
        return 0.0

    first, last = time_span(events)

    seconds = (last - first).total_seconds()

    if seconds <= 0:
        return float(len(events)) * 60.0

    return len(events) / (seconds / 60.0)


def is_remote_ip(ip_address: str | None) -> bool:
    #came over the network from another machine, even if that machine is on the LAN

    if not ip_address:
        return False

    try:
        parsed = ipaddress.ip_address(ip_address)
    except ValueError:
        return False

    return not parsed.is_loopback


def is_external_ip(ip_address: str | None) -> bool:
    #private, loopback and link-local addresses are treated as internal

    if not ip_address:
        return False

    try:
        parsed = ipaddress.ip_address(ip_address)
    except ValueError:
        return False

    return not (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_reserved
    )
