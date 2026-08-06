
#Log sources write time in different formats. This module turns any of them
#into a real ``datetime`` object so the rest of ACT never has to care.


from datetime import datetime, timedelta
from typing import Optional, Union

# "Jul 30 21:51:43"  and  "Jul  3 09:05:01" (day padded with a space)
SYSLOG_FORMAT = "%b %d %H:%M:%S"


def parse_syslog_timestamp(
    value: str,
    reference: Optional[datetime] = None,
) -> datetime:

    #Because the year is missing we assume the log belongs to the current
    #year. If that produces a date in the future (for example parsing a
    #December log during January) we roll back one year.

    reference = reference or datetime.now()

    # collapse the double space of "Jul  3" so strptime is happy
    cleaned = " ".join(value.split())

    parsed = datetime.strptime(cleaned, SYSLOG_FORMAT)

    candidate = parsed.replace(year=reference.year)

    if candidate > reference + timedelta(days=1):
        candidate = candidate.replace(year=reference.year - 1)

    return candidate


def parse_iso_timestamp(value: str) -> datetime:
    """Parse ISO 8601, including the ``+0300`` offset journalctl emits."""

    cleaned = value.strip().replace("Z", "+00:00")

    # journalctl writes "+0300"; fromisoformat wants "+03:00"
    if len(cleaned) >= 5:
        offset = cleaned[-5:]
        if (offset[0] in "+-") and offset[1:].isdigit():
            cleaned = cleaned[:-5] + offset[:3] + ":" + offset[3:]

    parsed = datetime.fromisoformat(cleaned)

    # ACT stores naive local time everywhere, so drop the tzinfo
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone().replace(tzinfo=None)

    return parsed


def parse_timestamp(
    value: Union[str, int, float, datetime, None],
    reference: Optional[datetime] = None,
    fallback: Optional[datetime] = None,
) -> datetime:


    #Falls back to ``fallback`` (default: now) when the value is missing or
    #unreadable. Ingestion must never crash because one line had a weird date.


    if isinstance(value, datetime):
        return value

    if value is None:
        return fallback or datetime.now()

    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value)

    text = str(value).strip()

    if not text:
        return fallback or datetime.now()

    if text.isdigit() and len(text) >= 9:
        return datetime.fromtimestamp(int(text))

    try:
        if text[:4].isdigit() and "-" in text[:8]:
            return parse_iso_timestamp(text)
        return parse_syslog_timestamp(text, reference=reference)
    except (ValueError, OSError, OverflowError):
        return fallback or datetime.now()
