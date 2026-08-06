from datetime import datetime

from app.utils.time_parser import (
    parse_iso_timestamp,
    parse_syslog_timestamp,
    parse_timestamp,
)


def test_syslog_timestamp_uses_reference_year():

    reference = datetime(2026, 8, 6, 22, 0, 0)

    result = parse_syslog_timestamp("Aug  6 21:11:09", reference=reference)

    assert result == datetime(2026, 8, 6, 21, 11, 9)


def test_syslog_timestamp_rolls_back_a_year_when_in_the_future():

    # Parsing a December log while it is January -> the log is from last year.
    reference = datetime(2026, 1, 5, 10, 0, 0)

    result = parse_syslog_timestamp("Dec 28 03:14:00", reference=reference)

    assert result.year == 2025


def test_iso_timestamp_with_journalctl_offset():

    result = parse_iso_timestamp("2026-08-06T21:11:09+0300")

    assert result.year == 2026
    assert result.tzinfo is None  # normalized to naive local time


def test_parse_timestamp_passes_datetime_through():

    moment = datetime(2026, 8, 6, 12, 0, 0)

    assert parse_timestamp(moment) is moment


def test_parse_timestamp_falls_back_instead_of_raising():

    fallback = datetime(2000, 1, 1)

    assert parse_timestamp("not a date at all", fallback=fallback) == fallback
    assert parse_timestamp(None, fallback=fallback) == fallback
    assert parse_timestamp("", fallback=fallback) == fallback
