"""ACT command line entry point.

Examples
--------
Replay a captured log file:

    python -m app.main --file tests/logs/auth_bruteforce.log

Read the real machine (Linux with systemd):

    python -m app.main --journal --since "-1h"

Watch the machine live and print events as they appear:

    sudo python -m app.main --journal --follow

Machine readable output for the future API/dashboard:

    python -m app.main --file tests/logs/auth_bruteforce.log --json
"""

import argparse
import sys
from typing import Optional

from app.analyzer.behavior_correlator import BehaviorCorrelator
from app.analyzer.normalizer import EventNormalizer
from app.ingestion.parsers.linux_parser import LinuxParser
from app.ingestion.pipeline import IngestionPipeline
from app.ingestion.readers.base_reader import BaseLogReader
from app.ingestion.readers.file_log_reader import FileLogReader
from app.ingestion.readers.journald_reader import JournaldReader
from app.storage.event_store import EventStore
from app.utils.json_printer import print_json
from app.utils.report_printer import (
    format_event,
    print_behaviors,
    print_events,
    print_header,
    print_stats,
)

DEFAULT_IDENTIFIERS = ["sshd", "sshd-session", "sudo", "useradd", "su"]


def build_reader(args: argparse.Namespace) -> BaseLogReader:

    if args.file:
        return FileLogReader(
            path=args.file,
            follow=args.follow,
            from_start=not args.tail,
        )

    return JournaldReader(
        units=args.unit or None,
        identifiers=None if args.unit else DEFAULT_IDENTIFIERS,
        since=args.since,
        follow=args.follow,
    )


def describe_target(args: argparse.Namespace) -> str:

    if args.file:
        return f"file {args.file}"

    if args.unit:
        units = ", ".join(args.unit)
        return f"systemd journal, units {units}, since {args.since}"

    return f"systemd journal, since {args.since}"


def build_parser_arguments() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(
        prog="act",
        description="ACT - Adaptive Cyber Twin. Linux log ingestion pipeline.",
    )

    source = parser.add_mutually_exclusive_group()

    source.add_argument(
        "--file",
        help="replay a log file instead of reading the live journal",
    )

    source.add_argument(
        "--journal",
        action="store_true",
        help="read systemd journal (default when no --file is given)",
    )

    parser.add_argument(
        "--unit",
        action="append",
        help="restrict journald to a systemd unit (repeatable), e.g. --unit ssh",
    )

    parser.add_argument(
        "--since",
        default="-24h",
        help="journald time window, e.g. '-1h', 'today' (default: -24h)",
    )

    parser.add_argument(
        "--follow",
        action="store_true",
        help="keep running and process new lines as they arrive",
    )

    parser.add_argument(
        "--tail",
        action="store_true",
        help="with --file --follow, start at the end instead of the beginning",
    )

    parser.add_argument(
        "--host",
        default="unknown",
        help="host name to use when a log line has no syslog envelope",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="print detected behaviors as JSON",
    )

    parser.add_argument(
        "--show-events",
        action="store_true",
        help="also print every normalized event",
    )

    parser.add_argument(
        "--evidence",
        type=int,
        default=10,
        help="max evidence events printed per behavior, 0 for all (default 10)",
    )

    parser.add_argument(
        "--raw",
        action="store_true",
        help="print the original log line under each evidence event",
    )

    return parser


def run(argv: Optional[list[str]] = None) -> int:

    args = build_parser_arguments().parse_args(argv)

    reader = build_reader(args)
    parser = LinuxParser(default_host=args.host)
    store = EventStore()
    correlator = BehaviorCorrelator(store)

    on_event = None

    if args.follow:
        # In live mode, report each event the moment it is understood.
        def on_event(event):  # noqa: F811
            print(format_event(event))

    pipeline = IngestionPipeline(
        reader=reader,
        parser=parser,
        event_store=store,
        normalizer=EventNormalizer(),
        on_event=on_event,
    )

    if not args.json:
        print_header(describe_target(args), args.follow)

    try:
        stats = pipeline.run()

    except KeyboardInterrupt:
        print("\nStopped by user.")
        return 0

    except (FileNotFoundError, RuntimeError) as error:
        print(f"Error. {error}", file=sys.stderr)
        return 1

    behaviors = correlator.detect_brute_force()

    if args.json:
        print_json(behaviors)
        return 0

    print_stats(stats)

    if args.show_events:
        print_events(store.all())

    print_behaviors(
        behaviors,
        evidence_limit=args.evidence,
        show_raw=args.raw,
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(run())
