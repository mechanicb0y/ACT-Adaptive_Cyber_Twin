"""ACT command line entry point.

Examples
--------
Replay a captured log file:

    python -m app.main --file tests/logs/auth_bruteforce.log

Read the real machine (Linux with systemd):

    python -m app.main --journal --since=-1h

Read the Kali virtual machine from Windows, over SSH:

    python -m app.main --ssh kali@192.168.86.130 --since=-1h
    python -m app.main --ssh kali@192.168.86.130 --follow

Watch the machine live and print events as they appear:

    sudo python -m app.main --journal --follow

Machine readable output for the future API/dashboard:

    python -m app.main --file tests/logs/auth_bruteforce.log --json
"""

import argparse
import sys
from typing import Optional

from app.config import env as _env  # noqa: F401  (loads backend/.env on import)
from app.analyzer.behavior_correlator import BehaviorCorrelator
from app.analyzer.normalizer import EventNormalizer
from app.config.detection_config import DetectionConfig
from app.ingestion.parsers.linux_parser import LinuxParser
from app.ingestion.pipeline import IngestionPipeline
from app.ingestion.readers.base_reader import BaseLogReader
from app.ingestion.readers.file_log_reader import FileLogReader
from app.ingestion.readers.journald_reader import JournaldReader
from app.ingestion.readers.ssh_journald_reader import SSHJournalReader
from app.storage.event_store import EventStore
from app.utils.json_printer import print_json
from app.intelligence.cognitive_twin import CognitiveTwin
from app.intelligence.llm_analyst import LlmAnalyst
from app.intelligence.rag.retriever import Retriever
from app.utils.report_printer import (
    format_event,
    print_attack_graph,
    print_behaviors,
    print_events,
    print_header,
    print_stats,
    print_twin,
)

DEFAULT_IDENTIFIERS = ["sshd", "sshd-session", "sudo", "useradd", "su"]


def split_ssh_target(target: str) -> tuple[Optional[str], str]:
    #accepts "kali@192.168.1.20" or just "192.168.1.20"

    if "@" in target:
        user, host = target.split("@", 1)
        return user, host

    return None, target


def build_reader(args: argparse.Namespace) -> BaseLogReader:

    if args.ssh:
        user, host = split_ssh_target(args.ssh)

        return SSHJournalReader(
            host=host,
            user=user,
            port=args.ssh_port,
            key_file=args.ssh_key,
            use_sudo=args.ssh_sudo,
            units=args.unit or None,
            identifiers=None if args.unit else DEFAULT_IDENTIFIERS,
            since=args.since,
            follow=args.follow,
        )

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

    if args.ssh:
        return f"systemd journal on {args.ssh}, since {args.since}"

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

    source.add_argument(
        "--ssh",
        metavar="USER@HOST",
        help="read the journal of another machine over SSH, e.g. kali@192.168.86.130",
    )

    parser.add_argument("--ssh-port", type=int, default=22, help="SSH port (default 22)")

    parser.add_argument("--ssh-key", help="path to the SSH private key to use")

    parser.add_argument(
        "--ssh-sudo",
        action="store_true",
        help="run journalctl with sudo -n on the remote machine",
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

    parser.add_argument(
        "--config",
        help="detection config file (default config/detection.json)",
    )

    parser.add_argument(
        "--no-factors",
        action="store_true",
        help="hide the risk score breakdown",
    )

    parser.add_argument(
        "--min-risk",
        type=int,
        default=0,
        help="only show behaviors at or above this risk score (default 0)",
    )

    parser.add_argument(
        "--graph",
        action="store_true",
        help="show the attack path instead of the behavior list",
    )

    parser.add_argument(
        "--twin",
        action="store_true",
        help="run the AI layer: predict, decide, respond (dry run), explain",
    )

    return parser


#options that take a value which often starts with a dash, e.g. --since -24h
_DASH_VALUE_OPTIONS = {"--since"}


def glue_dash_values(argv: list[str]) -> list[str]:
    """Let ``--since -24h`` work, not only ``--since=-24h``.

    argparse treats a value starting with '-' as another flag, so on PowerShell
    ``--since "-24h"`` fails with "expected one argument". We join those pairs
    into the ``--since=-24h`` form argparse accepts, before it ever sees them.
    """

    fixed: list[str] = []
    i = 0

    while i < len(argv):
        token = argv[i]

        if token in _DASH_VALUE_OPTIONS and i + 1 < len(argv):
            fixed.append(f"{token}={argv[i + 1]}")
            i += 2
            continue

        fixed.append(token)
        i += 1

    return fixed


def run(argv: Optional[list[str]] = None) -> int:

    raw = list(argv) if argv is not None else sys.argv[1:]

    args = build_parser_arguments().parse_args(glue_dash_values(raw))

    reader = build_reader(args)
    parser = LinuxParser(default_host=args.host)
    store = EventStore()

    correlator = BehaviorCorrelator(
        store,
        config=DetectionConfig.load(args.config),
    )

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

    behaviors = [
        behavior
        for behavior in correlator.detect()
        if behavior.risk_score >= args.min_risk
    ]

    twin_assessments = None
    if args.twin:
        graph = correlator.build_attack_graph(behaviors)
        #build the AI layer with RAG + local-model-preferred analyst
        try:
            retriever = Retriever.build()
        except Exception:                                   # noqa: BLE001
            retriever = None
        twin = CognitiveTwin(analyst=LlmAnalyst(retriever=retriever))
        twin_assessments = twin.assess(graph, store.all())

    if args.json:
        if args.twin:
            from app.api.serializers import assessments_to_list
            print_json(assessments_to_list(twin_assessments))
        elif args.graph:
            print_json(correlator.build_attack_graph(behaviors).to_dict())
        else:
            print_json(behaviors)
        return 0

    print_stats(stats)

    if args.show_events:
        print_events(store.all())

    if args.twin:
        print_twin(twin_assessments)
        return 0

    if args.graph:
        print_attack_graph(correlator.build_attack_graph(behaviors))
        return 0

    print_behaviors(
        behaviors,
        evidence_limit=args.evidence,
        show_raw=args.raw,
        show_factors=not args.no_factors,
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(run())
