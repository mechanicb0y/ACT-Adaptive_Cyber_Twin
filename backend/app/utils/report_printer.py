#This module handles ACT’s console formatting separately from main.py so it can be reused later. 
#It keeps the output simple with plain lines and indentation for structure.

from typing import Iterable, List

from app.ingestion.pipeline import IngestionStats
from app.models.attack_graph import AttackGraph, AttackPath
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
    show_factors: bool = True,
) -> None:
    """Print every behavior with its risk score, the reasons, and the proof."""

    if not behaviors:
        print("No behaviors detected.")
        return

    print(f"{len(behaviors)} behaviors detected")
    print()

    for index, behavior in enumerate(behaviors, start=1):

        print(
            f"{index}. {behavior.name}   "
            f"risk {behavior.risk_score}/100   {behavior.severity}"
        )
        print(f"    {behavior.description}")

        span = ""
        if behavior.first_seen and behavior.last_seen:
            span = (
                f", {behavior.first_seen:%H:%M:%S} to "
                f"{behavior.last_seen:%H:%M:%S}"
            )

        print(
            f"    rule {behavior.rule}, confidence {behavior.confidence}, "
            f"{len(behavior.evidence)} events{span}"
        )

        if behavior.techniques:
            stage = behavior.stage_name or "Unmapped"
            print(f"    MITRE ATT&CK, stage {behavior.stage} {stage}")
            for technique in behavior.techniques:
                print(f"        {technique}")

        if show_factors and behavior.risk_factors:
            print("    why this score")
            for factor in behavior.risk_factors:
                print(f"        {factor}")

        shown = behavior.evidence

        if evidence_limit > 0:
            shown = behavior.evidence[:evidence_limit]

        if shown:
            print("    evidence")

        for event in shown:
            print(f"        {format_event(event)}")

            if show_raw and event.raw_log:
                print(f"            {event.raw_log}")

        hidden = len(behavior.evidence) - len(shown)

        if hidden > 0:
            print(f"        and {hidden} more events")

        print()


def print_attack_path(path: AttackPath, index: int = 1) -> None:
    """One attacker, drawn as a chain from first stage to last."""

    actor = path.actor or "unknown source"

    outcome = "the attacker succeeded" if path.succeeded else "no confirmed compromise"

    print(f"Attack path {index}, source {actor}")
    print(
        f"    kill chain {path.deepest_stage} of {path.total_stages} stages, "
        f"{path.completeness:.0%} complete, {outcome}"
    )

    if path.started_at and path.ended_at:
        print(f"    from {path.started_at:%Y-%m-%d %H:%M:%S} to {path.ended_at:%H:%M:%S}")

    print(f"    highest risk {path.highest_risk}/100")
    print()

    #reasons for the link from the previous node, keyed by target
    incoming = {}
    for edge in path.edges:
        incoming.setdefault(edge.target, []).extend(edge.reasons)

    for position, node in enumerate(path.nodes):

        if position > 0:
            reasons = incoming.get(node.id)
            arrow = f"    |   {', '.join(sorted(set(reasons)))}" if reasons else "    |"
            print(arrow)

        techniques = ", ".join(node.technique_ids) or "unmapped"

        print(
            f"    {node.stage}. {node.stage_name}   {node.label}   "
            f"{techniques}   risk {node.risk_score}"
        )

    print()


def print_attack_graph(graph: AttackGraph) -> None:

    if not graph.paths:
        print("No attack paths found.")
        return

    print(f"{len(graph.paths)} attack path(s)")
    print()

    for index, path in enumerate(graph.paths, start=1):
        print_attack_path(path, index)


def print_twin(assessments) -> None:
    """Print the AI layer: predict, decide, respond, explain, per attacker."""

    if not assessments:
        print("No attackers to assess.")
        return

    print(f"Cyber Cognitive Twin — {len(assessments)} attacker(s) assessed")
    print()

    for index, a in enumerate(assessments, start=1):

        outcome = "compromised" if a.succeeded else "no compromise"
        print(f"{index}. {a.actor}   {a.completeness:.0%} of kill chain, {outcome}")

        pred = a.prediction
        print(f"    PREDICT   now at {pred.current_stage_name or 'early stage'}, "
              f"anomaly {pred.anomaly_score:.0%} (model: {pred.model})")
        for step in pred.next_steps[:3]:
            print(f"        next -> {step.stage_name}  {int(step.probability * 100)}%  ({step.reason})")

        dec = a.decision
        print(f"    DECIDE    {dec.action}"
              + (f" -> {dec.target}" if dec.target else "")
              + f"   urgency {dec.urgency}, confidence {dec.confidence}")
        print(f"        {dec.rationale}")

        if a.response:
            print(f"    RESPOND   {a.response.status}"
                  + (f"   {a.response.command}" if a.response.command else ""))

        print(f"    EXPLAIN   ({a.narrator})")
        print(f"        {a.narrative}")
        print()
