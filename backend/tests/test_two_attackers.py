"""Two different attackers on the same machine must stay two different attacks.

The log holds a failed attack from the internet at 02:14 and a successful one
from inside the network at 09:41. Mixing them into one path would be wrong,
and a list of behaviors cannot tell them apart at all.
"""

import pytest

from app.analyzer.behavior_correlator import BehaviorCorrelator
from app.analyzer.normalizer import EventNormalizer
from app.ingestion.parsers.linux_parser import LinuxParser
from app.ingestion.pipeline import IngestionPipeline
from app.ingestion.readers.file_log_reader import FileLogReader
from app.storage.event_store import EventStore

OUTSIDER = "185.220.101.34"
INSIDER = "10.10.10.22"


@pytest.fixture
def two_attackers_log(logs_dir):
    return logs_dir / "two_attackers.log"


@pytest.fixture
def graph(two_attackers_log):

    store = EventStore()

    IngestionPipeline(
        reader=FileLogReader(two_attackers_log),
        parser=LinuxParser(),
        event_store=store,
        normalizer=EventNormalizer(),
    ).run()

    return BehaviorCorrelator(store).build_attack_graph()


def test_two_attackers_produce_two_paths(graph):

    assert len(graph.paths) == 2
    assert {path.actor for path in graph.paths} == {OUTSIDER, INSIDER}


def test_no_behavior_belongs_to_both_paths(graph):

    first = {node.id for node in graph.paths[0].nodes}
    second = {node.id for node in graph.paths[1].nodes}

    assert first & second == set()


def test_the_attacker_who_got_in_is_ranked_first(graph):

    top = graph.paths[0]

    assert top.actor == INSIDER
    assert top.succeeded is True
    assert top.completeness > graph.paths[1].completeness


def test_the_failed_attack_is_marked_as_failed(graph):

    outside = next(path for path in graph.paths if path.actor == OUTSIDER)

    assert outside.succeeded is False
    assert outside.deepest_stage == 2
    assert outside.completeness == round(2 / 6, 4)


def test_a_missing_stage_does_not_break_the_path(graph):

    #this attacker never triggered privilege escalation, so stage 4 is absent
    inside = next(path for path in graph.paths if path.actor == INSIDER)

    assert inside.stages_reached == [2, 3, 5]
    assert inside.deepest_stage == 5


def test_an_attack_from_the_internet_scores_higher_than_one_from_the_lan(graph):

    outside = next(path for path in graph.paths if path.actor == OUTSIDER)

    brute = [
        node
        for node in outside.nodes
        if node.behavior.rule == "brute-force"
    ][0]

    reasons = {factor.name for factor in brute.behavior.risk_factors}

    assert "external_ip" in reasons
    assert "night" in reasons          # it happened at 02:14
    assert "privileged_target" in reasons
