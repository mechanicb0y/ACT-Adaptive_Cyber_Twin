"""End to end on the real attack log, Week 3 version.

Week 2 proved ACT finds every stage. This proves it can NAME every stage in
MITRE ATT&CK language and connect them into one attack path.
"""

from app.analyzer.behavior_correlator import BehaviorCorrelator
from app.analyzer.normalizer import EventNormalizer
from app.ingestion.parsers.linux_parser import LinuxParser
from app.ingestion.pipeline import IngestionPipeline
from app.ingestion.readers.file_log_reader import FileLogReader
from app.storage.event_store import EventStore

ATTACKER_IP = "192.168.1.50"


def correlator_for(log_path) -> BehaviorCorrelator:

    store = EventStore()

    IngestionPipeline(
        reader=FileLogReader(log_path),
        parser=LinuxParser(),
        event_store=store,
        normalizer=EventNormalizer(),
    ).run()

    return BehaviorCorrelator(store)


def test_every_behavior_carries_an_attack_technique(bruteforce_log):

    for behavior in correlator_for(bruteforce_log).detect():

        assert behavior.techniques, f"{behavior.rule} has no technique"
        assert behavior.stage > 0
        assert behavior.stage_name


def test_the_expected_techniques_are_all_present(bruteforce_log):

    found = set()

    for behavior in correlator_for(bruteforce_log).detect():
        found.update(behavior.technique_ids)

    assert found == {
        "T1087.001",   # account discovery
        "T1110.001",   # password guessing
        "T1078.003",   # valid accounts
        "T1548.003",   # sudo abuse
        "T1003.008",   # /etc/shadow
        "T1136.001",   # create local account
    }


def test_the_whole_attack_is_one_path(bruteforce_log):

    graph = correlator_for(bruteforce_log).build_attack_graph()

    assert len(graph.paths) == 1

    path = graph.paths[0]

    assert path.actor == ATTACKER_IP
    assert len(path.nodes) == 7
    assert path.edges


def test_the_attacker_completed_the_whole_kill_chain(bruteforce_log):

    path = correlator_for(bruteforce_log).build_attack_graph().paths[0]

    assert path.deepest_stage == 6
    assert path.total_stages == 6
    assert path.completeness == 1.0
    assert path.succeeded is True
    assert path.highest_risk == 100


def test_the_path_reads_in_attack_order(bruteforce_log):

    path = correlator_for(bruteforce_log).build_attack_graph().paths[0]

    stages = [node.stage_name for node in path.nodes]

    assert stages == [
        "Discovery",
        "Credential Access",
        "Credential Access",
        "Initial Access",
        "Privilege Escalation",
        "Credential Theft",
        "Persistence",
    ]


def test_every_step_after_the_first_is_linked_to_an_earlier_one(bruteforce_log):

    path = correlator_for(bruteforce_log).build_attack_graph().paths[0]

    linked = {edge.target for edge in path.edges}

    for node in path.nodes[1:]:
        assert node.id in linked, f"{node.label} is not connected to the attack"

    for edge in path.edges:
        assert edge.reasons


def test_the_graph_exports_cleanly_for_the_dashboard(bruteforce_log):

    data = correlator_for(bruteforce_log).build_attack_graph().to_dict()

    assert data["path_count"] == 1

    path = data["paths"][0]

    assert path["actor"] == ATTACKER_IP
    assert path["completeness"] == 1.0
    assert path["succeeded"] is True
    assert len(path["nodes"]) == 7
    assert "T1136.001" in path["techniques"]
