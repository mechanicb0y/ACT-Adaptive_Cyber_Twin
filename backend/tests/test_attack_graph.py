from datetime import datetime, timedelta
from uuid import uuid4

from app.analyzer.attack_graph_builder import AttackGraphBuilder
from app.analyzer.mitre_mapper import MitreMapper
from app.models.behavior import Behavior
from app.models.severity import Severity

START = datetime(2026, 8, 6, 21, 0, 0)


def behavior(rule, offset=0, ip="192.168.1.50", user=None, extra=None):

    attributes = {"ip_address": ip} if ip else {}

    if user:
        attributes["target_user"] = user

    attributes.update(extra or {})

    return Behavior(
        id=str(uuid4()),
        name=rule,
        description=rule,
        severity=Severity.MEDIUM,
        confidence=0.8,
        rule=rule,
        risk_score=50,
        first_seen=START + timedelta(seconds=offset),
        last_seen=START + timedelta(seconds=offset + 10),
        attributes=attributes,
    )


def build(behaviors):
    return AttackGraphBuilder(mapper=MitreMapper()).build(behaviors)


def test_empty_input_gives_an_empty_graph():

    graph = build([])

    assert graph.paths == []
    assert graph.worst_path is None


def test_behaviors_from_one_attacker_become_one_path():

    graph = build(
        [
            behavior("user-enumeration", 0),
            behavior("brute-force", 10, user="root"),
            behavior("successful-brute-force", 20, user="kali"),
        ]
    )

    assert len(graph.paths) == 1
    assert len(graph.paths[0].nodes) == 3


def test_two_attackers_become_two_separate_paths():

    graph = build(
        [
            behavior("brute-force", 0, ip="10.0.0.1", user="root"),
            behavior("brute-force", 10, ip="10.0.0.2", user="admin"),
        ]
    )

    assert len(graph.paths) == 2
    assert {path.actor for path in graph.paths} == {"10.0.0.1", "10.0.0.2"}


def test_nodes_are_ordered_by_kill_chain_stage_not_by_time():

    #the compromise starts earlier in the clock because its evidence includes
    #the failed logins, but logically it comes after the brute force
    compromise = behavior("successful-brute-force", 0, user="kali")
    enumeration = behavior("user-enumeration", 100)

    path = build([compromise, enumeration]).paths[0]

    stages = [node.stage for node in path.nodes]

    assert stages == sorted(stages)
    assert path.nodes[0].behavior.rule == "user-enumeration"
    assert path.nodes[-1].behavior.rule == "successful-brute-force"


def test_edges_say_why_two_behaviors_are_connected():

    path = build(
        [
            behavior("brute-force", 0, user="kali"),
            behavior("successful-brute-force", 10, user="kali"),
        ]
    ).paths[0]

    assert len(path.edges) == 1

    reasons = path.edges[0].reasons

    assert "same source address 192.168.1.50" in reasons
    assert "same user account kali" in reasons


def test_behaviors_with_nothing_in_common_are_not_linked():

    graph = build(
        [
            behavior("brute-force", 0, ip="10.0.0.1", user="root"),
            behavior("persistence", 10, ip="10.0.0.9", user="other"),
        ]
    )

    assert len(graph.paths) == 2
    assert all(path.edges == [] for path in graph.paths)


def test_behaviors_far_apart_in_time_are_not_the_same_attack():

    #two different people attacking the same account, five hours apart.
    #without a time limit they would be drawn as one attack.
    morning = behavior("brute-force", 0, ip="10.0.0.1", user="root")
    evening = behavior("brute-force", 5 * 3600, ip="10.0.0.2", user="root")

    graph = build([morning, evening])

    assert len(graph.paths) == 2


def test_the_time_limit_can_be_switched_off():

    morning = behavior("brute-force", 0, ip="10.0.0.1", user="root")
    evening = behavior("persistence", 5 * 3600, ip="10.0.0.2", user="root")

    builder = AttackGraphBuilder(mapper=MitreMapper(), max_gap_seconds=0)

    assert len(builder.build([morning, evening]).paths) == 1


def test_overlapping_behaviors_have_no_gap():

    first = behavior("brute-force", 0)
    second = behavior("successful-brute-force", 5)   # starts inside the first

    assert AttackGraphBuilder.gap_seconds(first, second) == 0.0

    apart = behavior("persistence", 600)

    assert AttackGraphBuilder.gap_seconds(first, apart) == 590.0


def test_kill_chain_completeness():

    #only reached stage 2 of 6
    early = build([behavior("user-enumeration", 0), behavior("brute-force", 10)]).paths[0]

    assert early.deepest_stage == 2
    assert early.completeness == round(2 / 6, 4)

    #reached the last stage
    full = build(
        [
            behavior("user-enumeration", 0),
            behavior("brute-force", 10),
            behavior("successful-brute-force", 20),
            behavior("privilege-escalation", 30),
            behavior("sensitive-file-access", 40),
            behavior("persistence", 50),
        ]
    ).paths[0]

    assert full.deepest_stage == 6
    assert full.completeness == 1.0
    assert full.stages_reached == [1, 2, 3, 4, 5, 6]


def test_the_path_knows_whether_the_attacker_got_in():

    failed = build([behavior("brute-force", 0)]).paths[0]

    assert failed.succeeded is False

    worked = build(
        [
            behavior("brute-force", 0),
            behavior("successful-brute-force", 10, extra={"compromised": True}),
        ]
    ).paths[0]

    assert worked.succeeded is True


def test_the_attacker_who_got_furthest_is_listed_first():

    graph = build(
        [
            behavior("user-enumeration", 0, ip="10.0.0.1"),
            behavior("brute-force", 10, ip="10.0.0.2", user="root"),
            behavior("persistence", 20, ip="10.0.0.2"),
        ]
    )

    assert graph.paths[0].actor == "10.0.0.2"
    assert graph.worst_path is graph.paths[0]


def test_the_graph_exports_json_for_the_dashboard():

    graph = build(
        [
            behavior("brute-force", 0, user="kali"),
            behavior("successful-brute-force", 10, user="kali"),
        ]
    )

    data = graph.to_dict()

    assert data["path_count"] == 1

    path = data["paths"][0]

    assert path["actor"] == "192.168.1.50"
    assert path["completeness"] > 0
    assert len(path["nodes"]) == 2
    assert len(path["edges"]) == 1

    node = path["nodes"][0]

    assert node["techniques"][0]["id"].startswith("T")
    assert node["techniques"][0]["url"].startswith("https://attack.mitre.org")
