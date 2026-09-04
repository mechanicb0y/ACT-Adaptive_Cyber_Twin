"""ACT must detect the multi-stage internal (lateral movement) attack in
tests/logs/lateral_movement.log - the committed default output of
scripts/attacks/lateral_movement.py.

The chain: external brute force into web-01, SSH hop to db-01 (priv-esc +
credential theft + persistence), second hop to app-02.
"""

import pytest

from app.api.engine import AnalysisEngine
from app.models.decision import Action


@pytest.fixture
def engine(logs_dir):
    e = AnalysisEngine()
    e.ingest_file(str(logs_dir / "lateral_movement.log"))
    return e


def test_each_pivoted_host_is_its_own_attack_path(engine):

    graph = engine.attack_graph()

    #web-01 (external source), db-01 (hop 1), app-02 (hop 2)
    assert len(graph.paths) >= 3

    actors = {p.actor for p in graph.paths}
    assert "203.0.113.66" in actors        # the external entry point
    assert "10.0.5.11" in actors           # web-01 -> db-01 pivot
    assert "10.0.5.20" in actors           # db-01 -> app-02 pivot


def test_the_internal_hops_end_in_compromise(engine):

    graph = engine.attack_graph()

    compromised = [p for p in graph.paths if p.succeeded]

    #every hop lands: at least the two internal pivots plus the entry
    assert len(compromised) >= 3


def test_the_full_kill_chain_is_observed(engine):

    rules = {
        n.behavior.rule
        for path in engine.attack_graph().paths
        for n in path.nodes
    }

    assert "successful-brute-force" in rules      # got in
    assert "privilege-escalation" in rules        # tried for root on a second box
    assert "sensitive-file-access" in rules       # read /etc/shadow
    assert "persistence" in rules                 # backdoor account


def test_a_path_reaches_the_persistence_stage(engine):

    deepest = max(p.deepest_stage for p in engine.attack_graph().paths)

    assert deepest >= 6          # stage 6 == Persistence


def test_act_responds_to_every_source_address(engine):

    by_actor = {a.actor: a.decision.action for a in engine.assessments()}

    #the entry point and the first deep pivot are blocked outright
    assert by_actor["203.0.113.66"] == Action.BLOCK_IP
    assert by_actor["10.0.5.11"] == Action.BLOCK_IP

    #the freshest hop has the least evidence, so ACT escalates it to a human
    #rather than blocking autonomously - but it does not stay silent
    assert by_actor["10.0.5.20"] in (Action.BLOCK_IP, Action.ALERT)


def test_lateral_movement_report_renders(engine):

    built = engine.report("10.0.5.11", fmt="html")
    assert built is not None

    html, media_type, filename = built
    assert "db-01" in html or "10.0.5.11" in html
    assert "Persistence" in html
