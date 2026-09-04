"""The API shape is a contract with the dashboard.

Every key checked here is read by frontend/index.html. If someone renames a
field, this test fails instead of the dashboard silently showing "undefined"
during the demo.
"""

import json

import pytest

from app.api.engine import AnalysisEngine
from app.api.serializers import behaviors_to_list, events_to_list


@pytest.fixture
def engine(bruteforce_log):
    item = AnalysisEngine()
    item.ingest_file(str(bruteforce_log))
    return item


def has(data, *keys):
    for key in keys:
        assert key in data, f"missing key '{key}'"


def test_everything_the_api_returns_is_json_serialisable(engine):

    payload = {
        "stats": engine.stats(),
        "behaviors": behaviors_to_list(engine.behaviors(), evidence_limit=6),
        "graph": engine.attack_graph().to_dict(),
        "events": events_to_list(engine.events(limit=10)[0]),
        "logs": engine.available_logs(),
    }

    assert json.loads(json.dumps(payload)) == payload


def test_stats_contract(engine):

    stats = engine.stats()

    has(stats, "events", "ingestion", "behaviors", "attack", "techniques",
        "top_attackers", "top_targets", "live")

    has(stats["events"], "total", "by_type", "first", "last")
    has(stats["ingestion"], "lines_read", "events_created", "coverage", "sources")
    has(stats["behaviors"], "total", "by_severity", "by_rule", "highest_risk")
    has(stats["attack"], "paths", "worst_completeness", "deepest_stage",
        "total_stages", "compromised", "actor")
    has(stats["live"], "running", "source")

    has(stats["techniques"][0], "id", "name", "tactic", "url", "count")
    has(stats["top_attackers"][0], "ip_address", "events", "highest_risk")
    has(stats["top_targets"][0], "user", "events")

    #the dashboard divides by these, they must be numbers
    assert isinstance(stats["attack"]["worst_completeness"], float)
    assert isinstance(stats["ingestion"]["coverage"], float)
    assert isinstance(stats["behaviors"]["highest_risk"], int)


def test_behaviour_contract(engine):

    behaviour = behaviors_to_list(engine.behaviors(), evidence_limit=6)[0]

    has(behaviour, "id", "name", "description", "rule", "severity", "risk_score",
        "confidence", "stage", "stage_name", "techniques", "risk_factors",
        "attributes", "first_seen", "last_seen", "duration_seconds",
        "evidence_count", "evidence")

    has(behaviour["techniques"][0], "id", "name", "tactic", "url")
    has(behaviour["risk_factors"][0], "name", "points", "detail")
    has(behaviour["evidence"][0], "timestamp", "event_type", "description",
        "user", "ip_address")

    #the dashboard colours the card by this exact string
    assert behaviour["severity"] in {"Low", "Medium", "High", "Critical"}

    #timestamps are strings the browser can print directly
    assert isinstance(behaviour["first_seen"], str)


def test_evidence_limit_is_respected_but_the_real_count_is_kept(engine):

    behaviour = behaviors_to_list(engine.behaviors(), evidence_limit=3)[0]

    assert len(behaviour["evidence"]) == 3

    #the sample log's compromise chain: brute-force failures (incl. one
    #"maximum authentication attempts exceeded" line) plus the successful login
    full = behaviour["evidence_count"]
    assert full == 21

    unlimited = behaviors_to_list(engine.behaviors(), evidence_limit=0)[0]

    assert len(unlimited["evidence"]) == full


def test_attack_graph_contract(engine):

    graph = engine.attack_graph().to_dict()

    has(graph, "path_count", "paths")

    path = graph["paths"][0]

    has(path, "actor", "succeeded", "deepest_stage", "stages_reached",
        "total_stages", "completeness", "highest_risk", "techniques",
        "started_at", "ended_at", "nodes", "edges")

    node = path["nodes"][0]

    has(node, "id", "label", "rule", "stage", "stage_name", "severity",
        "risk_score", "techniques", "description", "first_seen", "last_seen",
        "evidence_count")

    edge = path["edges"][0]

    has(edge, "source", "target", "reasons")

    #the dashboard draws links using node ids, so edges must point at real nodes
    ids = {item["id"] for item in path["nodes"]}

    for item in path["edges"]:
        assert item["source"] in ids
        assert item["target"] in ids


def test_event_contract(engine):

    event = events_to_list(engine.events(limit=1)[0])[0]

    has(event, "id", "timestamp", "ingested_at", "source", "host", "event_type",
        "description", "user", "process", "ip_address", "metadata", "raw_log")


def test_sample_log_contract(engine):

    has(engine.available_logs()[0], "name", "size")


def test_an_empty_engine_still_returns_a_valid_shape():

    engine = AnalysisEngine()

    stats = engine.stats()

    #the dashboard must not crash before any log is loaded
    assert stats["behaviors"]["highest_risk"] == 0
    assert stats["attack"]["worst_completeness"] == 0.0
    assert stats["techniques"] == []
    assert stats["top_attackers"] == []
    assert engine.attack_graph().to_dict()["path_count"] == 0
    assert behaviors_to_list(engine.behaviors()) == []
